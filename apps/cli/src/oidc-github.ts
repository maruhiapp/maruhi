import { egressHttpClientLayer } from "@maruhi/core";
import type { LeaseClaims } from "@maruhi/crypto";
import { Effect, Redacted, Result, Schema } from "effect";
import { Base64Url } from "effect/encoding";
import { HttpClient, HttpClientError, HttpClientRequest } from "effect/http";

import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { isLoopbackHostname } from "./session.ts";

export const OIDC_REQUEST_URL_ENV = "ACTIONS_ID_TOKEN_REQUEST_URL";
export const OIDC_REQUEST_TOKEN_ENV = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";

const OIDC_ENV_MISSING_MESSAGE =
  "The GitHub Actions OIDC endpoint is not available. Run this inside a GitHub Actions job, and grant the job `permissions: id-token: write` (both ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN must be set)";

function readIssuanceEndpoint(io: {
  readonly envVar: (name: string) => string | undefined;
}): { readonly requestUrl: string; readonly requestToken: string } | null {
  const requestUrl = io.envVar(OIDC_REQUEST_URL_ENV);
  const requestToken = io.envVar(OIDC_REQUEST_TOKEN_ENV);
  if (
    requestUrl === undefined ||
    requestUrl.length === 0 ||
    requestToken === undefined ||
    requestToken.length === 0
  ) {
    return null;
  }
  return { requestUrl, requestToken };
}

function validatedIssuanceUrl(requestUrl: string, audience: string): string | null {
  let url: URL;
  try {
    url = new URL(requestUrl);
  } catch {
    return null;
  }
  const schemeOk =
    url.protocol === "https:" || (url.protocol === "http:" && isLoopbackHostname(url.hostname));
  if (!schemeOk || url.username !== "" || url.password !== "") {
    return null;
  }
  url.searchParams.set("audience", audience);
  return url.toString();
}

const IssuanceResponse = Schema.Struct({ value: Schema.NonEmptyString });
const decodeIssuanceBody = Schema.decodeEffect(Schema.fromJsonString(IssuanceResponse));

const issuanceHttpClientLayer = egressHttpClientLayer({ redirect: "manual" });

function transportReason(error: HttpClientError.HttpClientError): string {
  const cause = error.reason.cause;
  return cause instanceof Error ? cause.message : error.message;
}

const OIDC_FETCH_TIMEOUT_MS = 30_000;

export function issuanceBoundFor(token: Redacted.Redacted<string>, nowMs: number): number {
  const expiresAtMs = tokenExpiresAtMs(token);
  if (expiresAtMs === null) {
    return OIDC_FETCH_TIMEOUT_MS;
  }
  const remaining = expiresAtMs - nowMs - ISSUANCE_MARGIN_MS;
  if (remaining < ISSUANCE_FLOOR_MS) {
    return OIDC_FETCH_TIMEOUT_MS;
  }
  return Math.min(OIDC_FETCH_TIMEOUT_MS, remaining);
}

const ISSUANCE_MARGIN_MS = 2000;
const ISSUANCE_FLOOR_MS = 1000;

export const fetchGitHubOidcToken = Effect.fn("oidc-github.fetchGitHubOidcToken")(function* (
  audience: string,
  timeoutMs: number = OIDC_FETCH_TIMEOUT_MS,
): Effect.fn.Return<Redacted.Redacted<string>, CliError, CliIo> {
  const io = yield* CliIo;
  const endpoint = readIssuanceEndpoint(io);
  if (endpoint === null) {
    return yield* Effect.fail(cliError(OIDC_ENV_MISSING_MESSAGE));
  }
  const url = validatedIssuanceUrl(endpoint.requestUrl, audience);
  if (url === null) {
    return yield* Effect.fail(
      cliError(
        "ACTIONS_ID_TOKEN_REQUEST_URL is not a valid https: URL, so the runner's bearer token will not be sent to it (check the runner environment)",
      ),
    );
  }
  const outcome = yield* Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const response = yield* client.execute(
      HttpClientRequest.get(url, {
        headers: {
          accept: "application/json",
          authorization: `Bearer ${endpoint.requestToken}`,
          "user-agent": "maruhi-cli",
        },
      }),
    );
    if (response.status < 200 || response.status >= 300) {
      return { tag: "status", status: response.status } as const;
    }
    const decoded = yield* response.text.pipe(Effect.flatMap(decodeIssuanceBody));
    return { tag: "ok", value: decoded.value } as const;
  }).pipe(
    Effect.timeout(timeoutMs),
    Effect.catchTags({
      TimeoutError: () =>
        Effect.succeed({ tag: "transport", reason: "The operation timed out." } as const),
      HttpClientError: (error) =>
        Effect.succeed({ tag: "transport", reason: transportReason(error) } as const),
      SchemaError: () => Effect.succeed({ tag: "uninterpretable" } as const),
    }),
    Effect.provide(issuanceHttpClientLayer, { local: true }),
  );
  if (outcome.tag === "status") {
    return yield* Effect.fail(
      cliError(
        `Failed to fetch the GitHub Actions OIDC token (check the runner's network): HTTP ${outcome.status}`,
      ),
    );
  }
  if (outcome.tag === "transport") {
    return yield* Effect.fail(
      cliError(
        `Failed to fetch the GitHub Actions OIDC token (check the runner's network): ${outcome.reason}`,
      ),
    );
  }
  if (outcome.tag === "uninterpretable") {
    return yield* Effect.fail(
      cliError("Cannot interpret the OIDC token response from the GitHub Actions runner"),
    );
  }
  return Redacted.make(outcome.value, { label: "oidc-token" });
});

function decodeBase64Url(segment: string): Uint8Array | null {
  const decoded = Base64Url.decode(segment);
  return Result.isSuccess(decoded) ? decoded.success : null;
}

const CLAIM_FAILURE_MESSAGES = {
  malformed:
    "Cannot read the OIDC token's claims (the token is not a compact JWS with a JSON payload)",
  "multiple-audiences":
    "The OIDC token carries multiple audiences, so it cannot be used for a lease (the claims digest is not uniquely determined). Request the token with exactly one audience",
  "missing-claim":
    "The OIDC token is missing a claim the lease needs (iss / sub / aud must be non-empty)",
} as const;

type ClaimsFailure = keyof typeof CLAIM_FAILURE_MESSAGES;

function decodeTokenPayload(raw: string): unknown | null {
  const segments = raw.split(".");
  const payloadSegment = segments[1];
  if (segments.length !== 3 || payloadSegment === undefined) {
    return null;
  }
  const payloadBytes = decodeBase64Url(payloadSegment);
  if (payloadBytes === null) {
    return null;
  }
  try {
    const payload: unknown = JSON.parse(new TextDecoder().decode(payloadBytes));
    return typeof payload === "object" && payload !== null ? payload : null;
  } catch {
    return null;
  }
}

export function tokenExpiresAtMs(token: Redacted.Redacted<string>): number | null {
  const payload = decodeTokenPayload(Redacted.value(token));
  if (typeof payload !== "object" || payload === null) {
    return null;
  }
  const exp = (payload as Record<string, unknown>)["exp"];
  return typeof exp === "number" && Number.isFinite(exp) ? exp * 1000 : null;
}

function claimsOfPayload(payload: unknown | null): LeaseClaims | ClaimsFailure {
  if (payload === null) {
    return "malformed";
  }
  const record = payload as Record<string, unknown>;
  const issuerUrl = record["iss"];
  const subject = record["sub"];
  const audience = singleAudience(record["aud"]);
  if (audience === "multiple") {
    return "multiple-audiences";
  }
  if (
    typeof issuerUrl !== "string" ||
    issuerUrl.length === 0 ||
    typeof subject !== "string" ||
    subject.length === 0 ||
    audience === null
  ) {
    return "missing-claim";
  }
  return { issuerUrl, subject, audience };
}

export function readLeaseClaims(
  token: Redacted.Redacted<string>,
): Effect.Effect<LeaseClaims, CliError> {
  const outcome = claimsOfPayload(decodeTokenPayload(Redacted.value(token)));
  if (typeof outcome === "string") {
    return Effect.fail(cliError(CLAIM_FAILURE_MESSAGES[outcome]));
  }
  return Effect.succeed(outcome);
}

function singleAudience(value: unknown): string | null | "multiple" {
  if (typeof value === "string") {
    return value.length > 0 ? value : null;
  }
  if (Array.isArray(value)) {
    if (value.length > 1) {
      return "multiple";
    }
    const only: unknown = value[0];
    return typeof only === "string" && only.length > 0 ? only : null;
  }
  return null;
}
