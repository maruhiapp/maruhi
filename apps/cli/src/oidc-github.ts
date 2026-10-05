// Fetching the GitHub Actions OIDC token and reading its claims
// (the client side of AUTH_SPEC §14-1 — v1's only supported issuer
// is GitHub Actions).
//
// The token is a bearer credential and is treated like a plaintext
// value / key material: wrap it in `Redacted` and never put it on
// logs, errors, or diagnostics (CLAUDE.md). Unwrapping happens in
// exactly two places: claims reading (this file) and assembling the
// lease request payload (ci-run.ts) (registered in redacted.test.ts's
// inventory).
//
// Claims reading needs only base64url decode + JSON.parse: signature
// verification is the server's job (AUTH_SPEC §14-1); the client
// only reads iss / sub / aud from **its own** token to compute
// claims_digest (CRYPTO_SPEC §9.1) independently. No JWT library is
// added (no new dependencies).
//
// Runner-supplied environment variables are read via `CliIo.envVar`
// (the Effect service boundary) — `process.env` is never read
// directly (CLAUDE.md. Production is live.ts; tests substitute a
// Map). Future pre-issued-style issuers (GitLab / k8s projected
// volumes) are handled by swapping this module (the verify/open
// layer stays lease-client.ts).

import { egressHttpClientLayer } from "@maruhi/core";
import type { LeaseClaims } from "@maruhi/crypto";
import { Effect, Redacted, Schema } from "effect";
import { HttpClient, HttpClientError, HttpClientRequest } from "effect/http";

import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { isLoopbackHostname } from "./session.ts";

/** The environment variables of the OIDC issuance endpoint the GitHub Actions runner supplies. */
export const OIDC_REQUEST_URL_ENV = "ACTIONS_ID_TOKEN_REQUEST_URL";
export const OIDC_REQUEST_TOKEN_ENV = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";

/** Guidance for a run without the OIDC issuance endpoint (states the requirement on the spot). */
const OIDC_ENV_MISSING_MESSAGE =
  "The GitHub Actions OIDC endpoint is not available. Run this inside a GitHub Actions job, and grant the job `permissions: id-token: write` (both ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN must be set)";

/** The runner-supplied issuance endpoint (missing or empty both count as "absent"). */
function readIssuanceEndpoint(io: {
  readonly envVar: (name: string) => string | undefined;
}): { readonly requestUrl: string; readonly requestToken: string } | null {
  const requestUrl = io.envVar(OIDC_REQUEST_URL_ENV);
  // The runner token is also a bearer credential, but it exists only
  // in this module's locals and is consumed by the header right
  // after (it does not cross the module boundary, so it is not
  // wrapped). Never onto logs or errors
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

/**
 * Validates the issuance endpoint URL and attaches the audience
 * parameter. Non-`https:`, embedded credentials, and unparseable
 * are null (the caller turns them into a typed error).
 */
function validatedIssuanceUrl(requestUrl: string, audience: string): string | null {
  let url: URL;
  try {
    url = new URL(requestUrl);
  } catch {
    return null;
  }
  // `http:` is allowed only for loopback (for tests and local
  // mocks — plaintext never crosses the network). Everything else
  // requires `https:`. Loopback judgment is the CLI-shared
  // isLoopbackHostname (session.ts) — strict IPv4-literal checking,
  // so a public DNS name like "127.evil.com" does not pass
  const schemeOk =
    url.protocol === "https:" || (url.protocol === "http:" && isLoopbackHostname(url.hostname));
  if (!schemeOk || url.username !== "" || url.password !== "") {
    return null;
  }
  url.searchParams.set("audience", audience);
  return url.toString();
}

/** The issuance endpoint's JSON body — only `{ value }` is read (any other shape is "uninterpretable", and nothing else leaves it). */
const IssuanceResponse = Schema.Struct({ value: Schema.NonEmptyString });
const decodeIssuanceBody = Schema.decodeEffect(Schema.fromJsonString(IssuanceResponse));

/**
 * The HttpClient layer the issuance fetch runs on — the repo's shared
 * egress client (no trace headers) with `redirect: "manual"` fixed for
 * every request: **never follow redirects** — a redirect could re-send
 * the runner's bearer token to the redirect target. A 3xx is rejected
 * by the status check below.
 */
const issuanceHttpClientLayer = egressHttpClientLayer({ redirect: "manual" });

/**
 * The message an `HttpClientError` carries: the transport's own cause (the
 * fetch rejection — a refused connection, a DNS failure) when it has one,
 * the client's wording ("Transport error", "Decode error"…) otherwise.
 * (Same chain as W1 rotate-connector.ts — kept local because its helper is
 * file-private there.)
 */
function transportReason(error: HttpClientError.HttpClientError): string {
  const cause = error.reason.cause;
  return cause instanceof Error ? cause.message : error.message;
}

/**
 * Fetches a fresh GitHub Actions OIDC token for `audience`.
 *
 * The token is issued **immediately before** the lease request
 * (session-24 §8 SHOULD — minimizing the first-come binding's
 * exposure window). Since each call mints a fresh token, retrying
 * `token-replayed` (ci-run.ts) is just calling this function again.
 */
/** The bound on the runner's issuance endpoint (the same as the API client's header bound). */
const OIDC_FETCH_TIMEOUT_MS = 30_000;

/**
 * The bound on the issuance fetch when a token is in hand: its remaining
 * life minus a margin, never above the default — a hung endpoint must not
 * eat the fallback to that token (ruling O revision, round 7). With no
 * token in hand, or one that cannot outlive even the shortest bound (an
 * expired one — there is no fallback left to protect, so a short bound
 * would only remove the one path to success; round 8, O-19), the default
 * applies.
 */
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

/** Left of the token's life for the request that presents it, after a fetch that times out. */
const ISSUANCE_MARGIN_MS = 2000;
/** The shortest bound worth giving the fetch; a token in hand with less life than this is no fallback. */
const ISSUANCE_FLOOR_MS = 1000;

export function fetchGitHubOidcToken(
  audience: string,
  /** The bound on the fetch (default {@link OIDC_FETCH_TIMEOUT_MS}; shorter when a token in hand would expire first). */
  timeoutMs: number = OIDC_FETCH_TIMEOUT_MS,
): Effect.Effect<Redacted.Redacted<string>, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const endpoint = readIssuanceEndpoint(io);
    if (endpoint === null) {
      return yield* Effect.fail(cliError(OIDC_ENV_MISSING_MESSAGE));
    }
    // Validate the URL before sending the runner token (a bearer
    // credential): refuse non-`https:` (plaintext http, custom
    // schemes) and embedded credentials. The host is not pinned —
    // GitHub-hosted runners do not have a fixed hostname and GHES
    // can be any host, so an allowlist would only break legitimate
    // runs without adding attack coverage (the position that can
    // swap env vars = a position that can already write the job
    // definition)
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
      // A hung issuance endpoint must not hold the job: the lease's token
      // fallback and the recovery message are reached while that token
      // lives (ruling O revision, round 6 — the API client's bound). It
      // covers the request and the body read, matching the pre-HttpClient
      // AbortSignal.timeout
      Effect.timeout(timeoutMs),
      // Inside this region every failure is foreign — transport, a hung
      // endpoint, an undecodable body — so each is normalized to its own
      // verdict wholesale. A decode failure's SchemaError can carry a
      // fragment of the response body, and this body is the token's
      // transport: it folds into "uninterpretable" so no part of it
      // reaches an error
      Effect.catchTags({
        TimeoutError: () =>
          Effect.succeed({ tag: "transport", reason: "The operation timed out." } as const),
        HttpClientError: (error) =>
          Effect.succeed({ tag: "transport", reason: transportReason(error) } as const),
        SchemaError: () => Effect.succeed({ tag: "uninterpretable" } as const),
      }),
      // `local: true` rebuilds the layer per use: a layer is shared between
      // `Effect.provide` calls by default, so the `FetchHttpClient.layer`
      // inside the egress layer would resolve to the ambient build (which
      // never carries the RequestInit) when a client already exists in the
      // environment — and `redirect: "manual"` would silently drop
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
    // The bare string that arrived from outside the environment is
    // wrapped here. From here on the token only flows as Redacted
    // (unwrapping is the 2 places: claims reading and the lease
    // payload)
    return Redacted.make(outcome.value, { label: "oidc-token" });
  });
}

/** base64url → bytes (null when malformed. Never put a token fragment onto an exception message). */
function decodeBase64Url(segment: string): Uint8Array | null {
  const base64 = segment.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    return null;
  }
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

/** A compact JWS's payload segment → JSON value (null when malformed). */
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

/** The token's `exp` as a millisecond instant (null when absent or malformed) — the fallback check of a mint (K-6). */
export function tokenExpiresAtMs(token: Redacted.Redacted<string>): number | null {
  // Why it is unwrapped: reading one numeric claim of my own token; nothing else leaves
  const payload = decodeTokenPayload(Redacted.value(token));
  if (typeof payload !== "object" || payload === null) {
    return null;
  }
  const exp = (payload as Record<string, unknown>)["exp"];
  return typeof exp === "number" && Number.isFinite(exp) ? exp * 1000 : null;
}

/** payload → the 3 claims the lease binds (a reason code when malformed). */
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

/**
 * Reads the claims the lease path binds (CRYPTO_SPEC §9.1: issuer / sub /
 * aud) from the workload's own token. The digest itself is computed by
 * `computeLeaseClaimsDigest` — never from the raw builder (the builder skips
 * the empty-field guard).
 *
 * A token with multiple `aud` is refused: claims_digest is not
 * uniquely determined, and the server refuses it for the same
 * reason as `ambiguous-audience` (errors/lease.ts). The client
 * issues the same judgment before making the round trip.
 */
export function readLeaseClaims(
  token: Redacted.Redacted<string>,
): Effect.Effect<LeaseClaims, CliError> {
  // Why it is unwrapped: reading the claims of my own token
  // (decoding the payload segment). The product is only the 3
  // strings iss / sub / aud — the token body does not leave
  const outcome = claimsOfPayload(decodeTokenPayload(Redacted.value(token)));
  if (typeof outcome === "string") {
    return Effect.fail(cliError(CLAIM_FAILURE_MESSAGES[outcome]));
  }
  return Effect.succeed(outcome);
}

/** Extracts a single `aud` claim value (only a single string | a 1-element array is accepted). */
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
