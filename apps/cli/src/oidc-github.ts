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

import type { LeaseClaims } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

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

/** Extracts the token from the issuance endpoint's response (`{ value }`). */
function tokenOfIssuanceBody(body: unknown): string | null {
  const value =
    typeof body === "object" && body !== null
      ? (body as Record<string, unknown>)["value"]
      : undefined;
  return typeof value === "string" && value.length > 0 ? value : null;
}

/**
 * Fetches a fresh GitHub Actions OIDC token for `audience`.
 *
 * The token is issued **immediately before** the lease request
 * (session-24 §8 SHOULD — minimizing the first-come binding's
 * exposure window). Since each call mints a fresh token, retrying
 * `token-replayed` (ci-run.ts) is just calling this function again.
 */
export function fetchGitHubOidcToken(
  audience: string,
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
    const body = yield* Effect.tryPromise({
      try: async () => {
        // Redirects are not followed: the default follow could
        // re-send the request with the bearer header to the redirect
        // target. 3xx falls to failure as !ok
        const response = await fetch(url, {
          method: "GET",
          redirect: "manual",
          headers: {
            accept: "application/json",
            authorization: `Bearer ${endpoint.requestToken}`,
            "user-agent": "maruhi-cli",
          },
        });
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        // JSON.parse exceptions are swallowed here (guarded parse):
        // a parse error's message can contain a fragment of the
        // response body, and this response's body is the token's
        // transport. Do not pass it through raw — fold into
        // "uninterpretable"
        const text = await response.text();
        try {
          return JSON.parse(text) as unknown;
        } catch {
          return null;
        }
      },
      catch: (error) =>
        cliError(
          `Failed to fetch the GitHub Actions OIDC token (check the runner's network): ${
            error instanceof Error ? error.message : String(error)
          }`,
        ),
    });
    const value = tokenOfIssuanceBody(body);
    if (value === null) {
      return yield* Effect.fail(
        cliError("Cannot interpret the OIDC token response from the GitHub Actions runner"),
      );
    }
    // The bare string that arrived from outside the environment is
    // wrapped here. From here on the token only flows as Redacted
    // (unwrapping is the 2 places: claims reading and the lease
    // payload)
    return Redacted.make(value, { label: "oidc-token" });
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
