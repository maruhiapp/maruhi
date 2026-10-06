// OIDC token verification (AUTH_SPEC §14-1's authentication stage).
//
// **Verification completes here and never consults chain-derived state
// (grants, lease_policy)** (§14-1). Comparison against the policy is
// authorization and belongs on the lease-program side. This separation
// structurally guarantees "authentication failure alone is 401 /
// authorization failure is uniformly 404" (§14-3's existence hiding).
//
// Check order (every step completes on the token alone; no project
// state is read):
//   1. Form (the 3 segments of a compact JWS; JSON header / payload)
//   2. `alg` inside the allowlist (RS256 / ES256)
//   3. `iss` inside **the static supported-issuer list** — **before any
//      external fetch**, so an unauthenticated endpoint cannot be made
//      to fetch arbitrary URLs
//   4. JWKS resolution (a fetch failure is 503 — §14-1's fail-closed)
//      and signature verification
//   5. Presence of required claims and time checks (clock skew ±60s)

import { LeaseUnauthorizedError, LeaseUnavailableError } from "@maruhi/api-schema";
import { encodeHex } from "@maruhi/crypto";
import { Context, Effect } from "effect";

import { decodeBase64Url, decodeBase64UrlJson } from "./base64url.ts";
import type { AllowedAlg } from "./jwk.ts";
import { verifyJwsSignature } from "./jwk.ts";
import { type JwksCacheShape, makeJwksCache } from "./jwks.ts";

/**
 * The supported-issuer list (§14-1): **a static configuration uniform
 * across the whole deployment** that carries no project existence or
 * state information. v1 covers GitHub Actions only (session-22 §2 R1:
 * "v1 enables GitHub only"). Adding GitLab / CircleCI / k8s etc. is a
 * matter of appending here alone; the chain format (the issuer-generic
 * lease_policy in grant_server payloads) needs no change.
 */
const SUPPORTED_ISSUERS: readonly string[] = ["https://token.actions.githubusercontent.com"];

/** The allowed algorithms (§14-1). Symmetric-key algs and `none` are absent here. */
const ALLOWED_ALGS: readonly AllowedAlg[] = ["RS256", "ES256"];

/**
 * The tolerated skew of the time checks (§14-1: ±60 seconds). It is
 * exported so a derivation can guarantee that the first-come-binding
 * (§14-1) retention slack (policy.ts's LEASE_BINDING_RETENTION_MARGIN_MS) is
 * **at least** this value — a binding retention shorter than the
 * acceptance window becomes a replay window (the precedent of
 * session-24 §2's PyPI audit).
 */
export const OIDC_CLOCK_SKEW_MS = 60 * 1000;
const CLOCK_SKEW_MS = OIDC_CLOCK_SKEW_MS;

/**
 * Only the values the lease path uses, extracted from the verified
 * token. `claims` is the raw payload used to evaluate claim
 * constraints (§14-1's existential quantification) and **appears in
 * neither audit nor responses** (no external identifiers are imported
 * — §14-4).
 */
export interface VerifiedOidcToken {
  readonly issuer: string;
  readonly subject: string;
  /** `aud` takes both string / array forms, so it is always normalized to an array. */
  readonly audiences: readonly string[];
  readonly claims: Readonly<Record<string, unknown>>;
  /**
   * The verified `exp` (seconds). Input to the binding row's lifetime
   * in first-come binding (§14-1) — the lifetime must be at least "the
   * last time a time check could accept this token".
   */
  readonly expiresAtSec: number;
  /**
   * The first-come-binding key (§14-1) = SHA-256 of the JWS signing
   * input (`header.payload`).
   *
   * **The raw token string must never be hashed**: the raw token
   * includes the third segment (the signature), which lies **outside
   * the signature's protection** and is malleable — via the unused
   * bits of base64url's trailing group (which WHATWG forgiving-base64
   * decode discards), the characters can be swapped without changing
   * the decoded bytes (an RS256 trailing character has 15 equivalent
   * values; ES256 additionally carries `s`-malleability). If the raw
   * token were the binding key, a one-character edit that changes only
   * the hash — leaving signature verification and claims_digest
   * untouched — would make the binding match miss, disabling replay
   * protection entirely. The signing input is the very byte string the
   * issuer actually signed, invariant under validity-preserving
   * mutation, and it closes this path.
   */
  readonly signingInputHashHex: string;
}

export interface OidcVerifierShape {
  readonly verify: (
    token: string,
    nowMs: number,
  ) => Effect.Effect<VerifiedOidcToken, LeaseUnauthorizedError | LeaseUnavailableError>;
}

export class OidcVerifier extends Context.Service<OidcVerifier, OidcVerifierShape>()(
  "OidcVerifier",
) {}

const unauthorized = (reason: LeaseUnauthorizedError["reason"]) =>
  Effect.fail(new LeaseUnauthorizedError({ reason }));

function asRecord(value: unknown): Readonly<Record<string, unknown>> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringClaim(claims: Readonly<Record<string, unknown>>, name: string): string | null {
  const value = claims[name];
  return typeof value === "string" && value.length > 0 ? value : null;
}

/** Numeric claims (`exp` / `iat` / `nbf`) accept only finite numbers in seconds. */
function numericClaim(claims: Readonly<Record<string, unknown>>, name: string): number | null {
  const value = claims[name];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/** `aud` is a string / string array (RFC 7519). Anything else is treated as a claim deficiency. */
function audiencesOf(claims: Readonly<Record<string, unknown>>): readonly string[] | null {
  const value = claims["aud"];
  if (typeof value === "string") {
    return value.length > 0 ? [value] : null;
  }
  if (Array.isArray(value) && value.length > 0 && value.every((a) => typeof a === "string")) {
    return value as readonly string[];
  }
  return null;
}

interface ParsedToken {
  readonly alg: AllowedAlg;
  readonly kid: string | null;
  readonly claims: Readonly<Record<string, unknown>>;
  readonly signature: Uint8Array;
  readonly signingInput: Uint8Array;
}

/** The 3 decoded segments (shape satisfied, contents not yet checked). */
interface DecodedSegments {
  readonly header: Readonly<Record<string, unknown>>;
  readonly claims: Readonly<Record<string, unknown>>;
  readonly signature: Uint8Array;
  readonly signingInput: Uint8Array;
}

/**
 * Decodes the 3 segments of a compact JWS (stage 1). The signed
 * content is **the received segment strings themselves**
 * (`header.payload`), not a decode → re-serialize product
 * (re-serialization would change the bytes and make signature
 * verification meaningless).
 */
function decodeSegments(token: string): DecodedSegments | null {
  const segments = token.split(".");
  if (segments.length !== 3) {
    return null;
  }
  const [headerSegment, payloadSegment, signatureSegment] = segments;
  if (
    headerSegment === undefined ||
    payloadSegment === undefined ||
    signatureSegment === undefined
  ) {
    return null;
  }
  const header = asRecord(decodeBase64UrlJson(headerSegment));
  const claims = asRecord(decodeBase64UrlJson(payloadSegment));
  const signature = decodeBase64Url(signatureSegment);
  if (header === null || claims === null || signature === null) {
    return null;
  }
  return {
    header,
    claims,
    signature,
    signingInput: new TextEncoder().encode(`${headerSegment}.${payloadSegment}`),
  };
}

/**
 * Checks form, `crit`, and the `alg` allowlist (stages 1–2).
 *
 * **`crit` (RFC 7515 §4.1.11) is rejected by its mere presence**: crit
 * declares "extensions that must not be accepted if not understood",
 * and since this implementation implements zero extensions, every crit
 * value falls under "not understood". Implementations that dropped
 * this check became CVEs in several major libraries in 2025–2026
 * (Authlib CVE-2025-59420 / PyJWT CVE-2026-32597 / fast-jwt
 * CVE-2026-35042).
 *
 * `typ` is **not checked** (intentionally): it is optional per RFC
 * 7519 §5.1, and cross-JWT confusion is already strongly mitigated by
 * the issuer allowlist + audience match + claim constraints. On top of
 * that, maruhi itself issues no JWTs (AUTH_SPEC §1-3 / §6 — sessions
 * and API tokens are opaque random values), so there is no counterpart
 * JWT to confuse with. Gaining nothing while carrying the risk of
 * dropping legitimate tokens over issuer-side implementation
 * differences, this stays lenient.
 */
function parseToken(token: string): Effect.Effect<ParsedToken, LeaseUnauthorizedError> {
  const decoded = decodeSegments(token);
  if (decoded === null) {
    return unauthorized("malformed-token");
  }
  if (decoded.header["crit"] !== undefined) {
    return unauthorized("unsupported-crit");
  }
  const alg = decoded.header["alg"];
  if (typeof alg !== "string" || !ALLOWED_ALGS.includes(alg as AllowedAlg)) {
    return unauthorized("unsupported-alg");
  }
  const kid = decoded.header["kid"];
  return Effect.succeed({
    alg: alg as AllowedAlg,
    kid: typeof kid === "string" ? kid : null,
    claims: decoded.claims,
    signature: decoded.signature,
    signingInput: decoded.signingInput,
  });
}

/** Time checks (stage 5. §14-1: clock skew ±60 seconds). */
function checkTimes(
  claims: Readonly<Record<string, unknown>>,
  nowMs: number,
): Effect.Effect<void, LeaseUnauthorizedError> {
  const exp = numericClaim(claims, "exp");
  const iat = numericClaim(claims, "iat");
  // exp / iat are both required (§14-1's (3)). A token lacking them
  // could become a credential usable without expiry, so do not fall on
  // the lenient side
  if (exp === null || iat === null) {
    return unauthorized("missing-claim");
  }
  if (exp * 1000 + CLOCK_SKEW_MS <= nowMs) {
    return unauthorized("token-expired");
  }
  if (iat * 1000 - CLOCK_SKEW_MS > nowMs) {
    return unauthorized("token-not-yet-valid");
  }
  const nbf = numericClaim(claims, "nbf");
  if (nbf !== null && nbf * 1000 - CLOCK_SKEW_MS > nowMs) {
    return unauthorized("token-not-yet-valid");
  }
  return Effect.void;
}

/**
 * The OIDC verifier (one per isolate; confines the JWKS cache).
 * `jwks` is taken as an argument so tests can substitute it.
 */
export function makeOidcVerifier(
  jwks: JwksCacheShape = makeJwksCache(),
  supportedIssuers: readonly string[] = SUPPORTED_ISSUERS,
): OidcVerifierShape {
  return {
    verify: Effect.fn("verifier.verify")(function* (token, nowMs) {
      const parsed = yield* parseToken(token);
      const issuer = stringClaim(parsed.claims, "iss");
      if (issuer === null) {
        return yield* unauthorized("missing-claim");
      }
      // Allowlist matching **before any external fetch** (the DoS
      // rationale in the header comment)
      if (!supportedIssuers.includes(issuer)) {
        return yield* unauthorized("unsupported-issuer");
      }
      const resolved = yield* jwks.resolveKey(issuer, parsed.kid).pipe(
        // A fetch failure is fail-closed (§14-1) but 503, not 401:
        // telling a transient issuer / network outage as "bad
        // credentials" would make the CI job treat it as a
        // non-retryable failure (errors/lease.ts)
        Effect.mapError(() => new LeaseUnavailableError({ reason: "oidc-jwks-unavailable" })),
      );
      if (resolved === null) {
        return yield* unauthorized("unknown-key");
      }
      // The header's alg is used only for the match check against
      // "the expectation derived from the JWK" (never an input to
      // branching — jwk.ts's design)
      if (parsed.alg !== resolved.binding.headerAlg) {
        return yield* unauthorized("unsupported-alg");
      }
      const verified = yield* Effect.promise(() =>
        verifyJwsSignature({
          key: resolved.key,
          binding: resolved.binding,
          signature: parsed.signature,
          signingInput: parsed.signingInput,
        }),
      );
      if (!verified) {
        return yield* unauthorized("signature-invalid");
      }
      yield* checkTimes(parsed.claims, nowMs);
      const subject = stringClaim(parsed.claims, "sub");
      const audiences = audiencesOf(parsed.claims);
      // exp's presence and type are already verified by checkTimes
      // (null cannot reach here)
      const expiresAtSec = numericClaim(parsed.claims, "exp");
      if (subject === null || audiences === null || expiresAtSec === null) {
        return yield* unauthorized("missing-claim");
      }
      // The first-come-binding key is a hash of **the signed bytes**
      // (not the raw token — see signingInputHashHex's doc). Computed
      // only after signature verification passes
      const digest = yield* Effect.promise(() =>
        crypto.subtle.digest("SHA-256", new Uint8Array(parsed.signingInput)),
      );
      const signingInputHashHex = encodeHex(new Uint8Array(digest));
      return {
        issuer,
        subject,
        audiences,
        claims: parsed.claims,
        expiresAtSec,
        signingInputHashHex,
      };
    }),
  };
}
