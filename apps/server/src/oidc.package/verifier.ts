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
import { Context, Effect, Exit, Result } from "effect";
import { Digest, Signature } from "effect/crypto";
import { Base64Url } from "effect/encoding";
import { Jws } from "effect/jose";

import { type JwksCacheShape, makeJwksCache } from "./jwks.ts";

/** JWS `alg` values this deployment accepts (AUTH_SPEC §14-1). */
type AllowedAlg = "RS256" | "ES256";

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
  ) => Effect.Effect<
    VerifiedOidcToken,
    LeaseUnauthorizedError | LeaseUnavailableError,
    Digest.Digest | Signature.Signature
  >;
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
  readonly signingInput: Uint8Array;
}

/** The 3 decoded segments (shape satisfied, contents not yet checked). */
interface DecodedSegments {
  readonly header: Readonly<Record<string, unknown>>;
  readonly claims: Readonly<Record<string, unknown>>;
  readonly signingInput: Uint8Array;
}

const BASE64URL_SEGMENT = /^[A-Za-z0-9_-]*$/;

/**
 * Decodes one base64url segment. Returns null for anything malformed.
 *
 * Decoding itself is `effect/encoding`'s, but the segment is first
 * held to the strict shape the JWS compact serialization requires
 * (RFC 7515 Appendix C): characters outside the alphabet and invalid
 * lengths (mod 4 == 1) are rejected up front, because the upstream
 * decoder is lenient about `=` padding and CR/LF — and a lenient
 * decode must not create a path that "passes as different bytes" (the
 * signed content is the raw segment strings, and lenient decoding
 * would create a gap between the verified bytes and the restored
 * value).
 */
function decodeBase64Url(segment: string): Uint8Array | null {
  if (!BASE64URL_SEGMENT.test(segment) || segment.length % 4 === 1) {
    return null;
  }
  const decoded = Base64Url.decode(segment);
  return Result.isSuccess(decoded) ? decoded.success : null;
}

/**
 * Decodes one base64url segment as UTF-8 JSON. Returns null for
 * anything malformed (the UTF-8 decode is fatal, for the same reason
 * as above).
 */
function decodeSegmentJson(segment: string): unknown {
  const bytes = decodeBase64Url(segment);
  if (bytes === null) {
    return null;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch {
    return null;
  }
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
  const header = asRecord(decodeSegmentJson(headerSegment));
  const claims = asRecord(decodeSegmentJson(payloadSegment));
  // The signature segment is only form-checked here (the strict shape
  // above): its bytes are consumed by effect/jose's own parse when the
  // signature is verified, never by this stage
  const signatureWellFormed =
    BASE64URL_SEGMENT.test(signatureSegment) && signatureSegment.length % 4 !== 1;
  if (header === null || claims === null || !signatureWellFormed) {
    return null;
  }
  return {
    header,
    claims,
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
      // branching — the key resolved above carries the algorithm the
      // JWK side determined, and effect/jose's verify enforces the
      // same equality again internally)
      if (parsed.alg !== resolved.key.algorithm) {
        return yield* unauthorized("unsupported-alg");
      }
      // Signature verification itself is effect/jose's: it re-parses
      // the compact serialization and verifies over the received
      // segment strings. Any failure of it — an invalid signature, a
      // header its parser refuses, a failing crypto service — is the
      // same verdict the old WebCrypto call's `false` / rejection
      // produced: the token does not verify
      const verification = yield* Effect.exit(Jws.verify(token, resolved.key));
      if (!Exit.isSuccess(verification)) {
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
      // only after signature verification passes. The hash goes through
      // the `Digest` service (crypto-services seam); a failed digest is
      // an environment defect, as a rejected `crypto.subtle.digest`
      // promise was before
      const signingInputHashHex = yield* Effect.orDie(
        Effect.flatMap(Digest.Digest, (digest) =>
          digest.digestHex(Digest.sha256, parsed.signingInput),
        ),
      );
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
