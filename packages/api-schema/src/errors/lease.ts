// Typed errors of the workload-lease API (AUTH_SPEC §14-3).
//
// Errors carry only reason codes and counters. They must not carry the
// OIDC token's value, claims, or external identifiers such as
// repository names (same discipline as §14-4 / AUDIT_SPEC §1-2 —
// responses do not carry what audit rows do not write).
//
// Existence concealment (§14-1 / §11-2): policy mismatch, out of scope,
// no grant, and unknown project are all 404 (ProjectNotFound /
// EnvironmentNotFound) and never appear in this file. Only three
// reasons live here: "authentication-stage failure", "cannot issue",
// and "window exhausted".

import { Schema } from "effect";

/**
 * Reason codes for a rejected OIDC token (the AUTH_SPEC §14-1
 * authentication stage).
 *
 * All of these are attributable to the presented token alone and carry no
 * project state, so returning the specific reason keeps existence hiding
 * intact while giving CI jobs something actionable to read in a log.
 *
 * - `malformed-token` — not a compact JWS, or the header / payload is not JSON
 * - `unsupported-alg` — `alg` outside the RS256 / ES256 allowlist (`none` and
 *   the symmetric algorithms land here)
 * - `unsupported-crit` — the JOSE header declares a `crit` extension. RFC 7515
 *   §4.1.11 requires rejecting a JWS whose critical extensions the recipient
 *   does not implement, and this deployment implements none
 * - `unsupported-issuer` — `iss` outside this deployment's static issuer list
 * - `unknown-key` — no JWKS key matches the token's `kid`
 * - `signature-invalid` — the signature does not verify under the JWKS key
 * - `token-expired` — `exp` is in the past (beyond the ±60s skew)
 * - `token-not-yet-valid` — `iat` / `nbf` is in the future (beyond the skew)
 * - `missing-claim` — a claim the lease path requires (`iss` / `sub` / `aud` /
 *   `exp` / `iat`) is absent or not a string
 * - `ambiguous-audience` — the token carries several audiences, so the
 *   `claims_digest` (CRYPTO_SPEC §9.1) is not uniquely determined. Distinct
 *   from `missing-claim`: the `aud` claim *is* present, and an operator
 *   reading the reason code should not go looking for a claim that exists
 * - `token-replayed` — the token was already used to issue a lease to a
 *   *different* ephemeral key (first-use binding — the AUTH_SPEC §14-1
 *   first-come binding).
 *   Retrying with the same token never succeeds; a runtime
 *   issuer (GitHub Actions) should mint a fresh token and retry once. Unlike
 *   the other reasons this is checked after authorization (it needs the
 *   project's binding state), which keeps existence hiding intact: only a
 *   caller whose token already matches an on-chain lease policy can reach it
 */
export const LeaseUnauthorizedReasonSchema = Schema.Literals([
  "malformed-token",
  "unsupported-alg",
  "unsupported-crit",
  "unsupported-issuer",
  "unknown-key",
  "signature-invalid",
  "token-expired",
  "token-not-yet-valid",
  "missing-claim",
  "ambiguous-audience",
  "token-replayed",
]);

/**
 * 401: the presented OIDC token cannot be used (AUTH_SPEC §14-1 / §14-3).
 * Everything here is attributable to the presented credential alone —
 * everything about *this project's* grant, policy and scope is 404 (the
 * §14-1 existence concealment). `token-replayed` is the one reason
 * produced after authorization
 * (see its note above); it still reveals nothing a policy-matching token
 * holder would not learn from a successful lease.
 */
export class LeaseUnauthorizedError extends Schema.TaggedError<LeaseUnauthorizedError>()(
  "LeaseUnauthorized",
  { reason: LeaseUnauthorizedReasonSchema },
  { httpApiStatus: 401 },
) {}

/**
 * Reason codes for a lease that is authorized but cannot be issued right now
 * (AUTH_SPEC §14-3).
 *
 * - `server-wraps-missing` — the grant is valid and the environment is in
 *   scope, but the epoch DEK has not been re-wrapped to the server key
 *   (the CRYPTO_SPEC §7 rotation obligation is still outstanding). A
 *   dedicated reason so that "granted but not yet re-wrapped" is not an
 *   opaque failure (§14-3)
 * - `oidc-jwks-unavailable` — the issuer's JWKS could not be fetched, so the
 *   signature could not be checked at all. Verification stays fail-closed
 *   (§14-1) — this reason only changes *how* the refusal is reported: a
 *   transient issuer / network outage is not the workload's credential being
 *   bad, and a 401 would make CI jobs fail permanently on a retryable
 *   condition (§14-3)
 * - `server-key-unconfigured` — this deployment has no `SERVER_ENC_KEY_IKM`
 *   (CRYPTO_SPEC §9). A grant existing on-chain while the server key is
 *   unconfigured is a missing deployment setting, so the response is
 *   the same "points to setup" kind as SetupIncomplete (without the
 *   private key no unwrap path exists)
 */
export const LeaseUnavailableReasonSchema = Schema.Literals([
  "server-wraps-missing",
  "oidc-jwks-unavailable",
  "server-key-unconfigured",
]);

/**
 * 503: the lease is authorized but cannot be issued (AUTH_SPEC §14-3).
 * Distinct from 404 on purpose — reaching this response already means the
 * caller matched an on-chain lease policy, so it leaks nothing new.
 */
export class LeaseUnavailableError extends Schema.TaggedError<LeaseUnavailableError>()(
  "LeaseUnavailable",
  { reason: LeaseUnavailableReasonSchema },
  { httpApiStatus: 503 },
) {}

/**
 * Which limit produced a lease 429:
 *
 * - `project-window` — the per-project fixed window (AUTH_SPEC §14-3, judged
 *   after authorization to preserve existence hiding)
 * - `source-address` — the request-level per-source-IP limit (judged first in
 *   the handler; independent of any project state, so it leaks nothing).
 *   Remedies differ: the project window drains on its own, while a legitimate
 *   shared-egress fleet hitting the per-IP limit needs the operator to raise
 *   the binding limit (docs/SELF_HOSTING.md)
 */
export const LeaseRateLimitScopeSchema = Schema.Literals(["project-window", "source-address"]);

/**
 * 429: a lease rate limit is exhausted (AUTH_SPEC §14-3).
 * `retryAfterSeconds` is the remaining seconds of the window (same
 * shape as the §13-3 precedent). `scope` distinguishes the two windows
 * above (omitted = an old server's response = equivalent to
 * project-window).
 *
 * The project window is judged *after* authorization: judged earlier,
 * an unauthorized caller would also get a 429 and "that project
 * exists" would leak (a §11-2 violation). Judged later, the 429
 * reaches only legitimate workloads, and the only principals that can
 * consume the window are those satisfying "valid signature by an
 * allowed issuer × policy match". The source-address window is
 * independent of project state, so it leaks no existence information
 * even when judged before authorization.
 */
export class LeaseRateLimitedError extends Schema.TaggedError<LeaseRateLimitedError>()(
  "LeaseRateLimited",
  {
    retryAfterSeconds: Schema.Number,
    scope: Schema.optionalKey(LeaseRateLimitScopeSchema),
  },
  { httpApiStatus: 429 },
) {}
