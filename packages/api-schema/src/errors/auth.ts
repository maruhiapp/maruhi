// Typed errors of the auth / identity API (AUTH_SPEC §3-§6 / §13).
//
// Errors carry only identifiers and counters (no plaintext values, key
// material, or external token values).

import { AUTH_FLOW_FAILURE_REASONS } from "@maruhi/core";
import { Schema } from "effect";

/** 401: the request presented no valid session cookie or API token. */
export class UnauthorizedError extends Schema.TaggedError<UnauthorizedError>()(
  "Unauthorized",
  {},
  { httpApiStatus: 401 },
) {}

/**
 * Reason codes for a 403 (AUTH_SPEC §5 CSRF / session-capability
 * restriction / §9-2 effective permission / §11-1 / §11-3 / §12-3).
 *
 * `session-not-allowed` = the capability restriction on session
 * principals (outside the §5 allowlist — W2b). A uniform response
 * determined solely by endpoint identity and principal kind; it carries
 * no project existence or state information (compatible with §11-2
 * existence concealment — the same "computable from the request alone"
 * argument as the §12-3 authorization-first exception).
 *
 * `insufficient-scope` = the target environment is outside the calling
 * principal's chain-derived scope (the §9-2 / §12-3 403
 * `InsufficientScope` — 2026-09-15 ES K3; same layer and same shape as
 * insufficient role, with reason distinguishing the refusal axis —
 * design record es-design.md §9 K3-A). Environment existence is
 * chain-derived and known to every member, so it is not folded into a
 * 404.
 */
export const ForbiddenReasonSchema = Schema.Literals([
  "csrf-header-required",
  "session-not-allowed",
  "insufficient-permission",
  "actor-mismatch",
  "org-membership-required",
  "insufficient-role",
  "insufficient-scope",
  // The project is a read-only mirror of another deployment (AUTH_SPEC
  // §11-7 — PF2): every write is refused after authentication; the
  // member writes to the source. Reads and leases are served
  "mirror-read-only",
]);

/** 403: the authenticated principal may not perform this operation. */
export class ForbiddenError extends Schema.TaggedError<ForbiddenError>()(
  "Forbidden",
  { reason: ForbiddenReasonSchema },
  { httpApiStatus: 403 },
) {}

/** Reason codes for a failed authentication flow (AUTH_SPEC §3 / §4 — core's AUTH_FLOW_FAILURE_REASONS). */
export const AuthFlowFailureReasonSchema = Schema.Literals(AUTH_FLOW_FAILURE_REASONS);

/**
 * 400: the web OAuth dance failed (state mismatch, code exchange rejection,
 * or a user-info fetch failure on the obtained token).
 * The presented external ID / token values are not carried (reason code
 * only).
 */
export class AuthFlowError extends Schema.TaggedError<AuthFlowError>()(
  "AuthFlow",
  { reason: AuthFlowFailureReasonSchema },
  { httpApiStatus: 400 },
) {}

/** Reason codes for a 503 on an unconfigured self-hosted server (AUTH_SPEC §3). */
export const SetupIncompleteReasonSchema = Schema.Literals(["github-oauth-unconfigured"]);

/**
 * 503: this deployment has not finished self-host setup — the GitHub OAuth
 * App is not configured (AUTH_SPEC §3: client_id is a placeholder /
 * empty / absent, or client_secret is unregistered / empty). The client
 * directs the user to the setup procedure in docs/SELF_HOSTING.md
 * (supports the semantics that a success response = both are
 * registered).
 */
export class SetupIncompleteError extends Schema.TaggedError<SetupIncompleteError>()(
  "SetupIncomplete",
  { reason: SetupIncompleteReasonSchema },
  { httpApiStatus: 503 },
) {}

/**
 * 429: too many requests to an unauthenticated auth surface from this source
 * address (AUTH_SPEC §3 / §4). The OAuth callback involves an outbound
 * call to GitHub (the OAuth App's shared quota), and CLI login's start /
 * poll are unauthenticated CPU-consuming surfaces, so a per-source-IP
 * best-effort limit is enforced even on the default deployment (the
 * §4-1 Workers Rate Limiting binding pattern). `retryAfterSeconds` is a
 * hint for when to try again (the fixed window's period).
 */
export class AuthRateLimitedError extends Schema.TaggedError<AuthRateLimitedError>()(
  "AuthRateLimited",
  { retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}

/**
 * 410: the CLI login flow credential has expired (AUTH_SPEC §4-2). A
 * typed termination instruction to a legitimate flowToken holder; the
 * CLI stops polling and guides the user to log in again. The expiry is
 * a self-declared value inside the flowToken's signature; this response
 * discloses nothing about flow state (row existence or approval
 * status).
 */
export class CliFlowExpiredError extends Schema.TaggedError<CliFlowExpiredError>()(
  "CliFlowExpired",
  {},
  { httpApiStatus: 410 },
) {}

/**
 * 400: uniform rejection of a CLI login poll (the AUTH_SPEC §4-2
 * uniform-refusal discipline). A MAC mismatch, a pair mismatch between
 * the in-signature flowId and the presented flowId, a re-poll after
 * consumed, and the CAS loser of concurrent polls — all get the same
 * response; the failure reason is not differentiated (no oracle of flow
 * state). Carries no reason or identifier.
 */
export class CliFlowRejectedError extends Schema.TaggedError<CliFlowRejectedError>()(
  "CliFlowRejected",
  {},
  { httpApiStatus: 400 },
) {}

/** 429: the per-user API token limit has been reached (AUTH_SPEC §6). */
export class TokenLimitError extends Schema.TaggedError<TokenLimitError>()(
  "TokenLimit",
  { limit: Schema.Number },
  { httpApiStatus: 429 },
) {}

/**
 * 404: the token id does not name a token owned by the authenticated principal
 * (AUTH_SPEC §6 — W3a targeted revocation). A uniform response to
 * another user's or a nonexistent token id (existence concealment — the
 * same discipline as the §12-6 deletion surfaces); it does not carry
 * the target id (the value the caller sent is not copied into the
 * error).
 */
export class TokenNotFoundError extends Schema.TaggedError<TokenNotFoundError>()(
  "TokenNotFound",
  {},
  { httpApiStatus: 404 },
) {}

/** 404: no recovery wrap is registered for the authenticated user (AUTH_SPEC §13). */
export class RecoveryWrapNotFoundError extends Schema.TaggedError<RecoveryWrapNotFoundError>()(
  "RecoveryWrapNotFound",
  {},
  { httpApiStatus: 404 },
) {}

/**
 * 429: the recovery-blob fetch window is exhausted (AUTH_SPEC §13-3 —
 * the CRYPTO_SPEC §8 rate limit). `retryAfterSeconds` is the remaining
 * seconds of the fixed window.
 */
export class RecoveryRateLimitedError extends Schema.TaggedError<RecoveryRateLimitedError>()(
  "RecoveryRateLimited",
  { retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}
