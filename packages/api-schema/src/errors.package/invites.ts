// Typed errors of the invite API (AUTH_SPEC §15).
//
// Errors carry only identifiers and counters (no raw token values or key
// material). InviteNotFound carries no project coordinates at all:
// holding the token is the capability (§15-1), and responses to unknown
// tokens must not let the project's existence be inferred (the
// acceptance-path version of §11-2's existence-concealment
// discipline).

import { Schema } from "effect";

/**
 * 404: no invitation matches the presented token (accept) or id (revoke).
 * Carries no fields, for existence concealment.
 */
export class InviteNotFoundError extends Schema.TaggedError<InviteNotFoundError>()(
  "InviteNotFound",
  {},
  { httpApiStatus: 404 },
) {}

/**
 * 410 reasons (AUTH_SPEC §15-1 single-use + expiry derivation). Only a
 * holder of the token in the 2^256 space (the capability holder) can
 * observe this; the reason is returned so the legitimate acceptor
 * detects a first-come acceptance from a link interception as a "noisy
 * race" (CRYPTO_SPEC §6.5). Decision order is state → expiry (revoked
 * and expired counts as revoked).
 */
export const InviteGoneReasonSchema = Schema.Literals([
  "accepted",
  "completed",
  "revoked",
  "expired",
]);

/** 410: the invitation is no longer usable (single-use CAS — AUTH_SPEC §15-1). */
export class InviteGoneError extends Schema.TaggedError<InviteGoneError>()(
  "InviteGone",
  { reason: InviteGoneReasonSchema },
  { httpApiStatus: 410 },
) {}

/**
 * 422: one of the acceptance co-signatures failed verification
 * (CRYPTO_SPEC §6.5 v2). `which` names the failed signature (`link` =
 * the link key's co-signature — checked first in the decision order;
 * `accept` = the acceptor's chain key). Because the signed_bytes'
 * project_id / link_pub are reconstructed from the stored row and
 * invitee_user_id from the calling principal (§15-2), a signature by a
 * different person, transplantation from another invite, and key
 * substitution all fold into this error (there is no dedicated
 * actor-mismatch).
 */
export class InviteSignatureInvalidError extends Schema.TaggedError<InviteSignatureInvalidError>()(
  "InviteSignatureInvalid",
  { which: Schema.Literals(["link", "accept"]) },
  { httpApiStatus: 422 },
) {}

/**
 * 409: the client-chosen invite id or link public key already exists
 * (AUTH_SPEC §15-2 — invite ids are client-assigned and link_pub is
 * UNIQUE). The client reassigns / regenerates and retries.
 */
export class InviteConflictError extends Schema.TaggedError<InviteConflictError>()(
  "InviteConflict",
  { field: Schema.Literals(["id", "linkPub"]) },
  { httpApiStatus: 409 },
) {}

/** 429: the per-project pending-invitation cap is reached (AUTH_SPEC §15-2). */
export class InvitePendingLimitError extends Schema.TaggedError<InvitePendingLimitError>()(
  "InvitePendingLimit",
  { limit: Schema.Number },
  { httpApiStatus: 429 },
) {}

/**
 * 429: the per-project issuance window is exhausted (AUTH_SPEC §15-2 —
 * fixed window, 30 per hour). `retryAfterSeconds` is the remaining
 * seconds of the window.
 */
export class InviteRateLimitedError extends Schema.TaggedError<InviteRateLimitedError>()(
  "InviteRateLimited",
  { retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}
