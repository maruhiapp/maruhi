// Typed errors of the master-key wrap ledger API (AUTH_SPEC §13-6 through
// §13-10 — KL3).
//
// Errors carry only identifiers, reason codes, and counters (no wraps,
// segments, or key material). Existence concealment (same discipline as
// §11-2): handoff-request lookups and approvals fold "not the ward
// themself or one of the ward's guardians", unknown, and revoked into
// the same uniform 404.

import { Schema } from "effect";

/** 404: no ledger row (passkey wrap / guardian group / share) is addressable by the caller. */
export class KeyWrapNotFoundError extends Schema.TaggedError<KeyWrapNotFoundError>()(
  "KeyWrapNotFound",
  {},
  { httpApiStatus: 404 },
) {}

/**
 * 404: the handoff request is unknown, expired, or not visible to the caller
 * (neither the ward nor one of the ward's guardians — the AUTH_SPEC
 * §13-7 uniform 404).
 */
export class HandoffNotFoundError extends Schema.TaggedError<HandoffNotFoundError>()(
  "HandoffNotFound",
  {},
  { httpApiStatus: 404 },
) {}

/** 409 reasons: the request id collides / a double approval of the same (request, source, share_index). */
export const HandoffConflictReasonSchema = Schema.Literals(["request-exists", "already-approved"]);

/** 409: the handoff request or approval already exists (AUTH_SPEC §13-7). */
export class HandoffConflictError extends Schema.TaggedError<HandoffConflictError>()(
  "HandoffConflict",
  { reason: HandoffConflictReasonSchema },
  { httpApiStatus: 409 },
) {}

/**
 * 422 reasons (the AUTH_SPEC §13-8 acceptance policy and the §13-7
 * structural conditions):
 * - too-many-passkeys / too-many-groups: per-user cap (5)
 * - share-count: the segment count is outside 1..5, under 2 with `all`,
 *   or share_index does not cover 1..n exactly once each
 * - unknown-guardian / self-guardian / duplicate-guardian: the
 *   segment-recipient conditions
 * - source-mismatch: the approval's source / share_index / blob
 *   combination does not fit the calling principal's role (ward =
 *   device only; guardian = own segment only)
 * - approvals-exceeded: the per-request approval cap
 * - duplicate-id: a client-assigned wrap_id / group_id collides with an
 *   existing row
 */
export const KeyWrapPolicyReasonSchema = Schema.Literals([
  "too-many-passkeys",
  "too-many-groups",
  "duplicate-id",
  "share-count",
  "unknown-guardian",
  "self-guardian",
  "duplicate-guardian",
  "source-mismatch",
  "approvals-exceeded",
]);

/** 422: the registration / approval violates a ledger policy (AUTH_SPEC §13-7 / §13-8). */
export class KeyWrapPolicyError extends Schema.TaggedError<KeyWrapPolicyError>()(
  "KeyWrapPolicy",
  { reason: KeyWrapPolicyReasonSchema },
  { httpApiStatus: 422 },
) {}

/** Fixed-window kinds (AUTH_SPEC §13-8): blob fetch (combined) / handoff request / approval. */
export const KeyWrapWindowSchema = Schema.Literals(["blob-fetch", "handoff-request", "approval"]);

/** 429: a §13-8 fixed window is exhausted. `retryAfterSeconds` is the remaining seconds of the window. */
export class KeyWrapRateLimitedError extends Schema.TaggedError<KeyWrapRateLimitedError>()(
  "KeyWrapRateLimited",
  { window: KeyWrapWindowSchema, retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}
