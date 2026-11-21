import { Schema } from "effect";

export class KeyWrapNotFoundError extends Schema.TaggedError<KeyWrapNotFoundError>()(
  "KeyWrapNotFound",
  {},
  { httpApiStatus: 404 },
) {}

export class HandoffNotFoundError extends Schema.TaggedError<HandoffNotFoundError>()(
  "HandoffNotFound",
  {},
  { httpApiStatus: 404 },
) {}

export const HandoffConflictReasonSchema = Schema.Literals(["request-exists", "already-approved"]);

export class HandoffConflictError extends Schema.TaggedError<HandoffConflictError>()(
  "HandoffConflict",
  { reason: HandoffConflictReasonSchema },
  { httpApiStatus: 409 },
) {}

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

export class KeyWrapPolicyError extends Schema.TaggedError<KeyWrapPolicyError>()(
  "KeyWrapPolicy",
  { reason: KeyWrapPolicyReasonSchema },
  { httpApiStatus: 422 },
) {}

export const KeyWrapWindowSchema = Schema.Literals(["blob-fetch", "handoff-request", "approval"]);

export class KeyWrapRateLimitedError extends Schema.TaggedError<KeyWrapRateLimitedError>()(
  "KeyWrapRateLimited",
  { window: KeyWrapWindowSchema, retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}
