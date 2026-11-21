import { Schema } from "effect";

export class InviteNotFoundError extends Schema.TaggedError<InviteNotFoundError>()(
  "InviteNotFound",
  {},
  { httpApiStatus: 404 },
) {}

export const InviteGoneReasonSchema = Schema.Literals([
  "accepted",
  "completed",
  "revoked",
  "expired",
]);

export class InviteGoneError extends Schema.TaggedError<InviteGoneError>()(
  "InviteGone",
  { reason: InviteGoneReasonSchema },
  { httpApiStatus: 410 },
) {}

export class InviteSignatureInvalidError extends Schema.TaggedError<InviteSignatureInvalidError>()(
  "InviteSignatureInvalid",
  { which: Schema.Literals(["link", "accept"]) },
  { httpApiStatus: 422 },
) {}

export class InviteConflictError extends Schema.TaggedError<InviteConflictError>()(
  "InviteConflict",
  { field: Schema.Literals(["id", "linkPub"]) },
  { httpApiStatus: 409 },
) {}

export class InvitePendingLimitError extends Schema.TaggedError<InvitePendingLimitError>()(
  "InvitePendingLimit",
  { limit: Schema.Number },
  { httpApiStatus: 429 },
) {}

export class InviteRateLimitedError extends Schema.TaggedError<InviteRateLimitedError>()(
  "InviteRateLimited",
  { retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}
