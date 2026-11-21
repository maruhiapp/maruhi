import { Schema } from "effect";

export const MirrorSyncRejectReasonSchema = Schema.Literals([
  "sequence-mismatch",
  "malformed",
  "schema-mismatch",
  "unknown-table",
  "row-count-mismatch",
  "chain-not-extension",
  "chain-invalid",
  "audit-not-extension",
  "audit-regression",
  "page-too-large",
]);

export class MirrorSyncRejectedError extends Schema.TaggedError<MirrorSyncRejectedError>()(
  "MirrorSyncRejected",
  { reason: MirrorSyncRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

export const MirrorStateReasonSchema = Schema.Literals(["already-mirror", "not-mirror"]);

export class MirrorStateError extends Schema.TaggedError<MirrorStateError>()(
  "MirrorState",
  { reason: MirrorStateReasonSchema },
  { httpApiStatus: 409 },
) {}
