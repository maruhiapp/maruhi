import { EnvironmentIdSchema, VariableIdSchema } from "@maruhi/core";
import { Schema } from "effect";

export class RotationFlagNotFoundError extends Schema.TaggedError<RotationFlagNotFoundError>()(
  "RotationFlagNotFound",
  { environmentId: EnvironmentIdSchema, variableId: VariableIdSchema },
  { httpApiStatus: 404 },
) {}

export const RotationProposalRejectReasonSchema = Schema.Literals([
  "duplicate-id",
  "duplicate-variable",
  "variable-inactive",
  "base-version-stale",
  "recipients-mismatch",
  "pending-limit",
  "version-missing",
  "storage-limit",
  "variable-pending",
  "mirror-read-only",
]);

export class RotationProposalRejectedError extends Schema.TaggedError<RotationProposalRejectedError>()(
  "RotationProposalRejected",
  { reason: RotationProposalRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

export class RotationProposalNotFoundError extends Schema.TaggedError<RotationProposalNotFoundError>()(
  "RotationProposalNotFound",
  { proposalId: Schema.String },
  { httpApiStatus: 404 },
) {}
