import { ProjectIdSchema } from "@maruhi/core";
import type { ChainInvalidReason } from "@maruhi/crypto";
import { Schema } from "effect";

const CHAIN_INVALID_REASONS = [
  "empty-chain",
  "bad-suite",
  "bad-seq",
  "bad-prev-hash",
  "bad-genesis",
  "bad-signature",
  "invalid-payload",
  "insufficient-role",
  "actor-not-member",
  "actor-key-mismatch",
  "last-owner-protected",
  "unknown-target",
  "duplicate-member",
  "duplicate-member-key",
  "duplicate-environment",
  "unknown-environment",
  "unknown-server-grant",
  "grant-scope-narrowed",
  "duplicate-server-key",
  "epoch-out-of-sequence",
  "checkpoint-audit-role-insufficient",
  "checkpoint-epoch-mismatch",
  "checkpoint-regression",
  "scope-role-mismatch",
  "scope-not-contained",
  "environment-out-of-scope",
  "approval-required",
  "approval-not-required",
  "approval-quorum-unreachable",
  "unknown-proposal",
  "duplicate-approval",
  "proposal-expired",
  "proposal-void",
  "unknown-device",
  "last-device-protected",
  "device-cap-exceeded",
  "environment-deleted",
] as const satisfies readonly ChainInvalidReason[];

type AllReasonsListed = ChainInvalidReason extends (typeof CHAIN_INVALID_REASONS)[number]
  ? true
  : never;
const allReasonsListed: AllReasonsListed = true;
void allReasonsListed;

export const ChainInvalidReasonSchema = Schema.Literals(CHAIN_INVALID_REASONS);

export class ProjectNotFoundError extends Schema.TaggedError<ProjectNotFoundError>()(
  "ProjectNotFound",
  { projectId: ProjectIdSchema },
  { httpApiStatus: 404 },
) {}

export class ProjectAlreadyInitializedError extends Schema.TaggedError<ProjectAlreadyInitializedError>()(
  "ProjectAlreadyInitialized",
  { projectId: ProjectIdSchema },
  { httpApiStatus: 409 },
) {}

export class ProjectLimitError extends Schema.TaggedError<ProjectLimitError>()(
  "ProjectLimit",
  { limit: Schema.Number },
  { httpApiStatus: 429 },
) {}

export class ChainHeadConflictError extends Schema.TaggedError<ChainHeadConflictError>()(
  "ChainHeadConflict",
  { currentHeadSeq: Schema.Number, currentHeadHashHex: Schema.String },
  { httpApiStatus: 409 },
) {}

export class ChainEntryInvalidError extends Schema.TaggedError<ChainEntryInvalidError>()(
  "ChainEntryInvalid",
  { seq: Schema.Number, reason: ChainInvalidReasonSchema },
  { httpApiStatus: 422 },
) {}

export class ChainEntryTooLargeError extends Schema.TaggedError<ChainEntryTooLargeError>()(
  "ChainEntryTooLarge",
  { limitBytes: Schema.Number },
  { httpApiStatus: 413 },
) {}

export class ChainCapacityExceededError extends Schema.TaggedError<ChainCapacityExceededError>()(
  "ChainCapacityExceeded",
  { maxEntries: Schema.Number, maxTotalBytes: Schema.Number },
  { httpApiStatus: 422 },
) {}

export class CompositeRequiredError extends Schema.TaggedError<CompositeRequiredError>()(
  "CompositeRequired",
  { op: Schema.Literals(["create_environment", "rotate_epoch", "delete_environment"]) },
  { httpApiStatus: 422 },
) {}

export class DeviceLimitError extends Schema.TaggedError<DeviceLimitError>()(
  "DeviceLimit",
  { limit: Schema.Number },
  { httpApiStatus: 422 },
) {}

export const ProposalLimitReasonSchema = Schema.Literals([
  "pending-proposals",
  "proposal-lifetime",
]);

export class ProposalLimitError extends Schema.TaggedError<ProposalLimitError>()(
  "ProposalLimit",
  { reason: ProposalLimitReasonSchema, limit: Schema.Number },
  { httpApiStatus: 422 },
) {}
