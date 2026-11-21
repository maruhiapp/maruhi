import { EnvironmentIdSchema, VariableIdSchema } from "@maruhi/core";
import { Schema } from "effect";

export class EnvironmentNotFoundError extends Schema.TaggedError<EnvironmentNotFoundError>()(
  "EnvironmentNotFound",
  { environmentId: EnvironmentIdSchema },
  { httpApiStatus: 404 },
) {}

export class VariableNotFoundError extends Schema.TaggedError<VariableNotFoundError>()(
  "VariableNotFound",
  { variableId: VariableIdSchema },
  { httpApiStatus: 404 },
) {}

export const ResourceConflictReasonSchema = Schema.Literals([
  "exists",
  "retired",
  "duplicate-name",
]);

export const EnvironmentConflictReasonSchema = Schema.Literals(["duplicate-name"]);

export class EnvironmentConflictError extends Schema.TaggedError<EnvironmentConflictError>()(
  "EnvironmentConflict",
  { environmentId: EnvironmentIdSchema, reason: EnvironmentConflictReasonSchema },
  { httpApiStatus: 409 },
) {}

export class VariableConflictError extends Schema.TaggedError<VariableConflictError>()(
  "VariableConflict",
  { variableId: VariableIdSchema, reason: ResourceConflictReasonSchema },
  { httpApiStatus: 409 },
) {}

export class VersionConflictError extends Schema.TaggedError<VersionConflictError>()(
  "VersionConflict",
  { currentVersion: Schema.Number },
  { httpApiStatus: 409 },
) {}

export class EpochConflictError extends Schema.TaggedError<EpochConflictError>()(
  "EpochConflict",
  { currentEpoch: Schema.Number },
  { httpApiStatus: 409 },
) {}

export class PayloadMismatchError extends Schema.TaggedError<PayloadMismatchError>()(
  "PayloadMismatch",
  { field: Schema.String },
  { httpApiStatus: 422 },
) {}

export const ValueSignatureRejectReasonSchema = Schema.Literals([
  "signature-invalid",
  "chain-head-unknown",
  "chain-head-state-mismatch",
]);

export class ValueSignatureRejectedError extends Schema.TaggedError<ValueSignatureRejectedError>()(
  "ValueSignatureRejected",
  { reason: ValueSignatureRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

export const MetaStatementRejectReasonSchema = Schema.Literals([
  "signature-invalid",
  "chain-head-unknown",
  "chain-head-state-mismatch",
  "layout-regression",
  "unsupported-layout",
]);

export class MetaStatementRejectedError extends Schema.TaggedError<MetaStatementRejectedError>()(
  "MetaStatementRejected",
  { reason: MetaStatementRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

export const SchemaPolicyRejectReasonSchema = Schema.Literals(["schema-required"]);

export class SchemaPolicyRejectedError extends Schema.TaggedError<SchemaPolicyRejectedError>()(
  "SchemaPolicyRejected",
  { reason: SchemaPolicyRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

export class ActivationRequiredError extends Schema.TaggedError<ActivationRequiredError>()(
  "ActivationRequired",
  { variableId: VariableIdSchema },
  { httpApiStatus: 422 },
) {}

export const SchemaDescriptionRejectReasonSchema = Schema.Literals([
  "too-long",
  "control-characters",
]);

export class SchemaDescriptionRejectedError extends Schema.TaggedError<SchemaDescriptionRejectedError>()(
  "SchemaDescriptionRejected",
  { reason: SchemaDescriptionRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

export const ManifestRejectReasonSchema = Schema.Literals([
  "signature-invalid",
  "chain-head-unknown",
  "chain-head-state-mismatch",
  "manifest-digest-mismatch",
  "manifest-epoch-mismatch",
  "checkpoint-binding-mismatch",
  "checkpoint-equivocation",
  "checkpoint-regressed",
]);

export class ManifestRejectedError extends Schema.TaggedError<ManifestRejectedError>()(
  "ManifestRejected",
  { reason: ManifestRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

export const CheckpointMismatchReasonSchema = Schema.Literals([
  "manifest-mismatch",
  "values-digest-mismatch",
  "audit-head-unknown",
  "audit-head-stale",
]);

export class CheckpointStateMismatchError extends Schema.TaggedError<CheckpointStateMismatchError>()(
  "CheckpointStateMismatch",
  { reason: CheckpointMismatchReasonSchema },
  { httpApiStatus: 422 },
) {}

export class AuditHeadNotReadyError extends Schema.TaggedError<AuditHeadNotReadyError>()(
  "AuditHeadNotReady",
  {},
  { httpApiStatus: 503 },
) {}

export class ManifestVersionConflictError extends Schema.TaggedError<ManifestVersionConflictError>()(
  "ManifestVersionConflict",
  { currentManifestVersion: Schema.Number },
  { httpApiStatus: 409 },
) {}

export class MetaVersionConflictError extends Schema.TaggedError<MetaVersionConflictError>()(
  "MetaVersionConflict",
  { currentMetaVersion: Schema.Number },
  { httpApiStatus: 409 },
) {}

export class NameNotNfcError extends Schema.TaggedError<NameNotNfcError>()(
  "NameNotNfc",
  {},
  { httpApiStatus: 422 },
) {}

export class ValueTooLargeError extends Schema.TaggedError<ValueTooLargeError>()(
  "ValueTooLarge",
  { limitBytes: Schema.Number },
  { httpApiStatus: 413 },
) {}

export const DataLimitResourceSchema = Schema.Literals([
  "environments",
  "environment-rows",
  "variables",
  "variable-rows",
  "versions",
  "meta-versions",
  "environment-ciphertext-bytes",
  "project-ciphertext-bytes",
  "dek-wraps-per-request",
  "dek-wrap-rows",
  "rotation-dismissals-per-request",
  "project-storage-bytes",
]);

export class DataLimitExceededError extends Schema.TaggedError<DataLimitExceededError>()(
  "DataLimitExceeded",
  { resource: DataLimitResourceSchema, limit: Schema.Number },
  { httpApiStatus: 422 },
) {}
