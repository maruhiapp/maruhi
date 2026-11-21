import type { EnvironmentId, UserId, VariableId } from "@maruhi/core";
import type { ChainInvalidReason, KeyFingerprintHex } from "@maruhi/crypto";
import { Data } from "effect";

export type ResourceConflictReason = "exists" | "retired" | "duplicate-name";

export type EnvironmentConflictReason = "duplicate-name";

export type DekWrapRejectReason =
  | "recipient-not-member"
  | "recipient-not-granted"
  | "recipient-key-mismatch"
  | "recipient-missing"
  | "duplicate-recipient"
  | "epoch-out-of-range"
  | "scope-out-of-range"
  | "signature-invalid";

export type ValueSignatureRejectReason =
  | "signature-invalid"
  | "chain-head-unknown"
  | "chain-head-state-mismatch";

export type MetaStatementRejectReason =
  | ValueSignatureRejectReason
  | "layout-regression"
  | "unsupported-layout";

export type SchemaPolicyRejectReason = "schema-required";

export type SchemaDescriptionRejectReason = "too-long" | "control-characters";

export type AttestationRejectReason = ValueSignatureRejectReason;

export type ManifestRejectReason =
  | ValueSignatureRejectReason
  | "manifest-digest-mismatch"
  | "manifest-epoch-mismatch"
  | "checkpoint-binding-mismatch"
  | "checkpoint-equivocation"
  | "checkpoint-regressed";

export type CheckpointMismatchReason =
  | "manifest-mismatch"
  | "values-digest-mismatch"
  | "audit-head-unknown"
  | "audit-head-stale";

export type ProposalLimitReason = "pending-proposals" | "proposal-lifetime";

export type DataLimitResource =
  | "environments"
  | "environment-rows"
  | "variables"
  | "variable-rows"
  | "versions"
  | "meta-versions"
  | "environment-ciphertext-bytes"
  | "project-ciphertext-bytes"
  | "dek-wraps-per-request"
  | "dek-wrap-rows"
  | "rotation-dismissals-per-request"
  | "project-storage-bytes";

export type DataRejection =
  | { readonly kind: "not-initialized" }
  | { readonly kind: "not-member" }
  | { readonly kind: "insufficient-role" }
  | { readonly kind: "insufficient-scope" }
  | { readonly kind: "environment-not-found"; readonly environmentId: EnvironmentId }
  | {
      readonly kind: "environment-conflict";
      readonly environmentId: EnvironmentId;
      readonly reason: EnvironmentConflictReason;
    }
  | {
      readonly kind: "composite-required";
      readonly op: "create_environment" | "rotate_epoch" | "delete_environment";
    }
  | { readonly kind: "device-limit"; readonly limit: number }
  | {
      readonly kind: "proposal-limit";
      readonly reason: ProposalLimitReason;
      readonly limit: number;
    }
  | {
      readonly kind: "checkpoint-state-mismatch";
      readonly reason: CheckpointMismatchReason;
    }
  | { readonly kind: "audit-head-not-ready" }
  | {
      readonly kind: "chain-head-conflict";
      readonly currentHeadSeq: number;
      readonly currentHeadHashHex: string;
    }
  | {
      readonly kind: "chain-entry-invalid";
      readonly seq: number;
      readonly reason: ChainInvalidReason;
    }
  | { readonly kind: "chain-entry-too-large"; readonly limitBytes: number }
  | {
      readonly kind: "chain-capacity-exceeded";
      readonly maxEntries: number;
      readonly maxTotalBytes: number;
    }
  | { readonly kind: "payload-mismatch"; readonly field: string }
  | { readonly kind: "variable-not-found"; readonly variableId: VariableId }
  | {
      readonly kind: "variable-conflict";
      readonly variableId: VariableId;
      readonly reason: ResourceConflictReason;
    }
  | { readonly kind: "version-conflict"; readonly currentVersion: number }
  | { readonly kind: "epoch-conflict"; readonly currentEpoch: number }
  | { readonly kind: "value-rejected"; readonly reason: ValueSignatureRejectReason }
  | { readonly kind: "meta-rejected"; readonly reason: MetaStatementRejectReason }
  | { readonly kind: "schema-policy-rejected"; readonly reason: SchemaPolicyRejectReason }
  | { readonly kind: "activation-required"; readonly variableId: VariableId }
  | { readonly kind: "description-rejected"; readonly reason: SchemaDescriptionRejectReason }
  | { readonly kind: "meta-version-conflict"; readonly currentMetaVersion: number }
  | { readonly kind: "manifest-rejected"; readonly reason: ManifestRejectReason }
  | { readonly kind: "manifest-version-conflict"; readonly currentManifestVersion: number }
  | { readonly kind: "name-not-nfc" }
  | { readonly kind: "dek-wrap-rejected"; readonly reason: DekWrapRejectReason }
  | {
      readonly kind: "dek-wrap-exists";
      readonly epoch: number;
      readonly recipientUserId: UserId | KeyFingerprintHex;
      readonly storedRecipientEncPubHex: string;
    }
  | {
      readonly kind: "dek-wrap-not-found";
      readonly epoch: number;
      readonly recipientUserId: UserId | KeyFingerprintHex;
    }
  | {
      readonly kind: "rotation-flag-not-found";
      readonly environmentId: EnvironmentId;
      readonly variableId: VariableId;
    }
  | { readonly kind: "rotation-proposal-not-found"; readonly proposalId: string }
  | { readonly kind: "rotation-proposal-rejected"; readonly reason: RotationProposalRejectReason }
  | { readonly kind: "export-changed" }
  | { readonly kind: "export-rate-limited"; readonly retryAfterSeconds: number }
  | { readonly kind: "mirror-read-only" }
  | { readonly kind: "mirror-state"; readonly reason: MirrorStateReason }
  | { readonly kind: "mirror-sync-rejected"; readonly reason: MirrorSyncRejectReason }
  | {
      readonly kind: "limit-exceeded";
      readonly resource: DataLimitResource;
      readonly limit: number;
    }
  | { readonly kind: "attestation-rejected"; readonly reason: AttestationRejectReason }
  | { readonly kind: "attestation-regression"; readonly storedSeq: number }
  | { readonly kind: "attestation-rate-limited"; readonly retryAfterSeconds: number };

export type MirrorStateReason = "already-mirror" | "not-mirror";

export type MirrorSyncRejectReason =
  | "sequence-mismatch"
  | "malformed"
  | "schema-mismatch"
  | "unknown-table"
  | "row-count-mismatch"
  | "chain-not-extension"
  | "chain-invalid"
  | "audit-regression"
  | "audit-not-extension"
  | "page-too-large";

export type RotationProposalRejectReason =
  | "duplicate-id"
  | "duplicate-variable"
  | "variable-inactive"
  | "base-version-stale"
  | "recipients-mismatch"
  | "pending-limit"
  | "storage-limit"
  | "version-missing"
  | "variable-pending"
  | "mirror-read-only";

export class DataRejectedError extends Data.TaggedError("DataRejected")<{
  readonly rejection: DataRejection;
}> {}

export const rejectData = (rejection: DataRejection): DataRejectedError =>
  new DataRejectedError({ rejection });

export type DataOutcome<T> =
  | { readonly kind: "ok"; readonly value: T }
  | { readonly kind: "rejected"; readonly rejection: DataRejection };
