// The data plane's rejection vocabulary (AUTH_SPEC §12): the reasons, the
// DataRejection union every refusal folds into, and the single
// DataRejectedError type a data-plane program fails with. Rejections cross
// the DO's RPC boundary as a DataOutcome discriminated union, which the
// worker maps onto api-schema's typed errors.

import type { EnvironmentId, UserId, VariableId } from "@maruhi/core";
import type { ChainInvalidReason, KeyFingerprintHex } from "@maruhi/crypto";
import { Data } from "effect";

export type ResourceConflictReason = "exists" | "retired" | "duplicate-name";

/**
 * The only 409 of an environment is a display-name collision: ID
 * uniqueness is owned by the chain consensus rule `duplicate-environment`
 * (chain-entry-invalid) (CRYPTO_SPEC §6.2 / AUTH_SPEC §12-4).
 */
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

/**
 * The 422 reasons of a value signature (AUTH_SPEC §12-5; provisional
 * ruling C — only the spec's 3 reasons): signature-invalid = an Ed25519
 * failure on a valid-format input / chain-head-unknown = a valid
 * signature but the declared seq is absent or the stored hash at that
 * seq mismatches / chain-head-state-mismatch = the head is known but the
 * key, role, environment, or epoch at the head disagrees, or prev
 * mismatches the stored predecessor.
 */
export type ValueSignatureRejectReason =
  | "signature-invalid"
  | "chain-head-unknown"
  | "chain-head-state-mismatch";

/**
 * The 422 reasons of a meta statement: the value signature's 3-vocabulary
 * (session-12 §6-7) plus the 2 layout reasons the spec names
 * explicitly — `layout-regression` = a v1 successor to a v3 variable
 * (layout monotonicity — §12-5); `unsupported-layout` = a declared
 * layoutVersion outside the supported range {1, 3} (the retired 2, or the
 * normal case of "old server × new client" — ruling CR; it is not squashed into an invalid
 * signature). chain-head-state-mismatch covers: membership, key binding,
 * and role at the head; mismatches of prev's shape / the stored
 * predecessor; a re-statement after deletion (revived-after-delete); and
 * an active → declared transition (declared-after-active). Kept in sync
 * with api-schema's MetaStatementRejectReasonSchema.
 */
export type MetaStatementRejectReason =
  | ValueSignatureRejectReason
  | "layout-regression"
  | "unsupported-layout";

/** The 422 reasons from schemaPolicy (§12-11 / §12-5). */
export type SchemaPolicyRejectReason = "schema-required";

/** The 422 reasons of the schema-description acceptance check (§12-8). */
export type SchemaDescriptionRejectReason = "too-long" | "control-characters";

/**
 * The head attestation's 422 reasons share the same 3-vocabulary
 * (AUTH_SPEC §16-1 — no new reason code is created). chain-head-unknown
 * also covers a seq ahead of the current head (the client-side resync
 * branch — chain-head-future — does not exist on the server).
 */
export type AttestationRejectReason = ValueSignatureRejectReason;

/**
 * The 422 reasons of an environment manifest (AUTH_SPEC §12-5): shares
 * the existing 3-vocabulary and adds the 2 manifest-specific reasons
 * (digest-recompute mismatch, epoch inconsistency). Kept in sync with
 * api-schema's ManifestRejectReasonSchema.
 */
export type ManifestRejectReason =
  | ValueSignatureRejectReason
  | "manifest-digest-mismatch"
  | "manifest-epoch-mismatch"
  // Checkpoint binding (CRYPTO_SPEC §4.3 (2) / §6.3 consistency rule 1)
  | "checkpoint-binding-mismatch"
  | "checkpoint-equivocation"
  | "checkpoint-regressed";

/**
 * The 422 reasons of a checkpoint content cross-check (CRYPTO_SPEC §6.4 /
 * AUTH_SPEC §16-2). Kept in sync with api-schema's
 * CheckpointMismatchReasonSchema.
 */
export type CheckpointMismatchReason =
  | "manifest-mismatch"
  | "values-digest-mismatch"
  | "audit-head-unknown"
  | "audit-head-stale";

/**
 * The reasons a `propose` violates the acceptance policy (AUTH_SPEC
 * §12-8 — 2026-09-16 K5). Kept in sync with api-schema's
 * ProposalLimitReasonSchema.
 */
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
  // The DO storage total guard (§12-8; storage-guard.ts. limit = the
  // rejection threshold in bytes)
  | "project-storage-bytes";

export type DataRejection =
  | { readonly kind: "not-initialized" }
  | { readonly kind: "not-member" }
  | { readonly kind: "insufficient-role" }
  // Target environment ∉ the calling principal's chain-derived scope
  // (AUTH_SPEC §9-2 / §12-3 — 2026-09-15 ES K3. Right after the role 403
  // and before the existence 404. The worker maps it to
  // ForbiddenError [insufficient-scope])
  | { readonly kind: "insufficient-scope" }
  | { readonly kind: "environment-not-found"; readonly environmentId: EnvironmentId }
  | {
      readonly kind: "environment-conflict";
      readonly environmentId: EnvironmentId;
      readonly reason: EnvironmentConflictReason;
    }
  // Chain-acceptance family (shared by the composite request §12-4 and
  // the generic chain API — programs-chain.ts. The worker maps them onto
  // api-schema's ChainHeadConflict / ChainEntryInvalid /
  // ChainEntryTooLarge / ChainCapacityExceeded / CompositeRequired)
  | {
      readonly kind: "composite-required";
      readonly op: "create_environment" | "rotate_epoch" | "delete_environment";
    }
  // The device-count acceptance policy (AUTH_SPEC §12-8 / CRYPTO_SPEC
  // §6.4 — 2026-09-19 DK K3): at the acceptance of an `add_device`, the
  // actor's valid devices have reached the cap (16). The worker maps it
  // to api-schema's DeviceLimit (422). Not a consensus rule
  | { readonly kind: "device-limit"; readonly limit: number }
  // The four-eyes `propose` acceptance policy (AUTH_SPEC §12-8 /
  // CRYPTO_SPEC §6.4 — 2026-09-16 K5): the pending cap (expired ones do
  // not count) and the `expires_at_ms` upper bound. The worker maps it
  // to api-schema's ProposalLimit (422). The vocabulary matches
  // ProposalLimitReasonSchema
  | {
      readonly kind: "proposal-limit";
      readonly reason: ProposalLimitReason;
      readonly limit: number;
    }
  // The checkpoint content cross-check (CRYPTO_SPEC §6.4 / AUTH_SPEC
  // §16-2 — common to both the boundary-bundled path [the
  // post-composite-application basis — §12-4] and the standalone path
  // [acceptance time = the pre-application basis]. The vocabulary matches
  // api-schema's CheckpointMismatchReasonSchema)
  | {
      readonly kind: "checkpoint-state-mismatch";
      readonly reason: CheckpointMismatchReason;
    }
  // The bounded extension of the audit-head derived row is unfinished
  // (AUDIT_SPEC §5.1). On every path that reads an audit head (GET
  // /audit-head, standalone acceptance, the boundary composite's
  // non-empty notarization), when the bound is reached this is the
  // retryable rejection returned instead of judging unknown / stale on a
  // stale row (the worker maps it to api-schema's AuditHeadNotReady
  // [503])
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
  // The composite-internal consistency check (§12-4): a URL coordinate
  // disagrees with the bundled entry's payload
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
  // The schemaPolicy acceptance check (§12-11): a creation without varType
  // under locked
  | { readonly kind: "schema-policy-rejected"; readonly reason: SchemaPolicyRejectReason }
  // A normal push to a declared variable (§12-5 — requires the activation composite)
  | { readonly kind: "activation-required"; readonly variableId: VariableId }
  // The schema-description acceptance check (§12-8 — ≤1024 code points, no control characters)
  | { readonly kind: "description-rejected"; readonly reason: SchemaDescriptionRejectReason }
  | { readonly kind: "meta-version-conflict"; readonly currentMetaVersion: number }
  | { readonly kind: "manifest-rejected"; readonly reason: ManifestRejectReason }
  // The manifestVersion CAS (§12-5 (6)). Only the latest number is
  // returned (the discipline of not carrying the winner's hash is the
  // same as the metaVersion CAS)
  | { readonly kind: "manifest-version-conflict"; readonly currentManifestVersion: number }
  | { readonly kind: "name-not-nfc" }
  | { readonly kind: "dek-wrap-rejected"; readonly reason: DekWrapRejectReason }
  | {
      readonly kind: "dek-wrap-exists";
      readonly epoch: number;
      readonly recipientUserId: UserId | KeyFingerprintHex;
      /**
       * The stored recipient enc public key of the occupying wrap
       * (AUTH_SPEC §12-6). Not secret (all historical keys are
       * chain-distributed). On a re-add backfill 409, the input for the
       * client to decide registered / old-key wrap by exact comparison.
       */
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
  // Sealed value proposals (AUTH_SPEC §14-5): the member-side resolution's
  // vocabulary (unknown / resolved / expired fold into not-found; an
  // acceptance naming a version that does not exist or is not newer than
  // the base is version-missing). The worker maps them to api-schema's
  // RotationProposalNotFound (404) / RotationProposalRejected (422)
  | { readonly kind: "rotation-proposal-not-found"; readonly proposalId: string }
  | { readonly kind: "rotation-proposal-rejected"; readonly reason: RotationProposalRejectReason }
  // Project export (AUTH_SPEC §11-6 — PF3): the project moved between two
  // pages of one export (409 — the client starts over), and the per-project
  // export window (429)
  | { readonly kind: "export-changed" }
  | { readonly kind: "export-rate-limited"; readonly retryAfterSeconds: number }
  // Mirrors (AUTH_SPEC §11-7 — PF2): a write on a read-only mirror (the
  // worker maps it to Forbidden [mirror-read-only]), the mark state
  // (409 MirrorState) and a refused replication page (422
  // MirrorSyncRejected — the vocabulary matches api-schema's
  // MirrorSyncRejectReasonSchema)
  | { readonly kind: "mirror-read-only" }
  | { readonly kind: "mirror-state"; readonly reason: MirrorStateReason }
  | { readonly kind: "mirror-sync-rejected"; readonly reason: MirrorSyncRejectReason }
  | {
      readonly kind: "limit-exceeded";
      readonly resource: DataLimitResource;
      readonly limit: number;
    }
  // Head attestations (CRYPTO_SPEC §6.6 / AUTH_SPEC §16-1)
  | { readonly kind: "attestation-rejected"; readonly reason: AttestationRejectReason }
  // seq regression (does not silently succeed — returns the stored seq.
  // An identical seq is an idempotent 204)
  | { readonly kind: "attestation-regression"; readonly storedSeq: number }
  | { readonly kind: "attestation-rate-limited"; readonly retryAfterSeconds: number };

/** Why the mirror state does not admit the operation (AUTH_SPEC §11-7). */
export type MirrorStateReason = "already-mirror" | "not-mirror";

/** Why a replication page is refused (the api-schema MirrorSyncRejectReasonSchema vocabulary — AUTH_SPEC §11-7). */
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

/** Why a sealed value proposal or its resolution is refused (the api-schema RotationProposalRejectReasonSchema vocabulary — AUTH_SPEC §14-5). */
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
  // The project is a read-only mirror (AUTH_SPEC §11-7)
  | "mirror-read-only";

/** The only typed error a data-plane program carries as a failure. */
export class DataRejectedError extends Data.TaggedError("DataRejected")<{
  readonly rejection: DataRejection;
}> {}

export const rejectData = (rejection: DataRejection): DataRejectedError =>
  new DataRejectedError({ rejection });

/** The result of a data operation crossing the RPC boundary (structured clone). */
export type DataOutcome<T> =
  | { readonly kind: "ok"; readonly value: T }
  | { readonly kind: "rejected"; readonly rejection: DataRejection };
