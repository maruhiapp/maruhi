// The shared parts of the data plane (AUTH_SPEC §12): the types crossing
// the RPC boundary, the rejection reasons, and the authorization guards
// (chain-derived role and environment scope — CRYPTO_SPEC §6.2).
//
// Rejections fold into the single DataRejectedError type and cross the DO's
// RPC boundary as a DataOutcome discriminated union (the worker maps it
// onto api-schema's typed errors).

import type { AuditActor } from "@maruhi/core";
import { auditPayloadWith } from "@maruhi/core";
import type {
  ChainDevice,
  ChainHistoryIndex,
  ChainInvalidReason,
  ChainMember,
  ChainState,
  EffectivePermission,
  Role,
} from "@maruhi/crypto";
import { effectivePermissionOf, scopeIncludesEnvironment } from "@maruhi/crypto";
import { Data, Effect } from "effect";

import type { AuditEventInput } from "../audit-store.ts";
import type { StateCache, StoredChain } from "../do/chain-store.ts";
import { ChainStore, deriveStoredState } from "../do/chain-store.ts";

// ---------------------------------------------------------------------------
// Inputs and values crossing the RPC boundary (only plain objects safe for
// structured clone)
// ---------------------------------------------------------------------------

/**
 * The audit actor of a data operation (AUDIT_SPEC §2). The worker builds
 * it from the authenticated principal via auditActorOf (@maruhi/core —
 * the mapping's only implementation).
 * It carries no key FP — most data operations involve no signature. The
 * only exception that does is DEK wrap registration (CRYPTO_SPEC §5.1),
 * whose signer FP is taken not by the worker but by the DO from the
 * chain-derived member and recorded on the dek.registered event.
 */
export type DataActor = AuditActor;

/**
 * The suite identifier (CRYPTO_SPEC §2 design principle 4). Since the wire
 * pins it via the Schema Literal, the types at the RPC boundary and the
 * stored rows express it as this same literal (AUTH_SPEC §12-2).
 */
export type WireSuite = "maruhi/v1";

/**
 * The recipient class of a DEK wrap (AUTH_SPEC §12-6): member = a current
 * member on the chain; server = the server key of a valid grant_server.
 * Omitted means member. For the server class, the recipientUserId position
 * carries the server key FP (lowercase hex) — the same substitution as the
 * HPKE info / §5.1 signed target (CRYPTO_SPEC §9).
 */
export type DekRecipientClass = "member" | "server";

/**
 * A DEK wrapped to one recipient (AUTH_SPEC §12-6; structurally identical
 * to the wire form). signatureHex is the registration signature
 * (CRYPTO_SPEC §5.1) — the signer matches the API calling principal
 * exactly (§12-6), so no signer ID rides the wire or the RPC boundary.
 */
export interface DekWrapInput {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly recipientClass: DekRecipientClass;
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly signatureHex: string;
}

/**
 * A reference to a stored wrap (the deletion unit of the §12-6 repair
 * path). `recipientEncPubHex` is on the device axis (2026-09-19 DK —
 * slots are per device).
 */
export interface DekWrapRefInput {
  readonly epoch: number;
  readonly recipientClass: DekRecipientClass;
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
}

/**
 * A statement's lifecycle state (CRYPTO_SPEC §4.2). declared is limited
 * to variables on layout v2 (environment meta and the v1 layout stay
 * two-valued — the wire Schema enforces it, and the DO side accepts all
 * three values as the storage / verification type).
 */
export type MetaStatementStatusInput = "active" | "deleted" | "declared";

/** The closed set of varType (CRYPTO_SPEC §4.2 — `""` = unspecified). */
export type MetaVarTypeInput = "" | "string" | "number" | "boolean" | "url";

/**
 * The layout-v2 schema fields (CRYPTO_SPEC §4.2 / AUTH_SPEC §12-2).
 * required rides as the wire's boolean (the mapping onto the signed
 * "true" / "false" strings happens in the one place that verifies —
 * verify-meta.ts).
 */
export interface MetaVariableSchemaInput {
  readonly varType: MetaVarTypeInput;
  readonly required: boolean;
  readonly description: string;
  /**
   * Layout v3 (CRYPTO_SPEC §4.2 — PF6 R9 expiring values): days after a
   * value's push within which it should be replaced (1..3650), null = no
   * declaration. Present iff the layout is 3 (verify-meta.ts enforces the
   * coupling as 422 payload-mismatch); absent on a v2 statement.
   */
  readonly maxAgeDays?: number | null;
}

/**
 * The stored input of a metadata statement (CRYPTO_SPEC §4.2 / AUTH_SPEC
 * §12-5). The coordinates (environment / variable) have already been
 * checked by the worker for a match against the URL and the statement's
 * declared values; the DO reconstructs the signed target from the
 * storage coordinates (§12-5 — it is never assembled from the wire's
 * declared values). Since author = the calling principal is the
 * contract, no author ID / FP is carried here (the DO takes it from the
 * chain-derived member at acceptance time).
 */
export interface MetaStatementInput {
  readonly suite: WireSuite;
  readonly name: string;
  readonly status: MetaStatementStatusInput;
  readonly metaVersion: number;
  /** SHA-256 of the previous statement's signed_bytes (empty string for metaVersion 1). */
  readonly prevMetaSigHashHex: string;
  /**
   * The wire's layoutVersion (§12-2 — omitted = 1). The wire Schema only
   * lets an explicit value of 2 or above through; an excess over the
   * supported range ({1, 2, 3}) is refused by the acceptance check ahead of
   * signature verification with a 422 `unsupported-layout` (ruling CR).
   */
  readonly layoutVersion?: number;
  /** The layout-v2 schema fields (always present when layoutVersion is explicit — the wire shape). */
  readonly schema?: MetaVariableSchemaInput;
  /** The chain head the author last verified at signing time (the §4.2 authorization-time binding). */
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  /** The statement signature (Ed25519 — CRYPTO_SPEC §4.2). */
  readonly signatureHex: string;
}

/**
 * The distributed metadata statement (structurally identical to
 * DistributedVariableMetaStatement /
 * DistributedEnvironmentMetaStatement — the variable one carries a
 * variableId). Returns the stored signature block and the author (the
 * user_id + chain-derived key FP at acceptance time) as-is (verifiability
 * of a past statement by a since-deleted author — §12-2).
 */
export interface DistributedMetaStatementValue {
  readonly suite: WireSuite;
  readonly environmentId: string;
  readonly name: string;
  /** An environment statement stays two-valued (declared is v2-only for variables — §4.2). */
  readonly status: "active" | "deleted";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
  readonly authorUserId: string;
  readonly authorKeyFingerprintHex: string;
}

/**
 * The distributed form of a variable statement (with variableId). The
 * layout-v2 carried fields exist as a complete set of four only on v2
 * stored rows (no new field is added to a v1 distribution — §12-2).
 */
export interface DistributedVariableMetaStatementValue extends Omit<
  DistributedMetaStatementValue,
  "status"
> {
  readonly variableId: string;
  readonly status: MetaStatementStatusInput;
  readonly layoutVersion?: number;
  readonly varType?: MetaVarTypeInput;
  readonly required?: boolean;
  readonly description?: string;
  /** Layout v3 only (present with null = no declaration). */
  readonly maxAgeDays?: number | null;
}

/**
 * The stored input of an environment manifest (CRYPTO_SPEC §4.3 /
 * AUTH_SPEC §12-5). The coordinate (environment) has already been
 * checked by the worker for a match against the URL; the DO reconstructs
 * the signed target from the storage coordinate (§12-5 — it is never
 * assembled from the wire's declared values). Since issuer = the calling
 * principal is the contract, no issuer ID / FP is carried here (the DO
 * takes it from the chain-derived member at acceptance time).
 */
export interface EnvManifestInput {
  readonly suite: WireSuite;
  /** The current epoch at issuance time (at the declared head) — §4.3's freshness anchor. */
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly variablesDigestHex: string;
  readonly envMetaVersion: number;
  readonly envMetaSigHashHex: string;
  /** SHA-256 of the previous manifest's signed_bytes (empty string for manifestVersion 1). */
  readonly prevManifestSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  /** The manifest signature (Ed25519 — CRYPTO_SPEC §4.3). */
  readonly signatureHex: string;
}

/**
 * The distributed environment manifest (structurally identical to
 * DistributedEnvironmentManifest). Returns the stored signature block and
 * the issuer (the user_id + chain-derived key FP at acceptance time)
 * as-is (verifiability of a past manifest by a since-deleted issuer —
 * §12-2).
 */
export interface DistributedEnvManifestValue extends EnvManifestInput {
  readonly environmentId: string;
  readonly issuerUserId: string;
  readonly issuerKeyFingerprintHex: string;
}

/**
 * The stored input of a variable value. Of the AAD components, the
 * coordinates (project / environment / variable) have already been
 * checked by the worker for a match against the URL (§12-2). The DO
 * verifies the state-dependent epoch / version and the value signature
 * (§12-5 = CRYPTO_SPEC §4.1 / §6.4).
 * Since writer = the calling principal is the contract, no writer ID / FP
 * is carried here (the DO takes it from the chain-derived member at
 * acceptance time).
 */
export interface ValueInput {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly version: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  /** SHA-256 of the previous version's value_signed_bytes (empty string for version 1). */
  readonly prevValueSigHashHex: string;
  /** The chain head the writer last verified at signing time (the §4.1 authorization-time binding). */
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  /** The value's write signature (Ed25519 — CRYPTO_SPEC §4.1). */
  readonly signatureHex: string;
}

export interface EnvironmentSummaryValue {
  readonly environmentId: string;
  readonly currentEpoch: number;
  /** The latest environment meta statement (a deleted environment carries a deleted statement). */
  readonly statement: DistributedMetaStatementValue;
}

export interface VariableVersionValue {
  readonly variableId: string;
  readonly version: number;
  readonly epoch: number;
}

/**
 * One variable of a bulk pull (§12-7). Distributes the stored signature
 * block and the writer (the user_id + chain-derived key FP at acceptance
 * time) — not re-derived from the current member set (so that a past
 * value by a since-deleted writer is still verifiable under the keys of
 * that time in the chain history). The server-recomputed signed_bytes
 * hash is not distributed (a verifier recomputes it themselves).
 */
export interface PulledVariableValue {
  readonly variableId: string;
  readonly version: number;
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  readonly prevValueSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
  readonly writerUserId: string;
  readonly writerKeyFingerprintHex: string;
}

/**
 * The distributed wrap (structurally identical to RecipientDek). Carries
 * the signature and the signer information (the user_id + key FP of the
 * chain-derived member at registration acceptance) to enable the
 * client's verification at distribution time (CRYPTO_SPEC §5.1).
 */
export interface RecipientDekValue {
  readonly suite: WireSuite;
  readonly epoch: number;
  /**
   * The recipient's device key (the enc public key — the device axis of
   * AUTH_SPEC §12-6; 2026-09-19 DK). Since wraps to multiple devices of
   * the same person appear side by side in one response, the recipient
   * opens only the row of its own device key (an open failure is not
   * mistaken for a poisoned wrap).
   */
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly signatureHex: string;
  readonly signerUserId: string;
  readonly signerKeyFingerprintHex: string;
}

/** One entry of the checkpoint-time value snapshot (the distributed form — §12-7). */
export interface CheckpointSnapshotEntryValue {
  readonly variableId: string;
  readonly version: number;
  readonly valueSigHashHex: string;
}

/**
 * The distributed checkpoint-time value snapshot (structurally identical
 * to api-schema's CheckpointValueSnapshot — §12-7 / §14-2).
 * The supply is the very rows atomically stored at checkpoint acceptance
 * (§16-2 — never reconstructed). chainSeq / entryHashHex are the
 * position of the stored corresponding checkpoint (on the client side an
 * advisory locator — the verification basis is chain-derived).
 */
export interface CheckpointSnapshotValue {
  readonly chainSeq: number;
  readonly entryHashHex: string;
  readonly values: readonly CheckpointSnapshotEntryValue[];
}

/**
 * The omittable verification-material field of a value-bearing response
 * (§12-7 / §14-2): bundled when a stored row exists for the latest
 * checkpoint covering this environment, otherwise the key itself is
 * absent (the optionalKey wire shape — legitimately absent on an
 * environment without a baseline). Shared by the response assembly of
 * pull and lease (the branch is not duplicated in each program). The
 * manifest is not omittable — a created environment always has one
 * (§12-4; required on the wire since 0.28-draft).
 */
export function optionalCheckpointSnapshot(checkpointSnapshot: CheckpointSnapshotValue | null): {
  readonly checkpointSnapshot?: CheckpointSnapshotValue;
} {
  return checkpointSnapshot === null ? {} : { checkpointSnapshot };
}

export interface EnvironmentPullValue {
  readonly environmentId: string;
  readonly currentEpoch: number;
  /** The environment's own latest meta statement (the bundled verification material of §12-7). */
  readonly statement: DistributedMetaStatementValue;
  /** The latest statement + latest version of each active variable. */
  readonly variables: readonly (PulledVariableValue & {
    readonly statement: DistributedVariableMetaStatementValue;
  })[];
  /** The deleted statements of deleted variables (kept being stored and distributed — §12-5). */
  readonly deletedVariables: readonly DistributedVariableMetaStatementValue[];
  /**
   * The latest statements of declared variables (§12-7 — no value or
   * version exists. Input for the manifest digest recomputation).
   * Omitted for an environment with no declared variable (same shape as
   * the wire's optionalKey).
   */
  readonly declaredVariables?: readonly DistributedVariableMetaStatementValue[];
  readonly deks: readonly RecipientDekValue[];
  /** The schemaPolicy advisory bundle (§12-7 / §12-11 — always present). */
  readonly schemaPolicy: SchemaPolicy;
  /**
   * The latest environment manifest (§12-7). Required — a created
   * environment always has a stored row (environment creation bundles
   * manifest_version 1, and every meta operation / rotate re-issues
   * it), so a missing row is an invariant violation = defect, never an
   * omission (0.28-draft; on the client side absence = unconditional
   * rejection §6.3).
   */
  readonly manifest: DistributedEnvManifestValue;
  /**
   * The checkpoint-time value snapshot enumeration (§12-7).
   * Always bundled when a stored row exists for the latest checkpoint
   * that contains an entry of the environment (client rule 2 rejects
   * "basis present + enumeration absent" — CRYPTO_SPEC §6.3).
   * undefined only for an environment with no basis checkpoint.
   */
  readonly checkpointSnapshot?: CheckpointSnapshotValue;
}

/**
 * The metadata-only mode's response (§12-7): carries no values
 * (ciphertexts) and no DEKs. Only the §6.3 meta-verification material
 * (environment + latest statements of active variables + tombstones).
 * var.read is not recorded (AUDIT_SPEC §3.3).
 */
export interface EnvironmentMetadataPullValue {
  readonly environmentId: string;
  readonly currentEpoch: number;
  /** The environment's own latest meta statement. */
  readonly statement: DistributedMetaStatementValue;
  /**
   * The latest statements of every non-deleted variable (no values
   * attached). The statements of declared variables also appear here
   * (§12-7 — status carries the discrimination).
   */
  readonly variables: readonly DistributedVariableMetaStatementValue[];
  /** The deleted statements of deleted variables (§12-5). */
  readonly deletedVariables: readonly DistributedVariableMetaStatementValue[];
  /**
   * The latest environment manifest (meta verification completeness is
   * at the same level in this mode — §12-7). Required, same as the
   * with-values pull.
   */
  readonly manifest: DistributedEnvManifestValue;
  /** The schemaPolicy advisory bundle (§12-7 / §12-11 — always present). */
  readonly schemaPolicy: SchemaPolicy;
}

/** The RPC value of the environment list (§12-4 + the schemaPolicy advisory bundle — §12-7). */
export interface EnvironmentListValue {
  readonly environments: readonly EnvironmentSummaryValue[];
  readonly schemaPolicy: SchemaPolicy;
}

// ---------------------------------------------------------------------------
// Rejection reasons (the worker maps them onto api-schema's typed errors)
// ---------------------------------------------------------------------------

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
 * (session-12 §6-7) plus the 2 layout-v2 reasons the spec names
 * explicitly — `layout-regression` = a v1 successor to a v2 variable
 * (layout monotonicity — §12-5); `unsupported-layout` = a declared
 * layoutVersion beyond the supported range (the normal case of "old
 * server × new client" — ruling CR; it is not squashed into an invalid
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

/**
 * A project's schema policy (AUTH_SPEC §12-11 — default disabled). The
 * acceptance decision reads the policy at acceptance time (inside the
 * project DO's serialization).
 */
export type SchemaPolicy = "disabled" | "enabled" | "locked";

/** The 422 reasons from schemaPolicy (§12-11 / §12-5). */
export type SchemaPolicyRejectReason = "schema-policy-disabled" | "schema-required";

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
  | "audit-head-stale"
  | "environment-deleted";

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
  | { readonly kind: "environment-not-found"; readonly environmentId: string }
  | {
      readonly kind: "environment-conflict";
      readonly environmentId: string;
      readonly reason: EnvironmentConflictReason;
    }
  // Chain-acceptance family (shared by the composite request §12-4 and
  // the generic chain API — chain-do.ts. The worker maps them onto
  // api-schema's ChainHeadConflict / ChainEntryInvalid /
  // ChainEntryTooLarge / ChainCapacityExceeded / CompositeRequired)
  | {
      readonly kind: "composite-required";
      readonly op: "create_environment" | "rotate_epoch";
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
  | { readonly kind: "variable-not-found"; readonly variableId: string }
  | {
      readonly kind: "variable-conflict";
      readonly variableId: string;
      readonly reason: ResourceConflictReason;
    }
  | { readonly kind: "version-conflict"; readonly currentVersion: number }
  | { readonly kind: "epoch-conflict"; readonly currentEpoch: number }
  | { readonly kind: "value-rejected"; readonly reason: ValueSignatureRejectReason }
  | { readonly kind: "meta-rejected"; readonly reason: MetaStatementRejectReason }
  // The schemaPolicy acceptance gate (§12-11): new v2 adoption under
  // disabled / a creation without varType under locked
  | { readonly kind: "schema-policy-rejected"; readonly reason: SchemaPolicyRejectReason }
  // A normal push to a declared variable (§12-5 — requires the activation composite)
  | { readonly kind: "activation-required"; readonly variableId: string }
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
      readonly recipientUserId: string;
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
      readonly recipientUserId: string;
    }
  | {
      readonly kind: "rotation-flag-not-found";
      readonly environmentId: string;
      readonly variableId: string;
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

// ---------------------------------------------------------------------------
// Authorization guards (chain-derived role — CRYPTO_SPEC §6.2 / AUTH_SPEC
// §12-3)
// ---------------------------------------------------------------------------

const ROLE_RANK: Record<Role, number> = { reader: 1, member: 2, admin: 3, owner: 4 };

/**
 * The lower-bound check of a chain role (reader < member < admin <
 * owner). Also shared with the invites API's worker-side level judgment
 * (handlers-invites.ts) — do not proliferate the rank table.
 */
export function roleAtLeast(role: Role, minimum: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[minimum];
}

/**
 * A chain member together with **the device that signed this request** (2026-09-19
 * DK — K3; design record dk-design.md §8 K3-1): the key every chain-external signature of
 * the request is attributed to (the signer FP at acceptance time, the DEK
 * wrap's recipient key, the audit row's FP) and the effective permission that device holds — `(min(role, role_cap), scope ∩
 * device scope)` (CRYPTO_SPEC §6.2). The device is resolved **from the signature
 * itself** (`withSigningDevice` — the caller's active devices are tried in
 * fingerprint order; key uniqueness across current members makes at most one
 * verify) or, for chain entries, from `entry.actor.keyFingerprintHex` (`deviceOf`).
 * The advisory device registry (AUTH_SPEC §13-11) is never an input here.
 */
export interface MemberWithDevice extends ChainMember {
  readonly device: ChainDevice;
  readonly keyFingerprintHex: string;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  /** The signing device's effective permission (§6.2 — the input of the second-stage authorization). */
  readonly permission: EffectivePermission;
}

/** `member` + the valid device of the given FP (undefined when absent — the caller picks the reason code). */
export function deviceOf(
  member: ChainMember,
  keyFingerprintHex: string,
): MemberWithDevice | undefined {
  const device = member.devices.get(keyFingerprintHex);
  return device === undefined ? undefined : withDevice(member, device);
}

function withDevice(member: ChainMember, device: ChainDevice): MemberWithDevice {
  return {
    ...member,
    device,
    keyFingerprintHex: device.keyFingerprintHex,
    encPubHex: device.encPubHex,
    sigPubHex: device.sigPubHex,
    permission: effectivePermissionOf(member, device),
  };
}

/** The calling principal's valid devices in ascending FP order (makes the trial order deterministic — the result does not depend on it). */
function activeDevicesOf(member: ChainMember): readonly MemberWithDevice[] {
  return [...member.devices.values()]
    .toSorted((a, b) => (a.keyFingerprintHex < b.keyFingerprintHex ? -1 : 1))
    .map((device) => withDevice(member, device));
}

/**
 * A rejection that only says "this signature does not verify under this key" —
 * the one outcome that makes `withSigningDevice` try the caller's next device.
 * Every other rejection (head unknown, state mismatch, CAS, …) is final for the
 * device that produced it: a signature that verified under one key has found
 * its device, and a non-signature rejection cannot be cured by another key.
 */
function isSignatureInvalidRejection(rejection: DataRejection): boolean {
  switch (rejection.kind) {
    case "value-rejected":
    case "meta-rejected":
    case "manifest-rejected":
    case "attestation-rejected":
    case "dek-wrap-rejected":
      return rejection.reason === "signature-invalid";
    default:
      return false;
  }
}

/**
 * Resolves the request's signing device from a signature (design record
 * §8 K3-1 — option a-3): runs `attempt` with each of the member's active devices in
 * fingerprint order until one does not answer `signature-invalid`. Returns that
 * device with the attempt's value. When every device answers `signature-invalid`
 * the last such rejection is returned (fail-closed — the signature belongs to no
 * active device of the caller: a revoked device, a foreign key, or garbage).
 * At most 16 devices (AUTH_SPEC §12-8) bound the trial.
 */
export const withSigningDevice = Effect.fn("data-plane.withSigningDevice")(function* <A, R>(
  member: ChainMember,
  attempt: (device: MemberWithDevice) => Effect.Effect<A, DataRejectedError, R>,
): Effect.fn.Return<
  { readonly device: MemberWithDevice; readonly value: A },
  DataRejectedError,
  R
> {
  const candidates = activeDevicesOf(member);
  if (candidates.length === 0) {
    // A current member of a verified chain holds at least one device (§6.2 last-device-protected)
    return yield* Effect.die(new Error("internal: a current member has no active device"));
  }
  let lastRejection: DataRejectedError | null = null;
  for (const device of candidates) {
    // Only signature-invalid folds into "try the next device". Every
    // other rejection is final for that device
    const outcome: { readonly verified: A } | { readonly retry: DataRejectedError } =
      yield* attempt(device).pipe(
        Effect.map((value) => ({ verified: value })),
        Effect.catchTag("DataRejected", (error) =>
          isSignatureInvalidRejection(error.rejection)
            ? Effect.succeed({ retry: error })
            : Effect.fail(error),
        ),
      );
    if ("verified" in outcome) {
      return { device, value: outcome.verified };
    }
    lastRejection = outcome.retry;
  }
  // candidates is non-empty, so lastRejection is always set
  return yield* Effect.fail(
    lastRejection ?? rejectData({ kind: "value-rejected", reason: "signature-invalid" }),
  );
});

/**
 * Second-stage authorization (design record §8 K3-1): the signing device's **effective**
 * permission must satisfy the same role floor and (when an environment is
 * targeted) the same scope predicate the person already passed at the first
 * stage. Same reason codes as the first stage (403 — AUTH_SPEC §12-3). A device
 * never exceeds its person, so this can only narrow what the first stage let
 * through.
 *
 * Reachability (design record §8 K3 implementation note): on the composite, checkpoint and DEK-register
 * paths this is the check that produces the 403 (pinned by
 * membership-negatives-composite / device-ops tests). On the value push, metadata
 * statement and manifest paths the crypto layer's declared-head authorization
 * (CRYPTO_SPEC §6.3 — `deviceStateAt`, effective permission since DK K2) runs
 * first inside signature verification and rejects a capped device with 422
 * `chain-head-state-mismatch`; a device cap is immutable and the person's role
 * is bounded by the first stage, so no request passes the declared-head check
 * and fails here. Those call sites are defense in depth by construction, not a
 * coverage gap — do not delete them, and do not expect a test to reach them.
 * The head-attestation path has no second-stage call at all: `reader` is the
 * floor of the role enum, so no device's effective role can fall below the
 * op's requirement, and the op is chain-wide (no environment to scope).
 */
export function ensureDevicePermission(
  device: MemberWithDevice,
  minimum: Role,
  environmentId?: string,
): Effect.Effect<void, DataRejectedError> {
  if (!roleAtLeast(device.permission.role, minimum)) {
    return Effect.fail(rejectData({ kind: "insufficient-role" }));
  }
  if (
    environmentId !== undefined &&
    !scopeIncludesEnvironment(device.permission.scope, environmentId)
  ) {
    return Effect.fail(rejectData({ kind: "insufficient-scope" }));
  }
  return Effect.void;
}

/**
 * The lower-bound check of a chain-derived role (shared with the
 * composite programs — composite-programs.ts).
 * First stage (the person's role — design record §8 K3-1): since a
 * device's effective permission never exceeds the person's, a principal
 * that fails here also fails on its device. The effective permission of
 * the signing device (second stage) is judged after signature
 * verification by ensureDevicePermission.
 */
export function requireRole(
  state: ChainState,
  callerUserId: string,
  minimum: Role,
): Effect.Effect<ChainMember, DataRejectedError> {
  const member = state.members.get(callerUserId);
  if (member === undefined) {
    // §11-2: a non-member gets nothing back, including the current head
    // and the acceptance decision (the worker maps it to 404)
    return Effect.fail(rejectData({ kind: "not-member" }));
  }
  return roleAtLeast(member.role, minimum)
    ? Effect.succeed(member)
    : Effect.fail(rejectData({ kind: "insufficient-role" }));
}

/**
 * The scope judgment of an environment-targeted op (the "environment ∈
 * scope" column of AUTH_SPEC §12-3 — the scope derived by the verified
 * state of CRYPTO_SPEC §6.2; 2026-09-15 ES K3): placed right after the
 * role floor and before the environment's existence (a data row)
 * (design record es-design.md §9 K3-C — a check decided by chain-derived
 * state alone goes before one that reads stored state). The judgment is
 * the single predicate `scopeIncludesEnvironment` (`all` = every
 * environment), and environment creation (the §12-3 "scope = all" row)
 * is judged by the same predicate — since a `listed` scope cannot
 * contain a not-yet-existent environment id, only an `all` principal
 * passes (the same shape as §6.2).
 */
function requireEnvironmentInScope<M extends ChainMember>(
  member: M,
  environmentId: string,
): Effect.Effect<M, DataRejectedError> {
  return scopeIncludesEnvironment(member.scope, environmentId)
    ? Effect.succeed(member)
    : Effect.fail(rejectData({ kind: "insufficient-scope" }));
}

/**
 * The two stages role floor → scope (the §12-3 check order). Used by the
 * environment-targeted ops that load the whole chain themselves (the
 * composite — composite-programs.ts — and the standalone checkpoint —
 * checkpoint-accept.ts). Data-plane programs use
 * requireEnvironmentAccess (below).
 */
export function requireRoleInScope(
  state: ChainState,
  callerUserId: string,
  minimum: Role,
  environmentId: string,
): Effect.Effect<ChainMember, DataRejectedError> {
  return Effect.flatMap(requireRole(state, callerUserId, minimum), (member) =>
    requireEnvironmentInScope(member, environmentId),
  );
}

/**
 * The result of requireMemberState: besides the derived state and the
 * history index (the input of the value signature's declared-head-time
 * verification — CRYPTO_SPEC §4.1 / §6.4), returns the calling
 * principal's chain member (the source of the verification key and
 * signer FP of registration and value signatures — §5.1 / §4.1) and the
 * project ID (= the genesis entry hash; the coordinate being signed).
 */
interface MemberContext {
  readonly state: ChainState;
  readonly history: ChainHistoryIndex;
  /**
   * The caller as a **person** (role, scope, the device set). The device that signed the
   * request is resolved later from the signature (`withSigningDevice`) or the
   * entry actor (`deviceOf`) — design record §8 K3-1. Unsigned operations (reads,
   * deletions, dismissals) have no device and are judged on the person alone.
   */
  readonly member: ChainMember;
  readonly projectId: string;
}

/** An initialized chain (a StoredChain whose type guarantees the genesis hash exists). */
export type InitializedChain = StoredChain & {
  readonly headHashHex: string;
  readonly genesisHashHex: string;
};

/**
 * Chain loading and the initialization check (the shared front stage of
 * data operations and composite acceptance). Uninitialized is
 * not-initialized; headSeq > 0 with genesis / head missing is storage
 * corruption (a defect).
 */
export const loadInitializedChain: Effect.Effect<InitializedChain, DataRejectedError, ChainStore> =
  Effect.gen(function* () {
    const store = yield* ChainStore;
    const chain = yield* store.load;
    if (chain.headSeq === 0 || chain.headHashHex === null) {
      return yield* rejectData({ kind: "not-initialized" });
    }
    if (chain.genesisHashHex === null) {
      return yield* Effect.die(new Error("initialized chain is missing its genesis hash"));
    }
    return { ...chain, headHashHex: chain.headHashHex, genesisHashHex: chain.genesisHashHex };
  });

/**
 * The front stage shared by data operations: initialization check →
 * chain derivation → membership and role-floor check (the §12-3 check
 * order). Derivation reuses the same cache as the chain API.
 */
export const requireMemberState = Effect.fn("data-plane.requireMemberState")(function* (
  callerUserId: string,
  minimum: Role,
  cache: StateCache,
): Effect.fn.Return<MemberContext, DataRejectedError, ChainStore> {
  const chain = yield* loadInitializedChain;
  const { state, history } = yield* deriveStoredState(chain, cache);
  const member = yield* requireRole(state, callerUserId, minimum);
  return { state, history, member, projectId: chain.genesisHashHex };
});

/**
 * The front stage shared by environment-targeted data operations
 * (§12-3): requireMemberState (uninitialized → membership → role floor)
 * → **environment ∈ the calling principal's scope** (403
 * insufficient-scope). The environment's existence (a data row —
 * requireActiveEnvironment) is checked by the caller after this
 * (design record §9 K3-C: role → scope → existence).
 * Paths without an environment / where scope does not apply
 * (environment list, metadata-only pull, flags, audit) use
 * requireMemberState as-is — splitting the functions lets the type
 * distinguish "does not apply" from "forgot to call".
 */
export const requireEnvironmentAccess = Effect.fn("data-plane.requireEnvironmentAccess")(function* (
  callerUserId: string,
  minimum: Role,
  environmentId: string,
  cache: StateCache,
): Effect.fn.Return<MemberContext, DataRejectedError, ChainStore> {
  const context = yield* requireMemberState(callerUserId, minimum, cache);
  yield* requireEnvironmentInScope(context.member, environmentId);
  return context;
});

/**
 * An environment's current epoch = the chain-derived value (CRYPTO_SPEC
 * §6.2 / §6.3).
 * Since the environment's very existence is chain-derived
 * (`create_environment`), there is no "default to 1 when unobserved"
 * fallback. A data row is created atomically with the chain entry in
 * composite acceptance (§12-4), so having an active data row while the
 * chain has no environment is an invariant violation (a storage /
 * implementation bug) and is dropped as a defect.
 */
export function currentEpochOf(state: ChainState, environmentId: string): number {
  const environment = state.environments.get(environmentId);
  if (environment === undefined) {
    throw new Error("environment missing from chain-derived state");
  }
  return environment.currentEpoch;
}

/**
 * Build the audit event of a data operation (AUDIT_SPEC §3.3). The
 * actor's auth_method rides the payload JSON rather than a column (§5.1:
 * only frequent attributes are promoted to columns).
 * The actor's key FP is in principle absent (the chain mirror's
 * exclusive remit), but **dek.registered alone is the exception** — the
 * signer FP of the registration signature (CRYPTO_SPEC §5.1) is recorded
 * into actorKeyFingerprintHex (AUDIT_SPEC §3.3 — for cross-checking the
 * audit row against the chain-external signature).
 */
export function dataEvent(
  actor: DataActor,
  serverTs: number,
  event: string,
  fields: Pick<
    AuditEventInput,
    | "environmentId"
    | "variableId"
    | "epoch"
    | "version"
    | "targetUserId"
    | "targetKeyFingerprintHex"
    | "payload"
    | "actorKeyFingerprintHex"
  >,
): AuditEventInput {
  const payload = auditPayloadWith(actor, fields.payload);
  return {
    ...fields,
    event,
    serverTs,
    actorType: "user",
    actorUserId: actor.userId,
    ...(actor.apiTokenId === undefined ? {} : { actorApiTokenId: actor.apiTokenId }),
    ...(Object.keys(payload).length === 0 ? {} : { payload }),
  };
}
