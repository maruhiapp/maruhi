// The Effect service isolating the data plane's storage (DO SQLite).
//
// - The tables are do-schema.ts's (the DO constructor has already
//   applied the DDL)
// - Environment/variable deletion is a tombstone (deleted_at); it feeds
//   the no-ID-reuse judgment (AUTH_SPEC §12-1). Ciphertexts
//   (variable_versions) and wraps (dek_wraps) are deleted immediately
// - The decision to forgo Drizzle is in the do-schema.ts head comment
//   and docs/notes/session-07.md

import { Context, Effect, Layer } from "effect";

import type {
  CheckpointSnapshotEntryValue,
  CheckpointSnapshotValue,
  DekWrapInput,
  DistributedEnvManifestValue,
  DistributedMetaStatementValue,
  DistributedVariableMetaStatementValue,
  EnvManifestInput,
  MetaStatementInput,
  MetaStatementStatusInput,
  MetaVariableSchemaInput,
  MetaVarTypeInput,
  PulledVariableValue,
  RecipientDekValue,
  SchemaPolicy,
  ValueInput,
  WireSuite,
} from "./data-plane.ts";
import { ATTESTATION_WINDOW_MS, LEASE_WINDOW_MS } from "./policy.ts";
import type { StoredServerWrap } from "./server-key.ts";

interface EnvironmentRow {
  readonly environmentId: string;
  readonly name: string;
  /** The latest statement's metaVersion (a derived cache — for the metaVersion CAS). */
  readonly latestMetaVersion: number;
  readonly deletedAtMs: number | null;
}

export interface VariableRow {
  readonly variableId: string;
  readonly name: string;
  readonly latestMetaVersion: number;
  readonly latestVersion: number;
  /**
   * The latest statement's status (the decision input for declared
   * variables — §12-5: a normal push to a declared one is
   * activation-required; only declared is eligible for activation). The
   * source of truth is the statement row (read via a JOIN — the
   * variable row and the statement row are written in the same
   * synchronous block).
   */
  readonly latestStatus: MetaStatementStatusInput;
  readonly deletedAtMs: number | null;
}

/** The signer of a wrap registration signature (stored into dek_wraps's signer_* columns). */
export interface WrapSignerInfo {
  readonly userId: string;
  readonly keyFingerprintHex: string;
}

/**
 * A value's writer (stored into variable_versions's writer_* columns —
 * the user_id + key FP of the chain-derived member at acceptance time.
 * CRYPTO_SPEC §4.1 / AUTH_SPEC §12-5).
 */
export interface ValueWriterInfo {
  readonly userId: string;
  readonly keyFingerprintHex: string;
}

/** One version-history row (metadata only — §12-7, 2026-09-27 VH). */
export interface StoredVersionMeta {
  readonly version: number;
  readonly epoch: number;
  readonly writerUserId: string;
  readonly writerKeyFingerprintHex: string;
  /** The acceptance time (the row's created_at). */
  readonly pushedAtMs: number;
}

/**
 * The verification anchor of a stored version: the server-recomputed
 * signed_bytes hash and the epoch at the time. The input of the next
 * version's prev check (§12-5's 5).
 */
interface VersionAnchor {
  readonly signedBytesHashHex: string;
  readonly epoch: number;
}

/**
 * A statement's author (stored into the *_meta_statements tables'
 * author_* columns — the user_id + key FP of the chain-derived member
 * at acceptance time. CRYPTO_SPEC §4.2).
 */
export interface MetaAuthorInfo {
  readonly userId: string;
  readonly keyFingerprintHex: string;
}

/**
 * The verification anchor of a stored statement: the server-recomputed
 * signed_bytes hash and status. The input of the next metaVersion's
 * prev check and of the post-deletion re-statement rejection (the §12-5
 * meta rules). layoutVersion is the stored actual value (the anchor of
 * the layout-monotonicity check — CRYPTO_SPEC §4.2); schema is the v2
 * row's schema fields (the input of the deleted statement's
 * predecessor-match check — §12-5; a v1 row is null). Environment meta
 * is always layoutVersion 1, schema null (outside v2's scope).
 */
export interface MetaAnchor {
  readonly signedBytesHashHex: string;
  readonly status: MetaStatementStatusInput;
  readonly layoutVersion: number;
  readonly schema: MetaVariableSchemaInput | null;
}

/**
 * One entry of variables_digest (CRYPTO_SPEC §4.3 — structurally
 * identical to @maruhi/crypto's VariablesDigestEntry; held as a
 * structural type because data-store does not depend on crypto).
 */
interface VariableDigestEntryRow {
  readonly variableId: string;
  readonly status: MetaStatementStatusInput;
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
}

/**
 * One entry of a checkpoint values_digest (CRYPTO_SPEC §6.2 —
 * structurally identical to @maruhi/crypto's EnvValuesDigestEntry; held
 * as a structural type because data-store does not depend on crypto).
 */
export interface CheckpointValueEntryRow {
  readonly variableId: string;
  readonly version: number;
  readonly valueSigHashHex: string;
}

/**
 * A boundary checkpoint's tuple + chain position (the input of snapshot
 * saving — the coordinate part of CRYPTO_SPEC §6.4 / AUTH_SPEC §16-2's
 * "the reconstructed value-snapshot enumeration + the corresponding
 * checkpoint seq / hash").
 */
export interface CheckpointSnapshotInput {
  readonly chainSeq: number;
  readonly entryHashHex: string;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly manifestSigHashHex: string;
  readonly valuesDigestHex: string;
}

/**
 * The verification anchor of the stored latest manifest:
 * manifestVersion (the CAS — §12-5 (6)), the server-recomputed
 * signed_bytes hash (the prev check — (5)), and the epoch at the time
 * (the predecessor's epoch-monotonicity check).
 */
interface EnvManifestAnchor {
  readonly manifestVersion: number;
  readonly signedBytesHashHex: string;
  readonly epoch: number;
}

/** Active count and row count (tombstones included). For the §12-8 quantity-policy judgment. */
interface ResourceCounts {
  readonly active: number;
  readonly rows: number;
}

/**
 * The recipient info of a stored wrap (the input of the existence check
 * and of the overwrite-prohibited 409 response — AUTH_SPEC §12-6). The
 * class is cross-checked on the delete path; the enc public key is the
 * only source of `storedRecipientEncPubHex` carried on the 409
 * response.
 */
interface StoredWrapRecipient {
  readonly recipientClass: string;
  readonly recipientEncPubHex: string;
}

/**
 * The synchronous write functions. By calling every write of one
 * operation (audit appends included) bundled into one synchronous block
 * (= the same event-loop task), a partial write on a crash is prevented
 * structurally (a DO SQLite write commits atomically per task).
 * Verification (reads) is done by the Effect-side methods ahead of the
 * write phase.
 */
export interface DataWriteOps {
  /** Insert an environment row. name / latest_meta_version are settled by the insertEnvironmentMetaStatement right after. */
  readonly insertEnvironment: (environmentId: string, name: string, nowMs: number) => void;
  /**
   * Insert an environment statement row + synchronously update the
   * environment-row cache (name / latest_meta_version). Called from
   * inside the same synchronous block on every path: create, rename,
   * delete.
   */
  readonly insertEnvironmentMetaStatement: (
    environmentId: string,
    statement: MetaStatementInput,
    signedBytesHashHex: string,
    author: MetaAuthorInfo,
    nowMs: number,
  ) => void;
  /**
   * Tombstone + immediately delete the subordinate data (variables,
   * variable statements, versions, wraps). The environment's own
   * deletion statement (insertEnvironmentMetaStatement) keeps being
   * stored and distributed (§12-4).
   */
  readonly retireEnvironment: (environmentId: string, nowMs: number) => void;
  readonly insertVariable: (
    environmentId: string,
    variableId: string,
    name: string,
    nowMs: number,
  ) => void;
  /** Insert a variable statement row + synchronously update the variable-row cache (same shape as the environment one). */
  readonly insertVariableMetaStatement: (
    environmentId: string,
    variableId: string,
    statement: MetaStatementInput,
    signedBytesHashHex: string,
    author: MetaAuthorInfo,
    nowMs: number,
  ) => void;
  /** Tombstone + immediately delete every version (ciphertext). The deleted statement stays. */
  readonly retireVariable: (environmentId: string, variableId: string, nowMs: number) => void;
  /**
   * The upsert of an environment manifest (CRYPTO_SPEC §4.3 / AUTH_SPEC
   * §12-5). Only **the latest one** is kept per environment (§12-5 — no
   * verification path needs the past rows). issuer is the chain-derived
   * member at acceptance time (= the owner of the key used for the
   * signature check).
   */
  readonly upsertEnvironmentManifest: (
    environmentId: string,
    manifest: EnvManifestInput,
    signedBytesHashHex: string,
    issuer: MetaAuthorInfo,
    nowMs: number,
  ) => void;
  /**
   * Save a boundary checkpoint's value snapshot (CRYPTO_SPEC §6.4 /
   * AUTH_SPEC §16-2): upsert the latest covering checkpoint's tuple per
   * environment and replace the value-snapshot enumeration wholesale
   * per environment (when it matches the stored values digest the
   * enumeration is identical, so the replacement is skipped — the tuple
   * row is always updated). The existing snapshot of an environment not
   * in the payload is not modified (re-checkpointing only A does not
   * lose B's basis — §6.4). Called from inside the same synchronous
   * block as the chain append.
   */
  readonly upsertCheckpointSnapshot: (
    environmentId: string,
    checkpoint: CheckpointSnapshotInput,
    values: readonly CheckpointValueEntryRow[],
    nowMs: number,
  ) => void;
  /** Insert a version row and advance latest_version (called under the write lock). */
  readonly insertVersion: (
    environmentId: string,
    variableId: string,
    value: ValueInput,
    ciphertextBytes: number,
    signedBytesHashHex: string,
    writer: ValueWriterInfo,
    nowMs: number,
  ) => void;
  /**
   * Insert a wrap row. signer is the chain-derived member at
   * registration acceptance (= the owner of the key used for the
   * signature check — CRYPTO_SPEC §5.1).
   */
  readonly insertWrap: (
    environmentId: string,
    wrap: DekWrapInput,
    signer: WrapSignerInfo,
    nowMs: number,
  ) => void;
  /** The §12-6 repair path: delete one wrap (device slot); the caller has already done the existence check. */
  readonly deleteWrap: (
    environmentId: string,
    epoch: number,
    recipientUserId: string,
    recipientEncPubHex: string,
  ) => void;
  /**
   * The cleanup at §12-6 re-add acceptance: delete the wraps to the
   * target user_id (recipient class member) whose recipient enc public
   * key does not match `keepEncPubHex`, and return the deleted
   * (environment, epoch) pairs (the input of the dek.deleted audit
   * rows). Wraps to the current chain keys are never a target (the
   * overwrite-prohibition invariant is unchanged). Called from inside
   * the write phase (a single task) of an add_member acceptance.
   */
  readonly deleteStaleMemberWraps: (
    recipientUserId: string,
    keepEncPubHex: string,
  ) => readonly StaleWrapRef[];
  /**
   * The upsert of a head attestation (AUTH_SPEC §16-1 — **per device**,
   * the latest one row. 2026-09-19 DK). Monotonic seq advancement is
   * the caller's (attestation-accept.ts) job, which first compares the
   * same device's stored seq (regression 409 / same-seq idempotent
   * 204).
   */
  readonly upsertHeadAttestation: (attestation: StoredHeadAttestation, nowMs: number) => void;
  /**
   * Delete the attestation rows (all the target's devices) and the rate
   * window row at `remove_member` acceptance (CRYPTO_SPEC §6.4 —
   * converging the storage to "distribute to current members only";
   * same shape as the §12-6 old-key wrap cleanup). Called from inside a
   * single task, like the write phase of an add_member acceptance.
   */
  readonly deleteHeadAttestation: (attesterUserId: string) => void;
  /**
   * Delete the attestation row of the revoked device at `revoke_device`
   * acceptance (AUTH_SPEC §16-1 — 2026-09-19 DK). The window row (per
   * member) is left alone.
   */
  readonly deleteDeviceHeadAttestation: (attesterUserId: string, keyFingerprintHex: string) => void;
  /**
   * The upsert of schemaPolicy (AUTH_SPEC §12-11). Called in the same
   * synchronous block as the project.schema_policy_changed audit row
   * (the setting change and the audit row are atomic).
   */
  readonly setSchemaPolicy: (policy: SchemaPolicy) => void;
  /** Stores a sealed value proposal with its variables and wraps (AUTH_SPEC §14-5 — one synchronous block with the audit row). */
  readonly insertProposal: (proposal: ProposalWriteInput, nowMs: number) => void;
  /** Removes a proposal and its rows (resolution — the audit row carries the outcome). */
  readonly deleteProposal: (proposalId: string) => void;
  /** Sweeps expired proposals (called before a mint and a resolution). */
  readonly deleteExpiredProposals: (nowMs: number) => void;
}

/** The coordinates of a wrap deleted by the cleanup (the input of a dek.deleted audit row). */
export interface StaleWrapRef {
  readonly environmentId: string;
  readonly epoch: number;
}

/**
 * A stored head attestation (CRYPTO_SPEC §6.6 / AUTH_SPEC §16-1 — **per
 * device**, the latest one row. 2026-09-19 DK).
 * attesterKeyFingerprintHex is the key FP of the device that signed
 * the attestation (part of the primary key; the verification material
 * at distribution). The acceptance time (accepted_at) is **not**
 * included — it is stored but never distributed (§16-1), so it is
 * absent from the distribution-material type from the start.
 */
export interface StoredHeadAttestation {
  readonly attesterUserId: string;
  readonly suite: WireSuite;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly signatureHex: string;
  readonly attesterKeyFingerprintHex: string;
}

export interface DataStoreShape {
  readonly findEnvironment: (environmentId: string) => Effect.Effect<EnvironmentRow | null>;
  readonly countEnvironments: Effect.Effect<ResourceCounts>;
  readonly environmentNameTaken: (
    name: string,
    excludeEnvironmentId: string | null,
  ) => Effect.Effect<boolean>;
  /** The list of all environments (deleted included) with their latest statements (for the environment-list response). */
  readonly listEnvironmentStatements: Effect.Effect<
    readonly { environmentId: string; statement: DistributedMetaStatementValue }[]
  >;
  /** One environment's latest statement (for the pull response; a missing row is an invariant violation = null). */
  readonly environmentStatement: (
    environmentId: string,
  ) => Effect.Effect<DistributedMetaStatementValue | null>;
  /** The environment statement's verification anchor (the prev check — the §12-5 meta rules). */
  readonly environmentMetaAnchor: (
    environmentId: string,
    metaVersion: number,
  ) => Effect.Effect<MetaAnchor | null>;
  /**
   * The latest environment manifest (the distributed form — the §12-7
   * bundled material). null when no stored row exists (environment
   * creation bundles manifest_version 1, so it cannot happen on a
   * created environment).
   */
  readonly environmentManifest: (
    environmentId: string,
  ) => Effect.Effect<DistributedEnvManifestValue | null>;
  /**
   * The verification anchor of the latest manifest (the inputs of the
   * manifestVersion CAS = §12-5 (6) and the prev check = (5). epoch is
   * used for the predecessor's epoch-monotonicity check).
   */
  readonly environmentManifestAnchor: (
    environmentId: string,
  ) => Effect.Effect<EnvManifestAnchor | null>;

  readonly findVariable: (
    environmentId: string,
    variableId: string,
  ) => Effect.Effect<VariableRow | null>;
  readonly countVariables: (environmentId: string) => Effect.Effect<ResourceCounts>;
  readonly variableNameTaken: (
    environmentId: string,
    name: string,
    excludeVariableId: string | null,
  ) => Effect.Effect<boolean>;
  readonly listActiveVariables: (
    environmentId: string,
  ) => Effect.Effect<readonly { variableId: string; name: string }[]>;
  /** The variable statement's verification anchor (the prev check — the §12-5 meta rules). */
  readonly variableMetaAnchor: (
    environmentId: string,
    variableId: string,
    metaVersion: number,
  ) => Effect.Effect<MetaAnchor | null>;
  /** The deleted statements of deleted variables (kept being distributed on pull — §12-5). */
  readonly deletedVariableStatements: (
    environmentId: string,
  ) => Effect.Effect<readonly DistributedVariableMetaStatementValue[]>;
  /**
   * The latest statements of every non-deleted variable (declared
   * included) (the metadata-only mode — §12-7).
   */
  readonly activeVariableStatements: (
    environmentId: string,
  ) => Effect.Effect<readonly DistributedVariableMetaStatementValue[]>;
  /**
   * The latest statements of declared variables (the bundled material
   * of a value-bearing pull / a lease — §12-7; no value or version
   * exists).
   */
  readonly declaredVariableStatements: (
    environmentId: string,
  ) => Effect.Effect<readonly DistributedVariableMetaStatementValue[]>;
  /**
   * The digest tuples of the latest statements of all variables
   * (tombstones included) (the recompute input of CRYPTO_SPEC §4.3's
   * variables_digest — §12-5 (7)). metaSigHashHex is the
   * server-recomputed signed_bytes hash.
   */
  readonly variableDigestEntries: (
    environmentId: string,
  ) => Effect.Effect<readonly VariableDigestEntryRow[]>;
  /**
   * The recompute input of a checkpoint values_digest (the §6.4 content
   * cross-check — the stored state at acceptance time): each active
   * variable's latest version and the server-recomputed
   * value_signed_bytes hash. Tombstones are excluded (§6.2 — active
   * variables only; the manifest side captures the tombstones).
   */
  readonly checkpointValueEntries: (
    environmentId: string,
  ) => Effect.Effect<readonly CheckpointValueEntryRow[]>;
  /**
   * The distributed form of the checkpoint-time value snapshot (§12-7 /
   * §14-2): returns the latest covering checkpoint's tuple + enumeration
   * atomically saved at checkpoint acceptance as-is (never
   * reconstructed — §16-2). An environment without a basis is null (not
   * carried on the response).
   */
  readonly checkpointSnapshot: (
    environmentId: string,
  ) => Effect.Effect<CheckpointSnapshotValue | null>;

  /** Each active variable's latest version + latest statement (for the bulk pull). */
  readonly latestVersions: (
    environmentId: string,
  ) => Effect.Effect<
    readonly (PulledVariableValue & { statement: DistributedVariableMetaStatementValue })[]
  >;
  /**
   * Every stored version of one variable, ascending — metadata only (the
   * version history — §12-7, 2026-09-27 VH). No ciphertext is selected.
   */
  readonly versionHistory: (
    environmentId: string,
    variableId: string,
  ) => Effect.Effect<readonly StoredVersionMeta[]>;
  /**
   * The distributed form of versions fromVersion … fromVersion + limit − 1
   * of one variable, ascending (the version value range — §12-7, 2026-09-27
   * VH). Same columns as the bulk pull's value part.
   */
  readonly versionRange: (
    environmentId: string,
    variableId: string,
    fromVersion: number,
    limit: number,
  ) => Effect.Effect<readonly PulledVariableValue[]>;
  /** The stored version's verification anchor (the prev check — §12-5's 5). */
  readonly versionAnchor: (
    environmentId: string,
    variableId: string,
    version: number,
  ) => Effect.Effect<VersionAnchor | null>;
  /** The project's cumulative ciphertext bytes (the amount currently stored. §12-8). */
  readonly totalCiphertextBytes: Effect.Effect<number>;

  readonly countWrapsForEpoch: (environmentId: string, epoch: number) => Effect.Effect<number>;
  /** The DEK wrap row count of the whole project (the amount currently stored. §12-8). */
  readonly countWrapRows: Effect.Effect<number>;
  /**
   * The recipient class and enc public key of a stored wrap (null when
   * the row is absent). The delete path cross-checks the class against
   * the request's class — the client-declared class is never used
   * verbatim to pick the audit column (it detaches the §1-2 column
   * semantics from wire input). The enc public key is the input of the
   * overwrite-prohibited 409 response (AUTH_SPEC §12-6).
   */
  /**
   * All slots of (environment, epoch, recipient) (per device —
   * 2026-09-19 DK). The input of the uniqueness judgment when a delete
   * reference omits the device key (design record §8 K3-3).
   */
  readonly listWrapSlots: (
    environmentId: string,
    epoch: number,
    recipientUserId: string,
  ) => Effect.Effect<
    readonly { readonly recipientClass: string; readonly recipientEncPubHex: string }[]
  >;
  readonly wrapStoredRecipient: (
    environmentId: string,
    epoch: number,
    recipientUserId: string,
    recipientEncPubHex: string,
  ) => Effect.Effect<StoredWrapRecipient | null>;
  readonly listWrapsForRecipient: (
    environmentId: string,
    recipientUserId: string,
  ) => Effect.Effect<readonly RecipientDekValue[]>;
  /**
   * Returns the wraps to the server key FP (recipient class server) for
   * every epoch (the lease path of AUTH_SPEC §14 — CRYPTO_SPEC §9.1).
   * Kept separate from listWrapsForRecipient because the distribution
   * semantics differ: that one is **distribution to the recipient
   * itself** and carries the registration signature and signer
   * information, while this one is **material for the server to unwrap
   * itself** and never goes out on a response (only the result of the
   * unwrap → re-wrap does — server-key.ts).
   */
  readonly listServerWraps: (
    environmentId: string,
    serverKeyFingerprintHex: string,
  ) => Effect.Effect<readonly StoredServerWrap[]>;
  /**
   * **Judgment only** of the fixed window (does not consume — §14-3 /
   * AUDIT_SPEC §3.5). An expired window is treated as counting from 0.
   * Judgment and consumption are separated so the caller can express
   * the discipline "a window may be consumed only when an issuance was
   * actually made (recorded)".
   */
  readonly checkLeaseWindow: (
    kind: LeaseWindowKind,
    limit: number,
    nowMs: number,
  ) => Effect.Effect<LeaseWindowDecision>;
  /**
   * Consume the fixed window (counts 1). If the window has expired, its
   * start time is reset to now. Serialized under the DO's permit, so
   * nothing can interpose between judgment and consumption.
   */
  readonly recordLeaseWindowUse: (kind: LeaseWindowKind, nowMs: number) => void;
  /**
   * Whether the project is a read-only mirror (AUTH_SPEC §11-7 — the
   * `mirror_state` row of do-mirror.ts). Programs that must refuse a
   * write after their own authorization step (the workload mint —
   * existence concealment comes first) ask here; the DO's write entry
   * points are guarded in chain-do.ts
   */
  readonly isMirrorSync: () => boolean;
  /**
   * Query a first-come binding (AUTH_SPEC §14-1): returns the bound
   * ephemeral public key when a binding row within its validity period
   * exists. Expired rows are ignored by the expires_at condition,
   * **without depending on the rows' physical deletion (GC)** — the
   * correctness of the judgment is detached from GC timing.
   * `bindingKeyHex` is the hash of the JWS signing input (not of the
   * raw token — see the doc of programs-lease.ts's
   * LeaseTokenFacts.bindingKeyHex).
   */
  readonly leaseBinding: (bindingKeyHex: string, nowMs: number) => Effect.Effect<string | null>;
  /**
   * Record a first-come binding (called in the same synchronous block
   * as issuance, audit, and window consumption — §14-1). An existing
   * row (an idempotent retry with the same key + same public key) is
   * not overwritten. Also GCs expired rows (the row count's upper bound
   * = issuance rate window × retention — policy.ts).
   */
  readonly recordLeaseBinding: (
    bindingKeyHex: string,
    ephemeralPubHex: string,
    expiresAtMs: number,
    nowMs: number,
  ) => void;
  /**
   * The project's schemaPolicy (AUTH_SPEC §12-11 — no row = the default
   * disabled). The acceptance decision reads this in each program under
   * the DO permit (the policy at acceptance time).
   */
  readonly schemaPolicy: Effect.Effect<SchemaPolicy>;
  /** The stored attestation seq of the same device (user_id + key FP) (AUTH_SPEC §16-1 — per device; null when none was submitted — the input of the monotonic-advance check). */
  readonly headAttestationSeq: (
    attesterUserId: string,
    keyFingerprintHex: string,
  ) => Effect.Effect<number | null>;
  /**
   * Every member's stored head attestations (the distribution material
   * of AUTH_SPEC §16-1). The narrowing to current members is done by
   * the caller (chain-do.ts — the chain-derived current-member set):
   * the distribution side holds an independent defensive layer in case
   * the row deletion at remove (§6.4) missed one.
   */
  readonly listHeadAttestations: Effect.Effect<readonly StoredHeadAttestation[]>;
  /**
   * Judgment only of the per-member fixed window of head attestations
   * (does not consume — the same separation discipline as
   * checkLeaseWindow).
   */
  readonly checkAttestationWindow: (
    attesterUserId: string,
    limit: number,
    nowMs: number,
  ) => Effect.Effect<LeaseWindowDecision>;
  /** Consume the head-attestation fixed window (counts 1; serialized under the permit — nothing interposes with the judgment). */
  readonly recordAttestationWindowUse: (attesterUserId: string, nowMs: number) => void;

  /**
   * Sealed value proposals (AUTH_SPEC §14-5). "Pending" = stored and
   * unexpired at `nowMs` (resolution deletes the rows, so a stored row
   * is unresolved by construction). Expired rows are ignored by the
   * expires_at condition without depending on the sweep (the same
   * discipline as leaseBinding).
   */
  readonly proposalExists: (proposalId: string) => Effect.Effect<boolean>;
  readonly findPendingProposal: (
    proposalId: string,
    nowMs: number,
  ) => Effect.Effect<StoredProposal | null>;
  readonly listPendingProposals: (nowMs: number) => Effect.Effect<readonly StoredProposal[]>;
  readonly countPendingProposals: (nowMs: number) => Effect.Effect<number>;

  readonly write: DataWriteOps;
}

/** The fixed-window kinds (§14-3 issuance / AUDIT_SPEC §3.5 denial record). */
/** `proposed` = the sealed-proposal mint window (AUTH_SPEC §14-5 — its own counter beside issuance). */
type LeaseWindowKind = "issued" | "denied" | "proposed" | "exported";

/** The fixed-window decision (on excess it returns the window's remaining seconds — same shape as the §13-3 precedent). */
interface LeaseWindowDecision {
  readonly allowed: boolean;
  readonly retryAfterSeconds: number;
}

/** A proposed value sealed to one recipient device (a stored row — AUTH_SPEC §14-5). */
export interface StoredProposalWrap {
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

export interface StoredProposalVariable {
  readonly variableId: string;
  readonly baseVersion: number;
  readonly wraps: readonly StoredProposalWrap[];
}

/** One stored sealed value proposal with its variables and wraps (CRYPTO_SPEC §5.3). */
export interface StoredProposal {
  readonly proposalId: string;
  readonly environmentId: string;
  readonly connector: string;
  readonly facts: readonly string[];
  readonly claimsDigestHex: string;
  readonly grantChainSeq: number;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly variables: readonly StoredProposalVariable[];
}

/** What the mint program hands the store (the wire proposal + the lease's attribution). */
export interface ProposalWriteInput {
  readonly proposalId: string;
  readonly environmentId: string;
  readonly connector: string;
  readonly facts: readonly string[];
  readonly claimsDigestHex: string;
  readonly grantChainSeq: number;
  readonly expiresAtMs: number;
  readonly variables: readonly StoredProposalVariable[];
}

export class DataStore extends Context.Service<DataStore, DataStoreShape>()("DataStore") {}

// ---------------------------------------------------------------------------
// The row-decode safety layer: check a required column's presence and
// type; a mismatch becomes a defect with an explanation. A bare
// String(...) / Number(...) passthrough would let a column-name typo /
// rename through as the string "undefined" or NaN, so every row →
// domain-type mapping goes through here (the same discipline as
// storedSuite / statementOf's status check — "an unknown value is a
// defect" — extended to every column).
// ---------------------------------------------------------------------------

type StoredRow = Record<string, unknown>;

/** A column's existence check (a column-name mismatch between the SELECT clause and the decoder = detection of an implementation bug). */
function columnValue(row: StoredRow, column: string): unknown {
  const value = row[column];
  if (value === undefined) {
    throw new Error(`stored row is missing column "${column}"`);
  }
  return value;
}

function stringColumn(row: StoredRow, column: string): string {
  const value = columnValue(row, column);
  if (typeof value !== "string") {
    throw new Error(`stored column "${column}" is not a string`);
  }
  return value;
}

function numberColumn(row: StoredRow, column: string): number {
  const value = columnValue(row, column);
  if (typeof value !== "number") {
    throw new Error(`stored column "${column}" is not a number`);
  }
  return value;
}

function nullableNumberColumn(row: StoredRow, column: string): number | null {
  const value = columnValue(row, column);
  if (value !== null && typeof value !== "number") {
    throw new Error(`stored column "${column}" is not a number or NULL`);
  }
  return value;
}

function countsOf(row: StoredRow | undefined): ResourceCounts {
  if (row === undefined) {
    return { active: 0, rows: 0 };
  }
  // SUM(CASE ...) returns NULL on zero rows, so it is read as 0 (COUNT is always a number)
  const active = nullableNumberColumn(row, "active_rows");
  return { active: active ?? 0, rows: numberColumn(row, "total_rows") };
}

/**
 * Read out the stored suite column. Since the write path is pinned by
 * the Schema Literal (§12-2), a value outside the known set is storage
 * corruption and drops to a defect (never swallowed by a cast).
 */
function storedSuite(value: unknown): WireSuite {
  if (value !== "maruhi/v1") {
    throw new Error("unexpected suite in stored row");
  }
  return value;
}

/**
 * The stored status column → an environment statement's 2 values
 * (environment meta is outside v2's scope — CRYPTO_SPEC §4.2). An
 * unknown value is a defect as storage corruption.
 */
function storedEnvStatus(value: string): "active" | "deleted" {
  if (value !== "active" && value !== "deleted") {
    // The write path is pinned by the Schema Literal (an unknown value is storage corruption)
    throw new Error("unexpected status in stored meta statement row");
  }
  return value;
}

/** The stored status column → a variable statement's 3 values (declared is v2 only). */
function storedVariableStatus(value: string): MetaStatementStatusInput {
  if (value !== "active" && value !== "deleted" && value !== "declared") {
    throw new Error("unexpected status in stored meta statement row");
  }
  return value;
}

/** The stored var_type column → the closed set (CRYPTO_SPEC §4.2 — an unknown value is a defect). */
function storedVarType(value: string): MetaVarTypeInput {
  if (
    value !== "" &&
    value !== "string" &&
    value !== "number" &&
    value !== "boolean" &&
    value !== "url"
  ) {
    throw new Error("unexpected var_type in stored meta statement row");
  }
  return value;
}

/** The stored required column ("true" / "false" — the signed-target representation) → boolean. */
function storedRequired(value: string): boolean {
  if (value !== "true" && value !== "false") {
    throw new Error("unexpected required in stored meta statement row");
  }
  return value === "true";
}

function nullableStringColumn(row: StoredRow, column: string): string | null {
  const value = columnValue(row, column);
  if (value !== null && typeof value !== "string") {
    throw new Error(`stored column "${column}" is not a string or NULL`);
  }
  return value;
}

/**
 * Decode the layout-v2 schema columns (a v1 row = all 4 columns treated
 * as absent → null). A NULL schema column on a v2 row is an invariant
 * violation of the write path (a defect).
 */
function storedSchemaColumns(row: StoredRow, prefix: string): MetaVariableSchemaInput | null {
  const layoutVersion = numberColumn(row, `${prefix}layout_version`);
  if (layoutVersion === 1) {
    return null;
  }
  const varType = nullableStringColumn(row, `${prefix}var_type`);
  const required = nullableStringColumn(row, `${prefix}required`);
  const description = nullableStringColumn(row, `${prefix}description`);
  if (varType === null || required === null || description === null) {
    throw new Error("layout v2 meta statement row is missing schema columns");
  }
  if (layoutVersion === 2) {
    return { varType: storedVarType(varType), required: storedRequired(required), description };
  }
  // Layout v3: max_age_days is stored as the signed string ("" = none)
  const maxAge = nullableStringColumn(row, `${prefix}max_age_days`);
  if (maxAge === null) {
    throw new Error("layout v3 meta statement row is missing max_age_days");
  }
  return {
    varType: storedVarType(varType),
    required: storedRequired(required),
    description,
    maxAgeDays: maxAge === "" ? null : Number(maxAge),
  };
}

/**
 * Decode the meta-statement columns (the common part excluding
 * environmentId / variableId). prefix serves latestVersions's SQL
 * aliases (ms_*) — the aliased row is read as-is without assembling a
 * pseudo-row object. The caller picks the status decode between
 * environment (2 values) and variable (3 values).
 */
function statementColumns<S extends MetaStatementStatusInput>(
  row: StoredRow,
  prefix: string,
  statusOf: (value: string) => S,
): Omit<DistributedMetaStatementValue, "environmentId" | "status"> & { readonly status: S } {
  return {
    suite: storedSuite(columnValue(row, `${prefix}suite`)),
    name: stringColumn(row, `${prefix}name`),
    status: statusOf(stringColumn(row, `${prefix}status`)),
    metaVersion: numberColumn(row, `${prefix}meta_version`),
    prevMetaSigHashHex: stringColumn(row, `${prefix}prev_meta_sig_hash_hex`),
    chainHeadHashHex: stringColumn(row, `${prefix}chain_head_hash_hex`),
    chainHeadSeq: numberColumn(row, `${prefix}chain_head_seq`),
    signatureHex: stringColumn(row, `${prefix}signature_hex`),
    authorUserId: stringColumn(row, `${prefix}author_user_id`),
    authorKeyFingerprintHex: stringColumn(row, `${prefix}author_key_fingerprint`),
  };
}

/** An environment meta-statement row → the distributed form (author included; environmentId comes from the column). */
function statementOf(row: StoredRow): DistributedMetaStatementValue {
  return {
    environmentId: stringColumn(row, "environment_id"),
    ...statementColumns(row, "", storedEnvStatus),
  };
}

/**
 * Variable-statement columns → the distributed form's v2 carried
 * fields (§12-2): on a v1 row all four fields are absent (no new field
 * is added to a v1 distribution); on a v2 row layoutVersion + the
 * schema fields are expanded.
 */
function variableStatementV2Fields(
  row: StoredRow,
  prefix: string,
): Pick<
  DistributedVariableMetaStatementValue,
  "layoutVersion" | "varType" | "required" | "description" | "maxAgeDays"
> {
  const schema = storedSchemaColumns(row, prefix);
  if (schema === null) {
    return {};
  }
  return {
    layoutVersion: numberColumn(row, `${prefix}layout_version`),
    varType: schema.varType,
    required: schema.required,
    description: schema.description,
    // Layout v3 carries maxAgeDays (null = none); a v2 row carries no such field
    ...(schema.maxAgeDays === undefined ? {} : { maxAgeDays: schema.maxAgeDays }),
  };
}

function variableStatementOf(row: StoredRow): DistributedVariableMetaStatementValue {
  return {
    environmentId: stringColumn(row, "environment_id"),
    variableId: stringColumn(row, "variable_id"),
    ...statementColumns(row, "", storedVariableStatus),
    ...variableStatementV2Fields(row, ""),
  };
}

/** A variable statement's anchor row → MetaAnchor (layoutVersion is the stored actual value). */
function variableAnchorOf(row: StoredRow | undefined): MetaAnchor | null {
  if (row === undefined) {
    return null;
  }
  return {
    signedBytesHashHex: stringColumn(row, "signed_bytes_hash_hex"),
    status: storedVariableStatus(stringColumn(row, "status")),
    layoutVersion: numberColumn(row, "layout_version"),
    schema: storedSchemaColumns(row, ""),
  };
}

/** An environment statement's anchor row → MetaAnchor (environment meta is always layout 1). */
function environmentAnchorOf(row: StoredRow | undefined): MetaAnchor | null {
  if (row === undefined) {
    return null;
  }
  return {
    signedBytesHashHex: stringColumn(row, "signed_bytes_hash_hex"),
    status: storedEnvStatus(stringColumn(row, "status")),
    layoutVersion: 1,
    schema: null,
  };
}

// Distribution (§12-2) does not select signed_bytes_hash_hex = never
// distributes it (a verifier recomputes it themselves). Only the
// anchor lookups (*AnchorOf) read the hash column
const MS_COLUMNS =
  "ms.environment_id, ms.suite, ms.name, ms.status, ms.meta_version, ms.prev_meta_sig_hash_hex, ms.chain_head_hash_hex, ms.chain_head_seq, ms.signature_hex, ms.author_user_id, ms.author_key_fingerprint";

// A variable statement also selects the v2 carried-field columns
// (columns that do not exist in the environment side's SELECT —
// environment_meta_statements is outside v2's scope)
const VAR_MS_COLUMNS = `${MS_COLUMNS}, ms.layout_version, ms.var_type, ms.required, ms.description, ms.max_age_days`;

const makeEnvironmentQueries = (sql: SqlStorage) => ({
  findEnvironment: (environmentId: string) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          "SELECT environment_id, name, latest_meta_version, deleted_at FROM environments WHERE environment_id = ?",
          environmentId,
        )
        .toArray()[0];
      if (row === undefined) {
        return null;
      }
      return {
        environmentId: stringColumn(row, "environment_id"),
        name: stringColumn(row, "name"),
        latestMetaVersion: numberColumn(row, "latest_meta_version"),
        deletedAtMs: nullableNumberColumn(row, "deleted_at"),
      };
    }),
  countEnvironments: Effect.sync(() => {
    const row = sql
      .exec(
        `SELECT COUNT(*) AS total_rows, SUM(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END) AS active_rows
         FROM environments`,
      )
      .toArray()[0];
    return countsOf(row);
  }),
  environmentNameTaken: (name: string, excludeEnvironmentId: string | null) =>
    Effect.sync(() => {
      const rows = sql
        .exec(
          `SELECT 1 FROM environments
           WHERE name = ? AND deleted_at IS NULL AND environment_id != ? LIMIT 1`,
          name,
          excludeEnvironmentId ?? "",
        )
        .toArray();
      return rows.length > 0;
    }),
  // Deleted environments are also listed with their deleted statement
  // (the detection material for a denied deletion / unauthorized
  // revival — §12-4; the client discriminates by the statement's
  // status)
  listEnvironmentStatements: Effect.sync(() =>
    sql
      .exec(
        `SELECT ${MS_COLUMNS}
         FROM environments e
         JOIN environment_meta_statements ms
           ON ms.environment_id = e.environment_id
          AND ms.meta_version = e.latest_meta_version
         ORDER BY e.created_at, e.environment_id`,
      )
      .toArray()
      .map((row) => ({
        environmentId: stringColumn(row, "environment_id"),
        statement: statementOf(row),
      })),
  ),
  environmentStatement: (environmentId: string) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          `SELECT ${MS_COLUMNS}
           FROM environments e
           JOIN environment_meta_statements ms
             ON ms.environment_id = e.environment_id
            AND ms.meta_version = e.latest_meta_version
           WHERE e.environment_id = ?`,
          environmentId,
        )
        .toArray()[0];
      return row === undefined ? null : statementOf(row);
    }),
  environmentMetaAnchor: (environmentId: string, metaVersion: number) =>
    Effect.sync(() =>
      environmentAnchorOf(
        sql
          .exec(
            `SELECT signed_bytes_hash_hex, status FROM environment_meta_statements
             WHERE environment_id = ? AND meta_version = ?`,
            environmentId,
            metaVersion,
          )
          .toArray()[0],
      ),
    ),
  // Distribution (§12-2) does not select signed_bytes_hash_hex = never
  // distributes it (a verifier recomputes it themselves — the same
  // discipline as statement distribution)
  environmentManifest: (environmentId: string) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          `SELECT environment_id, suite, epoch, manifest_version, variables_digest_hex,
                  env_meta_version, env_meta_sig_hash_hex, prev_manifest_sig_hash_hex,
                  chain_head_hash_hex, chain_head_seq, signature_hex,
                  issuer_user_id, issuer_key_fingerprint
           FROM environment_manifests WHERE environment_id = ?`,
          environmentId,
        )
        .toArray()[0];
      if (row === undefined) {
        return null;
      }
      return {
        environmentId: stringColumn(row, "environment_id"),
        suite: storedSuite(columnValue(row, "suite")),
        epoch: numberColumn(row, "epoch"),
        manifestVersion: numberColumn(row, "manifest_version"),
        variablesDigestHex: stringColumn(row, "variables_digest_hex"),
        envMetaVersion: numberColumn(row, "env_meta_version"),
        envMetaSigHashHex: stringColumn(row, "env_meta_sig_hash_hex"),
        prevManifestSigHashHex: stringColumn(row, "prev_manifest_sig_hash_hex"),
        chainHeadHashHex: stringColumn(row, "chain_head_hash_hex"),
        chainHeadSeq: numberColumn(row, "chain_head_seq"),
        signatureHex: stringColumn(row, "signature_hex"),
        issuerUserId: stringColumn(row, "issuer_user_id"),
        issuerKeyFingerprintHex: stringColumn(row, "issuer_key_fingerprint"),
      };
    }),
  environmentManifestAnchor: (environmentId: string) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          `SELECT manifest_version, signed_bytes_hash_hex, epoch
           FROM environment_manifests WHERE environment_id = ?`,
          environmentId,
        )
        .toArray()[0];
      if (row === undefined) {
        return null;
      }
      return {
        manifestVersion: numberColumn(row, "manifest_version"),
        signedBytesHashHex: stringColumn(row, "signed_bytes_hash_hex"),
        epoch: numberColumn(row, "epoch"),
      };
    }),
});

const makeVariableQueries = (sql: SqlStorage) => ({
  findVariable: (environmentId: string, variableId: string) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          `SELECT v.variable_id, v.name, v.latest_meta_version, v.latest_version, v.deleted_at,
                  ms.status
           FROM variables v
           JOIN variable_meta_statements ms
             ON ms.environment_id = v.environment_id
            AND ms.variable_id = v.variable_id
            AND ms.meta_version = v.latest_meta_version
           WHERE v.environment_id = ? AND v.variable_id = ?`,
          environmentId,
          variableId,
        )
        .toArray()[0];
      if (row === undefined) {
        return null;
      }
      return {
        variableId: stringColumn(row, "variable_id"),
        name: stringColumn(row, "name"),
        latestMetaVersion: numberColumn(row, "latest_meta_version"),
        latestVersion: numberColumn(row, "latest_version"),
        latestStatus: storedVariableStatus(stringColumn(row, "status")),
        deletedAtMs: nullableNumberColumn(row, "deleted_at"),
      };
    }),
  variableMetaAnchor: (environmentId: string, variableId: string, metaVersion: number) =>
    Effect.sync(() =>
      variableAnchorOf(
        sql
          .exec(
            `SELECT signed_bytes_hash_hex, status, layout_version, var_type, required, description,
                    max_age_days
             FROM variable_meta_statements
             WHERE environment_id = ? AND variable_id = ? AND meta_version = ?`,
            environmentId,
            variableId,
            metaVersion,
          )
          .toArray()[0],
      ),
    ),
  deletedVariableStatements: (environmentId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT ms.variable_id, ${VAR_MS_COLUMNS}
           FROM variables v
           JOIN variable_meta_statements ms
             ON ms.environment_id = v.environment_id
            AND ms.variable_id = v.variable_id
            AND ms.meta_version = v.latest_meta_version
           WHERE v.environment_id = ? AND v.deleted_at IS NOT NULL
           ORDER BY v.created_at, v.variable_id`,
          environmentId,
        )
        .toArray()
        .map(variableStatementOf),
    ),
  // The active side of deletedVariableStatements (the metadata-only
  // mode — §12-7): the latest statements only. Values and DEKs are not
  // selected (never distributed, so never touched). The statements of
  // declared variables are included too (the latest form of every
  // non-deleted variable — status carries the discrimination)
  activeVariableStatements: (environmentId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT ms.variable_id, ${VAR_MS_COLUMNS}
           FROM variables v
           JOIN variable_meta_statements ms
             ON ms.environment_id = v.environment_id
            AND ms.variable_id = v.variable_id
            AND ms.meta_version = v.latest_meta_version
           WHERE v.environment_id = ? AND v.deleted_at IS NULL
           ORDER BY v.created_at, v.variable_id`,
          environmentId,
        )
        .toArray()
        .map(variableStatementOf),
    ),
  // The latest statements of declared variables (the bundled material
  // of a value-bearing pull — §12-7; they never appear in
  // latestVersions because no value or version exists: the JOIN
  // naturally excludes the rows with latest_version 0)
  declaredVariableStatements: (environmentId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT ms.variable_id, ${VAR_MS_COLUMNS}
           FROM variables v
           JOIN variable_meta_statements ms
             ON ms.environment_id = v.environment_id
            AND ms.variable_id = v.variable_id
            AND ms.meta_version = v.latest_meta_version
           WHERE v.environment_id = ? AND v.deleted_at IS NULL AND ms.status = 'declared'
           ORDER BY v.created_at, v.variable_id`,
          environmentId,
        )
        .toArray()
        .map(variableStatementOf),
    ),
  countVariables: (environmentId: string) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          `SELECT COUNT(*) AS total_rows, SUM(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END) AS active_rows
           FROM variables WHERE environment_id = ?`,
          environmentId,
        )
        .toArray()[0];
      return countsOf(row);
    }),
  // The recompute input of variables_digest (§12-5 (7)): the latest
  // form of every variable, tombstones included. The canonical order
  // (byte-ascending variable_id) is established internally by crypto's
  // computeVariablesDigest, so the order is not canonicalized here
  variableDigestEntries: (environmentId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT v.variable_id, ms.status, ms.meta_version, ms.signed_bytes_hash_hex
           FROM variables v
           JOIN variable_meta_statements ms
             ON ms.environment_id = v.environment_id
            AND ms.variable_id = v.variable_id
            AND ms.meta_version = v.latest_meta_version
           WHERE v.environment_id = ?
           ORDER BY v.variable_id`,
          environmentId,
        )
        .toArray()
        .map((row): VariableDigestEntryRow => ({
          variableId: stringColumn(row, "variable_id"),
          // declared naturally rides along as an entry's status value
          // (CRYPTO_SPEC §4.3 — the canonical form and encoder are
          // unchanged)
          status: storedVariableStatus(stringColumn(row, "status")),
          metaVersion: numberColumn(row, "meta_version"),
          metaSigHashHex: stringColumn(row, "signed_bytes_hash_hex"),
        })),
    ),
  // The recompute input of a checkpoint values_digest (§6.4): each
  // active variable's latest version and stored value_signed_bytes
  // hash. The canonical order (byte-ascending variable_id) is
  // established internally by crypto's computeEnvValuesDigest, so the
  // order is not canonicalized here
  checkpointValueEntries: (environmentId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT v.variable_id, vv.version, vv.signed_bytes_hash_hex
           FROM variables v
           JOIN variable_versions vv
             ON vv.environment_id = v.environment_id
            AND vv.variable_id = v.variable_id
            AND vv.version = v.latest_version
           WHERE v.environment_id = ? AND v.deleted_at IS NULL
           ORDER BY v.variable_id`,
          environmentId,
        )
        .toArray()
        .map((row): CheckpointValueEntryRow => ({
          variableId: stringColumn(row, "variable_id"),
          version: numberColumn(row, "version"),
          valueSigHashHex: stringColumn(row, "signed_bytes_hash_hex"),
        })),
    ),
  // The distributed checkpoint snapshot (§12-7 — the stored rows
  // themselves)
  checkpointSnapshot: (environmentId: string) =>
    Effect.sync((): CheckpointSnapshotValue | null => {
      const row = sql
        .exec(
          "SELECT chain_seq, entry_hash_hex FROM environment_checkpoints WHERE environment_id = ?",
          environmentId,
        )
        .toArray()[0];
      if (row === undefined) {
        return null;
      }
      const values = sql
        .exec(
          `SELECT variable_id, version, value_sig_hash_hex
           FROM checkpoint_snapshot_values
           WHERE environment_id = ? ORDER BY variable_id`,
          environmentId,
        )
        .toArray()
        .map((value): CheckpointSnapshotEntryValue => ({
          variableId: stringColumn(value, "variable_id"),
          version: numberColumn(value, "version"),
          valueSigHashHex: stringColumn(value, "value_sig_hash_hex"),
        }));
      return {
        chainSeq: numberColumn(row, "chain_seq"),
        entryHashHex: stringColumn(row, "entry_hash_hex"),
        values,
      };
    }),
  variableNameTaken: (environmentId: string, name: string, excludeVariableId: string | null) =>
    Effect.sync(() => {
      const rows = sql
        .exec(
          `SELECT 1 FROM variables
           WHERE environment_id = ? AND name = ? AND deleted_at IS NULL AND variable_id != ? LIMIT 1`,
          environmentId,
          name,
          excludeVariableId ?? "",
        )
        .toArray();
      return rows.length > 0;
    }),
  listActiveVariables: (environmentId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT variable_id, name FROM variables
           WHERE environment_id = ? AND deleted_at IS NULL ORDER BY created_at, variable_id`,
          environmentId,
        )
        .toArray()
        .map((row) => ({
          variableId: stringColumn(row, "variable_id"),
          name: stringColumn(row, "name"),
        })),
    ),
});

/**
 * A variable_versions row's distributed value columns (§12-7 — shared by the
 * bulk pull and the version value range). signed_bytes_hash_hex is never
 * selected = never distributed (AUTH_SPEC §12-2).
 */
function pulledValueColumns(row: StoredRow, variableId: string): PulledVariableValue {
  return {
    variableId,
    version: numberColumn(row, "version"),
    suite: storedSuite(columnValue(row, "suite")),
    epoch: numberColumn(row, "epoch"),
    nonceHex: stringColumn(row, "nonce_hex"),
    ciphertextHex: stringColumn(row, "ciphertext_hex"),
    prevValueSigHashHex: stringColumn(row, "prev_value_sig_hash_hex"),
    chainHeadHashHex: stringColumn(row, "chain_head_hash_hex"),
    chainHeadSeq: numberColumn(row, "chain_head_seq"),
    signatureHex: stringColumn(row, "signature_hex"),
    writerUserId: stringColumn(row, "writer_user_id"),
    writerKeyFingerprintHex: stringColumn(row, "writer_key_fingerprint"),
  };
}

const makeVersionQueries = (sql: SqlStorage) => ({
  // Distribution (§12-7) returns the stored signature block and the
  // writer / author as-is (never re-derived from the current member
  // set — verifiability of past data by a since-deleted writer /
  // author). signed_bytes_hash_hex is not selected on either values or
  // statements = never distributed (AUTH_SPEC §12-2)
  latestVersions: (environmentId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT v.variable_id, vv.version, vv.suite, vv.epoch, vv.nonce_hex, vv.ciphertext_hex,
                  vv.prev_value_sig_hash_hex, vv.chain_head_hash_hex, vv.chain_head_seq,
                  vv.signature_hex, vv.writer_user_id, vv.writer_key_fingerprint,
                  ms.suite AS ms_suite, ms.name AS ms_name, ms.status AS ms_status,
                  ms.meta_version AS ms_meta_version,
                  ms.prev_meta_sig_hash_hex AS ms_prev_meta_sig_hash_hex,
                  ms.chain_head_hash_hex AS ms_chain_head_hash_hex,
                  ms.chain_head_seq AS ms_chain_head_seq,
                  ms.signature_hex AS ms_signature_hex,
                  ms.author_user_id AS ms_author_user_id,
                  ms.author_key_fingerprint AS ms_author_key_fingerprint,
                  ms.layout_version AS ms_layout_version, ms.var_type AS ms_var_type,
                  ms.required AS ms_required, ms.description AS ms_description,
                  ms.max_age_days AS ms_max_age_days
           FROM variables v
           JOIN variable_versions vv
             ON vv.environment_id = v.environment_id
            AND vv.variable_id = v.variable_id
            AND vv.version = v.latest_version
           JOIN variable_meta_statements ms
             ON ms.environment_id = v.environment_id
            AND ms.variable_id = v.variable_id
            AND ms.meta_version = v.latest_meta_version
           WHERE v.environment_id = ? AND v.deleted_at IS NULL
           ORDER BY v.created_at, v.variable_id`,
          environmentId,
        )
        .toArray()
        .map((row) => ({
          ...pulledValueColumns(row, stringColumn(row, "variable_id")),
          // The statement part reads the ms_* aliased columns as-is
          // (statementColumns's prefix). The environment ID is the
          // WHERE-clause argument; the variable ID is the row's value
          statement: {
            environmentId,
            variableId: stringColumn(row, "variable_id"),
            ...statementColumns(row, "ms_", storedVariableStatus),
            ...variableStatementV2Fields(row, "ms_"),
          },
        })),
    ),
  versionHistory: (environmentId: string, variableId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT version, epoch, writer_user_id, writer_key_fingerprint, created_at
           FROM variable_versions
           WHERE environment_id = ? AND variable_id = ?
           ORDER BY version`,
          environmentId,
          variableId,
        )
        .toArray()
        .map((row): StoredVersionMeta => ({
          version: numberColumn(row, "version"),
          epoch: numberColumn(row, "epoch"),
          writerUserId: stringColumn(row, "writer_user_id"),
          writerKeyFingerprintHex: stringColumn(row, "writer_key_fingerprint"),
          pushedAtMs: numberColumn(row, "created_at"),
        })),
    ),
  versionRange: (environmentId: string, variableId: string, fromVersion: number, limit: number) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT version, suite, epoch, nonce_hex, ciphertext_hex, prev_value_sig_hash_hex,
                  chain_head_hash_hex, chain_head_seq, signature_hex,
                  writer_user_id, writer_key_fingerprint
           FROM variable_versions
           WHERE environment_id = ? AND variable_id = ? AND version >= ?
           ORDER BY version
           LIMIT ?`,
          environmentId,
          variableId,
          fromVersion,
          limit,
        )
        .toArray()
        .map((row) => pulledValueColumns(row, variableId)),
    ),
  versionAnchor: (environmentId: string, variableId: string, version: number) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          `SELECT signed_bytes_hash_hex, epoch FROM variable_versions
           WHERE environment_id = ? AND variable_id = ? AND version = ?`,
          environmentId,
          variableId,
          version,
        )
        .toArray()[0];
      if (row === undefined) {
        return null;
      }
      return {
        signedBytesHashHex: stringColumn(row, "signed_bytes_hash_hex"),
        epoch: numberColumn(row, "epoch"),
      };
    }),
  // The §12-8 meter: version ciphertexts plus the sealed values of
  // pending proposals (hex columns — two characters per byte), so a
  // project cannot park ciphertext outside the cap in proposals
  totalCiphertextBytes: Effect.sync(() => {
    const row = sql
      .exec(
        `SELECT (SELECT COALESCE(SUM(ciphertext_bytes), 0) FROM variable_versions)
              + (SELECT COALESCE(SUM(length(ciphertext_hex)), 0) / 2 FROM rotation_proposal_wraps)
              AS total`,
      )
      .toArray()[0];
    return row === undefined ? 0 : numberColumn(row, "total");
  }),
});

const makeWrapQueries = (sql: SqlStorage) => ({
  countWrapsForEpoch: (environmentId: string, epoch: number) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          "SELECT COUNT(*) AS n FROM dek_wraps WHERE environment_id = ? AND epoch = ?",
          environmentId,
          epoch,
        )
        .toArray()[0];
      return row === undefined ? 0 : numberColumn(row, "n");
    }),
  countWrapRows: Effect.sync(() => {
    const row = sql.exec("SELECT COUNT(*) AS n FROM dek_wraps").toArray()[0];
    return row === undefined ? 0 : numberColumn(row, "n");
  }),
  listWrapSlots: (environmentId: string, epoch: number, recipientUserId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          "SELECT recipient_class, recipient_enc_pub_hex FROM dek_wraps WHERE environment_id = ? AND epoch = ? AND recipient_user_id = ? ORDER BY recipient_enc_pub_hex",
          environmentId,
          epoch,
          recipientUserId,
        )
        .toArray()
        .map((row) => ({
          recipientClass: stringColumn(row, "recipient_class"),
          recipientEncPubHex: stringColumn(row, "recipient_enc_pub_hex"),
        })),
    ),
  wrapStoredRecipient: (
    environmentId: string,
    epoch: number,
    recipientUserId: string,
    recipientEncPubHex: string,
  ) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          "SELECT recipient_class, recipient_enc_pub_hex FROM dek_wraps WHERE environment_id = ? AND epoch = ? AND recipient_user_id = ? AND recipient_enc_pub_hex = ? LIMIT 1",
          environmentId,
          epoch,
          recipientUserId,
          recipientEncPubHex,
        )
        .toArray()[0];
      return row === undefined
        ? null
        : {
            recipientClass: stringColumn(row, "recipient_class"),
            recipientEncPubHex: stringColumn(row, "recipient_enc_pub_hex"),
          };
    }),
  // Distribution is to the recipient only (§12-6). A server-class row
  // cannot be looked up by user_id because the identifier shapes do
  // not intersect, but the class condition is stated explicitly to pin
  // the boundary
  listWrapsForRecipient: (environmentId: string, recipientUserId: string) =>
    Effect.sync(() =>
      selectWrapRows(sql, {
        environmentId,
        recipientClass: "member",
        recipientUserId,
        extraColumns:
          "recipient_enc_pub_hex, signature_hex, signer_user_id, signer_key_fingerprint",
      }).map((row) => ({
        ...wrapBodyOf(row),
        recipientEncPubHex: stringColumn(row, "recipient_enc_pub_hex"),
        signatureHex: stringColumn(row, "signature_hex"),
        signerUserId: stringColumn(row, "signer_user_id"),
        signerKeyFingerprintHex: stringColumn(row, "signer_key_fingerprint"),
      })),
    ),
  // Narrowing by FP as well keeps an environment that went through
  // revocation → re-grant under a different key from grabbing a row
  // addressed to the old server key that the current key cannot unwrap
  // (an unwrap failure is indistinguishable from a poisoned wrap and
  // would muddy the 503's reason)
  listServerWraps: (environmentId: string, serverKeyFingerprintHex: string) =>
    Effect.sync(() =>
      selectWrapRows(sql, {
        environmentId,
        recipientClass: "server",
        recipientUserId: serverKeyFingerprintHex,
      }).map((row) => wrapBodyOf(row)),
    ),
  checkLeaseWindow: (kind: LeaseWindowKind, limit: number, nowMs: number) =>
    Effect.sync(() => {
      const current = leaseWindowRow(sql, kind, nowMs);
      // An expired window, a first request, and a clock rewind all mean
      // "count from 0" = always allowed
      if (current === null || current.count < limit) {
        return { allowed: true, retryAfterSeconds: 0 };
      }
      return {
        allowed: false,
        retryAfterSeconds: Math.ceil((LEASE_WINDOW_MS - current.elapsed) / 1000),
      };
    }),
  isMirrorSync: () => sql.exec("SELECT 1 FROM mirror_state WHERE id = 1").toArray().length > 0,
  recordLeaseWindowUse: (kind: LeaseWindowKind, nowMs: number) => {
    if (leaseWindowRow(sql, kind, nowMs) === null) {
      sql.exec(
        `INSERT INTO lease_windows (kind, window_start, count) VALUES (?, ?, 1)
         ON CONFLICT(kind) DO UPDATE SET window_start = excluded.window_start, count = 1`,
        kind,
        nowMs,
      );
      return;
    }
    sql.exec("UPDATE lease_windows SET count = count + 1 WHERE kind = ?", kind);
  },
  leaseBinding: (bindingKeyHex: string, nowMs: number) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          "SELECT ephemeral_pub_hex FROM lease_bindings WHERE binding_key_hex = ? AND expires_at > ?",
          bindingKeyHex,
          nowMs,
        )
        .toArray()[0];
      return row === undefined ? null : stringColumn(row, "ephemeral_pub_hex");
    }),
  recordLeaseBinding: (
    bindingKeyHex: string,
    ephemeralPubHex: string,
    expiresAtMs: number,
    nowMs: number,
  ) => {
    // Placing the GC first keeps an expired leftover of the same key
    // from blocking a new binding's record via a primary-key conflict
    // (the query side already ignores it via the expires_at condition)
    sql.exec("DELETE FROM lease_bindings WHERE expires_at <= ?", nowMs);
    sql.exec(
      `INSERT INTO lease_bindings (binding_key_hex, ephemeral_pub_hex, expires_at)
       VALUES (?, ?, ?) ON CONFLICT(binding_key_hex) DO NOTHING`,
      bindingKeyHex,
      ephemeralPubHex,
      expiresAtMs,
    );
  },
});

/**
 * Project settings (AUTH_SPEC §12-11 — currently only schemaPolicy). No
 * row = the default disabled. An unknown stored value is a defect as
 * storage corruption (the same discipline as storedSuite — never
 * silently re-read as the default).
 */
const makeSettingsQueries = (sql: SqlStorage) => ({
  schemaPolicy: Effect.sync((): SchemaPolicy => {
    const row = sql.exec("SELECT schema_policy FROM project_settings WHERE id = 1").toArray()[0];
    if (row === undefined) {
      return "disabled";
    }
    const policy = stringColumn(row, "schema_policy");
    if (policy !== "disabled" && policy !== "enabled" && policy !== "locked") {
      throw new Error("unexpected schema_policy in stored project settings row");
    }
    return policy;
  }),
});

/**
 * Reads and the fixed window of head attestations (AUTH_SPEC §16-1).
 * The window's semantics (separation of judgment and consumption;
 * expired = counting from 0) are identical to the lease window's — only
 * the key became per-member.
 */
const makeAttestationQueries = (sql: SqlStorage) => ({
  headAttestationSeq: (attesterUserId: string, keyFingerprintHex: string) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          "SELECT chain_head_seq FROM head_attestations WHERE attester_user_id = ? AND attester_key_fingerprint = ?",
          attesterUserId,
          keyFingerprintHex,
        )
        .toArray()[0];
      return row === undefined ? null : numberColumn(row, "chain_head_seq");
    }),
  listHeadAttestations: Effect.sync(() =>
    sql
      .exec(
        `SELECT attester_user_id, suite, chain_head_seq, chain_head_hash_hex,
                signature_hex, attester_key_fingerprint
         FROM head_attestations ORDER BY attester_user_id, attester_key_fingerprint`,
      )
      .toArray()
      .map((row): StoredHeadAttestation => ({
        attesterUserId: stringColumn(row, "attester_user_id"),
        suite: storedSuite(columnValue(row, "suite")),
        chainHeadSeq: numberColumn(row, "chain_head_seq"),
        chainHeadHashHex: stringColumn(row, "chain_head_hash_hex"),
        signatureHex: stringColumn(row, "signature_hex"),
        attesterKeyFingerprintHex: stringColumn(row, "attester_key_fingerprint"),
      })),
  ),
  checkAttestationWindow: (attesterUserId: string, limit: number, nowMs: number) =>
    Effect.sync(() => {
      const current = attestationWindowRow(sql, attesterUserId, nowMs);
      if (current === null || current.count < limit) {
        return { allowed: true, retryAfterSeconds: 0 };
      }
      return {
        allowed: false,
        retryAfterSeconds: Math.ceil((ATTESTATION_WINDOW_MS - current.elapsed) / 1000),
      };
    }),
  recordAttestationWindowUse: (attesterUserId: string, nowMs: number) => {
    if (attestationWindowRow(sql, attesterUserId, nowMs) === null) {
      sql.exec(
        `INSERT INTO attestation_windows (attester_user_id, window_start, count) VALUES (?, ?, 1)
         ON CONFLICT(attester_user_id) DO UPDATE
           SET window_start = excluded.window_start, count = 1`,
        attesterUserId,
        nowMs,
      );
      return;
    }
    sql.exec(
      "UPDATE attestation_windows SET count = count + 1 WHERE attester_user_id = ?",
      attesterUserId,
    );
  },
});

/** The live row of the attestation window (same "live window" definition as the lease window's leaseWindowRow). */
function attestationWindowRow(
  sql: SqlStorage,
  attesterUserId: string,
  nowMs: number,
): { readonly count: number; readonly elapsed: number } | null {
  const row = sql
    .exec(
      "SELECT window_start, count FROM attestation_windows WHERE attester_user_id = ?",
      attesterUserId,
    )
    .toArray()[0];
  if (row === undefined) {
    return null;
  }
  const elapsed = nowMs - numberColumn(row, "window_start");
  if (elapsed >= ATTESTATION_WINDOW_MS || elapsed < 0) {
    return null;
  }
  return { count: numberColumn(row, "count"), elapsed };
}

/**
 * The row of the currently-live fixed window (expired, first request,
 * or a clock rewind → null = count from 0). The single place where
 * judgment and consumption share the same "live window" definition.
 */
function leaseWindowRow(
  sql: SqlStorage,
  kind: LeaseWindowKind,
  nowMs: number,
): { readonly count: number; readonly elapsed: number } | null {
  const row = sql
    .exec("SELECT window_start, count FROM lease_windows WHERE kind = ?", kind)
    .toArray()[0];
  if (row === undefined) {
    return null;
  }
  const elapsed = nowMs - numberColumn(row, "window_start");
  if (elapsed >= LEASE_WINDOW_MS || elapsed < 0) {
    return null;
  }
  return { count: numberColumn(row, "count"), elapsed };
}

/**
 * The common SELECT of wrap rows (only the columns differ between
 * distribution and lease material). Ordered by ascending epoch.
 */
function selectWrapRows(
  sql: SqlStorage,
  query: {
    readonly environmentId: string;
    readonly recipientClass: "member" | "server";
    readonly recipientUserId: string;
    readonly extraColumns?: string;
  },
): readonly Record<string, SqlStorageValue>[] {
  const extra = query.extraColumns === undefined ? "" : `, ${query.extraColumns}`;
  return sql
    .exec(
      `SELECT suite, epoch, enc_hex, ciphertext_hex${extra}
       FROM dek_wraps
       WHERE environment_id = ? AND recipient_class = ? AND recipient_user_id = ?
       ORDER BY epoch`,
      query.environmentId,
      query.recipientClass,
      query.recipientUserId,
    )
    .toArray();
}

/**
 * The common part of a wrap row. `storedSuite` makes an unknown suite a
 * defect (a value the v1 write path cannot produce; it is never
 * silently distributed or re-wrapped as v1 — the same discipline as
 * the §13-5 recovery blob).
 */
function wrapBodyOf(row: Record<string, SqlStorageValue>): {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly encHex: string;
  readonly ciphertextHex: string;
} {
  return {
    suite: storedSuite(columnValue(row, "suite")),
    epoch: numberColumn(row, "epoch"),
    encHex: stringColumn(row, "enc_hex"),
    ciphertextHex: stringColumn(row, "ciphertext_hex"),
  };
}

/**
 * The layout-v2 column values (layout_version + the schema fields —
 * variable statements only). A v1 statement has layout_version 1 and
 * NULL schema fields. required is stored as the signed-target "true" /
 * "false" representation (identical to CRYPTO_SPEC §4.2's LP field).
 */
function layoutColumnValues(statement: MetaStatementInput): readonly (string | number | null)[] {
  const layoutVersion = statement.layoutVersion ?? 1;
  const schema = statement.schema;
  if (schema === undefined) {
    return [layoutVersion, null, null, null, null];
  }
  // max_age_days: NULL on a v2 row; the signed string ("" = none) on a v3 row
  const maxAge =
    schema.maxAgeDays === undefined
      ? null
      : schema.maxAgeDays === null
        ? ""
        : String(schema.maxAgeDays);
  return [
    layoutVersion,
    schema.varType,
    schema.required ? "true" : "false",
    schema.description,
    maxAge,
  ];
}

/**
 * The INSERT of a statement row (the column order shared by variable
 * and environment; only the table name is swapped). The variable side
 * also writes the layout-v2 columns ({@link layoutColumnValues}).
 */
function insertStatementRow(
  sql: SqlStorage,
  table: "variable_meta_statements" | "environment_meta_statements",
  keys: readonly (string | number)[],
  statement: MetaStatementInput,
  signedBytesHashHex: string,
  author: MetaAuthorInfo,
  nowMs: number,
): void {
  const isVariable = table === "variable_meta_statements";
  const keyColumns = isVariable
    ? "environment_id, variable_id, meta_version"
    : "environment_id, meta_version";
  const layoutColumns = isVariable
    ? ", layout_version, var_type, required, description, max_age_days"
    : "";
  const values: readonly (string | number | null)[] = [
    ...keys,
    statement.suite,
    statement.name,
    statement.status,
    statement.prevMetaSigHashHex,
    statement.chainHeadHashHex,
    statement.chainHeadSeq,
    statement.signatureHex,
    signedBytesHashHex,
    author.userId,
    author.keyFingerprintHex,
    nowMs,
    ...(isVariable ? layoutColumnValues(statement) : []),
  ];
  sql.exec(
    `INSERT INTO ${table}
       (${keyColumns}, suite, name, status, prev_meta_sig_hash_hex,
        chain_head_hash_hex, chain_head_seq, signature_hex, signed_bytes_hash_hex,
        author_user_id, author_key_fingerprint, created_at${layoutColumns})
     VALUES (${values.map(() => "?").join(", ")})`,
    ...values,
  );
}

const makeWriteOps = (sql: SqlStorage): DataWriteOps => ({
  // latest_meta_version is inserted as 0 and settled by the
  // insertEnvironmentMetaStatement (metaVersion 1) inside the same
  // synchronous block
  insertEnvironment: (environmentId, name, nowMs) => {
    sql.exec(
      "INSERT INTO environments (environment_id, name, latest_meta_version, created_at, deleted_at) VALUES (?, ?, 0, ?, NULL)",
      environmentId,
      name,
      nowMs,
    );
  },
  insertEnvironmentMetaStatement: (environmentId, statement, signedBytesHashHex, author, nowMs) => {
    insertStatementRow(
      sql,
      "environment_meta_statements",
      [environmentId, statement.metaVersion],
      statement,
      signedBytesHashHex,
      author,
      nowMs,
    );
    sql.exec(
      "UPDATE environments SET name = ?, latest_meta_version = ? WHERE environment_id = ?",
      statement.name,
      statement.metaVersion,
      environmentId,
    );
  },
  retireEnvironment: (environmentId, nowMs) => {
    sql.exec(
      "UPDATE environments SET deleted_at = ? WHERE environment_id = ?",
      nowMs,
      environmentId,
    );
    sql.exec("DELETE FROM variables WHERE environment_id = ?", environmentId);
    // The subordinate variable statements are also deleted immediately
    // (the §12-4 subordinate data). The environment's own statement
    // chain (deleted included) stays in environment_meta_statements —
    // since an environment ID cannot be reused under the chain
    // consensus rules, nothing on the variable side remains as
    // detection material
    sql.exec("DELETE FROM variable_meta_statements WHERE environment_id = ?", environmentId);
    sql.exec("DELETE FROM variable_versions WHERE environment_id = ?", environmentId);
    sql.exec("DELETE FROM dek_wraps WHERE environment_id = ?", environmentId);
    // The environment manifest is also cascade-deleted (§12-4: a
    // deleted environment has no distribution channel, and a
    // server-stored artifact that is never distributed has no residual
    // value as detection material. The environment's own deleted
    // statement is the terminal detection material)
    sql.exec("DELETE FROM environment_manifests WHERE environment_id = ?", environmentId);
    // The checkpoint tuple and value snapshot are cascade-deleted by
    // the same argument (§12-4: a deleted environment's snapshot has no
    // distribution channel)

    sql.exec("DELETE FROM environment_checkpoints WHERE environment_id = ?", environmentId);
    sql.exec("DELETE FROM checkpoint_snapshot_values WHERE environment_id = ?", environmentId);
  },
  insertVariable: (environmentId, variableId, name, nowMs) => {
    sql.exec(
      `INSERT INTO variables (environment_id, variable_id, name, latest_meta_version, latest_version, created_at, deleted_at)
       VALUES (?, ?, ?, 0, 0, ?, NULL)`,
      environmentId,
      variableId,
      name,
      nowMs,
    );
  },
  insertVariableMetaStatement: (
    environmentId,
    variableId,
    statement,
    signedBytesHashHex,
    author,
    nowMs,
  ) => {
    insertStatementRow(
      sql,
      "variable_meta_statements",
      [environmentId, variableId, statement.metaVersion],
      statement,
      signedBytesHashHex,
      author,
      nowMs,
    );
    sql.exec(
      "UPDATE variables SET name = ?, latest_meta_version = ? WHERE environment_id = ? AND variable_id = ?",
      statement.name,
      statement.metaVersion,
      environmentId,
      variableId,
    );
  },
  retireVariable: (environmentId, variableId, nowMs) => {
    sql.exec(
      "UPDATE variables SET deleted_at = ? WHERE environment_id = ? AND variable_id = ?",
      nowMs,
      environmentId,
      variableId,
    );
    sql.exec(
      "DELETE FROM variable_versions WHERE environment_id = ? AND variable_id = ?",
      environmentId,
      variableId,
    );
  },
  // Only the latest one is kept per environment (§12-5 — replaced via
  // upsert; rows are not accumulated)
  upsertEnvironmentManifest: (environmentId, manifest, signedBytesHashHex, issuer, nowMs) => {
    sql.exec(
      `INSERT INTO environment_manifests
         (environment_id, manifest_version, suite, epoch, variables_digest_hex,
          env_meta_version, env_meta_sig_hash_hex, prev_manifest_sig_hash_hex,
          chain_head_hash_hex, chain_head_seq, signature_hex, signed_bytes_hash_hex,
          issuer_user_id, issuer_key_fingerprint, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (environment_id) DO UPDATE SET
         manifest_version = excluded.manifest_version,
         suite = excluded.suite,
         epoch = excluded.epoch,
         variables_digest_hex = excluded.variables_digest_hex,
         env_meta_version = excluded.env_meta_version,
         env_meta_sig_hash_hex = excluded.env_meta_sig_hash_hex,
         prev_manifest_sig_hash_hex = excluded.prev_manifest_sig_hash_hex,
         chain_head_hash_hex = excluded.chain_head_hash_hex,
         chain_head_seq = excluded.chain_head_seq,
         signature_hex = excluded.signature_hex,
         signed_bytes_hash_hex = excluded.signed_bytes_hash_hex,
         issuer_user_id = excluded.issuer_user_id,
         issuer_key_fingerprint = excluded.issuer_key_fingerprint,
         created_at = excluded.created_at`,
      environmentId,
      manifest.manifestVersion,
      manifest.suite,
      manifest.epoch,
      manifest.variablesDigestHex,
      manifest.envMetaVersion,
      manifest.envMetaSigHashHex,
      manifest.prevManifestSigHashHex,
      manifest.chainHeadHashHex,
      manifest.chainHeadSeq,
      manifest.signatureHex,
      signedBytesHashHex,
      issuer.userId,
      issuer.keyFingerprintHex,
      nowMs,
    );
  },
  upsertCheckpointSnapshot: (environmentId, checkpoint, values, nowMs) => {
    // The digest of the stored enumeration (read before overwriting).
    // Every call site has already cross-checked "the digest of values =
    // checkpoint.valuesDigestHex" before saving
    // (ensureCheckpointValuesDigest — the 3 paths: standalone / create
    // / rotate), both tables' rows are written only inside the same
    // synchronous block, and deletion happens to both tables together
    // (retireEnvironment). So a stored row's values_digest_hex is the
    // SHA-256 of the stored enumeration itself, and a match means the
    // enumeration is identical — skipping the wholesale replacement
    // leaves the stored state unchanged (keeping §6.4's "the state at
    // acceptance time itself"). The tuple-coordinates row is always
    // updated
    const stored = sql
      .exec(
        "SELECT values_digest_hex FROM environment_checkpoints WHERE environment_id = ?",
        environmentId,
      )
      .toArray()[0];
    const valuesUnchanged =
      stored !== undefined &&
      stringColumn(stored, "values_digest_hex") === checkpoint.valuesDigestHex;
    sql.exec(
      `INSERT INTO environment_checkpoints
         (environment_id, chain_seq, entry_hash_hex, epoch, manifest_version,
          manifest_sig_hash_hex, values_digest_hex, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (environment_id) DO UPDATE SET
         chain_seq = excluded.chain_seq,
         entry_hash_hex = excluded.entry_hash_hex,
         epoch = excluded.epoch,
         manifest_version = excluded.manifest_version,
         manifest_sig_hash_hex = excluded.manifest_sig_hash_hex,
         values_digest_hex = excluded.values_digest_hex,
         updated_at = excluded.updated_at`,
      environmentId,
      checkpoint.chainSeq,
      checkpoint.entryHashHex,
      checkpoint.epoch,
      checkpoint.manifestVersion,
      checkpoint.manifestSigHashHex,
      checkpoint.valuesDigestHex,
      nowMs,
    );
    if (valuesUnchanged) {
      return;
    }
    // The enumeration is a wholesale replacement per environment (the
    // state at acceptance time itself — the §6.4 upsert semantics)
    sql.exec("DELETE FROM checkpoint_snapshot_values WHERE environment_id = ?", environmentId);
    for (const value of values) {
      sql.exec(
        `INSERT INTO checkpoint_snapshot_values
           (environment_id, variable_id, version, value_sig_hash_hex)
         VALUES (?, ?, ?, ?)`,
        environmentId,
        value.variableId,
        value.version,
        value.valueSigHashHex,
      );
    }
  },
  insertVersion: (
    environmentId,
    variableId,
    value,
    ciphertextBytes,
    signedBytesHashHex,
    writer,
    nowMs,
  ) => {
    sql.exec(
      `INSERT INTO variable_versions
         (environment_id, variable_id, version, suite, epoch, nonce_hex, ciphertext_hex, ciphertext_bytes,
          prev_value_sig_hash_hex, chain_head_hash_hex, chain_head_seq, signature_hex,
          signed_bytes_hash_hex, writer_user_id, writer_key_fingerprint, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      environmentId,
      variableId,
      value.version,
      value.suite,
      value.epoch,
      value.nonceHex,
      value.ciphertextHex,
      ciphertextBytes,
      value.prevValueSigHashHex,
      value.chainHeadHashHex,
      value.chainHeadSeq,
      value.signatureHex,
      signedBytesHashHex,
      writer.userId,
      writer.keyFingerprintHex,
      nowMs,
    );
    sql.exec(
      "UPDATE variables SET latest_version = ? WHERE environment_id = ? AND variable_id = ?",
      value.version,
      environmentId,
      variableId,
    );
  },
  insertWrap: (environmentId, wrap, signer, nowMs) => {
    sql.exec(
      `INSERT INTO dek_wraps
         (environment_id, epoch, recipient_class, recipient_user_id, suite, recipient_enc_pub_hex, enc_hex, ciphertext_hex,
          signature_hex, signer_user_id, signer_key_fingerprint, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      environmentId,
      wrap.epoch,
      wrap.recipientClass ?? "member",
      wrap.recipientUserId,
      wrap.suite,
      wrap.recipientEncPubHex,
      wrap.encHex,
      wrap.ciphertextHex,
      wrap.signatureHex,
      signer.userId,
      signer.keyFingerprintHex,
      nowMs,
    );
  },
  deleteWrap: (environmentId, epoch, recipientUserId, recipientEncPubHex) => {
    sql.exec(
      "DELETE FROM dek_wraps WHERE environment_id = ? AND epoch = ? AND recipient_user_id = ? AND recipient_enc_pub_hex = ?",
      environmentId,
      epoch,
      recipientUserId,
      recipientEncPubHex,
    );
  },
  // Two statements, SELECT → DELETE, but inside the same synchronous
  // task (under the permit, committed atomically). Since recipient is
  // the third component of the primary key, a key-prefix match is
  // impossible, so it is looked up via the recipient index dw_recipient
  // (recipient_user_id, recipient_class) (a migration step of
  // do-schema.ts) — the scan is limited to the wrap rows addressed to
  // the target user_id (test/do-schema.test.ts pins it via EXPLAIN
  // QUERY PLAN)
  deleteStaleMemberWraps: (recipientUserId, keepEncPubHex) => {
    const stale = sql
      .exec(
        `SELECT environment_id, epoch FROM dek_wraps
         WHERE recipient_user_id = ? AND recipient_class = 'member'
           AND recipient_enc_pub_hex != ?
         ORDER BY environment_id, epoch`,
        recipientUserId,
        keepEncPubHex,
      )
      .toArray()
      .map((row) => ({
        environmentId: stringColumn(row, "environment_id"),
        epoch: numberColumn(row, "epoch"),
      }));
    if (stale.length > 0) {
      sql.exec(
        `DELETE FROM dek_wraps
         WHERE recipient_user_id = ? AND recipient_class = 'member'
           AND recipient_enc_pub_hex != ?`,
        recipientUserId,
        keepEncPubHex,
      );
    }
    return stale;
  },
  upsertHeadAttestation: (attestation, nowMs) => {
    sql.exec(
      `INSERT INTO head_attestations
         (attester_user_id, suite, chain_head_seq, chain_head_hash_hex,
          signature_hex, attester_key_fingerprint, accepted_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(attester_user_id, attester_key_fingerprint) DO UPDATE SET
         suite = excluded.suite,
         chain_head_seq = excluded.chain_head_seq,
         chain_head_hash_hex = excluded.chain_head_hash_hex,
         signature_hex = excluded.signature_hex,
         accepted_at = excluded.accepted_at`,
      attestation.attesterUserId,
      attestation.suite,
      attestation.chainHeadSeq,
      attestation.chainHeadHashHex,
      attestation.signatureHex,
      attestation.attesterKeyFingerprintHex,
      nowMs,
    );
  },
  deleteHeadAttestation: (attesterUserId) => {
    sql.exec("DELETE FROM head_attestations WHERE attester_user_id = ?", attesterUserId);
    sql.exec("DELETE FROM attestation_windows WHERE attester_user_id = ?", attesterUserId);
  },
  deleteDeviceHeadAttestation: (attesterUserId, keyFingerprintHex) => {
    sql.exec(
      "DELETE FROM head_attestations WHERE attester_user_id = ? AND attester_key_fingerprint = ?",
      attesterUserId,
      keyFingerprintHex,
    );
  },
  setSchemaPolicy: (policy) => {
    sql.exec(
      `INSERT INTO project_settings (id, schema_policy) VALUES (1, ?)
       ON CONFLICT (id) DO UPDATE SET schema_policy = excluded.schema_policy`,
      policy,
    );
  },
  insertProposal: (proposal, nowMs) => {
    sql.exec(
      `INSERT INTO rotation_proposals
         (proposal_id, environment_id, connector, facts_json, claims_digest_hex, grant_chain_seq, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      proposal.proposalId,
      proposal.environmentId,
      proposal.connector,
      JSON.stringify(proposal.facts),
      proposal.claimsDigestHex,
      proposal.grantChainSeq,
      nowMs,
      proposal.expiresAtMs,
    );
    // The minted order is the push order (companions first — CRYPTO_SPEC
    // §5.3); variable ids are random, so the position is stored
    proposal.variables.forEach((variable, position) => {
      sql.exec(
        "INSERT INTO rotation_proposal_variables (proposal_id, variable_id, base_version, position) VALUES (?, ?, ?, ?)",
        proposal.proposalId,
        variable.variableId,
        variable.baseVersion,
        position,
      );
      for (const wrap of variable.wraps) {
        sql.exec(
          `INSERT INTO rotation_proposal_wraps
             (proposal_id, variable_id, recipient_user_id, recipient_enc_pub_hex, enc_hex, ciphertext_hex)
           VALUES (?, ?, ?, ?, ?, ?)`,
          proposal.proposalId,
          variable.variableId,
          wrap.recipientUserId,
          wrap.recipientEncPubHex,
          wrap.encHex,
          wrap.ciphertextHex,
        );
      }
    });
  },
  deleteProposal: (proposalId) => {
    deleteProposalRows(sql, proposalId);
  },
  deleteExpiredProposals: (nowMs) => {
    const expired = sql
      .exec("SELECT proposal_id FROM rotation_proposals WHERE expires_at <= ?", nowMs)
      .toArray()
      .map((row) => stringColumn(row, "proposal_id"));
    for (const proposalId of expired) {
      deleteProposalRows(sql, proposalId);
    }
  },
});

function deleteProposalRows(sql: SqlStorage, proposalId: string): void {
  sql.exec("DELETE FROM rotation_proposal_wraps WHERE proposal_id = ?", proposalId);
  sql.exec("DELETE FROM rotation_proposal_variables WHERE proposal_id = ?", proposalId);
  sql.exec("DELETE FROM rotation_proposals WHERE proposal_id = ?", proposalId);
}

/** The stored facts (a JSON array of strings written by insertProposal — anything else is storage corruption). */
function storedFacts(value: string): readonly string[] {
  const parsed: unknown = JSON.parse(value);
  if (!Array.isArray(parsed) || !parsed.every((fact) => typeof fact === "string")) {
    throw new Error("stored proposal facts are not a string array");
  }
  return parsed;
}

/**
 * Sealed value proposals (AUTH_SPEC §14-5). A proposal is read as three
 * queries (head / variables / wraps); the wraps are attached in variable
 * order. Only pending rows (expires_at > now) are returned by the
 * pending readers — expired rows wait for the sweep but never surface.
 */
const makeProposalQueries = (sql: SqlStorage) => {
  const proposalOf = (row: StoredRow): StoredProposal => {
    const proposalId = stringColumn(row, "proposal_id");
    const wraps = sql
      .exec(
        `SELECT variable_id, recipient_user_id, recipient_enc_pub_hex, enc_hex, ciphertext_hex
         FROM rotation_proposal_wraps WHERE proposal_id = ?
         ORDER BY variable_id, recipient_user_id, recipient_enc_pub_hex`,
        proposalId,
      )
      .toArray();
    const variables = sql
      .exec(
        "SELECT variable_id, base_version FROM rotation_proposal_variables WHERE proposal_id = ? ORDER BY position",
        proposalId,
      )
      .toArray()
      .map((variable): StoredProposalVariable => {
        const variableId = stringColumn(variable, "variable_id");
        return {
          variableId,
          baseVersion: numberColumn(variable, "base_version"),
          wraps: wraps
            .filter((wrap) => stringColumn(wrap, "variable_id") === variableId)
            .map((wrap) => ({
              recipientUserId: stringColumn(wrap, "recipient_user_id"),
              recipientEncPubHex: stringColumn(wrap, "recipient_enc_pub_hex"),
              encHex: stringColumn(wrap, "enc_hex"),
              ciphertextHex: stringColumn(wrap, "ciphertext_hex"),
            })),
        };
      });
    return {
      proposalId,
      environmentId: stringColumn(row, "environment_id"),
      connector: stringColumn(row, "connector"),
      facts: storedFacts(stringColumn(row, "facts_json")),
      claimsDigestHex: stringColumn(row, "claims_digest_hex"),
      grantChainSeq: numberColumn(row, "grant_chain_seq"),
      createdAtMs: numberColumn(row, "created_at"),
      expiresAtMs: numberColumn(row, "expires_at"),
      variables,
    };
  };
  const HEAD_COLUMNS =
    "proposal_id, environment_id, connector, facts_json, claims_digest_hex, grant_chain_seq, created_at, expires_at";
  return {
    proposalExists: (proposalId: string) =>
      Effect.sync(
        () =>
          sql
            .exec("SELECT 1 AS present FROM rotation_proposals WHERE proposal_id = ?", proposalId)
            .toArray().length > 0,
      ),
    findPendingProposal: (proposalId: string, nowMs: number) =>
      Effect.sync(() => {
        const row = sql
          .exec(
            `SELECT ${HEAD_COLUMNS} FROM rotation_proposals WHERE proposal_id = ? AND expires_at > ?`,
            proposalId,
            nowMs,
          )
          .toArray()[0];
        return row === undefined ? null : proposalOf(row);
      }),
    listPendingProposals: (nowMs: number) =>
      Effect.sync(() =>
        sql
          .exec(
            `SELECT ${HEAD_COLUMNS} FROM rotation_proposals WHERE expires_at > ? ORDER BY created_at, proposal_id`,
            nowMs,
          )
          .toArray()
          .map(proposalOf),
      ),
    countPendingProposals: (nowMs: number) =>
      Effect.sync(() =>
        numberColumn(
          sql
            .exec("SELECT COUNT(*) AS n FROM rotation_proposals WHERE expires_at > ?", nowMs)
            .toArray()[0] ?? { n: 0 },
          "n",
        ),
      ),
  };
};

export const dataStoreLayer = (sql: SqlStorage): Layer.Layer<DataStore> =>
  Layer.sync(DataStore, () => ({
    ...makeEnvironmentQueries(sql),
    ...makeVariableQueries(sql),
    ...makeVersionQueries(sql),
    ...makeWrapQueries(sql),
    ...makeSettingsQueries(sql),
    ...makeAttestationQueries(sql),
    ...makeProposalQueries(sql),
    write: makeWriteOps(sql),
  }));
