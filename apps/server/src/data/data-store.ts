// The Effect service isolating the data plane's storage (DO SQLite).
//
// - The tables are do-schema.ts's (the DO constructor has already
//   applied the DDL)
// - Environment/variable deletion is a tombstone (deleted_at); it feeds
//   the no-ID-reuse judgment (AUTH_SPEC §12-1). Ciphertexts
//   (variable_versions) and wraps (dek_wraps) are deleted immediately
// - The decision to forgo Drizzle is in the do-schema.ts head comment
//   and docs/notes/session-07.md

import type { EnvironmentId, KeyFingerprintHex, UserId, VariableId } from "@maruhi/core";
import { Context, Effect, Layer } from "effect";

import type { StoredServerWrap } from "../server-key.ts";
import type {
  CheckpointSnapshotValue,
  DekWrapInput,
  DistributedEnvManifestValue,
  DistributedMetaStatementValue,
  DistributedVariableMetaStatementValue,
  EnvManifestInput,
  MetaStatementInput,
  MetaStatementStatusInput,
  MetaVariableSchemaInput,
  PulledVariableValue,
  RecipientDekValue,
  SchemaPolicy,
  ValueInput,
  WireSuite,
} from "./data-plane.ts";
import { makeAttestationQueries } from "./data-store-attestation-queries.ts";
import { makeEnvironmentQueries } from "./data-store-environment-queries.ts";
import { makeProposalQueries } from "./data-store-proposal-queries.ts";
import { makeSettingsQueries } from "./data-store-settings-queries.ts";
import { makeVariableQueries } from "./data-store-variable-queries.ts";
import { makeVersionQueries } from "./data-store-version-queries.ts";
import { makeWrapQueries } from "./data-store-wrap-queries.ts";
import { makeWriteOps } from "./data-store-write-ops.ts";

interface EnvironmentRow {
  readonly environmentId: EnvironmentId;
  readonly name: string;
  /** The latest statement's metaVersion (a derived cache — for the metaVersion CAS). */
  readonly latestMetaVersion: number;
  readonly deletedAtMs: number | null;
}

export interface VariableRow {
  readonly variableId: VariableId;
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
  readonly userId: UserId;
  readonly keyFingerprintHex: KeyFingerprintHex;
}

/**
 * A value's writer (stored into variable_versions's writer_* columns —
 * the user_id + key FP of the chain-derived member at acceptance time.
 * CRYPTO_SPEC §4.1 / AUTH_SPEC §12-5).
 */
export interface ValueWriterInfo {
  readonly userId: UserId;
  readonly keyFingerprintHex: KeyFingerprintHex;
}

/** One version-history row (metadata only — §12-7, 2026-09-27 VH). */
export interface StoredVersionMeta {
  readonly version: number;
  readonly epoch: number;
  readonly writerUserId: UserId;
  readonly writerKeyFingerprintHex: KeyFingerprintHex;
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
  readonly userId: UserId;
  readonly keyFingerprintHex: KeyFingerprintHex;
}

/**
 * The verification anchor of a stored statement: the server-recomputed
 * signed_bytes hash, name and status. The input of the next metaVersion's
 * prev check and of the post-deletion re-statement rejection (the §12-5
 * meta rules). layoutVersion is the stored actual value (the anchor of
 * the layout-monotonicity check — CRYPTO_SPEC §4.2); schema is the v3
 * row's schema fields (the input of the deleted statement's
 * predecessor-match check — §12-5; a v1 row is null). Environment meta
 * is always layoutVersion 1, schema null (outside the schema layout's scope).
 */
export interface MetaAnchor {
  readonly signedBytesHashHex: string;
  /** The predecessor's name (the name-preservation checks of deletion and activation — §12-5). */
  readonly name: string;
  readonly status: MetaStatementStatusInput;
  readonly layoutVersion: number;
  readonly schema: MetaVariableSchemaInput | null;
}

/**
 * One entry of variables_digest (CRYPTO_SPEC §4.3 — structurally
 * identical to @maruhi/crypto's VariablesDigestEntry; held as a
 * structural type because data-store does not depend on crypto).
 */
export interface VariableDigestEntryRow {
  readonly variableId: VariableId;
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
  readonly variableId: VariableId;
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
export interface ResourceCounts {
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
  readonly insertEnvironment: (environmentId: EnvironmentId, name: string, nowMs: number) => void;
  /**
   * Insert an environment statement row + synchronously update the
   * environment-row cache (name / latest_meta_version). Called from
   * inside the same synchronous block on every path: create, rename,
   * delete.
   */
  readonly insertEnvironmentMetaStatement: (
    environmentId: EnvironmentId,
    statement: MetaStatementInput,
    signedBytesHashHex: string,
    author: MetaAuthorInfo,
    nowMs: number,
  ) => void;
  /**
   * Tombstone (a chain-derived cache — written in the same transaction as
   * the delete_environment entry) + immediately delete everything else of
   * the environment: variables, variable and environment statements,
   * versions, wraps, the manifest and the checkpoint snapshot (§12-4 —
   * 2026-10-07; the chain entry is the deletion's record), and the
   * environment's sealed value proposals (2026-10-08). Returns the removed
   * proposals so the caller can close each one's history with an audit row.
   */
  readonly retireEnvironment: (
    environmentId: EnvironmentId,
    nowMs: number,
  ) => readonly RemovedProposal[];
  readonly insertVariable: (
    environmentId: EnvironmentId,
    variableId: VariableId,
    name: string,
    nowMs: number,
  ) => void;
  /** Insert a variable statement row + synchronously update the variable-row cache (same shape as the environment one). */
  readonly insertVariableMetaStatement: (
    environmentId: EnvironmentId,
    variableId: VariableId,
    statement: MetaStatementInput,
    signedBytesHashHex: string,
    author: MetaAuthorInfo,
    nowMs: number,
  ) => void;
  /** Tombstone + immediately delete every version (ciphertext). The deleted statement stays. */
  readonly retireVariable: (
    environmentId: EnvironmentId,
    variableId: VariableId,
    nowMs: number,
  ) => void;
  /**
   * The upsert of an environment manifest (CRYPTO_SPEC §4.3 / AUTH_SPEC
   * §12-5). Only **the latest one** is kept per environment (§12-5 — no
   * verification path needs the past rows). issuer is the chain-derived
   * member at acceptance time (= the owner of the key used for the
   * signature check).
   */
  readonly upsertEnvironmentManifest: (
    environmentId: EnvironmentId,
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
    environmentId: EnvironmentId,
    checkpoint: CheckpointSnapshotInput,
    values: readonly CheckpointValueEntryRow[],
    nowMs: number,
  ) => void;
  /** Insert a version row and advance latest_version (called under the write lock). */
  readonly insertVersion: (
    environmentId: EnvironmentId,
    variableId: VariableId,
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
    environmentId: EnvironmentId,
    wrap: DekWrapInput,
    signer: WrapSignerInfo,
    nowMs: number,
  ) => void;
  /** The §12-6 repair path: delete one wrap (device slot); the caller has already done the existence check. */
  readonly deleteWrap: (
    environmentId: EnvironmentId,
    epoch: number,
    recipientUserId: UserId | KeyFingerprintHex,
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
    recipientUserId: UserId | KeyFingerprintHex,
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
  readonly deleteHeadAttestation: (attesterUserId: UserId) => void;
  /**
   * Delete the attestation row of the revoked device at `revoke_device`
   * acceptance (AUTH_SPEC §16-1 — 2026-09-19 DK). The window row (per
   * member) is left alone.
   */
  readonly deleteDeviceHeadAttestation: (
    attesterUserId: UserId,
    keyFingerprintHex: KeyFingerprintHex,
  ) => void;
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
  /** Sweeps expired proposals (called before a mint, a pre-flight and a resolution); returns what it removed so the audit row can close each one (AUDIT_SPEC §3.3 — P-2). */
  /** Removes the expired rows (all but `except`, a proposal being resolved by a member who evidently did not abandon it). */
  readonly deleteExpiredProposals: (
    nowMs: number,
    except?: string | undefined,
  ) => readonly RemovedProposal[];
}

/**
 * A proposal removed by the expiry sweep or by its environment's deletion —
 * the input of the audit row closing its history (rotation.proposal_expired /
 * rotation.proposal_cancelled).
 */
export interface RemovedProposal {
  readonly proposalId: string;
  readonly environmentId: EnvironmentId;
  /** When it expired (the row's history is exact whatever the sweep's time). */
  readonly expiresAtMs: number;
}

/** The coordinates of a wrap deleted by the cleanup (the input of a dek.deleted audit row). */
export interface StaleWrapRef {
  readonly environmentId: EnvironmentId;
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
  readonly attesterUserId: UserId;
  readonly suite: WireSuite;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly signatureHex: string;
  readonly attesterKeyFingerprintHex: KeyFingerprintHex;
}

export interface DataStoreShape {
  readonly findEnvironment: (environmentId: EnvironmentId) => Effect.Effect<EnvironmentRow | null>;
  readonly countEnvironments: Effect.Effect<ResourceCounts>;
  readonly environmentNameTaken: (
    name: string,
    excludeEnvironmentId: string | null,
  ) => Effect.Effect<boolean>;
  /** The list of all environments (deleted included) with their latest statements (for the environment-list response). */
  readonly listEnvironmentStatements: Effect.Effect<
    readonly { environmentId: EnvironmentId; statement: DistributedMetaStatementValue }[]
  >;
  /** One environment's latest statement (for the pull response; a missing row is an invariant violation = null). */
  readonly environmentStatement: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<DistributedMetaStatementValue | null>;
  /** The environment statement's verification anchor (the prev check — the §12-5 meta rules). */
  readonly environmentMetaAnchor: (
    environmentId: EnvironmentId,
    metaVersion: number,
  ) => Effect.Effect<MetaAnchor | null>;
  /**
   * The latest environment manifest (the distributed form — the §12-7
   * bundled material). null when no stored row exists (environment
   * creation bundles manifest_version 1, so it cannot happen on a
   * created environment).
   */
  readonly environmentManifest: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<DistributedEnvManifestValue | null>;
  /**
   * The verification anchor of the latest manifest (the inputs of the
   * manifestVersion CAS = §12-5 (6) and the prev check = (5). epoch is
   * used for the predecessor's epoch-monotonicity check).
   */
  readonly environmentManifestAnchor: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<EnvManifestAnchor | null>;

  readonly findVariable: (
    environmentId: EnvironmentId,
    variableId: VariableId,
  ) => Effect.Effect<VariableRow | null>;
  readonly countVariables: (environmentId: EnvironmentId) => Effect.Effect<ResourceCounts>;
  readonly variableNameTaken: (
    environmentId: EnvironmentId,
    name: string,
    excludeVariableId: string | null,
  ) => Effect.Effect<boolean>;
  readonly listActiveVariables: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<readonly { variableId: VariableId; name: string }[]>;
  /** The variable statement's verification anchor (the prev check — the §12-5 meta rules). */
  readonly variableMetaAnchor: (
    environmentId: EnvironmentId,
    variableId: VariableId,
    metaVersion: number,
  ) => Effect.Effect<MetaAnchor | null>;
  /** The deleted statements of deleted variables (kept being distributed on pull — §12-5). */
  readonly deletedVariableStatements: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<readonly DistributedVariableMetaStatementValue[]>;
  /**
   * The latest statements of every non-deleted variable (declared
   * included) (the metadata-only mode — §12-7).
   */
  readonly activeVariableStatements: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<readonly DistributedVariableMetaStatementValue[]>;
  /**
   * The latest statements of declared variables (the bundled material
   * of a value-bearing pull / a lease — §12-7; no value or version
   * exists).
   */
  readonly declaredVariableStatements: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<readonly DistributedVariableMetaStatementValue[]>;
  /**
   * The digest tuples of the latest statements of all variables
   * (tombstones included) (the recompute input of CRYPTO_SPEC §4.3's
   * variables_digest — §12-5 (7)). metaSigHashHex is the
   * server-recomputed signed_bytes hash.
   */
  readonly variableDigestEntries: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<readonly VariableDigestEntryRow[]>;
  /**
   * The recompute input of a checkpoint values_digest (the §6.4 content
   * cross-check — the stored state at acceptance time): each active
   * variable's latest version and the server-recomputed
   * value_signed_bytes hash. Tombstones are excluded (§6.2 — active
   * variables only; the manifest side captures the tombstones).
   */
  readonly checkpointValueEntries: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<readonly CheckpointValueEntryRow[]>;
  /**
   * The distributed form of the checkpoint-time value snapshot (§12-7 /
   * §14-2): returns the latest covering checkpoint's tuple + enumeration
   * atomically saved at checkpoint acceptance as-is (never
   * reconstructed — §16-2). An environment without a basis is null (not
   * carried on the response).
   */
  readonly checkpointSnapshot: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<CheckpointSnapshotValue | null>;

  /** Each active variable's latest version + latest statement (for the bulk pull). */
  readonly latestVersions: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<
    readonly (PulledVariableValue & { statement: DistributedVariableMetaStatementValue })[]
  >;
  /**
   * Every stored version of one variable, ascending — metadata only (the
   * version history — §12-7, 2026-09-27 VH). No ciphertext is selected.
   */
  readonly versionHistory: (
    environmentId: EnvironmentId,
    variableId: VariableId,
  ) => Effect.Effect<readonly StoredVersionMeta[]>;
  /**
   * The distributed form of versions fromVersion … fromVersion + limit − 1
   * of one variable, ascending (the version value range — §12-7, 2026-09-27
   * VH). Same columns as the bulk pull's value part.
   */
  readonly versionRange: (
    environmentId: EnvironmentId,
    variableId: VariableId,
    fromVersion: number,
    limit: number,
  ) => Effect.Effect<readonly PulledVariableValue[]>;
  /** The stored version's verification anchor (the prev check — §12-5's 5). */
  readonly versionAnchor: (
    environmentId: EnvironmentId,
    variableId: VariableId,
    version: number,
  ) => Effect.Effect<VersionAnchor | null>;
  /** The project's cumulative ciphertext bytes (the amount currently stored. §12-8). */
  readonly totalCiphertextBytes: Effect.Effect<number>;

  readonly countWrapsForEpoch: (
    environmentId: EnvironmentId,
    epoch: number,
  ) => Effect.Effect<number>;
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
    environmentId: EnvironmentId,
    epoch: number,
    recipientUserId: UserId | KeyFingerprintHex,
  ) => Effect.Effect<
    readonly { readonly recipientClass: string; readonly recipientEncPubHex: string }[]
  >;
  readonly wrapStoredRecipient: (
    environmentId: EnvironmentId,
    epoch: number,
    recipientUserId: UserId | KeyFingerprintHex,
    recipientEncPubHex: string,
  ) => Effect.Effect<StoredWrapRecipient | null>;
  readonly listWrapsForRecipient: (
    environmentId: EnvironmentId,
    recipientUserId: UserId | KeyFingerprintHex,
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
    environmentId: EnvironmentId,
    serverKeyFingerprintHex: KeyFingerprintHex,
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
   * enabled). The acceptance decision reads this in each program under
   * the DO permit (the policy at acceptance time).
   */
  readonly schemaPolicy: Effect.Effect<SchemaPolicy>;
  /** The stored attestation seq of the same device (user_id + key FP) (AUTH_SPEC §16-1 — per device; null when none was submitted — the input of the monotonic-advance check). */
  readonly headAttestationSeq: (
    attesterUserId: UserId,
    keyFingerprintHex: KeyFingerprintHex,
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
    attesterUserId: UserId,
    limit: number,
    nowMs: number,
  ) => Effect.Effect<LeaseWindowDecision>;
  /** Consume the head-attestation fixed window (counts 1; serialized under the permit — nothing interposes with the judgment). */
  readonly recordAttestationWindowUse: (attesterUserId: UserId, nowMs: number) => void;

  /**
   * Sealed value proposals (AUTH_SPEC §14-5). "Pending" = stored and
   * unexpired at `nowMs` (resolution deletes the rows, so a stored row
   * is unresolved by construction). Expired rows are ignored by the
   * expires_at condition without depending on the sweep (the same
   * discipline as leaseBinding).
   */
  readonly proposalExists: (proposalId: string) => Effect.Effect<boolean>;
  /** A stored proposal by id, expired or not (a resolution reaches an expired-but-unswept row — AUTH_SPEC §14-5). */
  readonly findProposal: (proposalId: string) => Effect.Effect<StoredProposal | null>;
  readonly listPendingProposals: (nowMs: number) => Effect.Effect<readonly StoredProposal[]>;
  readonly countPendingProposals: (nowMs: number) => Effect.Effect<number>;
  /** Whether a pending proposal already targets the variable (the pre-flight's `variable-pending` — AUTH_SPEC §14-5 O-4). */
  readonly variableHasPendingProposal: (
    environmentId: EnvironmentId,
    variableId: VariableId,
    nowMs: number,
  ) => Effect.Effect<boolean>;

  readonly write: DataWriteOps;
}

/** The fixed-window kinds (§14-3 issuance / AUDIT_SPEC §3.5 denial record). */
/** `proposed` = the sealed-proposal mint window (AUTH_SPEC §14-5 — its own counter beside issuance). */
export type LeaseWindowKind = "issued" | "denied" | "proposed" | "exported";

/** The fixed-window decision (on excess it returns the window's remaining seconds — same shape as the §13-3 precedent). */
interface LeaseWindowDecision {
  readonly allowed: boolean;
  readonly retryAfterSeconds: number;
}

/** A proposed value sealed to one recipient device (a stored row — AUTH_SPEC §14-5). */
export interface StoredProposalWrap {
  readonly recipientUserId: UserId;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

export interface StoredProposalVariable {
  readonly variableId: VariableId;
  readonly baseVersion: number;
  readonly wraps: readonly StoredProposalWrap[];
}

/** One stored sealed value proposal with its variables and wraps (CRYPTO_SPEC §5.3). */
export interface StoredProposal {
  readonly proposalId: string;
  readonly environmentId: EnvironmentId;
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
  readonly environmentId: EnvironmentId;
  readonly connector: string;
  readonly facts: readonly string[];
  readonly claimsDigestHex: string;
  readonly grantChainSeq: number;
  readonly expiresAtMs: number;
  readonly variables: readonly StoredProposalVariable[];
}

export class DataStore extends Context.Service<DataStore, DataStoreShape>()("DataStore") {}

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
