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
  readonly latestMetaVersion: number;
  readonly deletedAtMs: number | null;
}

export interface VariableRow {
  readonly variableId: VariableId;
  readonly name: string;
  readonly latestMetaVersion: number;
  readonly latestVersion: number;
  readonly latestStatus: MetaStatementStatusInput;
  readonly deletedAtMs: number | null;
}

export interface WrapSignerInfo {
  readonly userId: UserId;
  readonly keyFingerprintHex: KeyFingerprintHex;
}

export interface ValueWriterInfo {
  readonly userId: UserId;
  readonly keyFingerprintHex: KeyFingerprintHex;
}

export interface StoredVersionMeta {
  readonly version: number;
  readonly epoch: number;
  readonly writerUserId: UserId;
  readonly writerKeyFingerprintHex: KeyFingerprintHex;
  readonly pushedAtMs: number;
}

interface VersionAnchor {
  readonly signedBytesHashHex: string;
  readonly epoch: number;
}

interface EnvironmentCiphertextBytes {
  readonly totalBytes: number;
  readonly variableBytes: number;
}

export interface MetaAuthorInfo {
  readonly userId: UserId;
  readonly keyFingerprintHex: KeyFingerprintHex;
}

export interface MetaAnchor {
  readonly signedBytesHashHex: string;
  readonly name: string;
  readonly status: MetaStatementStatusInput;
  readonly layoutVersion: number;
  readonly schema: MetaVariableSchemaInput | null;
}

export interface VariableDigestEntryRow {
  readonly variableId: VariableId;
  readonly status: MetaStatementStatusInput;
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
}

export interface CheckpointValueEntryRow {
  readonly variableId: VariableId;
  readonly version: number;
  readonly valueSigHashHex: string;
}

export interface CheckpointSnapshotInput {
  readonly chainSeq: number;
  readonly entryHashHex: string;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly manifestSigHashHex: string;
  readonly valuesDigestHex: string;
}

interface EnvManifestAnchor {
  readonly manifestVersion: number;
  readonly signedBytesHashHex: string;
  readonly epoch: number;
}

export interface ResourceCounts {
  readonly active: number;
  readonly rows: number;
}

interface StoredWrapRecipient {
  readonly recipientClass: string;
  readonly recipientEncPubHex: string;
}

export interface DataWriteOps {
  readonly insertEnvironment: (environmentId: EnvironmentId, name: string, nowMs: number) => void;
  readonly insertEnvironmentMetaStatement: (
    environmentId: EnvironmentId,
    statement: MetaStatementInput,
    signedBytesHashHex: string,
    author: MetaAuthorInfo,
    nowMs: number,
  ) => void;
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
  readonly insertVariableMetaStatement: (
    environmentId: EnvironmentId,
    variableId: VariableId,
    statement: MetaStatementInput,
    signedBytesHashHex: string,
    author: MetaAuthorInfo,
    nowMs: number,
  ) => void;
  readonly retireVariable: (
    environmentId: EnvironmentId,
    variableId: VariableId,
    nowMs: number,
  ) => void;
  readonly upsertEnvironmentManifest: (
    environmentId: EnvironmentId,
    manifest: EnvManifestInput,
    signedBytesHashHex: string,
    issuer: MetaAuthorInfo,
    nowMs: number,
  ) => void;
  readonly upsertCheckpointSnapshot: (
    environmentId: EnvironmentId,
    checkpoint: CheckpointSnapshotInput,
    values: readonly CheckpointValueEntryRow[],
    nowMs: number,
  ) => void;
  readonly insertVersion: (
    environmentId: EnvironmentId,
    variableId: VariableId,
    value: ValueInput,
    ciphertextBytes: number,
    signedBytesHashHex: string,
    writer: ValueWriterInfo,
    nowMs: number,
  ) => void;
  readonly insertWrap: (
    environmentId: EnvironmentId,
    wrap: DekWrapInput,
    signer: WrapSignerInfo,
    nowMs: number,
  ) => void;
  readonly deleteWrap: (
    environmentId: EnvironmentId,
    epoch: number,
    recipientUserId: UserId | KeyFingerprintHex,
    recipientEncPubHex: string,
  ) => void;
  readonly deleteStaleMemberWraps: (
    recipientUserId: UserId | KeyFingerprintHex,
    keepEncPubHex: string,
  ) => readonly StaleWrapRef[];
  readonly upsertHeadAttestation: (attestation: StoredHeadAttestation, nowMs: number) => void;
  readonly deleteHeadAttestation: (attesterUserId: UserId) => void;
  readonly deleteDeviceHeadAttestation: (
    attesterUserId: UserId,
    keyFingerprintHex: KeyFingerprintHex,
  ) => void;
  readonly setSchemaPolicy: (policy: SchemaPolicy) => void;
  readonly insertProposal: (proposal: ProposalWriteInput, nowMs: number) => void;
  readonly deleteProposal: (proposalId: string) => void;
  readonly deleteExpiredProposals: (
    nowMs: number,
    except?: string | undefined,
  ) => readonly RemovedProposal[];
}

export interface RemovedProposal {
  readonly proposalId: string;
  readonly environmentId: EnvironmentId;
  readonly expiresAtMs: number;
}

export interface StaleWrapRef {
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
}

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
  readonly listEnvironmentStatements: Effect.Effect<
    readonly { environmentId: EnvironmentId; statement: DistributedMetaStatementValue }[]
  >;
  readonly environmentStatement: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<DistributedMetaStatementValue | null>;
  readonly environmentMetaAnchor: (
    environmentId: EnvironmentId,
    metaVersion: number,
  ) => Effect.Effect<MetaAnchor | null>;
  readonly environmentManifest: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<DistributedEnvManifestValue | null>;
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
  readonly variableMetaAnchor: (
    environmentId: EnvironmentId,
    variableId: VariableId,
    metaVersion: number,
  ) => Effect.Effect<MetaAnchor | null>;
  readonly deletedVariableStatements: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<readonly DistributedVariableMetaStatementValue[]>;
  readonly activeVariableStatements: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<readonly DistributedVariableMetaStatementValue[]>;
  readonly declaredVariableStatements: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<readonly DistributedVariableMetaStatementValue[]>;
  readonly variableDigestEntries: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<readonly VariableDigestEntryRow[]>;
  readonly checkpointValueEntries: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<readonly CheckpointValueEntryRow[]>;
  readonly checkpointSnapshot: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<CheckpointSnapshotValue | null>;

  readonly latestVersions: (
    environmentId: EnvironmentId,
  ) => Effect.Effect<
    readonly (PulledVariableValue & { statement: DistributedVariableMetaStatementValue })[]
  >;
  readonly versionHistory: (
    environmentId: EnvironmentId,
    variableId: VariableId,
  ) => Effect.Effect<readonly StoredVersionMeta[]>;
  readonly versionRange: (
    environmentId: EnvironmentId,
    variableId: VariableId,
    fromVersion: number,
    limit: number,
  ) => Effect.Effect<readonly PulledVariableValue[]>;
  readonly versionAnchor: (
    environmentId: EnvironmentId,
    variableId: VariableId,
    version: number,
  ) => Effect.Effect<VersionAnchor | null>;
  readonly totalCiphertextBytes: Effect.Effect<number>;
  readonly environmentCiphertextBytes: (
    environmentId: EnvironmentId,
    variableId: VariableId,
  ) => Effect.Effect<EnvironmentCiphertextBytes>;

  readonly countWrapsForEpoch: (
    environmentId: EnvironmentId,
    epoch: number,
  ) => Effect.Effect<number>;
  readonly countWrapRows: Effect.Effect<number>;
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
  readonly listServerWraps: (
    environmentId: EnvironmentId,
    serverKeyFingerprintHex: KeyFingerprintHex,
  ) => Effect.Effect<readonly StoredServerWrap[]>;
  readonly checkLeaseWindow: (
    kind: LeaseWindowKind,
    limit: number,
    nowMs: number,
  ) => Effect.Effect<LeaseWindowDecision>;
  readonly recordLeaseWindowUse: (kind: LeaseWindowKind, nowMs: number) => void;
  readonly isMirrorSync: () => boolean;
  readonly leaseBinding: (bindingKeyHex: string, nowMs: number) => Effect.Effect<string | null>;
  readonly recordLeaseBinding: (
    bindingKeyHex: string,
    ephemeralPubHex: string,
    expiresAtMs: number,
    nowMs: number,
  ) => void;
  readonly schemaPolicy: Effect.Effect<SchemaPolicy>;
  readonly headAttestationSeq: (
    attesterUserId: UserId,
    keyFingerprintHex: KeyFingerprintHex,
  ) => Effect.Effect<number | null>;
  readonly listHeadAttestations: Effect.Effect<readonly StoredHeadAttestation[]>;
  readonly checkAttestationWindow: (
    attesterUserId: UserId,
    limit: number,
    nowMs: number,
  ) => Effect.Effect<LeaseWindowDecision>;
  readonly recordAttestationWindowUse: (attesterUserId: UserId, nowMs: number) => void;

  readonly proposalExists: (proposalId: string) => Effect.Effect<boolean>;
  readonly findProposal: (proposalId: string) => Effect.Effect<StoredProposal | null>;
  readonly listPendingProposals: (nowMs: number) => Effect.Effect<readonly StoredProposal[]>;
  readonly countPendingProposals: (nowMs: number) => Effect.Effect<number>;
  readonly variableHasPendingProposal: (
    environmentId: EnvironmentId,
    variableId: VariableId,
    nowMs: number,
  ) => Effect.Effect<boolean>;

  readonly write: DataWriteOps;
}

export type LeaseWindowKind = "issued" | "denied" | "proposed" | "exported";

interface LeaseWindowDecision {
  readonly allowed: boolean;
  readonly retryAfterSeconds: number;
}

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
