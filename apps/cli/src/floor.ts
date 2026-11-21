import { dirname, join } from "node:path";

import {
  decodeVariableId,
  type EnvironmentId,
  isVariableId,
  type ProjectId,
  type UserId,
  type VariableId,
} from "@maruhi/core";
import { Context, type Effect } from "effect";

import type { CliError } from "./errors.ts";

export interface ChainHeadFloor {
  readonly seq: number;
  readonly hashHex: string;
}

export type VariableFloor =
  | {
      readonly status: "active";
      readonly version: number;
      readonly epoch: number;
      readonly valueSigHashHex: string;
      readonly metaVersion: number;
      readonly metaSigHashHex: string;
    }
  | {
      readonly status: "declared";
      readonly metaVersion: number;
      readonly metaSigHashHex: string;
    }
  | {
      readonly status: "deleted";
      readonly metaVersion: number;
      readonly metaSigHashHex: string;
    };

export interface ManifestFloor {
  readonly manifestVersion: number;
  readonly epoch: number;
  readonly manifestSigHashHex: string;
}

export interface EnvironmentFloor {
  readonly pullEpoch: number;
  readonly observedEpoch: number;
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  readonly manifest?: ManifestFloor;
  readonly variables: Readonly<Record<string, VariableFloor>>;
}

export interface FloorConflict {
  readonly kind:
    | "chain-head"
    | "value"
    | "variable-meta"
    | "environment-meta"
    | "manifest"
    | "undeletion";
  readonly environmentId: EnvironmentId | null;
  readonly variableId: VariableId | null;
  readonly firstVersion: number;
  readonly firstHashHex: string;
  readonly secondVersion: number;
  readonly secondHashHex: string;
}

export type FloorIntentOp =
  | "create_environment"
  | "rotate_epoch"
  | "meta-op"
  | "delete_environment";

export type FloorIntentOutcome =
  | "accepted"
  | "accepted-superseded"
  | "rejected"
  | "not-accepted"
  | "superseded";

export type FloorIntent = ManifestFloorIntent | DeletionFloorIntent;

export interface ManifestFloorIntent {
  readonly id: string;
  readonly op: Exclude<FloorIntentOp, "delete_environment">;
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
  readonly dekCommitmentHex: string | null;
  readonly variableId: VariableId | null;
  readonly manifestVersion: number;
  readonly manifestSigHashHex: string;
  readonly declaredHead: ChainHeadFloor;
}

export interface DeletionFloorIntent {
  readonly id: string;
  readonly op: "delete_environment";
  readonly environmentId: EnvironmentId;
  readonly declaredHead: ChainHeadFloor;
}

export type FloorIntentInput = Omit<ManifestFloorIntent, "id"> | Omit<DeletionFloorIntent, "id">;

export interface ProjectFloor {
  readonly chainHead: ChainHeadFloor | null;
  readonly environments: Readonly<Record<string, EnvironmentFloor>>;
  readonly conflicts: readonly FloorConflict[];
  readonly intents: readonly FloorIntent[];
}

export interface AttestationEvidenceRecord {
  readonly attestation: {
    readonly suite: string;
    readonly attesterUserId: UserId;
    readonly attesterKeyFingerprintHex: string;
    readonly chainHeadHashHex: string;
    readonly chainHeadSeq: number;
    readonly signatureHex: string;
  };
  readonly localView: {
    readonly headSeq: number;
    readonly headHashHex: string;
    readonly entryHashAtAttestedSeq: string;
  };
  readonly kind: "head-mismatch" | "unresolved-after-resync";
  readonly detectedAtMs: number;
}

export interface FloorLoadResult {
  readonly floor: ProjectFloor | null;
  readonly state: "loaded" | "missing" | "corrupt";
  readonly droppedRecords: number;
}

export interface PullCommit {
  readonly chainHead: ChainHeadFloor;
  readonly environmentId: EnvironmentId;
  readonly environment: EnvironmentFloor;
}

export interface PushCommit {
  readonly chainHead: ChainHeadFloor;
  readonly environmentId: EnvironmentId;
  readonly variableId: VariableId;
  readonly variable: VariableFloor;
}

export interface MetadataCommit {
  readonly chainHead: ChainHeadFloor;
  readonly environmentId: EnvironmentId;
  readonly observedEpoch: number;
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  readonly manifest: ManifestFloor;
}

export interface ManifestCommit {
  readonly chainHead: ChainHeadFloor;
  readonly environmentId: EnvironmentId;
  readonly manifest: ManifestFloor;
}

export interface FloorStoreShape {
  readonly load: (projectId: ProjectId) => Effect.Effect<FloorLoadResult, CliError>;
  readonly commitHead: (
    projectId: ProjectId,
    head: ChainHeadFloor,
  ) => Effect.Effect<void, CliError>;
  readonly commitPull: (
    projectId: ProjectId,
    commit: PullCommit,
  ) => Effect.Effect<EnvironmentFloor, CliError>;
  readonly commitPush: (
    projectId: ProjectId,
    commit: PushCommit,
  ) => Effect.Effect<EnvironmentFloor, CliError>;
  readonly commitMetadata: (
    projectId: ProjectId,
    commit: MetadataCommit,
  ) => Effect.Effect<EnvironmentFloor, CliError>;
  readonly commitManifest: (
    projectId: ProjectId,
    commit: ManifestCommit,
  ) => Effect.Effect<EnvironmentFloor, CliError>;
  readonly appendIntent: (
    projectId: ProjectId,
    intent: FloorIntentInput,
  ) => Effect.Effect<string, CliError>;
  readonly resolveIntent: (
    projectId: ProjectId,
    intentId: string,
    outcome: FloorIntentOutcome,
  ) => Effect.Effect<void, CliError>;
  readonly loadAttestedHead: (
    projectId: ProjectId,
  ) => Effect.Effect<ChainHeadFloor | null, CliError>;
  readonly saveAttestedHead: (
    projectId: ProjectId,
    head: ChainHeadFloor,
  ) => Effect.Effect<void, CliError>;
  readonly appendAttestationEvidence: (
    projectId: ProjectId,
    evidence: AttestationEvidenceRecord,
  ) => Effect.Effect<string, CliError>;
  readonly listProjectIds: () => Effect.Effect<readonly ProjectId[], CliError>;
}

export class FloorStore extends Context.Service<FloorStore, FloorStoreShape>()("cli/FloorStore") {}

export function floorDirOf(configPath: string): string {
  return join(dirname(configPath), "floor");
}

export function floorRecordGet<T>(
  record: Readonly<Record<string, T>> | undefined,
  key: string,
): T | undefined {
  return record !== undefined && Object.hasOwn(record, key) ? record[key] : undefined;
}

export function emptyEnvironmentFloor(): EnvironmentFloor {
  return { pullEpoch: 0, observedEpoch: 0, metaVersion: 0, metaSigHashHex: "", variables: {} };
}

export type ConflictSink = (conflict: FloorConflict) => void;

export function floorKeyAsVariableId(key: string): VariableId {
  if (!isVariableId(key)) {
    throw new Error(`floor record has a variable key out of the id form: ${key}`);
  }
  return decodeVariableId(key);
}

interface VersionedEvidence {
  readonly version: number;
  readonly hashHex: string;
}

function joinVersioned<T extends VersionedEvidence>(
  a: T,
  b: T,
  conflict: (first: VersionedEvidence, second: VersionedEvidence) => FloorConflict,
  sink: ConflictSink,
): T {
  if (a.version !== b.version) {
    return a.version > b.version ? a : b;
  }
  if (a.hashHex === b.hashHex) {
    return a;
  }
  sink(conflict(a, b));
  return a.hashHex > b.hashHex ? a : b;
}

export function joinChainHead(
  existing: ChainHeadFloor | null,
  incoming: ChainHeadFloor,
  sink: ConflictSink,
): ChainHeadFloor {
  if (existing === null) {
    return incoming;
  }
  const joined = joinVersioned(
    { version: existing.seq, hashHex: existing.hashHex },
    { version: incoming.seq, hashHex: incoming.hashHex },
    (first, second) => ({
      kind: "chain-head",
      environmentId: null,
      variableId: null,
      firstVersion: first.version,
      firstHashHex: first.hashHex,
      secondVersion: second.version,
      secondHashHex: second.hashHex,
    }),
    sink,
  );
  return { seq: joined.version, hashHex: joined.hashHex };
}

function metaConflict(
  kind: "variable-meta" | "environment-meta",
  environmentId: EnvironmentId,
  variableId: VariableId | null,
): (first: VersionedEvidence, second: VersionedEvidence) => FloorConflict {
  return (first, second) => ({
    kind,
    environmentId,
    variableId,
    firstVersion: first.version,
    firstHashHex: first.hashHex,
    secondVersion: second.version,
    secondHashHex: second.hashHex,
  });
}

interface MetaSide {
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
}

function joinMetaSide(
  environmentId: EnvironmentId,
  variableId: VariableId | null,
  a: MetaSide,
  b: MetaSide,
  sink: ConflictSink,
): MetaSide {
  const joined = joinVersioned(
    { version: a.metaVersion, hashHex: a.metaSigHashHex },
    { version: b.metaVersion, hashHex: b.metaSigHashHex },
    metaConflict(
      variableId === null ? "environment-meta" : "variable-meta",
      environmentId,
      variableId,
    ),
    sink,
  );
  return { metaVersion: joined.version, metaSigHashHex: joined.hashHex };
}

function joinDeletedWithLive(
  environmentId: EnvironmentId,
  variableId: VariableId,
  deleted: Extract<VariableFloor, { status: "deleted" }>,
  live: Extract<VariableFloor, { status: "active" | "declared" }>,
  sink: ConflictSink,
): VariableFloor {
  if (live.metaVersion > deleted.metaVersion) {
    sink({
      kind: "undeletion",
      environmentId,
      variableId,
      firstVersion: deleted.metaVersion,
      firstHashHex: deleted.metaSigHashHex,
      secondVersion: live.metaVersion,
      secondHashHex: live.metaSigHashHex,
    });
  } else if (live.metaVersion === deleted.metaVersion) {
    sink({
      kind: "variable-meta",
      environmentId,
      variableId,
      firstVersion: deleted.metaVersion,
      firstHashHex: deleted.metaSigHashHex,
      secondVersion: live.metaVersion,
      secondHashHex: live.metaSigHashHex,
    });
  }
  return deleted;
}

function joinLiveVariableFloor(
  environmentId: EnvironmentId,
  variableId: VariableId,
  existing: Extract<VariableFloor, { status: "active" | "declared" }>,
  incoming: Extract<VariableFloor, { status: "active" | "declared" }>,
  sink: ConflictSink,
): VariableFloor {
  const meta = joinMetaSide(environmentId, variableId, existing, incoming, sink);
  if (existing.status === "declared" || incoming.status === "declared") {
    const active =
      existing.status === "active" ? existing : incoming.status === "active" ? incoming : null;
    if (active === null) {
      return { status: "declared", ...meta };
    }
    return {
      status: "active",
      version: active.version,
      epoch: active.epoch,
      valueSigHashHex: active.valueSigHashHex,
      ...meta,
    };
  }
  const value = joinVersioned(
    { version: existing.version, hashHex: existing.valueSigHashHex, epoch: existing.epoch },
    { version: incoming.version, hashHex: incoming.valueSigHashHex, epoch: incoming.epoch },
    (first, second) => ({
      kind: "value",
      environmentId,
      variableId,
      firstVersion: first.version,
      firstHashHex: first.hashHex,
      secondVersion: second.version,
      secondHashHex: second.hashHex,
    }),
    sink,
  );
  return {
    status: "active",
    version: value.version,
    epoch: value.epoch,
    valueSigHashHex: value.hashHex,
    ...meta,
  };
}

function joinVariableFloor(
  environmentId: EnvironmentId,
  variableId: VariableId,
  existing: VariableFloor | undefined,
  incoming: VariableFloor,
  sink: ConflictSink,
): VariableFloor {
  if (existing === undefined) {
    return incoming;
  }
  if (existing.status === "deleted") {
    if (incoming.status === "deleted") {
      const meta = joinMetaSide(environmentId, variableId, existing, incoming, sink);
      return { status: "deleted", ...meta };
    }
    return joinDeletedWithLive(environmentId, variableId, existing, incoming, sink);
  }
  if (incoming.status === "deleted") {
    return joinDeletedWithLive(environmentId, variableId, incoming, existing, sink);
  }
  return joinLiveVariableFloor(environmentId, variableId, existing, incoming, sink);
}

function joinManifestFloor(
  environmentId: EnvironmentId,
  existing: ManifestFloor | undefined,
  incoming: ManifestFloor | undefined,
  sink: ConflictSink,
): ManifestFloor | undefined {
  if (existing === undefined || incoming === undefined) {
    return existing ?? incoming;
  }
  const joined = joinVersioned(
    {
      version: existing.manifestVersion,
      hashHex: existing.manifestSigHashHex,
      epoch: existing.epoch,
    },
    {
      version: incoming.manifestVersion,
      hashHex: incoming.manifestSigHashHex,
      epoch: incoming.epoch,
    },
    (first, second) => ({
      kind: "manifest",
      environmentId,
      variableId: null,
      firstVersion: first.version,
      firstHashHex: first.hashHex,
      secondVersion: second.version,
      secondHashHex: second.hashHex,
    }),
    sink,
  );
  return {
    manifestVersion: joined.version,
    epoch: joined.epoch,
    manifestSigHashHex: joined.hashHex,
  };
}

export function joinEnvironmentFloor(
  environmentId: EnvironmentId,
  existing: EnvironmentFloor | undefined,
  incoming: EnvironmentFloor,
  sink: ConflictSink,
): EnvironmentFloor {
  if (existing === undefined) {
    return incoming;
  }
  const meta =
    existing.metaVersion === 0
      ? { metaVersion: incoming.metaVersion, metaSigHashHex: incoming.metaSigHashHex }
      : incoming.metaVersion === 0
        ? { metaVersion: existing.metaVersion, metaSigHashHex: existing.metaSigHashHex }
        : joinMetaSide(environmentId, null, existing, incoming, sink);
  const manifest = joinManifestFloor(environmentId, existing.manifest, incoming.manifest, sink);
  const variables: Record<string, VariableFloor> = { ...existing.variables };
  for (const [key, variable] of Object.entries(incoming.variables)) {
    const variableId = floorKeyAsVariableId(key);
    variables[variableId] = joinVariableFloor(
      environmentId,
      variableId,
      floorRecordGet(existing.variables, variableId),
      variable,
      sink,
    );
  }
  return {
    pullEpoch: Math.max(existing.pullEpoch, incoming.pullEpoch),
    observedEpoch: Math.max(existing.observedEpoch, incoming.observedEpoch),
    ...meta,
    ...(manifest === undefined ? {} : { manifest }),
    variables,
  };
}
