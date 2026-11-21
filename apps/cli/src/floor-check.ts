import { type EnvironmentId, type ProjectId, type VariableId, type UserId } from "@maruhi/core";
import type { MetaVarType } from "@maruhi/crypto";
import { Effect } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import type { CliError } from "./errors.ts";
import { isServerRejection } from "./failure.ts";
import {
  type ChainHeadFloor,
  type EnvironmentFloor,
  type FloorConflict,
  type FloorIntent,
  type FloorIntentInput,
  type FloorIntentOutcome,
  floorKeyAsVariableId,
  floorRecordGet,
  type FloorStoreShape,
  joinEnvironmentFloor,
  type ManifestFloor,
  type MetadataCommit,
  type ProjectFloor,
  type VariableFloor,
} from "./floor.ts";
import type { VerifiedManifest } from "./manifest.ts";
import type { VerifiedPulledValue } from "./values-verify.ts";

export interface VerifiedMetaEvidence {
  readonly status: "active" | "deleted" | "declared";
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly signatureHex: string;
  readonly authorUserId: UserId;
  readonly authorKeyFingerprintHex: string;
}

export interface VerifiedEnvironmentStatement extends VerifiedMetaEvidence {
  readonly name: string;
}

export interface VerifiedTombstone extends VerifiedMetaEvidence {
  readonly variableId: VariableId;
  readonly name: string;
}

export interface VerifiedPullSnapshot {
  readonly environment: VerifiedMetaEvidence;
  readonly variables: readonly VerifiedPulledValue[];
  readonly declared: readonly VerifiedVariableStatement[];
  readonly tombstones: readonly VerifiedTombstone[];
  readonly manifest: VerifiedManifest;
}

export interface VerifiedMetadataSnapshot {
  readonly environment: VerifiedMetaEvidence;
  readonly variables: readonly VerifiedVariableStatement[];
  readonly tombstones: readonly VerifiedTombstone[];
  readonly manifest: VerifiedManifest;
}

export interface VerifiedSchemaFields {
  readonly varType: MetaVarType;
  readonly required: boolean;
  readonly description: string;
  readonly maxAgeDays: number | null;
}

export interface VerifiedVariableStatement extends VerifiedMetaEvidence {
  readonly variableId: VariableId;
  readonly name: string;
  readonly layoutVersion: number;
  readonly schema: VerifiedSchemaFields | null;
}

export interface PulledValueEvidence {
  readonly version: number;
  readonly epoch: number;
  readonly valueSigHashHex: string;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly signatureHex: string;
  readonly writerUserId: UserId;
  readonly writerKeyFingerprintHex: string;
}

export interface FloorMetaEvidence {
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
}

export type ActiveVariableFloor = Extract<VariableFloor, { status: "active" }>;

export type FloorViolation =
  | {
      readonly kind: "chain-shortened";
      readonly floorHead: ChainHeadFloor;
      readonly syncedHead: ChainHeadFloor;
    }
  | {
      readonly kind: "chain-diverged";
      readonly floorHead: ChainHeadFloor;
      readonly actualHashHex: string;
      readonly syncedHead: ChainHeadFloor;
    }
  | {
      readonly kind: "variable-omitted";
      readonly variableId: VariableId;
      readonly floor: VariableFloor;
    }
  | {
      readonly kind: "value-rollback";
      readonly variableId: VariableId;
      readonly floor: ActiveVariableFloor;
      readonly pulled: PulledValueEvidence;
    }
  | {
      readonly kind: "value-equivocation";
      readonly variableId: VariableId;
      readonly floor: ActiveVariableFloor;
      readonly pulled: PulledValueEvidence;
    }
  | {
      readonly kind: "value-epoch-regression";
      readonly variableId: VariableId;
      readonly floor: ActiveVariableFloor;
      readonly pulled: PulledValueEvidence;
    }
  | {
      readonly kind: "stale-epoch-injection";
      readonly variableId: VariableId;
      readonly baselineEpoch: number;
      readonly floorVersion: number;
      readonly pulled: PulledValueEvidence;
    }
  | {
      readonly kind: "meta-rollback";
      readonly target: "variable" | "environment";
      readonly variableId: VariableId | null;
      readonly floor: FloorMetaEvidence;
      readonly pulled: VerifiedMetaEvidence;
    }
  | {
      readonly kind: "meta-equivocation";
      readonly target: "variable" | "environment";
      readonly variableId: VariableId | null;
      readonly floor: FloorMetaEvidence;
      readonly pulled: VerifiedMetaEvidence;
    }
  | {
      readonly kind: "deletion-revoked";
      readonly variableId: VariableId;
      readonly floor: FloorMetaEvidence;
      readonly pulled: VerifiedMetaEvidence;
    }
  | {
      readonly kind: "tombstone-mismatch";
      readonly variableId: VariableId;
      readonly floor: FloorMetaEvidence;
      readonly pulled: VerifiedMetaEvidence;
    }
  | {
      readonly kind: "manifest-rollback";
      readonly floor: ManifestFloor;
      readonly pulled: VerifiedManifest;
    }
  | {
      readonly kind: "manifest-equivocation";
      readonly floor: ManifestFloor;
      readonly pulled: VerifiedManifest;
    }
  | {
      readonly kind: "stale-manifest-injection";
      readonly baselineEpoch: number;
      readonly floorManifestVersion: number;
      readonly pulled: VerifiedManifest;
    };

export function floorViolationLabel(violation: FloorViolation): string {
  switch (violation.kind) {
    case "chain-shortened":
      return "chain shortening (a rollback)";
    case "chain-diverged":
      return "distribution of a branch diverging from the verified chain head (immediate evidence of equivocation)";
    case "variable-omitted":
      return "omission of a verified variable (selective response truncation)";
    case "value-rollback":
      return "a value-version rollback";
    case "value-equivocation":
      return "different signed bytes served for the same version (evidence of equivocation)";
    case "value-epoch-regression":
      return "an epoch regression (a §4.1 monotonicity violation)";
    case "stale-epoch-injection":
      return "an advanced version below the pull-time epoch baseline (evidence of forward injection with an old epoch key)";
    case "meta-rollback":
      return "a meta-statement rollback";
    case "meta-equivocation":
      return "different signed bytes served for the same metaVersion (evidence of equivocation)";
    case "deletion-revoked":
      return "an unauthorized undeletion";
    case "tombstone-mismatch":
      return "replacement of a deleted variable's tombstone";
    case "manifest-rollback":
      return "an environment-manifest rollback";
    case "manifest-equivocation":
      return "different signed bytes served for the same manifestVersion (evidence of equivocation)";
    case "stale-manifest-injection":
      return "an advanced manifestVersion below the epoch baseline (evidence of forward meta injection with an old epoch key)";
  }
}

export function checkChainFloor(
  floor: ProjectFloor,
  verified: VerifiedProject,
): FloorViolation | null {
  const floorHead = floor.chainHead;
  if (floorHead === null) {
    return null;
  }
  const syncedHead: ChainHeadFloor = {
    seq: verified.state.headSeq,
    hashHex: verified.state.headHashHex,
  };
  if (verified.state.headSeq < floorHead.seq) {
    return { kind: "chain-shortened", floorHead, syncedHead };
  }
  const actualHashHex = verified.history.entryHashAt(floorHead.seq);
  if (actualHashHex !== floorHead.hashHex) {
    return {
      kind: "chain-diverged",
      floorHead,
      actualHashHex: actualHashHex ?? "",
      syncedHead,
    };
  }
  return null;
}

function valueEvidenceOf(value: VerifiedPulledValue): PulledValueEvidence {
  return {
    version: value.version,
    epoch: value.epoch,
    valueSigHashHex: value.signedBytesHashHex,
    chainHeadSeq: value.valueChainHeadSeq,
    chainHeadHashHex: value.valueChainHeadHashHex,
    signatureHex: value.valueSignatureHex,
    writerUserId: value.writerUserId,
    writerKeyFingerprintHex: value.writerKeyFingerprintHex,
  };
}

function metaEvidenceOf(value: VerifiedPulledValue): VerifiedMetaEvidence {
  return {
    status: "active",
    metaVersion: value.metaVersion,
    metaSigHashHex: value.metaSignedBytesHashHex,
    chainHeadSeq: value.metaChainHeadSeq,
    chainHeadHashHex: value.metaChainHeadHashHex,
    signatureHex: value.metaSignatureHex,
    authorUserId: value.authorUserId,
    authorKeyFingerprintHex: value.authorKeyFingerprintHex,
  };
}

function checkMetaAgainstFloor(
  target: "variable" | "environment",
  variableId: VariableId | null,
  floor: FloorMetaEvidence,
  pulled: VerifiedMetaEvidence,
): FloorViolation | null {
  if (pulled.metaVersion < floor.metaVersion) {
    return { kind: "meta-rollback", target, variableId, floor, pulled };
  }
  if (pulled.metaVersion === floor.metaVersion && pulled.metaSigHashHex !== floor.metaSigHashHex) {
    return { kind: "meta-equivocation", target, variableId, floor, pulled };
  }
  return null;
}

function checkManifestAgainstFloor(
  floor: EnvironmentFloor,
  manifest: VerifiedManifest,
): FloorViolation | null {
  const manifestFloor = floor.manifest;
  if (manifestFloor === undefined) {
    return null;
  }
  if (manifest.manifestVersion < manifestFloor.manifestVersion) {
    return { kind: "manifest-rollback", floor: manifestFloor, pulled: manifest };
  }
  if (
    manifest.manifestVersion === manifestFloor.manifestVersion &&
    manifest.signedBytesHashHex !== manifestFloor.manifestSigHashHex
  ) {
    return { kind: "manifest-equivocation", floor: manifestFloor, pulled: manifest };
  }
  return null;
}

function checkManifestEpochBaseline(
  floor: EnvironmentFloor,
  manifest: VerifiedManifest,
): FloorViolation | null {
  const floorVersion = floor.manifest?.manifestVersion ?? 0;
  const baselineEpoch = Math.max(floor.pullEpoch, floor.observedEpoch, floor.manifest?.epoch ?? 0);
  if (manifest.manifestVersion > floorVersion && manifest.epoch < baselineEpoch) {
    return {
      kind: "stale-manifest-injection",
      baselineEpoch,
      floorManifestVersion: floorVersion,
      pulled: manifest,
    };
  }
  return null;
}

function checkActiveVariable(
  floor: ActiveVariableFloor,
  value: VerifiedPulledValue,
): FloorViolation | null {
  const variableId = value.variableId;
  const pulled = valueEvidenceOf(value);
  if (value.version < floor.version) {
    return { kind: "value-rollback", variableId, floor, pulled };
  }
  if (value.version === floor.version && value.signedBytesHashHex !== floor.valueSigHashHex) {
    return { kind: "value-equivocation", variableId, floor, pulled };
  }
  if (value.version > floor.version && value.epoch < floor.epoch) {
    return { kind: "value-epoch-regression", variableId, floor, pulled };
  }
  return checkMetaAgainstFloor("variable", variableId, floor, metaEvidenceOf(value));
}

function checkFloorActiveMeta(
  variableId: VariableId,
  floor: ActiveVariableFloor,
  active: VerifiedMetaEvidence | undefined,
  tombstone: VerifiedTombstone | undefined,
): FloorViolation | null {
  if (active !== undefined) {
    return checkMetaAgainstFloor("variable", variableId, floor, active);
  }
  if (tombstone !== undefined) {
    return checkMetaAgainstFloor("variable", variableId, floor, tombstone);
  }
  return { kind: "variable-omitted", variableId, floor };
}

function checkFloorActive(
  variableId: VariableId,
  floor: ActiveVariableFloor,
  active: VerifiedPulledValue | undefined,
  tombstone: VerifiedTombstone | undefined,
): FloorViolation | null {
  if (active !== undefined) {
    return checkActiveVariable(floor, active);
  }
  return checkFloorActiveMeta(variableId, floor, undefined, tombstone);
}

function checkFloorDeclared(
  variableId: VariableId,
  floor: Extract<VariableFloor, { status: "declared" }>,
  meta: VerifiedMetaEvidence | undefined,
  tombstone: VerifiedTombstone | undefined,
): FloorViolation | null {
  const evidence = meta ?? tombstone;
  if (evidence === undefined) {
    return { kind: "variable-omitted", variableId, floor };
  }
  return checkMetaAgainstFloor("variable", variableId, floor, evidence);
}

function checkFloorDeleted(
  variableId: VariableId,
  floor: Extract<VariableFloor, { status: "deleted" }>,
  active: VerifiedMetaEvidence | undefined,
  tombstone: VerifiedTombstone | undefined,
): FloorViolation | null {
  if (active !== undefined) {
    return { kind: "deletion-revoked", variableId, floor, pulled: active };
  }
  if (tombstone === undefined) {
    return { kind: "variable-omitted", variableId, floor };
  }
  if (
    tombstone.metaVersion !== floor.metaVersion ||
    tombstone.metaSigHashHex !== floor.metaSigHashHex
  ) {
    return { kind: "tombstone-mismatch", variableId, floor, pulled: tombstone };
  }
  return null;
}

function checkFloorCommon<T extends { readonly variableId: VariableId }>(
  floor: EnvironmentFloor,
  environment: VerifiedMetaEvidence,
  activeList: readonly T[],
  declaredList: readonly VerifiedVariableStatement[],
  tombstoneList: readonly VerifiedTombstone[],
  checkActive: (
    variableId: VariableId,
    variableFloor: ActiveVariableFloor,
    active: T | undefined,
    tombstone: VerifiedTombstone | undefined,
  ) => FloorViolation | null,
  toMeta: (active: T) => VerifiedMetaEvidence,
): FloorViolation | null {
  const actives = new Map(activeList.map((value) => [value.variableId, value]));
  const declared = new Map(declaredList.map((statement) => [statement.variableId, statement]));
  const tombstones = new Map(tombstoneList.map((tombstone) => [tombstone.variableId, tombstone]));
  const environmentViolation = checkMetaAgainstFloor(
    "environment",
    null,
    { metaVersion: floor.metaVersion, metaSigHashHex: floor.metaSigHashHex },
    environment,
  );
  if (environmentViolation !== null) {
    return environmentViolation;
  }
  for (const [key, variableFloor] of Object.entries(floor.variables)) {
    const variableId = floorKeyAsVariableId(key);
    const active = actives.get(variableId);
    const meta = active === undefined ? declared.get(variableId) : toMeta(active);
    const violation =
      variableFloor.status === "active"
        ? checkActive(variableId, variableFloor, active, tombstones.get(variableId))
        : variableFloor.status === "declared"
          ? checkFloorDeclared(variableId, variableFloor, meta, tombstones.get(variableId))
          : checkFloorDeleted(variableId, variableFloor, meta, tombstones.get(variableId));
    if (violation !== null) {
      return violation;
    }
  }
  return null;
}

export function checkEnvironmentPull(
  floor: EnvironmentFloor | null,
  snapshot: VerifiedPullSnapshot,
): FloorViolation | null {
  if (floor === null) {
    return null;
  }
  const violation = checkFloorCommon(
    floor,
    snapshot.environment,
    snapshot.variables,
    snapshot.declared,
    snapshot.tombstones,
    checkFloorActive,
    metaEvidenceOf,
  );
  if (violation !== null) {
    return violation;
  }
  const manifestViolation =
    checkManifestAgainstFloor(floor, snapshot.manifest) ??
    checkManifestEpochBaseline(floor, snapshot.manifest);
  if (manifestViolation !== null) {
    return manifestViolation;
  }
  for (const value of snapshot.variables) {
    const variableFloor = floorRecordGet(floor.variables, value.variableId);
    const floorVersion = variableFloor?.status === "active" ? variableFloor.version : 0;
    if (value.version > floorVersion && value.epoch < floor.pullEpoch) {
      return {
        kind: "stale-epoch-injection",
        variableId: value.variableId,
        baselineEpoch: floor.pullEpoch,
        floorVersion,
        pulled: valueEvidenceOf(value),
      };
    }
  }
  return null;
}

export function checkEnvironmentMetadataPull(
  floor: EnvironmentFloor | null,
  snapshot: VerifiedMetadataSnapshot,
): FloorViolation | null {
  if (floor === null) {
    return null;
  }
  const violation = checkFloorCommon(
    floor,
    snapshot.environment,
    snapshot.variables,
    [],
    snapshot.tombstones,
    checkFloorActiveMeta,
    (statement) => statement,
  );
  if (violation !== null) {
    return violation;
  }
  return (
    checkManifestAgainstFloor(floor, snapshot.manifest) ??
    checkManifestEpochBaseline(floor, snapshot.manifest)
  );
}

export function buildEnvironmentFloor(
  chainCurrentEpoch: number,
  snapshot: VerifiedPullSnapshot,
): EnvironmentFloor {
  const variables: Record<string, VariableFloor> = {};
  for (const value of snapshot.variables) {
    variables[value.variableId] = {
      status: "active",
      version: value.version,
      epoch: value.epoch,
      valueSigHashHex: value.signedBytesHashHex,
      metaVersion: value.metaVersion,
      metaSigHashHex: value.metaSignedBytesHashHex,
    };
  }
  for (const declared of snapshot.declared) {
    variables[declared.variableId] = {
      status: "declared",
      metaVersion: declared.metaVersion,
      metaSigHashHex: declared.metaSigHashHex,
    };
  }
  for (const tombstone of snapshot.tombstones) {
    variables[tombstone.variableId] = {
      status: "deleted",
      metaVersion: tombstone.metaVersion,
      metaSigHashHex: tombstone.metaSigHashHex,
    };
  }
  return {
    pullEpoch: chainCurrentEpoch,
    observedEpoch: chainCurrentEpoch,
    metaVersion: snapshot.environment.metaVersion,
    metaSigHashHex: snapshot.environment.metaSigHashHex,
    manifest: {
      manifestVersion: snapshot.manifest.manifestVersion,
      epoch: snapshot.manifest.epoch,
      manifestSigHashHex: snapshot.manifest.signedBytesHashHex,
    },
    variables,
  };
}

export interface FloorHandle {
  readonly current: () => EnvironmentFloor | null;
  readonly unresolvedIntents: () => readonly FloorIntent[];
  readonly commitPull: (
    environment: EnvironmentFloor,
    head: ChainHeadFloor,
  ) => Effect.Effect<void, CliError>;
  readonly commitPush: (
    variableId: VariableId,
    variable: VariableFloor,
    head: ChainHeadFloor,
  ) => Effect.Effect<void, CliError>;
  readonly commitMetadata: (
    commit: Omit<MetadataCommit, "chainHead" | "environmentId">,
    head: ChainHeadFloor,
  ) => Effect.Effect<void, CliError>;
  readonly commitManifest: (
    manifest: ManifestFloor,
    head: ChainHeadFloor,
  ) => Effect.Effect<void, CliError>;
  readonly appendIntent: (input: FloorIntentInput) => Effect.Effect<string, CliError>;
  readonly resolveIntent: (
    intentId: string,
    outcome: FloorIntentOutcome,
  ) => Effect.Effect<void, CliError>;
}

export function rejectIntentOnServerRejection(
  floor: FloorHandle,
  intentId: string,
): (error: unknown) => Effect.Effect<void> {
  return (error) =>
    isServerRejection(error)
      ? Effect.ignore(floor.resolveIntent(intentId, "rejected"))
      : Effect.void;
}

export function makeFloorHandle(input: {
  readonly store: FloorStoreShape;
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly initial: EnvironmentFloor | null;
  readonly intents?: readonly FloorIntent[];
}): FloorHandle {
  let current = input.initial;
  const intents = new Map((input.intents ?? []).map((intent) => [intent.id, intent]));
  const adopt = (merged: EnvironmentFloor): void => {
    current = merged;
  };
  return {
    current: () => current,
    unresolvedIntents: () => [...intents.values()],
    commitPull: (environment, head) =>
      input.store
        .commitPull(input.projectId, {
          chainHead: head,
          environmentId: input.environmentId,
          environment,
        })
        .pipe(Effect.map(adopt)),
    commitPush: (variableId, variable, head) =>
      input.store
        .commitPush(input.projectId, {
          chainHead: head,
          environmentId: input.environmentId,
          variableId,
          variable,
        })
        .pipe(Effect.map(adopt)),
    commitMetadata: (commit, head) =>
      input.store
        .commitMetadata(input.projectId, {
          chainHead: head,
          environmentId: input.environmentId,
          ...commit,
        })
        .pipe(Effect.map(adopt)),
    commitManifest: (manifest, head) =>
      Effect.suspend(() => {
        if (current !== null) {
          const conflicts: FloorConflict[] = [];
          const joined = joinEnvironmentFloor(
            input.environmentId,
            current,
            {
              pullEpoch: 0,
              observedEpoch: manifest.epoch,
              metaVersion: 0,
              metaSigHashHex: "",
              manifest,
              variables: {},
            },
            (conflict) => conflicts.push(conflict),
          );
          if (conflicts.length === 0) {
            current = joined;
          }
        }
        return input.store
          .commitManifest(input.projectId, {
            chainHead: head,
            environmentId: input.environmentId,
            manifest,
          })
          .pipe(Effect.map(adopt));
      }),
    appendIntent: (intentInput) =>
      input.store.appendIntent(input.projectId, intentInput).pipe(
        Effect.tap((id) =>
          Effect.sync(() => {
            intents.set(id, { id, ...intentInput });
          }),
        ),
      ),
    resolveIntent: (intentId, outcome) =>
      Effect.suspend(() => {
        if (!intents.has(intentId)) {
          return Effect.void;
        }
        intents.delete(intentId);
        return input.store.resolveIntent(input.projectId, intentId, outcome);
      }),
  };
}
