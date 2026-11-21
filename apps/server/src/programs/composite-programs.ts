import type { EnvironmentId, ProjectId, UserId } from "@maruhi/core";
import type { ChainEntry, ChainState, KeyFingerprintHex } from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import type { AuditRotationRead } from "../audit-store-rotation-read.ts";
import type { AuditEventInput } from "../audit-store.ts";
import { AuditStore } from "../audit-store.ts";
import { ensureAuditHeadAcceptable, ensureCheckpointValuesDigest } from "../checkpoint-accept.ts";
import type {
  DataActor,
  DataWriteOps,
  DekWrapInput,
  EnvManifestInput,
  MemberWithDevice,
  MetaStatementInput,
} from "../data.package/index.ts";
import {
  acceptEnvManifest,
  acceptEnvManifestForCreation,
  dataEvent,
  DataStore,
  deviceOf,
  ensureDevicePermission,
  ensureMetaStatementSignature,
  ensureNfcName,
  loadInitializedChain,
  manifestDigestEntries,
  projectIdOf,
  rejectData,
  requireRole,
  requireRoleInScope,
  storedEnvMeta,
} from "../data.package/index.ts";
import {
  dekRegisteredEvent,
  ensureWrapSetAcceptable,
  expectedWrapRecipientCount,
} from "../dek-wraps.ts";
import {
  ensureParentHead,
  insertAcceptedEntryPairSync,
  verifyAcceptableEntry,
  verifyAcceptableEntryPair,
} from "../do/chain-accept.ts";
import { commitAcceptedEntry } from "../do/chain-commit.ts";
import type { StateCache, StoredChain } from "../do/chain-store.ts";
import { ChainStore, deriveStoredState, updateStateCache } from "../do/chain-store.ts";
import { ensureEnvironmentQuota, requireActiveEnvironment } from "../quotas.ts";
import { ensureStorageAdmitsGrowth } from "../storage-guard.ts";

export interface EnvironmentChainResultValue {
  readonly environmentId: EnvironmentId;
  readonly currentEpoch: number;
  readonly headSeq: number;
  readonly headHashHex: string;
}

const loadChainForComposite = Effect.fn("composite-programs.loadChainForComposite")(function* (
  callerUserId: UserId,
  entryActorFingerprintHex: KeyFingerprintHex,
  entrySeq: number,
  cache: StateCache,
) {
  const chain = yield* loadInitializedChain;
  const { state, history } = yield* deriveStoredState(chain, cache);
  const person = yield* requireRole(state, callerUserId, "member");
  const member = deviceOf(person, entryActorFingerprintHex);
  if (member === undefined) {
    return yield* rejectData({
      kind: "chain-entry-invalid",
      seq: entrySeq,
      reason: "actor-key-mismatch",
    });
  }
  yield* ensureDevicePermission(member, "member");
  return { chain, state, history, member, projectId: projectIdOf(chain) };
});

const ensureCompositeScope = Effect.fn("composite-programs.ensureCompositeScope")(function* (
  state: ChainState,
  callerUserId: UserId,
  member: MemberWithDevice,
  environmentId: EnvironmentId,
) {
  yield* requireRoleInScope(state, callerUserId, "member", environmentId);
  yield* ensureDevicePermission(member, "member", environmentId);
});

const ensureCompositeWrapSet = Effect.fn("composite-programs.ensureCompositeWrapSet")(
  function* (input: {
    readonly projectId: ProjectId;
    readonly environmentId: EnvironmentId;
    readonly appliedState: ChainState;
    readonly member: MemberWithDevice;
    readonly establishedEpoch: number;
    readonly deks: readonly DekWrapInput[];
  }) {
    for (const wrap of input.deks) {
      if (wrap.epoch !== input.establishedEpoch) {
        return yield* rejectData({ kind: "dek-wrap-rejected", reason: "epoch-out-of-range" });
      }
    }
    const signer = yield* ensureWrapSetAcceptable(
      input.projectId,
      input.environmentId,
      input.appliedState,
      input.member,
      input.establishedEpoch,
      input.deks,
    );
    if (signer !== null && signer.keyFingerprintHex !== input.member.keyFingerprintHex) {
      return yield* rejectData({ kind: "dek-wrap-rejected", reason: "signature-invalid" });
    }
    if (input.deks.length !== expectedWrapRecipientCount(input.appliedState, input.environmentId)) {
      return yield* rejectData({ kind: "dek-wrap-rejected", reason: "recipient-missing" });
    }
  },
);

const ensureBoundaryCheckpointShape = Effect.fn("composite-programs.ensureBoundaryCheckpointShape")(
  function* (input: {
    readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
    readonly environmentId: EnvironmentId;
    readonly establishedEpoch: number;
    readonly manifestVersion: number;
  }) {
    const environments = input.checkpoint.payload.environments;
    const tuple = environments[0];
    if (environments.length !== 1 || tuple === undefined) {
      return yield* rejectData({ kind: "payload-mismatch", field: "checkpointEnvironment" });
    }
    if (tuple.environmentId !== input.environmentId) {
      return yield* rejectData({ kind: "payload-mismatch", field: "checkpointEnvironment" });
    }
    if (tuple.epoch !== input.establishedEpoch) {
      return yield* rejectData({ kind: "payload-mismatch", field: "checkpointEpoch" });
    }
    if (tuple.manifestVersion !== input.manifestVersion) {
      return yield* rejectData({ kind: "payload-mismatch", field: "checkpointManifestVersion" });
    }
    return tuple;
  },
);

const ensureCheckpointAuditHead = Effect.fn("composite-programs.ensureCheckpointAuditHead")(
  function* (input: {
    readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
    readonly state: ChainState;
    readonly callerUserId: UserId;
  }) {
    if (input.checkpoint.payload.auditHeadHashHex === "") {
      return;
    }
    yield* requireRole(input.state, input.callerUserId, "admin");
    yield* ensureAuditHeadAcceptable(input.checkpoint.payload.auditHeadHashHex);
  },
);

const acceptBoundaryCheckpointPair = Effect.fn("composite-programs.acceptBoundaryCheckpointPair")(
  function* (input: {
    readonly chain: StoredChain;
    readonly state: ChainState;
    readonly callerUserId: UserId;
    readonly entry: ChainEntry;
    readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
    readonly environmentId: EnvironmentId;
    readonly establishedEpoch: number;
    readonly manifestVersion: number;
  }) {
    const checkpointTuple = yield* ensureBoundaryCheckpointShape({
      checkpoint: input.checkpoint,
      environmentId: input.environmentId,
      establishedEpoch: input.establishedEpoch,
      manifestVersion: input.manifestVersion,
    });
    yield* ensureCheckpointAuditHead({
      checkpoint: input.checkpoint,
      state: input.state,
      callerUserId: input.callerUserId,
    });
    const pair = yield* verifyAcceptableEntryPair(input.chain, input.entry, input.checkpoint);
    return { checkpointTuple, ...pair };
  },
);

interface CompositeWriteContext {
  readonly chainStore: {
    readonly insertSync: (entry: ChainEntry, entryHashHex: string, canonicalBytes: number) => void;
  };
  readonly dataStore: { readonly write: DataWriteOps };
  readonly audit: {
    readonly appendSync: (event: AuditEventInput) => void;
    readonly appendManySync: (events: readonly AuditEventInput[]) => void;
    readonly readRotationSync: AuditRotationRead;
  };
  readonly actor: DataActor;
  readonly member: MemberWithDevice;
  readonly environmentId: EnvironmentId;
  readonly nowMs: number;
}

function insertCompositeWrapsSync(
  context: CompositeWriteContext,
  deks: readonly DekWrapInput[],
): void {
  for (const wrap of deks) {
    context.dataStore.write.insertWrap(context.environmentId, wrap, context.member, context.nowMs);
  }
  context.audit.appendManySync(
    deks.map((wrap) =>
      dekRegisteredEvent(context.actor, context.member, context.nowMs, context.environmentId, wrap),
    ),
  );
}

const makeWriteContext = Effect.fn("composite-programs.makeWriteContext")(function* (input: {
  readonly dataStore: { readonly write: DataWriteOps };
  readonly actor: DataActor;
  readonly member: MemberWithDevice;
  readonly environmentId: EnvironmentId;
}) {
  const chainStore = yield* ChainStore;
  const audit = yield* AuditStore;
  return {
    chainStore,
    dataStore: input.dataStore,
    audit,
    actor: input.actor,
    member: input.member,
    environmentId: input.environmentId,
    nowMs: yield* Clock.currentTimeMillis,
  } satisfies CompositeWriteContext;
});

function compositeResult(
  environmentId: EnvironmentId,
  currentEpoch: number,
  appliedState: ChainState,
): EnvironmentChainResultValue {
  return {
    environmentId,
    currentEpoch,
    headSeq: appliedState.headSeq,
    headHashHex: appliedState.headHashHex,
  };
}

export const createEnvironmentCompositeProgram = Effect.fn(
  "composite-programs.createEnvironmentCompositeProgram",
)(function* (
  actor: DataActor,
  input: {
    readonly parentHeadHashHex: string;
    readonly entry: ChainEntry & { readonly op: "create_environment" };
    readonly statement: MetaStatementInput;
    readonly deks: readonly DekWrapInput[];
    readonly manifest: EnvManifestInput;
    readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
  },
  cache: StateCache,
) {
  const { chain, state, history, member, projectId } = yield* loadChainForComposite(
    actor.userId,
    input.entry.actor.keyFingerprintHex,
    input.entry.seq,
    cache,
  );
  yield* ensureStorageAdmitsGrowth;
  yield* ensureParentHead(chain, input.parentHeadHashHex);
  yield* ensureCompositeScope(state, actor.userId, member, input.entry.payload.environmentId);
  if (
    input.statement.chainHeadHashHex !== chain.headHashHex ||
    input.statement.chainHeadSeq !== chain.headSeq
  ) {
    return yield* rejectData({ kind: "payload-mismatch", field: "statementChainHead" });
  }
  if (
    input.manifest.chainHeadHashHex !== chain.headHashHex ||
    input.manifest.chainHeadSeq !== chain.headSeq
  ) {
    return yield* rejectData({ kind: "payload-mismatch", field: "manifestChainHead" });
  }
  if (input.manifest.epoch !== 1) {
    return yield* rejectData({ kind: "payload-mismatch", field: "manifestEpoch" });
  }
  const environmentId = input.entry.payload.environmentId;
  const { checkpointTuple, firstCanonicalBytes, secondCanonicalBytes, applied } =
    yield* acceptBoundaryCheckpointPair({
      chain,
      state,
      callerUserId: actor.userId,
      entry: input.entry,
      checkpoint: input.checkpoint,
      environmentId,
      establishedEpoch: 1,
      manifestVersion: input.manifest.manifestVersion,
    });
  const appliedState = applied.state;
  const store = yield* DataStore;
  yield* ensureEnvironmentQuota;
  yield* ensureNfcName(input.statement.name);
  if (yield* store.environmentNameTaken(input.statement.name, null)) {
    return yield* rejectData({
      kind: "environment-conflict",
      environmentId,
      reason: "duplicate-name",
    });
  }
  const metaSignedBytesHashHex = yield* ensureMetaStatementSignature({
    projectId,
    environmentId,
    target: { kind: "environment" },
    history,
    member,
    statement: input.statement,
  });
  const manifestSignedBytesHashHex = yield* acceptEnvManifestForCreation({
    projectId,
    environmentId,
    history: applied.history,
    member,
    manifest: input.manifest,
    entries: [],
    envMeta: { metaVersion: input.statement.metaVersion, sigHashHex: metaSignedBytesHashHex },
  });
  yield* ensureCheckpointValuesDigest(checkpointTuple, []);
  yield* ensureCompositeWrapSet({
    projectId,
    environmentId,
    appliedState,
    member,
    establishedEpoch: 1,
    deks: input.deks,
  });
  const writeContext = yield* makeWriteContext({
    dataStore: store,
    actor,
    member,
    environmentId,
  });
  yield* Effect.sync(() => {
    insertAcceptedEntryPairSync(
      writeContext,
      input.entry,
      input.checkpoint,
      applied,
      firstCanonicalBytes,
      secondCanonicalBytes,
      writeContext.nowMs,
    );
    store.write.insertEnvironment(environmentId, input.statement.name, writeContext.nowMs);
    store.write.insertEnvironmentMetaStatement(
      environmentId,
      input.statement,
      metaSignedBytesHashHex,
      { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
      writeContext.nowMs,
    );
    store.write.upsertEnvironmentManifest(
      environmentId,
      input.manifest,
      manifestSignedBytesHashHex,
      { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
      writeContext.nowMs,
    );
    writeContext.audit.appendSync(
      dataEvent(actor, writeContext.nowMs, {
        event: "env.created",
        environmentId,
        payload: { name: input.statement.name },
        actorKeyFingerprintHex: member.keyFingerprintHex,
      }),
    );
    insertCompositeWrapsSync(writeContext, input.deks);
    store.write.upsertCheckpointSnapshot(
      environmentId,
      {
        chainSeq: input.checkpoint.seq,
        entryHashHex: appliedState.headHashHex,
        epoch: checkpointTuple.epoch,
        manifestVersion: checkpointTuple.manifestVersion,
        manifestSigHashHex: checkpointTuple.manifestSigHashHex,
        valuesDigestHex: checkpointTuple.valuesDigestHex,
      },
      [],
      writeContext.nowMs,
    );
  });
  updateStateCache(cache, applied);
  return compositeResult(environmentId, 1, appliedState);
});

export const rotateEpochCompositeProgram = Effect.fn(
  "composite-programs.rotateEpochCompositeProgram",
)(function* (
  actor: DataActor,
  environmentId: EnvironmentId,
  input: {
    readonly parentHeadHashHex: string;
    readonly entry: ChainEntry & { readonly op: "rotate_epoch" };
    readonly deks: readonly DekWrapInput[];
    readonly manifest: EnvManifestInput;
    readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
  },
  cache: StateCache,
) {
  const { chain, state, member, projectId } = yield* loadChainForComposite(
    actor.userId,
    input.entry.actor.keyFingerprintHex,
    input.entry.seq,
    cache,
  );
  if (input.entry.payload.environmentId !== environmentId) {
    return yield* rejectData({ kind: "payload-mismatch", field: "environmentId" });
  }
  yield* ensureParentHead(chain, input.parentHeadHashHex);
  yield* ensureCompositeScope(state, actor.userId, member, environmentId);
  yield* requireActiveEnvironment(environmentId);
  if (
    input.manifest.chainHeadHashHex !== chain.headHashHex ||
    input.manifest.chainHeadSeq !== chain.headSeq
  ) {
    return yield* rejectData({ kind: "payload-mismatch", field: "manifestChainHead" });
  }
  if (input.manifest.epoch !== input.entry.payload.newEpoch) {
    return yield* rejectData({ kind: "payload-mismatch", field: "manifestEpoch" });
  }
  const { checkpointTuple, firstCanonicalBytes, secondCanonicalBytes, applied } =
    yield* acceptBoundaryCheckpointPair({
      chain,
      state,
      callerUserId: actor.userId,
      entry: input.entry,
      checkpoint: input.checkpoint,
      environmentId,
      establishedEpoch: input.entry.payload.newEpoch,
      manifestVersion: input.manifest.manifestVersion,
    });
  const appliedState = applied.state;
  const manifestSignedBytesHashHex = yield* acceptEnvManifest({
    projectId,
    environmentId,
    history: applied.history,
    member,
    manifest: input.manifest,
    entries: yield* manifestDigestEntries(environmentId, null),
    envMeta: yield* storedEnvMeta(environmentId),
  });
  const snapshotValues = yield* Effect.flatMap(DataStore, (store) =>
    store.checkpointValueEntries(environmentId),
  );
  yield* ensureCheckpointValuesDigest(checkpointTuple, snapshotValues);
  yield* ensureCompositeWrapSet({
    projectId,
    environmentId,
    appliedState,
    member,
    establishedEpoch: input.entry.payload.newEpoch,
    deks: input.deks,
  });
  const writeContext = yield* makeWriteContext({
    dataStore: yield* DataStore,
    actor,
    member,
    environmentId,
  });
  yield* Effect.sync(() => {
    insertAcceptedEntryPairSync(
      writeContext,
      input.entry,
      input.checkpoint,
      applied,
      firstCanonicalBytes,
      secondCanonicalBytes,
      writeContext.nowMs,
    );
    writeContext.dataStore.write.upsertEnvironmentManifest(
      environmentId,
      input.manifest,
      manifestSignedBytesHashHex,
      { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
      writeContext.nowMs,
    );
    insertCompositeWrapsSync(writeContext, input.deks);
    writeContext.dataStore.write.upsertCheckpointSnapshot(
      environmentId,
      {
        chainSeq: input.checkpoint.seq,
        entryHashHex: appliedState.headHashHex,
        epoch: checkpointTuple.epoch,
        manifestVersion: checkpointTuple.manifestVersion,
        manifestSigHashHex: checkpointTuple.manifestSigHashHex,
        valuesDigestHex: checkpointTuple.valuesDigestHex,
      },
      snapshotValues,
      writeContext.nowMs,
    );
  });
  updateStateCache(cache, applied);
  return compositeResult(environmentId, input.entry.payload.newEpoch, appliedState);
});

export const deleteEnvironmentCompositeProgram = Effect.fn(
  "composite-programs.deleteEnvironmentCompositeProgram",
)(function* (
  actor: DataActor,
  environmentId: EnvironmentId,
  input: {
    readonly parentHeadHashHex: string;
    readonly entry: ChainEntry & { readonly op: "delete_environment" };
  },
  cache: StateCache,
) {
  const chain = yield* loadInitializedChain;
  const { state } = yield* deriveStoredState(chain, cache);
  const person = yield* requireRole(state, actor.userId, "admin");
  if (input.entry.payload.environmentId !== environmentId) {
    return yield* rejectData({ kind: "payload-mismatch", field: "environmentId" });
  }
  if (input.entry.prevHashHex !== input.parentHeadHashHex) {
    return yield* rejectData({ kind: "payload-mismatch", field: "parentHeadHashHex" });
  }
  const member = deviceOf(person, input.entry.actor.keyFingerprintHex);
  if (member === undefined) {
    return yield* rejectData({
      kind: "chain-entry-invalid",
      seq: input.entry.seq,
      reason: "actor-key-mismatch",
    });
  }
  yield* ensureDevicePermission(member, "admin");
  yield* ensureParentHead(chain, input.parentHeadHashHex);
  yield* ensureDevicePermission(member, "admin", environmentId);
  const { canonicalBytes, applied } = yield* verifyAcceptableEntry(chain, input.entry);
  const store = yield* DataStore;
  const environment = yield* store.findEnvironment(environmentId);
  if (environment === null || environment.deletedAtMs !== null) {
    return yield* Effect.die(
      new Error(
        "environment live on the verified chain has no live data row (composite atomicity)",
      ),
    );
  }
  const variables = yield* store.listActiveVariables(environmentId);
  const audit = yield* AuditStore;
  yield* commitAcceptedEntry(chain, input.entry, applied, canonicalBytes, (nowMs) => {
    const proposals = store.write.retireEnvironment(environmentId, nowMs);
    audit.appendManySync([
      ...variables.map((variable) =>
        dataEvent(actor, nowMs, {
          event: "var.deleted",
          environmentId,
          variableId: variable.variableId,
          actorKeyFingerprintHex: member.keyFingerprintHex,
        }),
      ),
      ...proposals.map((proposal) =>
        proposal.expiresAtMs <= nowMs
          ? {
              event: "rotation.proposal_expired" as const,
              serverTs: nowMs,
              actorType: "system" as const,
              environmentId,
              payload: { proposalId: proposal.proposalId, expiresAtMs: proposal.expiresAtMs },
            }
          : dataEvent(actor, nowMs, {
              event: "rotation.proposal_cancelled",
              environmentId,
              payload: { proposalId: proposal.proposalId },
              actorKeyFingerprintHex: member.keyFingerprintHex,
            }),
      ),
      dataEvent(actor, nowMs, {
        event: "env.deleted",
        environmentId,
        payload: { name: environment.name },
        actorKeyFingerprintHex: member.keyFingerprintHex,
      }),
    ]);
  });
  updateStateCache(cache, applied);
});
