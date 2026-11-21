import type { EnvironmentId, ProjectId } from "@maruhi/core";
import { auditReadPayload, VAR_READ_EVENT } from "@maruhi/core";
import type { ChainHistoryIndex, ChainMember } from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import { AuditStore } from "../audit-store.ts";
import type {
  DataActor,
  EnvironmentListValue,
  EnvironmentMetadataPullValue,
  EnvironmentPullValue,
  EnvironmentSummaryValue,
  EnvManifestInput,
  MetaStatementInput,
} from "../data.package/index.ts";
import {
  acceptManifestForMetaOp,
  acceptMetaStatement,
  currentEpochOf,
  dataEvent,
  DataStore,
  ensureDevicePermission,
  ensureNfcName,
  optionalCheckpointSnapshot,
  rejectData,
  requireEnvironmentAccess,
  requireMemberState,
  withSigningDevice,
} from "../data.package/index.ts";
import type { StateCache } from "../do/chain-store.ts";
import { requireActiveEnvironment } from "../quotas.ts";
import { ensureStorageAdmitsGrowth, observeStorageLevel } from "../storage-guard.ts";

const acceptEnvironmentStatement = Effect.fn("programs-environment.acceptEnvironmentStatement")(
  function* (
    access: {
      readonly history: ChainHistoryIndex;
      readonly member: ChainMember;
      readonly projectId: ProjectId;
    },
    environment: { readonly environmentId: EnvironmentId; readonly latestMetaVersion: number },
    statement: MetaStatementInput,
  ) {
    const { device: author, value: signedBytesHashHex } = yield* withSigningDevice(
      access.member,
      (candidate) =>
        acceptMetaStatement({
          projectId: access.projectId,
          environmentId: environment.environmentId,
          target: { kind: "environment" },
          operation: "reissue",
          latestMetaVersion: environment.latestMetaVersion,
          history: access.history,
          member: candidate,
          statement,
        }),
    );
    yield* ensureDevicePermission(author, "member", environment.environmentId);
    return { author, signedBytesHashHex };
  },
);

export const renameEnvironmentProgram = Effect.fn("programs-environment.renameEnvironmentProgram")(
  function* (
    actor: DataActor,
    environmentId: EnvironmentId,
    statement: MetaStatementInput,
    manifest: EnvManifestInput,
    cache: StateCache,
  ) {
    const access = yield* requireEnvironmentAccess(actor.userId, "member", environmentId, cache);
    const environment = yield* requireActiveEnvironment(environmentId);
    yield* ensureStorageAdmitsGrowth;
    yield* ensureNfcName(statement.name);
    const store = yield* DataStore;
    if (yield* store.environmentNameTaken(statement.name, environmentId)) {
      return yield* rejectData({
        kind: "environment-conflict",
        environmentId,
        reason: "duplicate-name",
      });
    }
    const { author, signedBytesHashHex } = yield* acceptEnvironmentStatement(
      access,
      environment,
      statement,
    );
    const acceptedManifest = yield* acceptManifestForMetaOp({
      projectId: access.projectId,
      environmentId,
      history: access.history,
      member: author,
      manifest,
      digestOverride: null,
      envMeta: { metaVersion: statement.metaVersion, sigHashHex: signedBytesHashHex },
    });
    const audit = yield* AuditStore;
    const now = yield* Clock.currentTimeMillis;
    yield* Effect.sync(() => {
      store.write.insertEnvironmentMetaStatement(
        environmentId,
        statement,
        signedBytesHashHex,
        { userId: author.userId, keyFingerprintHex: author.keyFingerprintHex },
        now,
      );
      acceptedManifest.writeSync(now);
      audit.appendSync(
        dataEvent(actor, now, {
          event: "env.renamed",
          environmentId,
          payload: { name: statement.name },
          actorKeyFingerprintHex: author.keyFingerprintHex,
        }),
      );
    });
  },
);

export const listEnvironmentsProgram = Effect.fn("programs-environment.listEnvironmentsProgram")(
  function* (actor: DataActor, cache: StateCache) {
    const { state } = yield* requireMemberState(actor.userId, "reader", cache);
    const store = yield* DataStore;
    const environments = yield* store.listEnvironmentStatements;
    return {
      environments: environments.map((environment): EnvironmentSummaryValue => ({
        environmentId: environment.environmentId,
        currentEpoch: currentEpochOf(state, environment.environmentId),
        statement: environment.statement,
      })),
      schemaPolicy: yield* store.schemaPolicy,
    } satisfies EnvironmentListValue;
  },
);

const requirePullContext = Effect.fn("programs-environment.requirePullContext")(function* (
  actor: DataActor,
  environmentId: EnvironmentId,
  mode: "values" | "metadata-only",
  cache: StateCache,
) {
  const { state } =
    mode === "values"
      ? yield* requireEnvironmentAccess(actor.userId, "reader", environmentId, cache)
      : yield* requireMemberState(actor.userId, "reader", cache);
  yield* requireActiveEnvironment(environmentId);
  const store = yield* DataStore;
  const statement = yield* store.environmentStatement(environmentId);
  if (statement === null) {
    return yield* Effect.die(new Error("environment meta statement row missing"));
  }
  const manifest = yield* store.environmentManifest(environmentId);
  if (manifest === null) {
    return yield* Effect.die(new Error("environment manifest row missing"));
  }
  return { state, store, statement, manifest };
});

export const pullEnvironmentProgram = Effect.fn("programs-environment.pullEnvironmentProgram")(
  function* (actor: DataActor, environmentId: EnvironmentId, cache: StateCache) {
    const { state, store, statement, manifest } = yield* requirePullContext(
      actor,
      environmentId,
      "values",
      cache,
    );
    yield* observeStorageLevel;
    const variables = yield* store.latestVersions(environmentId);
    const deletedVariables = yield* store.deletedVariableStatements(environmentId);
    const declaredVariables = yield* store.declaredVariableStatements(environmentId);
    const deks = yield* store.listWrapsForRecipient(environmentId, actor.userId);
    const checkpointSnapshot = yield* store.checkpointSnapshot(environmentId);
    const audit = yield* AuditStore;
    const now = yield* Clock.currentTimeMillis;
    if (variables.length > 0) {
      yield* Effect.sync(() => {
        audit.appendSync(
          dataEvent(actor, now, {
            event: VAR_READ_EVENT,
            environmentId,
            payload: auditReadPayload(
              variables.map((variable) => ({
                variableId: variable.variableId,
                epoch: variable.epoch,
                version: variable.version,
              })),
            ),
          }),
        );
      });
    }
    return {
      environmentId,
      currentEpoch: currentEpochOf(state, environmentId),
      statement,
      variables,
      deletedVariables,
      ...(declaredVariables.length === 0 ? {} : { declaredVariables }),
      deks,
      schemaPolicy: yield* store.schemaPolicy,
      manifest,
      ...optionalCheckpointSnapshot(checkpointSnapshot),
    } satisfies EnvironmentPullValue;
  },
);

export const pullEnvironmentMetadataProgram = Effect.fn(
  "programs-environment.pullEnvironmentMetadataProgram",
)(function* (actor: DataActor, environmentId: EnvironmentId, cache: StateCache) {
  const { state, store, statement, manifest } = yield* requirePullContext(
    actor,
    environmentId,
    "metadata-only",
    cache,
  );
  const variables = yield* store.activeVariableStatements(environmentId);
  const deletedVariables = yield* store.deletedVariableStatements(environmentId);
  return {
    environmentId,
    currentEpoch: currentEpochOf(state, environmentId),
    statement,
    variables,
    deletedVariables,
    schemaPolicy: yield* store.schemaPolicy,
    manifest,
  } satisfies EnvironmentMetadataPullValue;
});
