import type { EnvironmentId, ProjectId, VariableId } from "@maruhi/core";
import type { ChainHistoryIndex, ChainMember, ChainState } from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import type { AuditEventInput } from "../audit-store.ts";
import { AuditStore } from "../audit-store.ts";
import type {
  DataActor,
  DataRejection,
  DataWriteOps,
  EnvManifestInput,
  MemberWithDevice,
  MetaOperation,
  MetaStatementInput,
  SchemaPolicy,
  ValueInput,
  VariableRow,
  VariableVersionValue,
} from "../data.package/index.ts";
import {
  acceptManifestForMetaOp,
  acceptMetaStatement,
  currentEpochOf,
  dataEvent,
  DataStore,
  ensureDescriptionPolicy,
  ensureDevicePermission,
  ensureMetaCas,
  ensureMetaStatementSignature,
  ensureNfcName,
  ensureSupportedLayout,
  ensureValueCas,
  ensureValueSignature,
  rejectData,
  requireEnvironmentAccess,
  statementLayoutVersion,
  withSigningDevice,
} from "../data.package/index.ts";
import type { StateCache } from "../do/chain-store.ts";
import { MAX_VERSIONS_PER_VARIABLE } from "../policy.ts";
import {
  ensureEnvironmentCapacity,
  ensureProjectCapacity,
  ensureVariableQuota,
  requireActiveEnvironment,
  requireActiveVariable,
} from "../quotas.ts";
import { ensureStorageAdmitsGrowth } from "../storage-guard.ts";

function variableIdUnavailable(
  existing: VariableRow | null,
  variableId: VariableId,
): DataRejection | null {
  if (existing === null) {
    return null;
  }
  const reason = existing.deletedAtMs === null ? "exists" : "retired";
  return { kind: "variable-conflict", variableId, reason };
}

function writeVersionWithAudit(
  write: DataWriteOps,
  appendAudit: (event: AuditEventInput) => void,
  actor: DataActor,
  writer: MemberWithDevice,
  environmentId: EnvironmentId,
  variableId: VariableId,
  value: ValueInput,
  sameValueAs: number | undefined,
  signedBytesHashHex: string,
  nowMs: number,
): void {
  write.insertVersion(
    environmentId,
    variableId,
    value,
    value.ciphertextHex.length / 2,
    signedBytesHashHex,
    { userId: writer.userId, keyFingerprintHex: writer.keyFingerprintHex },
    nowMs,
  );
  appendAudit(
    dataEvent(actor, nowMs, {
      event: "var.version_pushed",
      environmentId,
      variableId,
      epoch: value.epoch,
      version: value.version,
      actorKeyFingerprintHex: writer.keyFingerprintHex,
      ...(sameValueAs === undefined ? {} : { payload: { sameValueAs } }),
    }),
  );
}

function ensureSchemaLockedCreation(
  schemaPolicy: SchemaPolicy,
  statement: MetaStatementInput,
): Effect.Effect<void, ReturnType<typeof rejectData>> {
  if (schemaPolicy !== "locked") {
    return Effect.void;
  }
  if (statementLayoutVersion(statement) !== 3 || (statement.schema?.varType ?? "") === "") {
    return Effect.fail(rejectData({ kind: "schema-policy-rejected", reason: "schema-required" }));
  }
  return Effect.void;
}

const ensureCreationSchemaGates = Effect.fn("programs-variable.ensureCreationSchemaGates")(
  function* (statement: MetaStatementInput) {
    const store = yield* DataStore;
    yield* ensureSchemaLockedCreation(yield* store.schemaPolicy, statement);
    yield* ensureDescriptionPolicy(statement);
  },
);

const ensureVariableCreatable = Effect.fn("programs-variable.ensureVariableCreatable")(function* (
  environmentId: EnvironmentId,
  statement: MetaStatementInput,
  variableId: VariableId,
) {
  const store = yield* DataStore;
  const existing = yield* store.findVariable(environmentId, variableId);
  const unavailable = variableIdUnavailable(existing, variableId);
  if (unavailable !== null) {
    return yield* rejectData(unavailable);
  }
  yield* ensureVariableQuota(environmentId);
  yield* ensureNfcName(statement.name);
  if (yield* store.variableNameTaken(environmentId, statement.name, null)) {
    return yield* rejectData({
      kind: "variable-conflict",
      variableId,
      reason: "duplicate-name",
    });
  }
});

const acceptCreationValue = Effect.fn("programs-variable.acceptCreationValue")(function* (context: {
  readonly state: ChainState;
  readonly history: ChainHistoryIndex;
  readonly member: MemberWithDevice;
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly variableId: VariableId;
  readonly value: ValueInput;
}) {
  yield* ensureValueCas(context.state, context.environmentId, 0, context.value);
  const signedBytesHashHex = yield* ensureValueSignature({
    projectId: context.projectId,
    environmentId: context.environmentId,
    variableId: context.variableId,
    history: context.history,
    member: context.member,
    value: context.value,
  });
  return { value: context.value, signedBytesHashHex };
});

const requireVariableWriteContext = Effect.fn("programs-variable.requireVariableWriteContext")(
  function* (
    actor: DataActor,
    environmentId: EnvironmentId,
    variableId: VariableId,
    cache: StateCache,
  ) {
    const context = yield* requireEnvironmentAccess(actor.userId, "member", environmentId, cache);
    yield* requireActiveEnvironment(environmentId);
    const variable = yield* requireActiveVariable(environmentId, variableId);
    return { ...context, variable };
  },
);

const requireVariableMetaOpContext = Effect.fn("programs-variable.requireVariableMetaOpContext")(
  function* (
    actor: DataActor,
    environmentId: EnvironmentId,
    variableId: VariableId,
    statement: MetaStatementInput,
    cache: StateCache,
  ) {
    const context = yield* requireVariableWriteContext(actor, environmentId, variableId, cache);
    yield* ensureSupportedLayout(statement);
    return context;
  },
);

const acceptVariableMetaOp = Effect.fn("programs-variable.acceptVariableMetaOp")(function* (input: {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly variableId: VariableId;
  readonly operation: MetaOperation;
  readonly latestMetaVersion: number;
  readonly history: ChainHistoryIndex;
  readonly member: ChainMember;
  readonly statement: MetaStatementInput;
  readonly manifest: EnvManifestInput;
  readonly digestStatus: "active" | "deleted" | "declared";
}) {
  const { projectId, environmentId, variableId, history, statement } = input;
  const { device: author, value: signedBytesHashHex } = yield* withSigningDevice(
    input.member,
    (candidate) =>
      acceptMetaStatement({
        projectId,
        environmentId,
        target: { kind: "variable", variableId },
        operation: input.operation,
        latestMetaVersion: input.latestMetaVersion,
        history,
        member: candidate,
        statement,
      }),
  );
  yield* ensureDevicePermission(author, "member", environmentId);
  const acceptedManifest = yield* acceptManifestForMetaOp({
    projectId,
    environmentId,
    history,
    member: author,
    manifest: input.manifest,
    digestOverride: {
      variableId,
      status: input.digestStatus,
      metaVersion: statement.metaVersion,
      signedBytesHashHex,
    },
  });
  return { author, signedBytesHashHex, acceptedManifest };
});

export const createVariableProgram = Effect.fn("programs-variable.createVariableProgram")(
  function* (
    actor: DataActor,
    environmentId: EnvironmentId,
    input: {
      readonly variableId: VariableId;
      readonly statement: MetaStatementInput;
      readonly value?: ValueInput;
      readonly manifest: EnvManifestInput;
    },
    cache: StateCache,
  ) {
    const { state, history, member, projectId } = yield* requireEnvironmentAccess(
      actor.userId,
      "member",
      environmentId,
      cache,
    );
    yield* requireActiveEnvironment(environmentId);
    yield* ensureSupportedLayout(input.statement);
    yield* ensureStorageAdmitsGrowth;
    yield* ensureVariableCreatable(environmentId, input.statement, input.variableId);
    yield* ensureCreationSchemaGates(input.statement);
    yield* ensureMetaCas(0, input.statement);
    const { device: author, value: metaSignedBytesHashHex } = yield* withSigningDevice(
      member,
      (candidate) =>
        ensureMetaStatementSignature({
          projectId,
          environmentId,
          target: { kind: "variable", variableId: input.variableId },
          history,
          member: candidate,
          statement: input.statement,
        }),
    );
    yield* ensureDevicePermission(author, "member", environmentId);
    const acceptedValue =
      input.value === undefined
        ? null
        : yield* acceptCreationValue({
            state,
            history,
            member: author,
            projectId,
            environmentId,
            variableId: input.variableId,
            value: input.value,
          });
    const acceptedManifest = yield* acceptManifestForMetaOp({
      projectId,
      environmentId,
      history,
      member: author,
      manifest: input.manifest,
      digestOverride: {
        variableId: input.variableId,
        status: input.statement.status,
        metaVersion: input.statement.metaVersion,
        signedBytesHashHex: metaSignedBytesHashHex,
      },
    });
    if (acceptedValue !== null) {
      const addedBytes = acceptedValue.value.ciphertextHex.length / 2;
      yield* ensureEnvironmentCapacity(environmentId, input.variableId, addedBytes);
      yield* ensureProjectCapacity(addedBytes);
    }
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = yield* Clock.currentTimeMillis;
    yield* Effect.sync(() => {
      store.write.insertVariable(environmentId, input.variableId, input.statement.name, now);
      acceptedManifest.writeSync(now);
      store.write.insertVariableMetaStatement(
        environmentId,
        input.variableId,
        input.statement,
        metaSignedBytesHashHex,
        { userId: author.userId, keyFingerprintHex: author.keyFingerprintHex },
        now,
      );
      audit.appendSync(
        dataEvent(actor, now, {
          event: "var.created",
          environmentId,
          variableId: input.variableId,
          payload: { name: input.statement.name },
          actorKeyFingerprintHex: author.keyFingerprintHex,
        }),
      );
      if (acceptedValue !== null) {
        writeVersionWithAudit(
          store.write,
          audit.appendSync,
          actor,
          author,
          environmentId,
          input.variableId,
          acceptedValue.value,
          undefined,
          acceptedValue.signedBytesHashHex,
          now,
        );
      }
    });
    return {
      variableId: input.variableId,
      version: acceptedValue?.value.version ?? 0,
      epoch: acceptedValue?.value.epoch ?? currentEpochOf(state, environmentId),
    } satisfies VariableVersionValue;
  },
);

export const pushVersionProgram = Effect.fn("programs-variable.pushVersionProgram")(function* (
  actor: DataActor,
  environmentId: EnvironmentId,
  variableId: VariableId,
  value: ValueInput,
  sameValueAs: number | undefined,
  cache: StateCache,
) {
  const { state, history, member, projectId, variable } = yield* requireVariableWriteContext(
    actor,
    environmentId,
    variableId,
    cache,
  );
  if (variable.latestStatus === "declared") {
    return yield* rejectData({ kind: "activation-required", variableId });
  }
  yield* ensureStorageAdmitsGrowth;
  yield* ensureValueCas(state, environmentId, variable.latestVersion, value);
  if (sameValueAs !== undefined && sameValueAs >= value.version) {
    return yield* rejectData({ kind: "payload-mismatch", field: "sameValueAs" });
  }
  const { device: writer, value: signedBytesHashHex } = yield* withSigningDevice(
    member,
    (candidate) =>
      ensureValueSignature({
        projectId,
        environmentId,
        variableId,
        history,
        member: candidate,
        value,
      }),
  );
  yield* ensureDevicePermission(writer, "member", environmentId);
  if (value.version > MAX_VERSIONS_PER_VARIABLE) {
    return yield* rejectData({
      kind: "limit-exceeded",
      resource: "versions",
      limit: MAX_VERSIONS_PER_VARIABLE,
    });
  }
  yield* ensureEnvironmentCapacity(environmentId, variableId, value.ciphertextHex.length / 2);
  yield* ensureProjectCapacity(value.ciphertextHex.length / 2);
  const store = yield* DataStore;
  const audit = yield* AuditStore;
  const now = yield* Clock.currentTimeMillis;
  yield* Effect.sync(() => {
    writeVersionWithAudit(
      store.write,
      audit.appendSync,
      actor,
      writer,
      environmentId,
      variableId,
      value,
      sameValueAs,
      signedBytesHashHex,
      now,
    );
  });
  return {
    variableId,
    version: value.version,
    epoch: value.epoch,
  } satisfies VariableVersionValue;
});

export const activateVariableProgram = Effect.fn("programs-variable.activateVariableProgram")(
  function* (
    actor: DataActor,
    environmentId: EnvironmentId,
    variableId: VariableId,
    input: {
      readonly value: ValueInput;
      readonly statement: MetaStatementInput;
      readonly manifest: EnvManifestInput;
    },
    cache: StateCache,
  ) {
    const { state, history, member, projectId, variable } = yield* requireVariableMetaOpContext(
      actor,
      environmentId,
      variableId,
      input.statement,
      cache,
    );
    yield* ensureStorageAdmitsGrowth;
    yield* ensureValueCas(state, environmentId, variable.latestVersion, input.value);
    const { device: author, value: metaSignedBytesHashHex } = yield* withSigningDevice(
      member,
      (candidate) =>
        acceptMetaStatement({
          projectId,
          environmentId,
          target: { kind: "variable", variableId },
          operation: "activate",
          latestMetaVersion: variable.latestMetaVersion,
          history,
          member: candidate,
          statement: input.statement,
        }),
    );
    yield* ensureDevicePermission(author, "member", environmentId);
    const signedBytesHashHex = yield* ensureValueSignature({
      projectId,
      environmentId,
      variableId,
      history,
      member: author,
      value: input.value,
    });
    const acceptedManifest = yield* acceptManifestForMetaOp({
      projectId,
      environmentId,
      history,
      member: author,
      manifest: input.manifest,
      digestOverride: {
        variableId,
        status: "active",
        metaVersion: input.statement.metaVersion,
        signedBytesHashHex: metaSignedBytesHashHex,
      },
    });
    const addedBytes = input.value.ciphertextHex.length / 2;
    yield* ensureEnvironmentCapacity(environmentId, variableId, addedBytes);
    yield* ensureProjectCapacity(addedBytes);
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = yield* Clock.currentTimeMillis;
    yield* Effect.sync(() => {
      store.write.insertVariableMetaStatement(
        environmentId,
        variableId,
        input.statement,
        metaSignedBytesHashHex,
        { userId: author.userId, keyFingerprintHex: author.keyFingerprintHex },
        now,
      );
      acceptedManifest.writeSync(now);
      writeVersionWithAudit(
        store.write,
        audit.appendSync,
        actor,
        author,
        environmentId,
        variableId,
        input.value,
        undefined,
        signedBytesHashHex,
        now,
      );
    });
    return {
      variableId,
      version: input.value.version,
      epoch: input.value.epoch,
    } satisfies VariableVersionValue;
  },
);

const variableMetaProgram = <A, E, R>(
  name: string,
  body: (
    context: Effect.Success<ReturnType<typeof requireVariableMetaOpContext>>,
    input: {
      readonly actor: DataActor;
      readonly environmentId: EnvironmentId;
      readonly variableId: VariableId;
      readonly statement: MetaStatementInput;
      readonly manifest: EnvManifestInput;
      readonly cache: StateCache;
    },
  ) => Effect.Effect<A, E, R>,
) =>
  Effect.fn(name)(function* (
    actor: DataActor,
    environmentId: EnvironmentId,
    variableId: VariableId,
    statement: MetaStatementInput,
    manifest: EnvManifestInput,
    cache: StateCache,
  ) {
    const context = yield* requireVariableMetaOpContext(
      actor,
      environmentId,
      variableId,
      statement,
      cache,
    );
    return yield* body(context, {
      actor,
      environmentId,
      variableId,
      statement,
      manifest,
      cache,
    });
  });

export const renameVariableProgram = variableMetaProgram(
  "programs-variable.renameVariableProgram",
  (
    { history, member, projectId, variable },
    { actor, environmentId, variableId, statement, manifest },
  ) =>
    Effect.gen(function* () {
      yield* ensureStorageAdmitsGrowth;
      yield* ensureNfcName(statement.name);
      const store = yield* DataStore;
      if (yield* store.variableNameTaken(environmentId, statement.name, variableId)) {
        return yield* rejectData({
          kind: "variable-conflict",
          variableId,
          reason: "duplicate-name",
        });
      }
      const { author, signedBytesHashHex, acceptedManifest } = yield* acceptVariableMetaOp({
        projectId,
        environmentId,
        variableId,
        operation: "reissue",
        latestMetaVersion: variable.latestMetaVersion,
        history,
        member,
        statement,
        manifest,
        digestStatus: statement.status,
      });
      const audit = yield* AuditStore;
      const now = yield* Clock.currentTimeMillis;
      const event = statement.name === variable.name ? "var.schema_reissued" : "var.renamed";
      yield* Effect.sync(() => {
        store.write.insertVariableMetaStatement(
          environmentId,
          variableId,
          statement,
          signedBytesHashHex,
          { userId: author.userId, keyFingerprintHex: author.keyFingerprintHex },
          now,
        );
        acceptedManifest.writeSync(now);
        audit.appendSync(
          dataEvent(actor, now, {
            event,
            environmentId,
            variableId,
            payload: { name: statement.name },
            actorKeyFingerprintHex: author.keyFingerprintHex,
          }),
        );
      });
    }),
);

export const deleteVariableProgram = variableMetaProgram(
  "programs-variable.deleteVariableProgram",
  (
    { history, member, projectId, variable },
    { actor, environmentId, variableId, statement, manifest },
  ) =>
    Effect.gen(function* () {
      const { author, signedBytesHashHex, acceptedManifest } = yield* acceptVariableMetaOp({
        projectId,
        environmentId,
        variableId,
        operation: "delete",
        latestMetaVersion: variable.latestMetaVersion,
        history,
        member,
        statement,
        manifest,
        digestStatus: "deleted",
      });
      const store = yield* DataStore;
      const audit = yield* AuditStore;
      const now = yield* Clock.currentTimeMillis;
      yield* Effect.sync(() => {
        store.write.retireVariable(environmentId, variableId, now);
        store.write.insertVariableMetaStatement(
          environmentId,
          variableId,
          statement,
          signedBytesHashHex,
          { userId: author.userId, keyFingerprintHex: author.keyFingerprintHex },
          now,
        );
        acceptedManifest.writeSync(now);
        audit.appendSync(
          dataEvent(actor, now, {
            event: "var.deleted",
            environmentId,
            variableId,
            actorKeyFingerprintHex: author.keyFingerprintHex,
          }),
        );
      });
    }),
);
