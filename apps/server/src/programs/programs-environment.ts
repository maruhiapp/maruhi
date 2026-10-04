// Effect programs for environment management and bulk pull
// (AUTH_SPEC §12-4 / §12-7).
// Creation and rotation go through composite requests
// (composite-programs.ts).
//
// The check order (§12-3) and the permit-serialization premise are
// the same as the former data-programs.ts:
// requireMemberState / requireEnvironmentAccess (role → scope —
// 2026-09-15 ES K3) → environment existence → semantic checks →
// quantity policy → atomic write. The environment list and
// metadata-only pull are scope-agnostic (§12-3's table / §12-7).

import { auditReadPayload, VAR_READ_EVENT } from "@maruhi/core";
import { Effect } from "effect";

import { AuditStore } from "../audit-store.ts";
import type {
  DataActor,
  EnvironmentListValue,
  EnvironmentMetadataPullValue,
  EnvironmentPullValue,
  EnvironmentSummaryValue,
  EnvManifestInput,
  MetaStatementInput,
} from "../data/data-plane.ts";
import {
  currentEpochOf,
  dataEvent,
  ensureDevicePermission,
  optionalDistributionFields,
  rejectData,
  requireEnvironmentAccess,
  requireMemberState,
  withSigningDevice,
} from "../data/data-plane.ts";
import { DataStore } from "../data/data-store.ts";
import { acceptManifestForMetaOp } from "../data/verify-manifest.ts";
import { acceptMetaStatement, ensureNfcName } from "../data/verify-meta.ts";
import type { StateCache } from "../do/chain-store.ts";
import { requireActiveEnvironment } from "../quotas.ts";
import { ensureStorageAdmitsGrowth, observeStorageLevel } from "../storage-guard.ts";

export const renameEnvironmentProgram = (
  actor: DataActor,
  environmentId: string,
  statement: MetaStatementInput,
  manifest: EnvManifestInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { history, member, projectId } = yield* requireEnvironmentAccess(
      actor.userId,
      "member",
      environmentId,
      cache,
    );
    const environment = yield* requireActiveEnvironment(environmentId);
    // The DO storage-total guard (§12-8 — H2): renaming an
    // environment stacks a statement row + a manifest, so it is a
    // growth surface (after the existence check, before NFC /
    // uniqueness / CAS / signature). Deletion
    // (deleteEnvironmentProgram) does not call it — it must not plug
    // the release path
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
    // The check order (isomorphic to the value ruling D): caps →
    // CAS → statement signature → manifest acceptance → atomic
    // write. The signing device is resolved from the statement
    // signature (design record §8 K3-1), and the manifest is
    // verified under the same device after passing the stage-2
    // authorization (the device's effective permission — member ×
    // environment ∈ effective scope)
    const { device: author, value: signedBytesHashHex } = yield* withSigningDevice(
      member,
      (candidate) =>
        acceptMetaStatement({
          projectId,
          environmentId,
          target: { kind: "environment" },
          latestMetaVersion: environment.latestMetaVersion,
          history,
          member: candidate,
          statement,
        }),
    );
    yield* ensureDevicePermission(author, "member", environmentId);
    // Composite acceptance of the manifest (§12-4 / §12-5): an
    // environment rename bundles a manifest (manifestVersion + 1)
    // that copies in the new envMetaSigHashHex. The envMeta
    // expectation is post-rename = this very statement
    const acceptedManifest = yield* acceptManifestForMetaOp({
      projectId,
      environmentId,
      history,
      member: author,
      manifest,
      digestOverride: null,
      envMeta: { metaVersion: statement.metaVersion, sigHashHex: signedBytesHashHex },
    });
    const audit = yield* AuditStore;
    const now = Date.now();
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
        dataEvent(actor, now, "env.renamed", {
          environmentId,
          payload: { name: statement.name },
          actorKeyFingerprintHex: author.keyFingerprintHex,
        }),
      );
    });
  });

export const deleteEnvironmentProgram = (
  actor: DataActor,
  environmentId: string,
  statement: MetaStatementInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    // Admin × environment ∈ scope at acceptance time (§12-3). The
    // admin / scope check at declared-head time is covered by
    // signature verification (§12-3's dual check — the required role
    // for env × deleted, 3′)
    const { history, member, projectId } = yield* requireEnvironmentAccess(
      actor.userId,
      "admin",
      environmentId,
      cache,
    );
    const environment = yield* requireActiveEnvironment(environmentId);
    // deleted's name preserves the immediately-prior active name
    // (§4.2 — byte-exact)
    if (statement.name !== environment.name) {
      return yield* rejectData({ kind: "payload-mismatch", field: "name" });
    }
    const { device: author, value: signedBytesHashHex } = yield* withSigningDevice(
      member,
      (candidate) =>
        acceptMetaStatement({
          projectId,
          environmentId,
          target: { kind: "environment" },
          latestMetaVersion: environment.latestMetaVersion,
          history,
          member: candidate,
          statement,
        }),
    );
    // Stage 2 (design record §8 K3-1): admin × environment ∈
    // effective scope under the signing device's effective
    // permission
    yield* ensureDevicePermission(author, "admin", environmentId);
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = Date.now();
    const variables = yield* store.listActiveVariables(environmentId);
    // The write phase (a single task): atomically writes the
    // tombstone + data deletion + the deleted statement row, plus a
    // per-variable var.deleted (§12-4) closing each existence
    // interval, and env.deleted. Variables deleted by cascade carry
    // no statement of their own, so their var.deleted's FP copies
    // the environment-deletion statement's author FP (the semantics
    // "FP = evidence of a signature" — the signature that authorized
    // this deletion lives on the env side)
    yield* Effect.sync(() => {
      store.write.retireEnvironment(environmentId, now);
      store.write.insertEnvironmentMetaStatement(
        environmentId,
        statement,
        signedBytesHashHex,
        { userId: author.userId, keyFingerprintHex: author.keyFingerprintHex },
        now,
      );
      audit.appendManySync([
        ...variables.map((variable) =>
          dataEvent(actor, now, "var.deleted", {
            environmentId,
            variableId: variable.variableId,
            actorKeyFingerprintHex: author.keyFingerprintHex,
          }),
        ),
        dataEvent(actor, now, "env.deleted", {
          environmentId,
          payload: { name: environment.name },
          actorKeyFingerprintHex: author.keyFingerprintHex,
        }),
      ]);
    });
  });

export const listEnvironmentsProgram = (actor: DataActor, cache: StateCache) =>
  Effect.gen(function* () {
    const { state } = yield* requireMemberState(actor.userId, "reader", cache);
    const store = yield* DataStore;
    const environments = yield* store.listEnvironmentStatements;
    // Even a deleted environment carries create_environment on the
    // chain (the chain does not observe deletion — §6.2), so
    // currentEpochOf can be derived for every row
    return {
      environments: environments.map((environment): EnvironmentSummaryValue => ({
        environmentId: environment.environmentId,
        currentEpoch: currentEpochOf(state, environment.environmentId),
        statement: environment.statement,
      })),
      // The advisory bundle of schemaPolicy (§12-7 / §12-11 — not
      // an input to the verification rules)
      schemaPolicy: yield* store.schemaPolicy,
    } satisfies EnvironmentListValue;
  });

/**
 * The shared front half of the pull family (with-values and
 * metadata-only): reader authorization (with-values additionally
 * requires environment ∈ scope — §12-7; the metadata-only mode is
 * scope-agnostic = plaintext meta is visible to all members —
 * CRYPTO_SPEC §6.3), environment existence, and the environment's
 * own latest statement (bundled as §12-7 verification material).
 * The environment row is created atomically with its statement
 * (composite acceptance), so its absence is an invariant violation
 * = defect.
 */
const requirePullContext = (
  actor: DataActor,
  environmentId: string,
  mode: "values" | "metadata-only",
  cache: StateCache,
) =>
  Effect.gen(function* () {
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
    // The latest manifest (the material bundled per §12-7). Since
    // environment creation, every meta operation, and rotate upsert
    // it atomically, it always exists for a created environment
    const manifest = yield* store.environmentManifest(environmentId);
    return { state, store, statement, manifest };
  });

export const pullEnvironmentProgram = (
  actor: DataActor,
  environmentId: string,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { state, store, statement, manifest } = yield* requirePullContext(
      actor,
      environmentId,
      "values",
      cache,
    );
    // Observation only for the DO storage-total guard (§12-8 —
    // does not refuse): a with-values pull is a read that writes
    // var.read rows, and is the dominant growth term of a pull-heavy
    // project. If the warning band (8–9 GB) never logs here either,
    // that project enters the refusal band unwarned. After
    // membership (requirePullContext) = nothing is observed by
    // non-members
    yield* observeStorageLevel;
    const variables = yield* store.latestVersions(environmentId);
    // The deleted statements of deleted variables keep being
    // distributed (§12-5 — material for detecting denial of
    // deletion / unauthorized resurrection; the ciphertext is
    // already deleted so no value accompanies it)
    const deletedVariables = yield* store.deletedVariableStatements(environmentId);
    // declared variables distribute their statements only (§12-7 —
    // no values or versions exist; required as material for the
    // manifest's digest recomputation)
    const declaredVariables = yield* store.declaredVariableStatements(environmentId);
    const deks = yield* store.listWrapsForRecipient(environmentId, actor.userId);
    // The value snapshot at the checkpoint (§12-7): the stored row
    // of the newest checkpoint containing this environment (§16-2),
    // always bundled when present. Client rule 2 (CRYPTO_SPEC §6.3)
    // rejects a basis-present + enumeration-absent combination
    const checkpointSnapshot = yield* store.checkpointSnapshot(environmentId);
    // Audit (AUDIT_SPEC §3.3 — the aggregate form): a with-values
    // bulk pull is one row per environment, carrying the enumeration
    // of returned variables (variableId / epoch / version —
    // ascending) in the payload (the variable_id / epoch / version
    // columns are NULL). Since it records against the returned rows,
    // the enumeration and the response always agree. If zero
    // variables were returned nothing is recorded (no ciphertext was
    // distributed — the recording condition is unchanged)
    const audit = yield* AuditStore;
    const now = Date.now();
    if (variables.length > 0) {
      yield* Effect.sync(() => {
        audit.appendSync(
          dataEvent(actor, now, VAR_READ_EVENT, {
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
      // Without declared variables the key itself is omitted (the
      // optionalKey wire shape)
      ...(declaredVariables.length === 0 ? {} : { declaredVariables }),
      deks,
      schemaPolicy: yield* store.schemaPolicy,
      ...optionalDistributionFields(manifest, checkpointSnapshot),
    } satisfies EnvironmentPullValue;
  });

/**
 * The metadata-only mode (§12-7): returns neither values
 * (ciphertext) nor DEKs — only §6.3's meta-verification material.
 * Authorization is identical to bulk pull (reader). It records
 * **no audit** — var.read's recording condition is the
 * distribution of ciphertext, and what was not read is not
 * recorded as read (AUDIT_SPEC §3.3).
 */
export const pullEnvironmentMetadataProgram = (
  actor: DataActor,
  environmentId: string,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { state, store, statement, manifest } = yield* requirePullContext(
      actor,
      environmentId,
      "metadata-only",
      cache,
    );
    // declared variables' statements also ride on variables (the
    // latest shape of every non-deleted variable — §12-7; status
    // does the discrimination)
    const variables = yield* store.activeVariableStatements(environmentId);
    const deletedVariables = yield* store.deletedVariableStatements(environmentId);
    return {
      environmentId,
      currentEpoch: currentEpochOf(state, environmentId),
      statement,
      variables,
      deletedVariables,
      schemaPolicy: yield* store.schemaPolicy,
      ...(manifest === null ? {} : { manifest }),
    } satisfies EnvironmentMetadataPullValue;
  });
