// Effect programs for variables and versioning (AUTH_SPEC §12-5).
//
// The check order (§12-3) and permit-serialization premise are as in the old
// data-programs.ts: requireEnvironmentAccess (role → scope — §12-3;
// 2026-09-15 ES K3) → environment/variable existence → CAS → signature
// verification → quantity policy → atomic write + audit (AUDIT_SPEC §3.3).

import type { ChainHistoryIndex, ChainMember, ChainState } from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import type { AuditEventInput } from "../audit-store.ts";
import { AuditStore } from "../audit-store.ts";
import type {
  DataActor,
  DataRejection,
  EnvManifestInput,
  MemberWithDevice,
  MetaStatementInput,
  SchemaPolicy,
  ValueInput,
  VariableVersionValue,
} from "../data/data-plane.ts";
import {
  currentEpochOf,
  dataEvent,
  ensureDevicePermission,
  rejectData,
  requireEnvironmentAccess,
  withSigningDevice,
} from "../data/data-plane.ts";
import type { DataWriteOps, VariableRow } from "../data/data-store.ts";
import { DataStore } from "../data/data-store.ts";
import { acceptManifestForMetaOp } from "../data/verify-manifest.ts";
import type { MetaOperation } from "../data/verify-meta.ts";
import {
  acceptMetaStatement,
  ensureDescriptionPolicy,
  ensureMetaCas,
  ensureMetaStatementSignature,
  ensureNfcName,
  ensureSupportedLayout,
  statementLayoutVersion,
} from "../data/verify-meta.ts";
import { ensureValueCas, ensureValueSignature } from "../data/verify-value.ts";
import type { StateCache } from "../do/chain-store.ts";
import { MAX_VERSIONS_PER_VARIABLE } from "../policy.ts";
import {
  ensureProjectCapacity,
  ensureVariableQuota,
  requireActiveEnvironment,
  requireActiveVariable,
} from "../quotas.ts";
import { ensureStorageAdmitsGrowth } from "../storage-guard.ts";

function variableIdUnavailable(
  existing: VariableRow | null,
  variableId: string,
): DataRejection | null {
  if (existing === null) {
    return null;
  }
  const reason = existing.deletedAtMs === null ? "exists" : "retired";
  return { kind: "variable-conflict", variableId, reason };
}

/**
 * Write a version row + record var.version_pushed (the shared tail of create
 * and push). A synchronous function: used inside the caller's write phase (a
 * single Effect.sync). writer is the chain-derived member at acceptance time
 * (the owner of the key that verified the value signature — CRYPTO_SPEC
 * §4.1). The audit records only the chain-derived writer FP (AUDIT_SPEC §3.3
 * — signature, signed bytes, hash, nonce, and ciphertext never go on the
 * audit).
 *
 * `sameValueAs` is the writer-declared value lineage (AUTH_SPEC §12-5 —
 * 2026-09-27 VH: "this version's plaintext equals version k's"; the caller
 * has already range-checked it). Copied to the payload only when declared
 * (§3.3). It plays no other part in the acceptance decision — the only
 * reader is the lineage derivation of rotation-needed detection (§4.1-5).
 */
function writeVersionWithAudit(
  write: DataWriteOps,
  appendAudit: (event: AuditEventInput) => void,
  actor: DataActor,
  writer: MemberWithDevice,
  environmentId: string,
  variableId: string,
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

/**
 * schema-locked (§12-11 / §12-5): in a locked project, variable creation
 * (metaVersion 1 — both declared and value-bundled) requires layoutVersion 3
 * and a non-empty varType (write-time blocking of the silent creation of
 * shadow variables by typos). It is a **one-time check at creation**, not a
 * continuing invariant — a later schema reissue may set varType back to ""
 * even under locked, and it does not reach back to a declared variable's
 * activation.
 */
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

/**
 * Run the creation-time (metaVersion 1) schema-family acceptance checks
 * (§12-11 / §12-8) under the policy at acceptance time: the schema-locked
 * creation check → the description acceptance policy. The layoutVersion support-range check
 * is done by the caller (createVariableProgram) before every
 * statement-dependent check.
 */
const ensureCreationSchemaGates = Effect.fn("programs-variable.ensureCreationSchemaGates")(
  function* (statement: MetaStatementInput) {
    const store = yield* DataStore;
    yield* ensureSchemaLockedCreation(yield* store.schemaPolicy, statement);
    yield* ensureDescriptionPolicy(statement);
  },
);

/**
 * The pre-checks of creation (§12-1 / §12-8): ID availability (no tombstone
 * reuse) → quantity policy → NFC → name uniqueness.
 */
const ensureVariableCreatable = Effect.fn("programs-variable.ensureVariableCreatable")(function* (
  environmentId: string,
  statement: MetaStatementInput,
  variableId: string,
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

/** The verification pipeline for a bundled version-1 value (only for creation with a value): value CAS → value signature → capacity. */
const acceptCreationValue = Effect.fn("programs-variable.acceptCreationValue")(function* (context: {
  readonly state: ChainState;
  readonly history: ChainHistoryIndex;
  readonly member: MemberWithDevice;
  readonly projectId: string;
  readonly environmentId: string;
  readonly variableId: string;
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

/**
 * The shared prefix of writes to an existing variable (push / activation /
 * rename-or-schema-reissue / delete) (§12-3): requireEnvironmentAccess (role
 * → scope) → environment existence → variable existence. Bundles the same
 * three stages so the four paths do not repeat them.
 */
const requireVariableWriteContext = Effect.fn("programs-variable.requireVariableWriteContext")(
  function* (actor: DataActor, environmentId: string, variableId: string, cache: StateCache) {
    const context = yield* requireEnvironmentAccess(actor.userId, "member", environmentId, cache);
    yield* requireActiveEnvironment(environmentId);
    const variable = yield* requireActiveVariable(environmentId, variableId);
    return { ...context, variable };
  },
);

/**
 * The shared prefix of the meta ops on an existing variable (activation,
 * rename / schema reissue, delete): the write context, then the
 * support-range check, which runs before every statement-dependent check
 * (ruling CR — for an unsupported layout, a v3 client always gets the honest
 * update-required rather than a misleading error from a later check).
 */
const requireVariableMetaOpContext = Effect.fn("programs-variable.requireVariableMetaOpContext")(
  function* (
    actor: DataActor,
    environmentId: string,
    variableId: string,
    statement: MetaStatementInput,
    cache: StateCache,
  ) {
    const context = yield* requireVariableWriteContext(actor, environmentId, variableId, cache);
    yield* ensureSupportedLayout(statement);
    return context;
  },
);

/**
 * The shared acceptance core of rename / schema reissue and delete (§12-5):
 * the meta acceptance pipeline under the signing device (verify-meta.ts's
 * acceptMetaStatement) → the author's member permission → the composite
 * acceptance of the manifest, with the accepted statement standing in for
 * the variable's digest entry.
 */
const acceptVariableMetaOp = Effect.fn("programs-variable.acceptVariableMetaOp")(function* (input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly variableId: string;
  /** Selects the pipeline's predecessor-match checks (run after the metaVersion CAS — §12-5). */
  readonly operation: MetaOperation;
  readonly latestMetaVersion: number;
  readonly history: ChainHistoryIndex;
  readonly member: ChainMember;
  readonly statement: MetaStatementInput;
  readonly manifest: EnvManifestInput;
  /** The status the manifest digest takes for this variable after the operation. */
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

/**
 * Variable creation (§12-5): active (with the bundled version-1 value) or
 * declared (no value — the sole exception to "a variable without a value does
 * not exist"; layout v3 only). The wire Schema fixes the combination of
 * status and value presence (creating a deleted variable is structurally
 * impossible).
 */
export const createVariableProgram = Effect.fn("programs-variable.createVariableProgram")(
  function* (
    actor: DataActor,
    environmentId: string,
    input: {
      readonly variableId: string;
      readonly statement: MetaStatementInput;
      /** The version-1 value of an active creation. undefined for a declared creation (no value). */
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
    // The support-range check runs before every statement-dependent check
    // (including the pre-checks — NFC, duplicate name — inside
    // ensureVariableCreatable; same discipline as rename / delete /
    // activation — do not return duplicate-name to a v3 client whose name
    // collides)
    yield* ensureSupportedLayout(input.statement);
    // The DO storage total guard (§12-8): after membership, role, existence,
    // and the layout support range; before the semantic checks — CAS,
    // signature, quantity policy (resource protection outranks semantics;
    // storage-guard.ts)
    yield* ensureStorageAdmitsGrowth;
    yield* ensureVariableCreatable(environmentId, input.statement, input.variableId);
    // The schema policy (§12-11 — read the policy at acceptance time under
    // the permit): locked requires v3 + non-empty varType on creation. The
    // description bound and character class are §12-8
    yield* ensureCreationSchemaGates(input.statement);
    // Creation = the bundled version-1 value + the metaVersion-1 statement
    // (§12-5). The wire Schema already fixes metaVersion 1, active/declared,
    // and empty prev, but keep the CAS as a defensive line (equivalent to
    // latest = 0)
    yield* ensureMetaCas(0, input.statement);
    // Both the bundled version-1 value and the bundled statement undergo the
    // same signature verification as the normal path (§12-5 — bypassing
    // verification via the creation path is impossible for value and meta
    // alike; a declared creation has no value, so only the value signature is
    // out of scope). Check order:
    // CAS → meta signature → value signature → quantity policy (insertion
    // into ruling D). The signing device is resolved from the meta signature
    // (design record §8 K3-1), and after the second-stage authorization, the
    // value signature and the manifest are verified with the same device
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
    // Composite acceptance of the environment manifest (§12-5): recompute the
    // digest from the post-creation meta state (the set including the new
    // variable's statement) and cross-check it against the declaration. The
    // manifestVersion CAS is judged in the same transaction (same program,
    // same permit) as the metaVersion CAS
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
      yield* ensureProjectCapacity(acceptedValue.value.ciphertextHex.length / 2);
    }
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = yield* Clock.currentTimeMillis;
    // Write phase (single task): the variable row + the statement row + (for
    // an active creation) version 1 + the manifest (upsert of the latest one)
    // + the audit row, written atomically (never leave "an active variable
    // occupying only an ID with latest_version = 0" — declared is the only
    // legitimate version-0 state)
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
      // var.created's FP = the author FP (a declared creation — no value
      // signature — records only the statement signature's author key FP.
      // AUDIT_SPEC §3.3)
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
        // Creation is by definition not a re-encryption (it carries no marker
        // declaration surface either — §12-5)
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
      // A declared creation stays at stored version 0 (§12-5)
      version: acceptedValue?.value.version ?? 0,
      epoch: acceptedValue?.value.epoch ?? currentEpochOf(state, environmentId),
    } satisfies VariableVersionValue;
  },
);

export const pushVersionProgram = Effect.fn("programs-variable.pushVersionProgram")(function* (
  actor: DataActor,
  environmentId: string,
  variableId: string,
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
  // A normal push to a declared variable is not accepted (§12-5): the
  // first value is only the activation composite (value version 1 + a
  // status active statement + manifest)
  if (variable.latestStatus === "declared") {
    return yield* rejectData({ kind: "activation-required", variableId });
  }
  // The DO storage total guard (§12-8): after the existence and kind
  // checks, before CAS / signature. A re-encryption / rollback push is also covered
  // (under rejection, no new value can be written — the consistent
  // consequence; (d) of the same section)
  yield* ensureStorageAdmitsGrowth;
  yield* ensureValueCas(state, environmentId, variable.latestVersion, value);
  // The lineage declaration names an earlier version of this variable
  // (§12-5 — 2026-09-27 VH). Versions are contiguous from 1, so after the
  // CAS "< version" is exactly "an existing earlier version". The claim
  // itself is unverifiable (E2EE) and affects nothing else
  if (sameValueAs !== undefined && sameValueAs >= value.version) {
    return yield* rejectData({ kind: "payload-mismatch", field: "sameValueAs" });
  }
  // Check order (ruling D): epoch / version CAS → value signature
  // (signature → declared head → state at head → predecessor) → quantity
  // policy → atomic write. On non-acceptance, neither variable / version /
  // latest / audit changes. The writer's device is resolved from the value
  // signature (design record §8 K3-1) — the second-stage authorization (the
  // device's effective permission: member × environment ∈ effective scope)
  // runs right after the signature
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

/**
 * activation (declared → active — §12-5): the first value push to a declared
 * variable is accepted as the composite of "EncryptedPayload (version 1) + a
 * status active statement (metaVersion + 1, v3) + EnvironmentManifest". The
 * value signature, statement signature, and manifest checks are a composition
 * of the existing rules. Because the predecessor is necessarily v3 (declared
 * is v3-only), it is accepted as a continuation statement regardless of the
 * policy (the §12-11 reversibility — the schema-locked varType check does not
 * reach back either: activation is not a creation).
 */
export const activateVariableProgram = Effect.fn("programs-variable.activateVariableProgram")(
  function* (
    actor: DataActor,
    environmentId: string,
    variableId: string,
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
    // The DO storage total guard (§12-8): after existence and the support
    // range, before CAS and signature
    yield* ensureStorageAdmitsGrowth;
    // Since declared is the only legitimate latestVersion-0 state, the CAS
    // forces value version 1 (the "value version 1" of §12-5)
    yield* ensureValueCas(state, environmentId, variable.latestVersion, input.value);
    // The meta acceptance pipeline (§12-5): CAS → anchor → the activation's
    // predecessor-match checks (the target is a declared variable — this is
    // not a general-purpose composite of "value push + meta reissue" — and
    // the declared name is kept: activation does not double as a rename, so
    // the NFC and uniqueness checks at declaration stay valid) → description
    // acceptance check → signature verification (the declared → active
    // transition and layout monotonicity are crypto's predecessor check).
    // The predecessor-match checks run after the CAS, so an activation
    // signed before a concurrent rename is a 409 (§12-5's check order)
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
    // Composite acceptance of the manifest (§12-5): activation changes the
    // meta state, so it involves a manifest reissue (the invariant "a value
    // push does not touch the manifest" covers only a normal push —
    // CRYPTO_SPEC §4.3)
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
    yield* ensureProjectCapacity(input.value.ciphertextHex.length / 2);
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = yield* Clock.currentTimeMillis;
    // Write phase (single task): the statement row + version 1 + the manifest
    // + var.version_pushed (version 1 — AUDIT_SPEC §3.3. The start of the
    // existence interval is already held by the var.created of the declared
    // creation)
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
      // activation is the first value and is by definition not a
      // re-encryption
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

export const renameVariableProgram = Effect.fn("programs-variable.renameVariableProgram")(
  function* (
    actor: DataActor,
    environmentId: string,
    variableId: string,
    statement: MetaStatementInput,
    manifest: EnvManifestInput,
    cache: StateCache,
  ) {
    const { history, member, projectId, variable } = yield* requireVariableMetaOpContext(
      actor,
      environmentId,
      variableId,
      statement,
      cache,
    );
    // The DO storage total guard (§12-8): rename / schema reissue is a growth
    // surface that stacks a statement row + a manifest (applies independently
    // of the metaVersion bound). It sits after the existence and layout checks
    // and before CAS / signature verification (keeps the same prefix shape as
    // the delete path — delete does not call the guard)
    yield* ensureStorageAdmitsGrowth;
    yield* ensureNfcName(statement.name);
    const store = yield* DataStore;
    if (yield* store.variableNameTaken(environmentId, statement.name, variableId)) {
      return yield* rejectData({ kind: "variable-conflict", variableId, reason: "duplicate-name" });
    }
    // rename / schema reissue never changes status (§12-5): declared →
    // active is only the activation composite (with value), and active →
    // declared is forbidden. The wire can carry both statuses, so the
    // pipeline pins the match against the predecessor after the CAS. The
    // manifest is recomputed and cross-checked on the set after the rename
    // is applied
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
    // Audit-event branching (AUDIT_SPEC §3.3): only a reissue that actually
    // changed the name is var.renamed; a name-preserving reissue (setting or
    // changing schema fields — the §12-5 schema reissue) is
    // var.schema_reissued. The wire has the same operation shape for both, so
    // branch on a byte comparison against the previous statement's name at
    // acceptance time (do not record an operation that did not rename as
    // "renamed"). Changing the name and the schema fields at once is a single
    // var.renamed row (the rename is the main event — the one-row-per-
    // operation recording discipline)
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
  },
);

export const deleteVariableProgram = Effect.fn("programs-variable.deleteVariableProgram")(
  function* (
    actor: DataActor,
    environmentId: string,
    variableId: string,
    statement: MetaStatementInput,
    manifest: EnvManifestInput,
    cache: StateCache,
  ) {
    const { history, member, projectId, variable } = yield* requireVariableMetaOpContext(
      actor,
      environmentId,
      variableId,
      statement,
      cache,
    );
    // A deleted statement preserves the previous name, schema fields and
    // layout (§4.2 — byte-exact): the pipeline checks this after the
    // metaVersion CAS (§12-5's check order). The manifest is recomputed and
    // cross-checked on the set including the tombstone (a digest mismatch
    // from hiding a tombstone is caught here — §4.3 (3))
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
    // Write phase: tombstone + delete all versions + the deleted statement
    // row (keeps being stored and distributed — §12-5) + the manifest +
    // var.deleted (author FP — AUDIT_SPEC §3.3)
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
  },
);
