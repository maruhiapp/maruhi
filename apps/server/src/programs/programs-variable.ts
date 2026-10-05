// Effect programs for variables and versioning (AUTH_SPEC §12-5).
//
// The check order (§12-3) and permit-serialization premise are as in the old
// data-programs.ts: requireEnvironmentAccess (role → scope — §12-3;
// 2026-09-15 ES K3) → environment/variable existence → CAS → signature
// verification → quantity policy → atomic write + audit (AUDIT_SPEC §3.3).

import type { ChainHistoryIndex, ChainState } from "@maruhi/crypto";
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
import {
  acceptMetaStatement,
  ensureDescriptionPolicy,
  ensureMetaCas,
  ensureMetaStatementSignature,
  ensureNfcName,
  ensureSchemaPolicyAllowsLayout,
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
    dataEvent(actor, nowMs, "var.version_pushed", {
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
 * (metaVersion 1 — both declared and value-bundled) requires layoutVersion 2
 * or above and a non-empty varType (write-time blocking of the silent creation of
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
  if (statementLayoutVersion(statement) < 2 || (statement.schema?.varType ?? "") === "") {
    return Effect.fail(rejectData({ kind: "schema-policy-rejected", reason: "schema-required" }));
  }
  return Effect.void;
}

/**
 * Run the creation-time (metaVersion 1) schema-family acceptance checks
 * (§12-11 / §12-8) under the policy at acceptance time: the disabled
 * enablement gate (reject new v2 adoption) → the schema-locked creation check
 * → the description acceptance policy. The layoutVersion support-range check
 * is done by the caller (createVariableProgram) before every
 * statement-dependent check.
 */
const ensureCreationSchemaGates = (statement: MetaStatementInput) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const schemaPolicy = yield* store.schemaPolicy;
    yield* ensureSchemaPolicyAllowsLayout({
      schemaPolicy,
      statement,
      predecessorLayoutVersion: 1,
    });
    yield* ensureSchemaLockedCreation(schemaPolicy, statement);
    yield* ensureDescriptionPolicy(statement);
  });

/**
 * The pre-checks of creation (§12-1 / §12-8): ID availability (no tombstone
 * reuse) → quantity policy → NFC → name uniqueness.
 */
const ensureVariableCreatable = (
  environmentId: string,
  statement: MetaStatementInput,
  variableId: string,
) =>
  Effect.gen(function* () {
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
const acceptCreationValue = (context: {
  readonly state: ChainState;
  readonly history: ChainHistoryIndex;
  readonly member: MemberWithDevice;
  readonly projectId: string;
  readonly environmentId: string;
  readonly variableId: string;
  readonly value: ValueInput;
}) =>
  Effect.gen(function* () {
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
const requireVariableWriteContext = (
  actor: DataActor,
  environmentId: string,
  variableId: string,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const context = yield* requireEnvironmentAccess(actor.userId, "member", environmentId, cache);
    yield* requireActiveEnvironment(environmentId);
    const variable = yield* requireActiveVariable(environmentId, variableId);
    return { ...context, variable };
  });

/**
 * Variable creation (§12-5): active (with the bundled version-1 value) or
 * declared (no value — the sole exception to "a variable without a value does
 * not exist"; layout v2 only). The wire Schema fixes the combination of
 * status and value presence (creating a deleted variable is structurally
 * impossible).
 */
export const createVariableProgram = (
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
) =>
  Effect.gen(function* () {
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
    // the permit): disabled rejects new v2 adoption (v2 creation at
    // metaVersion 1); locked requires v2 + non-empty varType on creation. The
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
        dataEvent(actor, now, "var.created", {
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
  });

export const pushVersionProgram = (
  actor: DataActor,
  environmentId: string,
  variableId: string,
  value: ValueInput,
  sameValueAs: number | undefined,
  cache: StateCache,
) =>
  Effect.gen(function* () {
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
 * status active statement (metaVersion + 1, v2) + EnvironmentManifest". The
 * value signature, statement signature, and manifest checks are a composition
 * of the existing rules. Because the predecessor is necessarily v2 (declared
 * is v2-only), it is accepted as a continuation statement regardless of the
 * policy (the §12-11 reversibility — the schema-locked varType check does not
 * reach back either: activation is not a creation).
 */
export const activateVariableProgram = (
  actor: DataActor,
  environmentId: string,
  variableId: string,
  input: {
    readonly value: ValueInput;
    readonly statement: MetaStatementInput;
    readonly manifest: EnvManifestInput;
  },
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { state, history, member, projectId, variable } = yield* requireVariableWriteContext(
      actor,
      environmentId,
      variableId,
      cache,
    );
    // The support-range check runs before every statement-dependent check
    // (same discipline as rename / delete — to a v3 client, always return the
    // honest update-required rather than a misleading error from the status /
    // name guards or the value CAS below)
    yield* ensureSupportedLayout(input.statement);
    // The DO storage total guard (§12-8): after existence and the support
    // range, before the status / name guards, CAS, and signature
    yield* ensureStorageAdmitsGrowth;
    // The activation target is only declared (§12-5 — it is not a
    // general-purpose composite of "value push + meta reissue"). Since the
    // value CAS only enforces version = latestVersion + 1 it cannot double as
    // the target check (sending version N+1 to an active variable would pass),
    // so this explicit guard is what makes the schemaPolicy exemption's
    // premise below hold — "the predecessor is necessarily v2 (declared is
    // v2-only)". Without it, an active v1 variable could be promoted to v2
    // under disabled, bypassing the §12-11 enablement gate
    if (variable.latestStatus !== "declared") {
      return yield* rejectData({ kind: "payload-mismatch", field: "status" });
    }
    // activation does not double as a rename: name keeps the name declared at
    // declaration as-is (the same acceptance check as delete's name
    // preservation — renames are owned by the rename path together with the
    // var.renamed audit, and the "name change ⇔ var.renamed row"
    // correspondence must not break). With preservation matching, the NFC and
    // uniqueness checks at declaration acceptance stay valid as-is
    if (input.statement.name !== variable.name) {
      return yield* rejectData({ kind: "payload-mismatch", field: "name" });
    }
    // Since declared is the only legitimate latestVersion-0 state, the CAS
    // forces value version 1 (the "value version 1" of §12-5)
    yield* ensureValueCas(state, environmentId, variable.latestVersion, input.value);
    // The meta acceptance pipeline (§12-5): CAS → anchor → description
    // acceptance check → signature verification (the declared → active
    // transition and v2 monotonicity are crypto's predecessor check).
    // schemaPolicy is not passed — thanks to the declared guard above the
    // predecessor is necessarily v2, and a continuation statement is accepted
    // regardless of the policy (§12-11)
    const { device: author, value: metaSignedBytesHashHex } = yield* withSigningDevice(
      member,
      (candidate) =>
        acceptMetaStatement({
          projectId,
          environmentId,
          target: { kind: "variable", variableId },
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
  });

export const renameVariableProgram = (
  actor: DataActor,
  environmentId: string,
  variableId: string,
  statement: MetaStatementInput,
  manifest: EnvManifestInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { history, member, projectId, variable } = yield* requireVariableWriteContext(
      actor,
      environmentId,
      variableId,
      cache,
    );
    // The support-range check runs before every statement-dependent check
    // (ruling CR — for an unsupported layout, never return a misleading error
    // from a later check)
    yield* ensureSupportedLayout(statement);
    // The DO storage total guard (§12-8): rename / schema reissue is a growth
    // surface that stacks a statement row + a manifest (applies independently
    // of the metaVersion bound). It sits after the existence and layout checks
    // and before CAS / signature verification (keeps the same prefix shape as
    // the delete path — delete does not call the guard)
    yield* ensureStorageAdmitsGrowth;
    // rename / schema reissue never changes status (§12-5): declared →
    // active is only the activation composite (with value), and active →
    // declared is forbidden. Since the wire can carry both statuses, the
    // acceptance check pins the match against the current state (the same
    // payload-mismatch as the name-preservation check)
    if (statement.status !== variable.latestStatus) {
      return yield* rejectData({ kind: "payload-mismatch", field: "status" });
    }
    yield* ensureNfcName(statement.name);
    const store = yield* DataStore;
    if (yield* store.variableNameTaken(environmentId, statement.name, variableId)) {
      return yield* rejectData({ kind: "variable-conflict", variableId, reason: "duplicate-name" });
    }
    const schemaPolicy = yield* store.schemaPolicy;
    const { device: author, value: signedBytesHashHex } = yield* withSigningDevice(
      member,
      (candidate) =>
        acceptMetaStatement({
          projectId,
          environmentId,
          target: { kind: "variable", variableId },
          latestMetaVersion: variable.latestMetaVersion,
          history,
          member: candidate,
          statement,
          // The enablement gate (§12-11): rejects "v2 reissue of a v1
          // variable" under disabled (a continuation whose predecessor is v2
          // passes regardless of the policy — judged on the anchor's real
          // values)
          schemaPolicy,
        }),
    );
    yield* ensureDevicePermission(author, "member", environmentId);
    // Composite acceptance of the manifest (§12-5): recompute and cross-check
    // on the set after the rename is applied
    const acceptedManifest = yield* acceptManifestForMetaOp({
      projectId,
      environmentId,
      history,
      member: author,
      manifest,
      digestOverride: {
        variableId,
        status: statement.status,
        metaVersion: statement.metaVersion,
        signedBytesHashHex,
      },
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
        dataEvent(actor, now, event, {
          environmentId,
          variableId,
          payload: { name: statement.name },
          actorKeyFingerprintHex: author.keyFingerprintHex,
        }),
      );
    });
  });

export const deleteVariableProgram = (
  actor: DataActor,
  environmentId: string,
  variableId: string,
  statement: MetaStatementInput,
  manifest: EnvManifestInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { history, member, projectId, variable } = yield* requireVariableWriteContext(
      actor,
      environmentId,
      variableId,
      cache,
    );
    // The support-range check runs before every statement-dependent check
    // (same discipline as rename)
    yield* ensureSupportedLayout(statement);
    // A deleted statement's name preserves the previous active name (§4.2 —
    // byte-exact)
    if (statement.name !== variable.name) {
      return yield* rejectData({ kind: "payload-mismatch", field: "name" });
    }
    const { device: author, value: signedBytesHashHex } = yield* withSigningDevice(
      member,
      (candidate) =>
        acceptMetaStatement({
          projectId,
          environmentId,
          target: { kind: "variable", variableId },
          latestMetaVersion: variable.latestMetaVersion,
          history,
          member: candidate,
          statement,
        }),
    );
    yield* ensureDevicePermission(author, "member", environmentId);
    // Composite acceptance of the manifest (§12-5): recompute and cross-check
    // on the set including the tombstone (a digest mismatch from hiding a
    // tombstone is caught here — §4.3 (3))
    const acceptedManifest = yield* acceptManifestForMetaOp({
      projectId,
      environmentId,
      history,
      member: author,
      manifest,
      digestOverride: {
        variableId,
        status: "deleted",
        metaVersion: statement.metaVersion,
        signedBytesHashHex,
      },
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
        dataEvent(actor, now, "var.deleted", {
          environmentId,
          variableId,
          actorKeyFingerprintHex: author.keyFingerprintHex,
        }),
      );
    });
  });
