// Effect programs for composite requests (the composite acceptance of
// AUTH_SPEC §12-4 / CRYPTO_SPEC §6.4).
//
// - Environment creation = a `create_environment` chain entry (carrying the
//   epoch-1 DEK commitment — §5.2/§6.2) + an EnvironmentMetaStatement
//   (metaVersion 1 — §4.2; the declared head is the current head before the
//   append = the bundled entry's prev) + the epoch-1 complete wrap set
// - Rotation = a `rotate_epoch` entry (carrying the new epoch's commitment)
//   + the new epoch's complete wrap set (re-encrypting current values is a
//   later normal push — §12-7)
//
// The chain append (parent-head CAS + verifyChain re-run) and the data
// registration are accepted atomically in a single synchronous block, so no
// intermediate state — "an epoch exists but no wraps" or "a commitment
// exists but no environment row" — is created. Every check completes before
// the write phase (same discipline as the data-plane programs in
// programs-*). Assumes execution under the DO's Semaphore(1) permit.
//
// The judgment state for the wrap-set acceptance condition (§12-6) is "the
// chain state after applying the bundled entry" (§12-4 — judging on the
// pre-append state would reject every legitimate rotate composite, whose
// wraps address the new epoch). Acceptance of the entry itself has
// verifyChain (§6.4 = re-verification of the consensus rules) as its
// authority: duplicate-environment / unknown-environment / epoch ordering /
// role / commitment format are all judged there.

import type { ChainEntry, ChainState } from "@maruhi/crypto";
import { Effect } from "effect";

import type { AuditEventInput, AuditRotationRead } from "./audit-store.ts";
import { AuditStore } from "./audit-store.ts";
import {
  ensureParentHead,
  insertAcceptedEntryPairSync,
  verifyAcceptableEntryPair,
} from "./chain-accept.ts";
import type { StateCache, StoredChain } from "./chain-store.ts";
import { ChainStore, deriveStoredState, updateStateCache } from "./chain-store.ts";
import { ensureAuditHeadAcceptable, ensureCheckpointValuesDigest } from "./checkpoint-accept.ts";
import type {
  DataActor,
  DekWrapInput,
  EnvManifestInput,
  MemberWithDevice,
  MetaStatementInput,
} from "./data-plane.ts";
import {
  dataEvent,
  deviceOf,
  ensureDevicePermission,
  loadInitializedChain,
  rejectData,
  requireRole,
  requireRoleInScope,
} from "./data-plane.ts";
import type { DataWriteOps } from "./data-store.ts";
import { DataStore } from "./data-store.ts";
import {
  dekRegisteredEvent,
  ensureWrapSetAcceptable,
  expectedWrapRecipientCount,
} from "./dek-wraps.ts";
import { ensureEnvironmentQuota, requireActiveEnvironment } from "./quotas.ts";
import { ensureStorageAdmitsGrowth } from "./storage-guard.ts";
import { acceptEnvManifest, manifestDigestEntries, storedEnvMeta } from "./verify-manifest.ts";
import { ensureMetaStatementSignature, ensureNfcName } from "./verify-meta.ts";

/** The result of a composite acceptance (crosses the RPC boundary). */
export interface EnvironmentChainResultValue {
  readonly environmentId: string;
  readonly currentEpoch: number;
  readonly headSeq: number;
  readonly headHashHex: string;
}

/**
 * The shared front stage of a composite: uninitialized / membership /
 * role floor (all member — the §12-3 level for environment creation and
 * rotate_epoch) / the check of **environment ∈ scope** (§12-3 —
 * 2026-09-15 ES K3; rotate = the target environment, create = the new
 * environment_id. Since creation cannot carry a not-yet-existent id in
 * `listed`, only a scope = all principal passes — the same single
 * predicate satisfies the table's "scope = all" row), plus loading the
 * whole chain.
 * The acceptance surface's 403 stands first; the consensus rule
 * `environment-out-of-scope` (verifyChain's 422) remains as defense in
 * depth (design record es-design.md §9 K3-G).
 */
const loadChainForComposite = (
  callerUserId: string,
  environmentId: string,
  entryActorFingerprintHex: string,
  entrySeq: number,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const chain = yield* loadInitializedChain;
    // history is the pre-append chain's history index: the bundled
    // statement's declared-head existence check runs against the pre-append
    // chain (§12-4 — a shape declaring the bundled entry itself as head is
    // not accepted)
    const { state, history } = yield* deriveStoredState(chain, cache);
    const person = yield* requireRoleInScope(state, callerUserId, "member", environmentId);
    // Second stage (design record §8 K3-1): re-judge member × environment
    // ∈ effective scope under the effective permission of the device the
    // bundled entry's actor FP names (no device trial needed — the entry
    // names it). An FP that is not a valid device of the calling principal
    // is rejected for the same reason as verifyChain's actor-key-mismatch
    // (the acceptance surface's 403 standing ahead of verifyChain's 422 is
    // unchanged)
    const member = deviceOf(person, entryActorFingerprintHex);
    if (member === undefined) {
      return yield* rejectData({
        kind: "chain-entry-invalid",
        seq: entrySeq,
        reason: "actor-key-mismatch",
      });
    }
    yield* ensureDevicePermission(member, "member", environmentId);
    return { chain, state, history, member, projectId: chain.genesisHashHex };
  });

/**
 * Checks of a composite's bundled wraps (§12-4 / §12-6): every wrap's epoch
 * = the epoch the bundled entry establishes (composite-internal
 * consistency), exact match against the recipient set R(E) (count match =
 * exact match — recipients and duplicates are already checked by
 * ensureWrapSetAcceptable), registration signatures, row-count bound.
 * The judgment state is after the bundled entry applies (appliedState).
 */
const ensureCompositeWrapSet = (input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly appliedState: ChainState;
  readonly member: MemberWithDevice;
  readonly establishedEpoch: number;
  readonly deks: readonly DekWrapInput[];
}) =>
  Effect.gen(function* () {
    // The composite-internal consistency check (§12-4): every wrap's
    // epoch = the epoch the bundled entry establishes. A stricter equality
    // check than ensureWrapSetAcceptable's range check (1..current epoch),
    // it also rejects a stray wrap addressed to a past epoch (e.g. epoch 1
    // inside a rotate composite)
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
    // The bundled wraps' signer = the bundled entry's device (§12-4 — one
    // request, one device). A wrap signed by another valid device is not
    // accepted (fail-closed)
    if (signer !== null && signer.keyFingerprintHex !== input.member.keyFingerprintHex) {
      return yield* rejectData({ kind: "dek-wrap-rejected", reason: "signature-invalid" });
    }
    // Exact match (the §12-6 first registration) is explicitly demanded by
    // count: checkWrapSets only looks at epochs present in the request, so
    // the empty set must not slip through. Since recipients and duplicates
    // are already checked, count match = exact match (the reason-code
    // check order keeps the environment-creation program's "individual
    // checks → completeness"). The target is the recipient set R(E) = the
    // current members whose scope contains E + the server key of a valid
    // in-disclosure-scope grant_server (§12-4 — 2026-09-15 ES K3; shares
    // the expected-count definition of dek-wraps.ts)
    if (input.deks.length !== expectedWrapRecipientCount(input.appliedState, input.environmentId)) {
      return yield* rejectData({ kind: "dek-wrap-rejected", reason: "recipient-missing" });
    }
  });

/**
 * The bundled-contents match check of a boundary checkpoint (AUTH_SPEC
 * §12-4): exactly one tuple for the environment, coordinate match, epoch =
 * the epoch the bundled entry establishes, manifestVersion = the bundled
 * manifest's version. The hash match between the tuple's
 * manifest_sig_hash and the bundled manifest is uniquely owned by
 * acceptEnvManifest's checkpoint-binding check (CRYPTO_SPEC §4.3 (2))
 * against the history after both entries apply (§6.4's "the split with
 * the bundled-contents match check is uniquified in the implementation
 * PR").
 */
const ensureBoundaryCheckpointShape = (input: {
  readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
  readonly environmentId: string;
  readonly establishedEpoch: number;
  readonly manifestVersion: number;
}) =>
  Effect.gen(function* () {
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
    // A non-empty audit_head_hash is accepted under the §16-2 rule
    // (effective permission admin + the §6.4 existence/position check) —
    // the role half and the content check are the caller-side
    // ensureCheckpointAuditHead's job (shared with checkpoint-accept.ts)
    return tuple;
  });

/**
 * The boundary checkpoint's audit-head notarization (§16-2 — the same rule
 * as the standalone path): when non-empty, chain role admin-or-above
 * (403 if short; the scope half is the worker's already-run pre-check) +
 * the §6.4 existence/position check. An empty string = no notarization
 * does nothing.
 */
const ensureCheckpointAuditHead = (input: {
  readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
  readonly state: ChainState;
  readonly callerUserId: string;
}) =>
  Effect.gen(function* () {
    if (input.checkpoint.payload.auditHeadHashHex === "") {
      return;
    }
    yield* requireRole(input.state, input.callerUserId, "admin");
    yield* ensureAuditHeadAcceptable(input.checkpoint.payload.auditHeadHashHex);
  });

/**
 * The shared acceptance front-pipeline of a boundary checkpoint (H+2)
 * (common to create / rotate): bundled-contents match check (§12-4) →
 * audit-head check (§16-2) → the 2-entry acceptance check (size →
 * capacity → verifyChain — the §6.4 consensus rules; shared with
 * chain-accept.ts).
 */
const acceptBoundaryCheckpointPair = (input: {
  readonly chain: StoredChain;
  readonly state: ChainState;
  readonly callerUserId: string;
  readonly entry: ChainEntry;
  readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
  readonly environmentId: string;
  readonly establishedEpoch: number;
  readonly manifestVersion: number;
}) =>
  Effect.gen(function* () {
    const checkpointTuple = yield* ensureBoundaryCheckpointShape({
      checkpoint: input.checkpoint,
      environmentId: input.environmentId,
      establishedEpoch: input.establishedEpoch,
      manifestVersion: input.manifestVersion,
    });
    // The non-empty audit_head_hash's effective-permission admin +
    // existence/position check (§16-2 — the same rule as the standalone
    // path)
    yield* ensureCheckpointAuditHead({
      checkpoint: input.checkpoint,
      state: input.state,
      callerUserId: input.callerUserId,
    });
    const pair = yield* verifyAcceptableEntryPair(input.chain, input.entry, input.checkpoint);
    return { checkpointTuple, ...pair };
  });

// The boundary checkpoint's values_digest content cross-check (CRYPTO_SPEC
// §6.4 — the cross-check basis is "the stored state after the composite
// applies". A composite does not change values, so the stored values at
// acceptance time = the stored values after application) and the audit-head
// check are shared with the standalone path (checkpoint-accept.ts — §16-2's
// "the storage discipline is identical across paths").

/** The dependencies and parameters shared across a composite's write phase (the synchronous functions' argument). */
interface CompositeWriteContext {
  readonly chainStore: {
    readonly insertSync: (entry: ChainEntry, entryHashHex: string, canonicalBytes: number) => void;
  };
  readonly dataStore: { readonly write: DataWriteOps };
  readonly audit: {
    readonly appendSync: (event: AuditEventInput) => void;
    readonly appendManySync: (events: readonly AuditEventInput[]) => void;
    // The detection input of acceptance side effects (chain-accept.ts).
    // Not read for a composite's ops (create_environment / rotate_epoch),
    // but keeps the acceptance path's type surface as one
    readonly readRotationSync: AuditRotationRead;
  };
  readonly actor: DataActor;
  readonly member: MemberWithDevice;
  readonly environmentId: string;
  readonly nowMs: number;
}

/** Insert the bundled wraps + dek.registered (one row per recipient — AUDIT_SPEC §3.3). */
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

/** Bundle the write phase's dependencies (ChainStore / AuditStore) into a CompositeWriteContext. */
const makeWriteContext = (input: {
  readonly dataStore: { readonly write: DataWriteOps };
  readonly actor: DataActor;
  readonly member: MemberWithDevice;
  readonly environmentId: string;
}) =>
  Effect.gen(function* () {
    const chainStore = yield* ChainStore;
    const audit = yield* AuditStore;
    return {
      chainStore,
      dataStore: input.dataStore,
      audit,
      actor: input.actor,
      member: input.member,
      environmentId: input.environmentId,
      nowMs: Date.now(),
    } satisfies CompositeWriteContext;
  });

function compositeResult(
  environmentId: string,
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

export const createEnvironmentCompositeProgram = (
  actor: DataActor,
  input: {
    readonly parentHeadHashHex: string;
    readonly entry: ChainEntry & { readonly op: "create_environment" };
    readonly statement: MetaStatementInput;
    readonly deks: readonly DekWrapInput[];
    readonly manifest: EnvManifestInput;
    /** The boundary checkpoint (H+2 — AUTH_SPEC §12-4). */
    readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
  },
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { chain, state, history, member, projectId } = yield* loadChainForComposite(
      actor.userId,
      input.entry.payload.environmentId,
      input.entry.actor.keyFingerprintHex,
      input.entry.seq,
      cache,
    );
    // The DO storage total guard (§12-8): environment creation is a growth
    // surface (environment row, statement, manifest, wraps to every member,
    // snapshot). The rotation composite (below) does not call it — the
    // mandatory rotation after a remove (CRYPTO_SPEC §7) is a security
    // remediation and its write volume is bounded ((d) of the same
    // section)
    yield* ensureStorageAdmitsGrowth;
    yield* ensureParentHead(chain, input.parentHeadHashHex);
    // The composite-internal declared head (§12-4): the bundled
    // statement's and manifest's declared heads match the pre-append
    // current head (= the bundled entry's prev) exactly. Since the CAS has
    // passed, current head = parentHeadHashHex. On a retry after a head
    // CAS failure, the client re-signs all of the entry, the statement,
    // and the manifest (client side — env-create.ts)
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
    // The composite-internal consistency check (§12-4): the manifest's
    // epoch = the epoch the bundled entry establishes (creation = 1). An
    // early composite-internal rejection like the wraps' epoch check; the
    // full epoch-consistency verification is done by acceptEnvManifest
    // (over the post-application history)
    if (input.manifest.epoch !== 1) {
      return yield* rejectData({ kind: "payload-mismatch", field: "manifestEpoch" });
    }
    const environmentId = input.entry.payload.environmentId;
    // The boundary checkpoint's bundled-contents match (§12-4): one tuple
    // for the environment, epoch 1, manifestVersion 1 (the wire pins
    // Literal 1, but the tuple side is cross-checked too). Accept-judge
    // the 2 entries — create = H+1, boundary checkpoint = H+2 — with one
    // whole-chain re-verification (acceptBoundaryCheckpointPair)
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
    // ID uniqueness is the chain consensus rule's job
    // (duplicate-environment — verifyChain). The only checks left on the
    // data plane are display-name uniqueness and the quantity policy
    yield* ensureEnvironmentQuota;
    yield* ensureNfcName(input.statement.name);
    if (yield* store.environmentNameTaken(input.statement.name, null)) {
      return yield* rejectData({
        kind: "environment-conflict",
        environmentId,
        reason: "duplicate-name",
      });
    }
    // The statement is verified against the pre-append history (§12-4).
    // A meta statement does not check the environment's existence, so it
    // is accepted even if the environment did not exist at the declared
    // head (the intended asymmetry against value signatures). author =
    // the calling principal and member-or-above at the declared head are
    // checked by verifyDistributedMetaStatement
    const metaSignedBytesHashHex = yield* ensureMetaStatementSignature({
      projectId,
      environmentId,
      target: { kind: "environment" },
      history,
      member,
      statement: input.statement,
    });
    // Acceptance of the bundled manifest (§12-4 / §12-5): manifestVersion
    // 1, the empty variable set, epoch 1. Epoch consistency is judged by
    // the checkpoint binding (§4.3 (2) — exact match with the H+2
    // boundary checkpoint tuple; if the tuple's hash disagrees with the
    // bundled manifest it is rejected as checkpoint-binding-mismatch =
    // doubling as the §12-4 hash-match check) against the history after
    // both entries apply (applied.history)
    const manifestSignedBytesHashHex = yield* acceptEnvManifest({
      projectId,
      environmentId,
      history: applied.history,
      member,
      manifest: input.manifest,
      entries: [],
      envMeta: { metaVersion: input.statement.metaVersion, sigHashHex: metaSignedBytesHashHex },
    });
    // The boundary checkpoint's values_digest (§6.4 — creation = an
    // enumeration of the empty variable set)
    yield* ensureCheckpointValuesDigest(checkpointTuple, []);
    // The current epoch after the bundled entry applies is always 1
    // (create_environment — §12-4)
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
    // Write phase: a single synchronous block = an atomic commit in one
    // task (do not split chain entry + mirror + environment row +
    // statement row + manifest + wraps + audit — §12-4)
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
      // env.created records the statement author's key FP (AUDIT_SPEC §3.3)
      writeContext.audit.appendSync(
        dataEvent(actor, writeContext.nowMs, "env.created", {
          environmentId,
          payload: { name: input.statement.name },
          actorKeyFingerprintHex: member.keyFingerprintHex,
        }),
      );
      insertCompositeWrapsSync(writeContext, input.deks);
      // Atomic save of the value snapshot (§6.4 / §16-2): for creation,
      // the empty enumeration + the tuple coordinates
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

export const rotateEpochCompositeProgram = (
  actor: DataActor,
  environmentId: string,
  input: {
    readonly parentHeadHashHex: string;
    readonly entry: ChainEntry & { readonly op: "rotate_epoch" };
    readonly deks: readonly DekWrapInput[];
    readonly manifest: EnvManifestInput;
    /** The boundary checkpoint (H+2 — AUTH_SPEC §12-4). */
    readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
  },
  cache: StateCache,
) =>
  Effect.gen(function* () {
    // scope is judged on the URL-coordinate environment (a mismatch
    // between URL and entry is rejected by the composite-internal
    // consistency check right after — the accepted combinations are the
    // same whichever side judges)
    const { chain, state, member, projectId } = yield* loadChainForComposite(
      actor.userId,
      environmentId,
      input.entry.actor.keyFingerprintHex,
      input.entry.seq,
      cache,
    );
    // The composite-internal consistency check (§12-4): the URL
    // coordinate must match the bundled entry's environment_id.
    // Independent verification of each part alone must not accept a pair
    // of "an entry for one environment × wraps for another"
    if (input.entry.payload.environmentId !== environmentId) {
      return yield* rejectData({ kind: "payload-mismatch", field: "environmentId" });
    }
    // A rotate to a deleted (tombstone) environment is a 404 (§12-4 —
    // §7's "all environments" does not include deleted ones; do not
    // silently accept and advance an epoch nothing is left to protect)
    yield* requireActiveEnvironment(environmentId);
    yield* ensureParentHead(chain, input.parentHeadHashHex);
    // The composite-internal declared-head (§12-4) and epoch (=
    // new_epoch) consistency checks. On a retry after a head CAS failure,
    // both the entry and the manifest are re-signed
    if (
      input.manifest.chainHeadHashHex !== chain.headHashHex ||
      input.manifest.chainHeadSeq !== chain.headSeq
    ) {
      return yield* rejectData({ kind: "payload-mismatch", field: "manifestChainHead" });
    }
    if (input.manifest.epoch !== input.entry.payload.newEpoch) {
      return yield* rejectData({ kind: "payload-mismatch", field: "manifestEpoch" });
    }
    // The boundary checkpoint's bundled-contents match (§12-4): one tuple
    // for the environment, epoch = new_epoch, manifestVersion = the
    // bundled manifest's version. The 2-entry acceptance check of rotate
    // = H+1 and boundary checkpoint = H+2 (acceptBoundaryCheckpointPair)
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
    // Acceptance of the bundled manifest (§12-5 (4): epoch consistency
    // is the checkpoint binding against the history after both entries
    // apply — §4.3 (2). The exact match with the H+2 tuple doubles as the
    // §12-4 hash-match check). The meta set is unchanged (a reissue that
    // only reflects the epoch advancement — §4.3), so entries is the
    // stored latest shape as-is
    const manifestSignedBytesHashHex = yield* acceptEnvManifest({
      projectId,
      environmentId,
      history: applied.history,
      member,
      manifest: input.manifest,
      entries: yield* manifestDigestEntries(environmentId, null),
      envMeta: yield* storedEnvMeta(environmentId),
    });
    // The boundary checkpoint's values_digest (§6.4 — the cross-check
    // basis is the state after the composite applies. A composite does
    // not change values, so it equals the stored values at acceptance
    // time. Under rotate, un-re-encrypted = an enumeration of the old
    // epoch's current values — a legitimate §12-7 state. If a concurrent
    // push slips in after the declared head was fixed, the mismatch is a
    // 422 and the client re-pulls + retries bounded)
    const snapshotValues = yield* Effect.flatMap(DataStore, (store) =>
      store.checkpointValueEntries(environmentId),
    );
    yield* ensureCheckpointValuesDigest(checkpointTuple, snapshotValues);
    // The current epoch after the bundled entry applies = new_epoch
    // (epoch ordering is already verified by verifyChain)
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
      // Atomic save of the value snapshot (§6.4 / §16-2): upsert the
      // enumeration of current values at acceptance time (already
      // cross-checked) + the tuple coordinates as the latest covering
      // checkpoint
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
