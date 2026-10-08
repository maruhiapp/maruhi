// Acceptance of standalone (periodic) checkpoints and the shared
// implementation of checkpoint content matching
// (CRYPTO_SPEC §6.4 / AUTH_SPEC §16-2).
//
// - standalone goes through the generic chain-append API (§16-2 — there is
//   no client-supplied accompanying data and no separate input to bundle in
//   a composite). The consensus rules (form, role, audit admin,
//   unknown-environment, strict epoch equality, checkpoint-regression) are
//   carried by verifyChain (via chain-accept.ts — since 2026-10-07 also
//   environment-deleted, CRYPTO_SPEC §6.2); here lives the acceptance
//   policy = **content matching against the stored state at acceptance time
//   (before applying)** and the atomic snapshot store
// - The mismatch vocabulary is CheckpointStateMismatch (422):
//   manifest-mismatch / values-digest-mismatch / audit-head-unknown /
//   audit-head-stale. The boundary-bundled case
//   (composite-programs.ts — the matching reference is the composite's
//   post-application state) also shares the values_digest and audit-head
//   checks from here, structuring "the storage discipline is identical
//   across paths" (§16-2) as an implementation sharing
// - Non-empty audit_head_hash requires effective permission admin (§16-2):
//   the scope half is the worker's (handlers-membership /
//   handlers-environments); the chain-role half is here via
//   requireRole(admin) — insufficient is 403. The API's 403 precedes the
//   consensus rule's checkpoint-audit-role-insufficient (422)
//   (session-27 §13-5 permission matrix (c))
// - Every tuple's environment ∈ the caller's scope (AUTH_SPEC §12-3 —
//   2026-09-15 ES K3): 403 insufficient-scope after the parent-head CAS
//   (a concurrent delete_environment prunes listed scopes, so a stale view
//   is a 409 — AUTH_SPEC §16-2, 2026-10-07). Precedes the consensus rule
//   environment-out-of-scope (422) (defense in depth on the same state)

import type { UserId } from "@maruhi/core";
import { cryptoEffect } from "@maruhi/core";
import type { ChainEntry, CheckpointEnvironmentEntry } from "@maruhi/crypto";
import { computeEnvValuesDigest, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import { AuditStore } from "./audit-store.ts";
import {
  deviceOf,
  ensureDevicePermission,
  loadInitializedChain,
  rejectData,
  requireRole,
  requireRoleInScope,
} from "./data/data-plane.ts";
import type { CheckpointValueEntryRow } from "./data/data-store.ts";
import { DataStore } from "./data/data-store.ts";
import { ensureParentHead, verifyAcceptableEntry } from "./do/chain-accept.ts";
import { commitAcceptedEntry } from "./do/chain-commit.ts";
import type { StateCache } from "./do/chain-store.ts";
import { deriveStoredState, updateStateCache } from "./do/chain-store.ts";
import { ensureStorageAdmitsAuditHeadExtension } from "./storage-guard.ts";

/**
 * Content match of a checkpoint's values_digest (CRYPTO_SPEC §6.4).
 * `values` is a re-enumeration of the stored state at acceptance time
 * (standalone) / after the composite is applied (boundary — same value
 * since a composite does not change values). A mismatch is 422 (the
 * issuer's view is stale / a concurrent push).
 */
export const ensureCheckpointValuesDigest = Effect.fn(
  "checkpoint-accept.ensureCheckpointValuesDigest",
)(function* (tuple: CheckpointEnvironmentEntry, values: readonly CheckpointValueEntryRow[]) {
  const digest = yield* cryptoEffect(() => computeEnvValuesDigest(SUITE_ID, values)).pipe(
    // Malformed input derived from stored rows is an implementation bug (no secrets in error values)
    Effect.orDie,
  );
  if (digest !== tuple.valuesDigestHex) {
    return yield* rejectData({
      kind: "checkpoint-state-mismatch",
      reason: "values-digest-mismatch",
    });
  }
});

/**
 * Existence/position check of a non-empty audit_head_hash (CRYPTO_SPEC
 * §6.4 / AUDIT_SPEC §5.1). The empty string = no notarization is out of
 * scope. Before the check, the cumulative hash column is extended to
 * MAX(seq) (lazy materialization — audit-store.ts).
 *
 * - Bounded extension: when extension hits the per-call cap without
 *   reaching MAX(seq), reject with the retryable audit-head-not-ready
 *   (503). **Never judge unknown / stale on a stale column** (fail-closed —
 *   judging membership/position against a partially extended column would
 *   both wrongly reject a legitimate declaration [unknown] and wrongly
 *   base the protected prefix). Progress is stored, so a retry always
 *   advances
 * - Membership: the declared hash exists in the computed column
 *   (audit-head-unknown)
 * - Position floor: the position of occurrence is at or beyond the mirror
 *   row (chain.checkpointed) of the immediately preceding checkpoint
 *   (notarized or not) (audit-head-stale). The first checkpoint with no
 *   predecessor is not bound (vacuously true — same predicate, same base
 *   case as the admin match [AUDIT_SPEC §6]). With this acceptance check,
 *   under an honest server the matching-side position check always holds
 *   structurally (a benign issuance that did not re-declare after a CAS
 *   conflict is type-rejected here rather than surfacing as a tamper
 *   accusation)
 */
export const ensureAuditHeadAcceptable = Effect.fn("checkpoint-accept.ensureAuditHeadAcceptable")(
  function* (auditHeadHashHex: string) {
    if (auditHeadHashHex === "") {
      return;
    }
    const audit = yield* AuditStore;
    // DO storage-total guard (AUTH_SPEC §12-8): judged as a growth surface
    // only when materializing the derived column (a write proportional to
    // the audit row count) is needed. An empty notarization (the CLI's
    // boundary / periodic checkpoint) never reaches here = is accepted even
    // under rejection
    yield* ensureStorageAdmitsAuditHeadExtension;
    if ((yield* audit.ensureHeadCurrent) === "more-remains") {
      return yield* rejectData({ kind: "audit-head-not-ready" });
    }
    const position = audit.headPositionSync(auditHeadHashHex);
    if (position === null) {
      return yield* rejectData({ kind: "checkpoint-state-mismatch", reason: "audit-head-unknown" });
    }
    const floor = audit.latestCheckpointMirrorSeqSync();
    if (floor !== null && position < floor) {
      return yield* rejectData({ kind: "checkpoint-state-mismatch", reason: "audit-head-stale" });
    }
  },
);

/**
 * Acceptance-time match of one environment tuple (§6.4): match against the
 * latest manifest (manifest-mismatch — notarizing a nonexistent earlier
 * manifest_version also falls here) → values_digest. On pass, returns the
 * stored value enumeration (material for the snapshot store). The
 * environment's existence and liveness on the chain are already guaranteed
 * by the consensus rules (unknown-environment / environment-deleted —
 * CRYPTO_SPEC §6.2) — a chain-live environment with no data row, or with a
 * tombstoned row, is a violation of composite-acceptance atomicity (the
 * deletion composite writes the tombstone with its chain entry — AUTH_SPEC
 * §12-4), so it dies. So does a live environment with no stored
 * manifest: the creation composite writes it atomically, so its absence
 * is corruption, not a mismatch (AUTH_SPEC §12-5 (6) / §16-2 — the
 * server-fault discipline of every other surface).
 */
const ensureCheckpointTupleState = Effect.fnUntraced(function* (tuple: CheckpointEnvironmentEntry) {
  const store = yield* DataStore;
  const environment = yield* store.findEnvironment(tuple.environmentId);
  if (environment === null || environment.deletedAtMs !== null) {
    return yield* Effect.die(
      new Error(
        "environment live on the verified chain has no live data row (composite atomicity)",
      ),
    );
  }
  const anchor = yield* store.environmentManifestAnchor(tuple.environmentId);
  if (anchor === null) {
    return yield* Effect.die(new Error("environment manifest row missing"));
  }
  if (
    anchor.manifestVersion !== tuple.manifestVersion ||
    anchor.signedBytesHashHex !== tuple.manifestSigHashHex
  ) {
    return yield* rejectData({ kind: "checkpoint-state-mismatch", reason: "manifest-mismatch" });
  }
  const values = yield* store.checkpointValueEntries(tuple.environmentId);
  yield* ensureCheckpointValuesDigest(tuple, values);
  return values;
});

/**
 * Acceptance of a standalone checkpoint (the checkpoint branch of the
 * generic chain append — called from chain-do.ts's appendProgram). Chain
 * append + mirror + snapshot upsert commit atomically in a single
 * synchronous block (§16-2's "same transaction as the chain append";
 * existing snapshots of environments absent from the payload are left
 * unchanged).
 */
export const standaloneCheckpointProgram = Effect.fn(
  "checkpoint-accept.standaloneCheckpointProgram",
)(function* (
  parentHeadHashHex: string,
  entry: ChainEntry & { readonly op: "checkpoint" },
  callerUserId: UserId,
  cache: StateCache,
) {
  const chain = yield* loadInitializedChain;
  const { state } = yield* deriveStoredState(chain, cache);
  // §11-2: non-members get nothing back (the worker maps to 404). The
  // checkpoint's own role floor (member) is rejected with 422 by the
  // consensus rules (verifyChain)
  const person = yield* requireRole(state, callerUserId, "reader");
  // §16-2: a non-empty audit_head_hash requires chain role admin or
  // higher (insufficient → 403. The scope half [admin scope] was
  // pre-checked by the worker)
  if (entry.payload.auditHeadHashHex !== "") {
    yield* requireRole(state, callerUserId, "admin");
  }
  // Stage 2 (design record §8 K3-1): repeat the role check with the
  // effective permission of the device the entry's actor FP names (an FP
  // that is not one of the caller's valid devices is
  // actor-key-mismatch)
  const device = deviceOf(person, entry.actor.keyFingerprintHex);
  if (device === undefined) {
    return yield* rejectData({
      kind: "chain-entry-invalid",
      seq: entry.seq,
      reason: "actor-key-mismatch",
    });
  }
  yield* ensureDevicePermission(device, entry.payload.auditHeadHashHex === "" ? "reader" : "admin");
  yield* ensureParentHead(chain, parentHeadHashHex);
  // §12-3: every tuple's environment ∈ the caller's scope, then the
  // signing device's (403 insufficient-scope — before verifyChain; the
  // consensus rule `environment-out-of-scope`'s 422 remains as defense in
  // depth — design record es-design.md §9 K3-G). After the CAS: a
  // concurrent delete_environment prunes listed scopes (CRYPTO_SPEC §6.2),
  // so the scope depends on the chain the entry is appended onto, and a
  // checkpoint signed over a stale view is a 409 (§12-5's check-order rule)
  for (const tuple of entry.payload.environments) {
    yield* requireRoleInScope(state, callerUserId, "reader", tuple.environmentId);
    yield* ensureDevicePermission(device, "reader", tuple.environmentId);
  }
  // The 4 acceptance steps (size → capacity → verifyChain = §6.2's
  // consensus rules) are shared with the other paths
  const { canonicalBytes, applied } = yield* verifyAcceptableEntry(chain, entry);
  // Content match against the stored state at acceptance time (before
  // applying) (§6.4). Enumeration order = payload order
  const snapshots: {
    readonly tuple: CheckpointEnvironmentEntry;
    readonly values: readonly CheckpointValueEntryRow[];
  }[] = [];
  for (const tuple of entry.payload.environments) {
    snapshots.push({ tuple, values: yield* ensureCheckpointTupleState(tuple) });
  }
  yield* ensureAuditHeadAcceptable(entry.payload.auditHeadHashHex);
  const dataStore = yield* DataStore;
  // The snapshot store (§6.4) commits atomically in the same synchronous
  // block as the chain insert and mirror (commitAcceptedEntry's extraSync)
  yield* commitAcceptedEntry(chain, entry, applied, canonicalBytes, (nowMs) => {
    for (const { tuple, values } of snapshots) {
      dataStore.write.upsertCheckpointSnapshot(
        tuple.environmentId,
        {
          chainSeq: entry.seq,
          entryHashHex: applied.state.headHashHex,
          epoch: tuple.epoch,
          manifestVersion: tuple.manifestVersion,
          manifestSigHashHex: tuple.manifestSigHashHex,
          valuesDigestHex: tuple.valuesDigestHex,
        },
        values,
        nowMs,
      );
    }
  });
  updateStateCache(cache, applied);
  // checkpoint is a non-proposable op (CRYPTO_SPEC §6.2) — no proposal was applied
  return {
    headSeq: applied.state.headSeq,
    headHashHex: applied.state.headHashHex,
    appliedProposal: null,
  };
});
