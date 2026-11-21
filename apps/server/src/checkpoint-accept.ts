import type { UserId } from "@maruhi/core";
import { cryptoEffect } from "@maruhi/core";
import type { ChainEntry, CheckpointEnvironmentEntry } from "@maruhi/crypto";
import { computeEnvValuesDigest, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import { AuditStore } from "./audit-store.ts";
import type { CheckpointValueEntryRow } from "./data.package/index.ts";
import {
  DataStore,
  deviceOf,
  ensureDevicePermission,
  loadInitializedChain,
  rejectData,
  requireRole,
  requireRoleInScope,
} from "./data.package/index.ts";
import { ensureParentHead, verifyAcceptableEntry } from "./do/chain-accept.ts";
import { commitAcceptedEntry } from "./do/chain-commit.ts";
import type { StateCache } from "./do/chain-store.ts";
import { deriveStoredState, updateStateCache } from "./do/chain-store.ts";
import { ensureStorageAdmitsAuditHeadExtension } from "./storage-guard.ts";

export const ensureCheckpointValuesDigest = Effect.fn(
  "checkpoint-accept.ensureCheckpointValuesDigest",
)(function* (tuple: CheckpointEnvironmentEntry, values: readonly CheckpointValueEntryRow[]) {
  const digest = yield* cryptoEffect(() => computeEnvValuesDigest(SUITE_ID, values)).pipe(
    Effect.orDie,
  );
  if (digest !== tuple.valuesDigestHex) {
    return yield* rejectData({
      kind: "checkpoint-state-mismatch",
      reason: "values-digest-mismatch",
    });
  }
});

export const ensureAuditHeadAcceptable = Effect.fn("checkpoint-accept.ensureAuditHeadAcceptable")(
  function* (auditHeadHashHex: string) {
    if (auditHeadHashHex === "") {
      return;
    }
    const audit = yield* AuditStore;
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
  const person = yield* requireRole(state, callerUserId, "reader");
  if (entry.payload.auditHeadHashHex !== "") {
    yield* requireRole(state, callerUserId, "admin");
  }
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
  for (const tuple of entry.payload.environments) {
    yield* requireRoleInScope(state, callerUserId, "reader", tuple.environmentId);
    yield* ensureDevicePermission(device, "reader", tuple.environmentId);
  }
  const { canonicalBytes, applied } = yield* verifyAcceptableEntry(chain, entry);
  const snapshots: {
    readonly tuple: CheckpointEnvironmentEntry;
    readonly values: readonly CheckpointValueEntryRow[];
  }[] = [];
  for (const tuple of entry.payload.environments) {
    snapshots.push({ tuple, values: yield* ensureCheckpointTupleState(tuple) });
  }
  yield* ensureAuditHeadAcceptable(entry.payload.auditHeadHashHex);
  const dataStore = yield* DataStore;
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
  return {
    headSeq: applied.state.headSeq,
    headHashHex: applied.state.headHashHex,
    appliedProposal: null,
  };
});
