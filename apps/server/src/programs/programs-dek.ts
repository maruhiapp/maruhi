import type { EnvironmentId } from "@maruhi/core";
import { Clock, Effect } from "effect";

import { AuditStore } from "../audit-store.ts";
import type {
  DataActor,
  DekRecipientPosition,
  DekWrapInput,
  DekWrapRefInput,
} from "../data.package/index.ts";
import {
  currentEpochOf,
  dataEvent,
  DataStore,
  dekRecipientTarget,
  ensureDevicePermission,
  rejectData,
  requireEnvironmentAccess,
  roleAtLeast,
} from "../data.package/index.ts";
import {
  allRecipientsAreOwnDevices,
  checkWrapRequestCount,
  dekRegisteredEvent,
  ensureWrapSetAcceptable,
  wrapRefKey,
} from "../dek-wraps.ts";
import type { StateCache } from "../do/chain-store.ts";
import { requireActiveEnvironment } from "../quotas.ts";
import { ensureStorageAdmitsGrowth } from "../storage-guard.ts";

export const registerDekWrapsProgram = Effect.fn("programs-dek.registerDekWrapsProgram")(function* (
  actor: DataActor,
  environmentId: EnvironmentId,
  wraps: readonly DekWrapInput[],
  cache: StateCache,
) {
  const { state, member, projectId } = yield* requireEnvironmentAccess(
    actor.userId,
    "reader",
    environmentId,
    cache,
  );
  const selfBackfill = allRecipientsAreOwnDevices(member, wraps);
  const requiredRole = selfBackfill ? "reader" : "member";
  if (!roleAtLeast(member.role, requiredRole)) {
    return yield* rejectData({ kind: "insufficient-role" });
  }
  yield* requireActiveEnvironment(environmentId);
  yield* ensureStorageAdmitsGrowth;
  const currentEpoch = currentEpochOf(state, environmentId);
  const signer = yield* ensureWrapSetAcceptable(
    projectId,
    environmentId,
    state,
    member,
    currentEpoch,
    wraps,
  );
  if (signer === null) {
    return yield* rejectData({ kind: "dek-wrap-rejected", reason: "recipient-missing" });
  }
  yield* ensureDevicePermission(signer, requiredRole, environmentId);
  const store = yield* DataStore;
  const audit = yield* AuditStore;
  const now = yield* Clock.currentTimeMillis;
  yield* Effect.sync(() => {
    for (const wrap of wraps) {
      store.write.insertWrap(environmentId, wrap, signer, now);
    }
    audit.appendManySync(
      wraps.map((wrap) => dekRegisteredEvent(actor, signer, now, environmentId, wrap)),
    );
  });
});

type ResolvedWrapRef = DekRecipientPosition & {
  readonly epoch: number;
  readonly recipientEncPubHex: string;
};

export const deleteDekWrapsProgram = Effect.fn("programs-dek.deleteDekWrapsProgram")(function* (
  actor: DataActor,
  environmentId: EnvironmentId,
  refs: readonly DekWrapRefInput[],
  cache: StateCache,
) {
  yield* requireEnvironmentAccess(actor.userId, "admin", environmentId, cache);
  yield* requireActiveEnvironment(environmentId);
  const countRejection = checkWrapRequestCount(refs.length);
  if (countRejection !== null) {
    return yield* rejectData(countRejection);
  }
  const store = yield* DataStore;
  const seen = new Set<string>();
  const resolved: ResolvedWrapRef[] = [];
  for (const ref of refs) {
    const key = wrapRefKey(ref);
    if (seen.has(key)) {
      return yield* rejectData({ kind: "dek-wrap-rejected", reason: "duplicate-recipient" });
    }
    seen.add(key);
    const slot = (yield* store.listWrapSlots(environmentId, ref.epoch, ref.recipientUserId)).find(
      (candidate) =>
        candidate.recipientClass === ref.recipientClass &&
        candidate.recipientEncPubHex === ref.recipientEncPubHex,
    );
    if (slot === undefined) {
      return yield* rejectData({
        kind: "dek-wrap-not-found",
        epoch: ref.epoch,
        recipientUserId: ref.recipientUserId,
      });
    }
    resolved.push({ ...ref, recipientEncPubHex: slot.recipientEncPubHex });
  }
  const audit = yield* AuditStore;
  const now = yield* Clock.currentTimeMillis;
  yield* Effect.sync(() => {
    for (const ref of resolved) {
      store.write.deleteWrap(environmentId, ref.epoch, ref.recipientUserId, ref.recipientEncPubHex);
    }
    audit.appendManySync(
      resolved.map((ref) =>
        dataEvent(actor, now, {
          event: "dek.deleted",
          environmentId,
          epoch: ref.epoch,
          ...dekRecipientTarget(ref),
        }),
      ),
    );
  });
});

export const listMyDekWrapsProgram = Effect.fn("programs-dek.listMyDekWrapsProgram")(function* (
  actor: DataActor,
  environmentId: EnvironmentId,
  cache: StateCache,
) {
  yield* requireEnvironmentAccess(actor.userId, "reader", environmentId, cache);
  yield* requireActiveEnvironment(environmentId);
  const store = yield* DataStore;
  return yield* store.listWrapsForRecipient(environmentId, actor.userId);
});
