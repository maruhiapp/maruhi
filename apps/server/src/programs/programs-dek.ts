// Effect programs for DEK-wrap registration, distribution, and repair
// (AUTH_SPEC §12-6).
//
// The body of acceptance checking (recipients, the set, the
// registration signature, the row-count cap) lives in dek-wraps.ts.
// The permit-serialization premise is the same as the former
// data-programs.ts.

import type { EnvironmentId } from "@maruhi/core";
import { Clock, Effect } from "effect";

import { AuditStore } from "../audit-store.ts";
import type {
  DataActor,
  DekRecipientPosition,
  DekWrapInput,
  DekWrapRefInput,
} from "../data/data-plane.ts";
import {
  currentEpochOf,
  dataEvent,
  dekRecipientTarget,
  ensureDevicePermission,
  rejectData,
  requireEnvironmentAccess,
  roleAtLeast,
} from "../data/data-plane.ts";
import { DataStore } from "../data/data-store.ts";
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
  // The registrant (the signer = the caller — §12-6 (1)) must also
  // have the target environment in scope (the tail of §12-6 — the
  // same scope check of the caller as §12-3's → 403; distinct from
  // the recipient-axis 422 scope-out-of-range, and this one comes
  // first). The role floor is reader — except for a reader's own
  // backfill (§12-3 — 2026-09-19 DK: all recipients are the caller's
  // own device keys), member-or-above is required immediately after
  // (design record §8 K3-5)
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
  // The DO storage-total guard (§12-8): registration (backfill,
  // repair re-registration) is a growth surface (after the existence
  // check, before the set / registration-signature checks). Deletion
  // (deleteDekWrapsProgram) does not call it — it must not plug the
  // release path
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
    // Unreachable: the wire Schema enforces at least one entry (an
    // empty deks is a 400)
    return yield* rejectData({ kind: "dek-wrap-rejected", reason: "recipient-missing" });
  }
  // Stage 2 (design record §8 K3-1): re-check role / scope against
  // the signing device's effective permission
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

/** The stored slot a deletion reference points at (device key may be omitted — design record §8 K3-3). */
type ResolvedWrapRef = DekRecipientPosition & {
  readonly epoch: number;
  readonly recipientEncPubHex: string;
};

/**
 * §12-6's repair path: an admin deletes wraps per (environment,
 * epoch, recipient, device key) tuple. With overwrite prohibition
 * (blocking availability attacks) kept intact, poisoned wraps are
 * deleted and then re-registered via the append path for the missing
 * part. A nonexistent tuple is a 404 (no silent success).
 */
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
    // Compare against the stored row's recipient class: the
    // client-declared class must not be used as-is for choosing the
    // audit column (the dek.deleted distinction below). A mismatch
    // = no wrap of that class exists (treated the same as a 404 —
    // no silent success). This also guarantees that one of two
    // "same (epoch, recipient) refs with different classes" always
    // fails here, and simultaneously closes the shape where one
    // row's deletion would stack two audit rows
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
  // The write phase (a single task): writes the deletion and the
  // dek.deleted (one row per recipient — AUDIT_SPEC §3.3)
  // atomically
  yield* Effect.sync(() => {
    for (const ref of resolved) {
      store.write.deleteWrap(environmentId, ref.epoch, ref.recipientUserId, ref.recipientEncPubHex);
    }
    audit.appendManySync(
      resolved.map((ref) =>
        // A server recipient has no user_id, so the FP rides on
        // target_key_fingerprint (the same distinction as
        // dek.registered — dek-wraps.ts; AUDIT_SPEC §3.3).
        // Using ref's class here is sound because the check phase
        // above already confirmed it matches the stored row's
        // recipient_class
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
  // Fetching one's own DEK requires environment ∈ scope (§12-3's
  // "bulk pull (with values) / own-DEK fetch" row). Wraps addressed
  // to out-of-scope members are never accepted by §12-6, so the
  // result is normally empty — but the acceptance surface's 403
  // makes "do not distribute" structural (fail-closed).
  // The response is the rows addressed to all of one's own devices
  // (each carrying the device key's recipientEncPubHex — a recipient
  // unseals only the rows for its own device key)
  yield* requireEnvironmentAccess(actor.userId, "reader", environmentId, cache);
  yield* requireActiveEnvironment(environmentId);
  const store = yield* DataStore;
  return yield* store.listWrapsForRecipient(environmentId, actor.userId);
});
