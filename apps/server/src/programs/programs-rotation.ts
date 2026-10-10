// Effect programs for the needs-rotation flags (AUDIT_SPEC §4.1 / §6
// / §7).
//
// - flags: the derived view of §4.1 step 5. Visibility is class 1
//   (chain role reader or above = all members — §6; detection's
//   purpose is prompting upstream credential rotation)
// - dismiss: a dedicated operation for rotation.dismissed (§7 — no
//   raw-event append API is made). admin or above (§3.3 — a
//   governance operation at the same level as wrap deletion).
//   Dismissal to a pair with no active flag is a 404 (no silent
//   success)
//
// The permit-serialization premise is the same as the other
// programs-*. Derivation is a fold over the event sequence only (no
// mutable store of flags — §4.1).

import type { EnvironmentId, VariableId } from "@maruhi/core";
import { Clock, Effect } from "effect";

import { AuditStore } from "../audit-store.ts";
import type { DataActor } from "../data/data-plane.ts";
import { dataEvent, rejectData, requireMemberState } from "../data/data-plane.ts";
import type { StateCache } from "../do/chain-store.ts";
import { MAX_ROTATION_DISMISSALS_PER_REQUEST } from "../policy.ts";
import type { EffectiveRotationFlag } from "../rotation-detect.ts";
import { deriveEffectiveFlags } from "../rotation-detect.ts";

/** A dismissal target (crosses the RPC boundary). */
export interface RotationDismissTargetInput {
  readonly environmentId: EnvironmentId;
  readonly variableId: VariableId;
}

const pairKey = (target: { readonly environmentId: string; readonly variableId: string }): string =>
  `${target.environmentId} ${target.variableId}`;

export const rotationFlagsProgram = Effect.fn("programs-rotation.rotationFlagsProgram")(function* (
  actor: DataActor,
  cache: StateCache,
) {
  yield* requireMemberState(actor.userId, "reader", cache);
  const audit = yield* AuditStore;
  return yield* Effect.sync((): readonly EffectiveRotationFlag[] =>
    deriveEffectiveFlags(audit.readRotationSync.rotationFlagEvents()),
  );
});

export const dismissRotationFlagsProgram = Effect.fn(
  "programs-rotation.dismissRotationFlagsProgram",
)(function* (actor: DataActor, targets: readonly RotationDismissTargetInput[], cache: StateCache) {
  // Dismissal carries an environment coordinate but does not
  // consult scope (a governance operation absent from AUTH_SPEC
  // §12-3's table — AUDIT_SPEC §3.3 / §6: the flag view is class 1
  // with no environment axis in the visibility predicate, and
  // dismissal is an admin's decision; design record §9 K3-C).
  // The only write that still keeps requireMemberState on a path
  // carrying an environment coordinate
  yield* requireMemberState(actor.userId, "admin", cache);
  if (targets.length > MAX_ROTATION_DISMISSALS_PER_REQUEST) {
    return yield* rejectData({
      kind: "limit-exceeded",
      resource: "rotation-dismissals-per-request",
      limit: MAX_ROTATION_DISMISSALS_PER_REQUEST,
    });
  }
  const audit = yield* AuditStore;
  const live = new Set(
    deriveEffectiveFlags(audit.readRotationSync.rotationFlagEventsFor(targets)).map(pairKey),
  );
  // Duplicate pairs are folded into one (dismissal semantics are
  // idempotent per pair — one request, one event per pair). A pair
  // with no active flag rejects the whole request all-or-nothing
  const deduped: RotationDismissTargetInput[] = [];
  const seen = new Set<string>();
  for (const target of targets) {
    const key = pairKey(target);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    if (!live.has(key)) {
      return yield* rejectData({
        kind: "rotation-flag-not-found",
        environmentId: target.environmentId,
        variableId: target.variableId,
      });
    }
    deduped.push(target);
  }
  const now = yield* Clock.currentTimeMillis;
  // The write phase (a single task): one rotation.dismissed row
  // per pair (AUDIT_SPEC §3.3 — the actor is the dismisser
  // themselves)
  yield* Effect.sync(() => {
    audit.appendManySync(
      deduped.map((target) =>
        dataEvent(actor, now, {
          event: "rotation.dismissed",
          environmentId: target.environmentId,
          variableId: target.variableId,
        }),
      ),
    );
  });
});
