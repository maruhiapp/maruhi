import type { EnvironmentId, VariableId } from "@maruhi/core";
import { Clock, Effect } from "effect";

import { AuditStore } from "../audit-store.ts";
import type { DataActor } from "../data.package/index.ts";
import { dataEvent, rejectData, requireMemberState } from "../data.package/index.ts";
import type { StateCache } from "../do/chain-store.ts";
import { MAX_ROTATION_DISMISSALS_PER_REQUEST } from "../policy.ts";
import type { EffectiveRotationFlag } from "../rotation-detect.ts";
import { deriveEffectiveFlags } from "../rotation-detect.ts";

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
