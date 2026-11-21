import { MAX_VERSION_VALUES_PAGE } from "@maruhi/api-schema";
import type { EnvironmentId, VariableId } from "@maruhi/core";
import { auditReadPayload, VAR_READ_EVENT } from "@maruhi/core";
import { Clock, Effect } from "effect";

import { AuditStore } from "../audit-store.ts";
import type { DataActor, PulledVariableValue, StoredVersionMeta } from "../data.package/index.ts";
import {
  dataEvent,
  DataStore,
  rejectData,
  requireEnvironmentAccess,
  requireMemberState,
} from "../data.package/index.ts";
import type { StateCache } from "../do/chain-store.ts";
import { MAX_VERSION_VALUES_PAGE_BYTES } from "../policy.ts";
import { requireActiveEnvironment, requireActiveVariable } from "../quotas.ts";
import { flagsIfCurrentByVersion } from "../rotation-detect.ts";
import { observeStorageLevel } from "../storage-guard.ts";

export interface VariableVersionHistoryRow extends StoredVersionMeta {
  readonly sameValueAs?: number;
  readonly flagsIfCurrent: number;
}

export interface VariableVersionHistoryValue {
  readonly variableId: VariableId;
  readonly versions: readonly VariableVersionHistoryRow[];
}

export interface VariableVersionValuesValue {
  readonly variableId: VariableId;
  readonly latestVersion: number;
  readonly values: readonly PulledVariableValue[];
}

export function withinByteBudget(
  values: readonly PulledVariableValue[],
): readonly PulledVariableValue[] {
  let bytes = 0;
  const page: PulledVariableValue[] = [];
  for (const value of values) {
    bytes += value.ciphertextHex.length / 2;
    if (page.length > 0 && bytes > MAX_VERSION_VALUES_PAGE_BYTES) {
      break;
    }
    page.push(value);
  }
  return page;
}

function sameValueAsOf(payload: Readonly<Record<string, unknown>> | null): number | undefined {
  const value = payload?.["sameValueAs"];
  return typeof value === "number" && Number.isInteger(value) && value >= 1 ? value : undefined;
}

export const variableHistoryProgram = Effect.fn("programs-history.variableHistoryProgram")(
  function* (
    actor: DataActor,
    environmentId: EnvironmentId,
    variableId: VariableId,
    cache: StateCache,
  ) {
    yield* requireMemberState(actor.userId, "reader", cache);
    yield* requireActiveEnvironment(environmentId);
    yield* requireActiveVariable(environmentId, variableId);
    const store = yield* DataStore;
    const stored = yield* store.versionHistory(environmentId, variableId);
    const audit = yield* AuditStore;
    const rows = yield* Effect.sync(() =>
      audit.readRotationSync.rotationFlagEventsFor([{ environmentId, variableId }]),
    );
    const flagCounts = flagsIfCurrentByVersion(
      rows,
      stored.map((version) => version.version),
    );
    const lineage = new Map<number, number>();
    for (const row of rows) {
      const sameValueAs = sameValueAsOf(row.payload);
      if (row.event === "var.version_pushed" && row.version !== null && sameValueAs !== undefined) {
        lineage.set(row.version, sameValueAs);
      }
    }
    return {
      variableId,
      versions: stored.map((version): VariableVersionHistoryRow => {
        const sameValueAs = lineage.get(version.version);
        return {
          ...version,
          ...(sameValueAs === undefined ? {} : { sameValueAs }),
          flagsIfCurrent: flagCounts.get(version.version) ?? 0,
        };
      }),
    } satisfies VariableVersionHistoryValue;
  },
);

export const variableVersionValuesProgram = Effect.fn(
  "programs-history.variableVersionValuesProgram",
)(function* (
  actor: DataActor,
  environmentId: EnvironmentId,
  variableId: VariableId,
  fromVersion: number,
  cache: StateCache,
) {
  yield* requireEnvironmentAccess(actor.userId, "reader", environmentId, cache);
  yield* requireActiveEnvironment(environmentId);
  const variable = yield* requireActiveVariable(environmentId, variableId);
  if (fromVersion < 1 || fromVersion > variable.latestVersion) {
    return yield* rejectData({ kind: "payload-mismatch", field: "fromVersion" });
  }
  yield* observeStorageLevel;
  const store = yield* DataStore;
  const values = withinByteBudget(
    yield* store.versionRange(environmentId, variableId, fromVersion, MAX_VERSION_VALUES_PAGE),
  );
  const audit = yield* AuditStore;
  const now = yield* Clock.currentTimeMillis;
  yield* Effect.sync(() => {
    audit.appendSync(
      dataEvent(actor, now, {
        event: VAR_READ_EVENT,
        environmentId,
        payload: auditReadPayload(
          values.map((value) => ({
            variableId,
            epoch: value.epoch,
            version: value.version,
          })),
        ),
      }),
    );
  });
  return {
    variableId,
    latestVersion: variable.latestVersion,
    values,
  } satisfies VariableVersionValuesValue;
});
