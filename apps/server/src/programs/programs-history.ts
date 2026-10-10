// Effect programs for a variable's version history (AUTH_SPEC §12-7 —
// 2026-09-27 VH, design record docs/notes/vh-design.md ruling V3).
//
// - history: every stored version's metadata (no ciphertext, no DEK ⇒ no
//   var.read — AUDIT_SPEC §3.3) plus the per-version flagsIfCurrent, derived
//   by the same lineage fold as the flag view (rotation-detect.ts). Reader,
//   scope-agnostic (the metadata-only mode's row — every field is already on
//   class-1 audit rows or the class-1 flag view)
// - versionValues: the distributed payloads of a version range. Reader ×
//   environment ∈ scope (the with-values pull's row); one aggregate var.read
//   row enumerating every returned version

import { MAX_VERSION_VALUES_PAGE } from "@maruhi/api-schema";
import type { EnvironmentId, VariableId } from "@maruhi/core";
import { auditReadPayload, VAR_READ_EVENT } from "@maruhi/core";
import { Clock, Effect } from "effect";

import { AuditStore } from "../audit-store.ts";
import type { DataActor, PulledVariableValue } from "../data/data-plane.ts";
import {
  dataEvent,
  rejectData,
  requireEnvironmentAccess,
  requireMemberState,
} from "../data/data-plane.ts";
import type { StoredVersionMeta } from "../data/data-store.ts";
import { DataStore } from "../data/data-store.ts";
import type { StateCache } from "../do/chain-store.ts";
import { MAX_VERSION_VALUES_PAGE_BYTES } from "../policy.ts";
import { requireActiveEnvironment, requireActiveVariable } from "../quotas.ts";
import { flagsIfCurrentByVersion } from "../rotation-detect.ts";
import { observeStorageLevel } from "../storage-guard.ts";

/** One history row as the program returns it (the wire's VariableVersionHistoryEntry). */
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

/**
 * Trims a fetched page to the ciphertext byte budget (§12-7): stops before
 * the version that would exceed it, always keeping the first (a single value
 * is at most 64 KiB — §12-8 — so progress is guaranteed).
 */
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

/** Read the lineage declaration copied into a var.version_pushed payload (rows this server wrote). */
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
  // The query Schema already refuses fromVersion < 1 (400). A declared
  // variable has no version (latestVersion 0), so every fromVersion is
  // past the latest
  if (fromVersion < 1 || fromVersion > variable.latestVersion) {
    return yield* rejectData({ kind: "payload-mismatch", field: "fromVersion" });
  }
  // Same observation as the with-values pull (§12-8 — a read that writes
  // var.read rows)
  yield* observeStorageLevel;
  const store = yield* DataStore;
  const values = withinByteBudget(
    yield* store.versionRange(environmentId, variableId, fromVersion, MAX_VERSION_VALUES_PAGE),
  );
  // Audit (AUDIT_SPEC §3.3 — the aggregate form): one row per request
  // enumerating every returned version (each is a distributed ciphertext
  // the reader can decrypt). The range check above guarantees at least
  // one row
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
