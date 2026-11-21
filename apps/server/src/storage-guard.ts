import { Context, Effect, Layer } from "effect";

import { AuditStore } from "./audit-store.ts";
import type { DataRejectedError } from "./data.package/index.ts";
import { rejectData } from "./data.package/index.ts";
import { DO_STORAGE_REJECT_BYTES, DO_STORAGE_WARN_BYTES } from "./policy.ts";

export type StorageGuardDecision = "admit" | "warn" | "reject";

export interface StorageGuardThresholds {
  readonly warnBytes: number;
  readonly rejectBytes: number;
}

const STORAGE_GUARD_THRESHOLDS: StorageGuardThresholds = {
  warnBytes: DO_STORAGE_WARN_BYTES,
  rejectBytes: DO_STORAGE_REJECT_BYTES,
};

export function storageGuardDecision(
  databaseSizeBytes: number,
  thresholds: StorageGuardThresholds = STORAGE_GUARD_THRESHOLDS,
): StorageGuardDecision {
  if (databaseSizeBytes >= thresholds.rejectBytes) {
    return "reject";
  }
  if (databaseSizeBytes >= thresholds.warnBytes) {
    return "warn";
  }
  return "admit";
}

type StorageGuardLogLevel = "warn" | "reject";

interface StorageMeterShape {
  readonly databaseSizeBytes: () => number;
  readonly noteLogged: (level: StorageGuardLogLevel) => boolean;
}

export class StorageMeter extends Context.Service<StorageMeter, StorageMeterShape>()(
  "StorageMeter",
) {}

export function makeStorageMeter(databaseSizeBytes: () => number): StorageMeterShape {
  const logged = new Set<StorageGuardLogLevel>();
  return {
    databaseSizeBytes,
    noteLogged: (level) => {
      if (logged.has(level)) {
        return false;
      }
      logged.add(level);
      return true;
    },
  };
}

export const storageMeterLayer = (sql: SqlStorage): Layer.Layer<StorageMeter> =>
  Layer.sync(StorageMeter, () => makeStorageMeter(() => sql.databaseSize));

export const observeStorageLevel: Effect.Effect<StorageGuardDecision, never, StorageMeter> =
  Effect.gen(function* () {
    const meter = yield* StorageMeter;
    const decision = storageGuardDecision(meter.databaseSizeBytes());
    if (decision === "warn" && meter.noteLogged("warn")) {
      yield* Effect.logWarning(
        "project storage crossed the warning threshold (AUTH_SPEC §12-8 DO storage guard); growth writes are still accepted until the rejection threshold",
      );
    }
    if (decision === "reject" && meter.noteLogged("reject")) {
      yield* Effect.logError(
        "project storage reached the rejection threshold (AUTH_SPEC §12-8 DO storage guard); growth writes are rejected until space is freed — reads, deletions, revocations and rotations remain accepted",
      );
    }
    return decision;
  });

export const ensureStorageAdmitsGrowth: Effect.Effect<void, DataRejectedError, StorageMeter> =
  Effect.gen(function* () {
    if ((yield* observeStorageLevel) !== "reject") {
      return;
    }
    return yield* rejectData({
      kind: "limit-exceeded",
      resource: "project-storage-bytes",
      limit: DO_STORAGE_REJECT_BYTES,
    });
  });

export const ensureStorageAdmitsAuditHeadExtension: Effect.Effect<
  void,
  DataRejectedError,
  StorageMeter | AuditStore
> = Effect.gen(function* () {
  const audit = yield* AuditStore;
  if (audit.headColumnBehindSync()) {
    yield* ensureStorageAdmitsGrowth;
  }
});
