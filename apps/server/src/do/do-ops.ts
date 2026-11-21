import { Effect } from "effect";

import { AuditStore } from "../audit-store.ts";
import type { StorageGuardDecision } from "../storage-guard.ts";
import { observeStorageLevel, StorageMeter, storageGuardDecision } from "../storage-guard.ts";
import type { StateCache } from "./chain-store.ts";
import {
  ensureProjectDoTables,
  PROJECT_DO_TABLES,
  readProjectDoSchemaVersion,
} from "./do-schema.ts";
import type { RestoreFailureCode } from "./do-snapshot-restore.ts";
import { RestoreRefusedError, restoreSnapshot } from "./do-snapshot-restore.ts";
import { snapshotObjectKey, writeSnapshot } from "./do-snapshot-write.ts";
import type { SnapshotTrailer } from "./do-snapshot.ts";
import { readWatermarks } from "./do-snapshot.ts";

export interface OpsBackupInput {
  readonly keyPrefix: string;
  readonly nowMs: number;
  readonly maxBytes: number;
  readonly skipIfUnchanged: {
    readonly auditSeq: number;
    readonly chainSeq: number;
    readonly attestationMark: number;
  } | null;
  readonly partBytes?: number;
}

export type OpsBackupOutcome =
  | {
      readonly kind: "uploaded";
      readonly objectKey: string;
      readonly bytes: number;
      readonly auditSeq: number;
      readonly chainSeq: number;
      readonly attestationMark: number;
      readonly storageLevel: StorageGuardDecision;
      readonly databaseSizeBytes: number;
      readonly trailer: SnapshotTrailer;
    }
  | {
      readonly kind: "skipped";
      readonly auditSeq: number;
      readonly chainSeq: number;
      readonly attestationMark: number;
      readonly storageLevel: StorageGuardDecision;
      readonly databaseSizeBytes: number;
    }
  | {
      readonly kind: "oversize";
      readonly storageLevel: StorageGuardDecision;
      readonly databaseSizeBytes: number;
    }
  | {
      readonly kind: "upload-failed";
      readonly storageLevel: StorageGuardDecision;
      readonly databaseSizeBytes: number;
    }
  | { readonly kind: "no-bucket" };

export type OpsRestoreOutcome =
  | {
      readonly kind: "restored";
      readonly rows: Readonly<Record<string, number>>;
      readonly chainHeadSeq: number;
      readonly chainHeadHashHex: string | null;
      readonly auditMaxSeq: number;
      readonly auditHeadHashHex: string;
    }
  | { readonly kind: "refused"; readonly code: RestoreFailureCode }
  | { readonly kind: "no-bucket" };

export const backupProgram = Effect.fn("do-ops.backupProgram")(function* (
  input: OpsBackupInput,
  sql: SqlStorage,
  doIdHex: string,
  bucket: R2Bucket,
): Effect.fn.Return<OpsBackupOutcome, never, StorageMeter> {
  const meter = yield* StorageMeter;
  const databaseSizeBytes = meter.databaseSizeBytes();
  const storageLevel = storageGuardDecision(databaseSizeBytes);
  const marks = readWatermarks(sql);
  if (
    input.skipIfUnchanged !== null &&
    input.skipIfUnchanged.auditSeq === marks.auditMaxSeq &&
    input.skipIfUnchanged.chainSeq === marks.chainHeadSeq &&
    input.skipIfUnchanged.attestationMark === marks.attestationMark
  ) {
    return {
      kind: "skipped",
      auditSeq: marks.auditMaxSeq,
      chainSeq: marks.chainHeadSeq,
      attestationMark: marks.attestationMark,
      storageLevel,
      databaseSizeBytes,
    } satisfies OpsBackupOutcome;
  }
  if (databaseSizeBytes > input.maxBytes) {
    return { kind: "oversize", storageLevel, databaseSizeBytes } satisfies OpsBackupOutcome;
  }
  const objectKey = snapshotObjectKey(input.keyPrefix, doIdHex, input.nowMs);
  return yield* writeSnapshot({
    sql,
    tables: PROJECT_DO_TABLES,
    schemaVersion: readProjectDoSchemaVersion(sql),
    doIdHex,
    takenAtMs: input.nowMs,
    bucket,
    key: objectKey,
    ...(input.partBytes === undefined ? {} : { partBytes: input.partBytes }),
  }).pipe(
    Effect.map((result): OpsBackupOutcome => ({
      kind: "uploaded",
      objectKey,
      bytes: result.bytes,
      auditSeq: result.trailer.auditMaxSeq,
      chainSeq: result.trailer.chainHeadSeq,
      attestationMark: marks.attestationMark,
      storageLevel,
      databaseSizeBytes,
      trailer: result.trailer,
    })),
    Effect.catchDefect((defect) =>
      Effect.logWarning(
        "project snapshot upload failed; retried on the next sweep",
        defect instanceof Error ? defect.name : "unknown",
      ).pipe(
        Effect.as<OpsBackupOutcome>({
          kind: "upload-failed",
          storageLevel,
          databaseSizeBytes,
        }),
      ),
    ),
  );
});

export function restoreBody(
  bucket: R2Bucket,
  objectKey: string,
  etag: string | undefined,
): Effect.Effect<ReadableStream, RestoreRefusedError> {
  return Effect.gen(function* () {
    const object = yield* Effect.promise(() =>
      etag === undefined
        ? bucket.get(objectKey)
        : bucket.get(objectKey, { onlyIf: { etagMatches: etag } }),
    );
    if (object === null) {
      return yield* new RestoreRefusedError({ code: "object-missing" });
    }
    const verified = "body" in object ? (object as R2ObjectBody) : null;
    if (verified === null) {
      return yield* new RestoreRefusedError({ code: "object-changed" });
    }
    return verified.body;
  });
}

export const restoreProgram = Effect.fn("do-ops.restoreProgram")(function* (
  storage: DurableObjectStorage,
  body: Effect.Effect<ReadableStream, RestoreRefusedError>,
  cache: StateCache,
): Effect.fn.Return<OpsRestoreOutcome, never, AuditStore | StorageMeter> {
  const sql = storage.sql;
  const audit = yield* AuditStore;
  const meter = yield* StorageMeter;
  const restored = yield* body.pipe(
    Effect.flatMap((stream) =>
      Effect.sync(() => ensureProjectDoTables(storage)).pipe(Effect.as(stream)),
    ),
    Effect.flatMap((stream) =>
      restoreSnapshot({
        storage,
        tables: PROJECT_DO_TABLES,
        schemaVersion: readProjectDoSchemaVersion(sql),
        body: stream,
        storesAuditHeads: () => storageGuardDecision(meter.databaseSizeBytes()) !== "reject",
      }).pipe(
        Effect.ensuring(
          Effect.sync(() => {
            cache.chain = null;
            cache.current = null;
            audit.resetSeqCacheSync();
          }),
        ),
      ),
    ),
    Effect.catchTag("RestoreRefused", (error) =>
      Effect.succeed({
        kind: "refused",
        code: error.code,
      } satisfies OpsRestoreOutcome),
    ),
  );
  if ("code" in restored) {
    return restored;
  }
  while (
    (yield* observeStorageLevel) !== "reject" &&
    (yield* audit.ensureHeadCurrent) === "more-remains"
  ) {}
  const marks = readWatermarks(sql);
  return {
    kind: "restored",
    rows: restored.rows,
    chainHeadSeq: marks.chainHeadSeq,
    chainHeadHashHex: marks.chainHeadHashHex,
    auditMaxSeq: marks.auditMaxSeq,
    auditHeadHashHex: restored.auditHeadHashHex,
  } satisfies OpsRestoreOutcome;
});
