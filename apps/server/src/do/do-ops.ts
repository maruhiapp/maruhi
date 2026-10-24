// The project DO's side of the ops RPC (hosted-ops.md §2-D / §2-E): the
// evacuation of every table to R2 and the restore from one, which
// chain-do.ts's opsBackup / opsRestore run under the DO's permit. Called
// only from inside the worker (the cron sweep, the restore worker); no HTTP
// handler calls them. Writing a snapshot is do-snapshot-write.ts, restoring
// one do-snapshot-restore.ts.

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
  /** The object key's prefix (`do`). The project ID never appears on the key. */
  readonly keyPrefix: string;
  readonly nowMs: number;
  /** A DO larger than this is not evacuated (oversize). */
  readonly maxBytes: number;
  /**
   * The watermark of the last success (audit seq, chain seq, the latest
   * acceptance time of a head attestation). Skip when all three match
   * (null = always evacuate).
   */
  readonly skipIfUnchanged: {
    readonly auditSeq: number;
    readonly chainSeq: number;
    readonly attestationMark: number;
  } | null;
  /** For tests: the multipart part length. */
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
      /** The audit head at the restored log's end, as the derivation computed it — stored or not past the storage guard's line (empty string when no audit rows). */
      readonly auditHeadHashHex: string;
    }
  | { readonly kind: "refused"; readonly code: RestoreFailureCode }
  | { readonly kind: "no-bucket" };

/**
 * The DO → R2 evacuation, run by opsBackup under the permit (= all tables
 * consistent). Reading and writing is do-snapshot-write.ts. The census (the
 * AUTH_SPEC §12-8 judgment) shares the existing meter and pure function
 * (feeding into the §12-8 warning line — hosted-ops.md §2-C; the warning
 * line's wording and once-only discipline are unchanged).
 * An evacuation failure is returned as a static code (retried on the
 * next sweep).
 */
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
    // Every evacuation failure is a defect (do-snapshot-write.ts); it is
    // answered with the static code and retried on the next sweep
    Effect.catchDefect((defect) =>
      // A static message only (up to the class name). The
      // record lives in the worker-side D1
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

/**
 * The evacuation body opsRestore restores, fetched from the bucket. An
 * import restores the body its pre-check verified, by its etag (ruling H
 * revision, round 4): a re-put between the two reads is refused, never
 * restored unchecked.
 */
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
    // A precondition failure answers the object without a body
    const verified = "body" in object ? (object as R2ObjectBody) : null;
    if (verified === null) {
      return yield* new RestoreRefusedError({ code: "object-changed" });
    }
    return verified.body;
  });
}

/**
 * The restore of one evacuation body into this (empty) DO, under the
 * caller's permit (opsRestore; storage-guard.test.ts runs it under a
 * fixed-size meter). The derivation stores heads, and the convergence
 * after it extends the column, only below the storage guard's rejection
 * threshold (AUTH_SPEC §11-7 / §12-8); the head reported is the one the
 * derivation computed, stored or not.
 */
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
      Effect.sync(() =>
        // A restore materializes a fresh destination DO (hosted-ops.md §2-E):
        // the restore reads and writes the schema's tables (isProjectDoEmpty,
        // wipe, acceptColumns), so create them (Sc-7 / A-4 — a fresh
        // destination holds none; idempotent on a re-run into an empty DO).
        // Created only **after** the object is fetched, so an object-missing /
        // object-changed refusal leaves the destination with no tables.
        ensureProjectDoTables(storage),
      ).pipe(Effect.as(stream)),
    ),
    Effect.flatMap((stream) =>
      restoreSnapshot({
        storage,
        tables: PROJECT_DO_TABLES,
        schemaVersion: readProjectDoSchemaVersion(sql),
        body: stream,
        storesAuditHeads: () => storageGuardDecision(meter.databaseSizeBytes()) !== "reject",
      }).pipe(
        // Discard the memory regardless of success or failure (no
        // residue of a partial restore is handed out either)
        Effect.ensuring(
          Effect.sync(() => {
            cache.chain = null;
            cache.current = null;
            audit.resetSeqCacheSync();
          }),
        ),
      ),
    ),
    // A refusal is answered, never thrown past the permit
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
  // Extend the audit-head row to the end (bounded extension — a one-time
  // operation at restore, so run it to convergence) below the same line
  while (
    (yield* observeStorageLevel) !== "reject" &&
    (yield* audit.ensureHeadCurrent) === "more-remains"
  ) {
    // Always terminates because each call makes progress (the bounded
    // contract of audit-store.ts)
  }
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
