// The evacuation's write-out (DO → R2 — docs/notes/hosted-ops.md §2-D /
// §4-2): every table read under the DO's permit and written as gzipped
// NDJSON lines (do-snapshot.ts's format), uploaded to R2 in equal-size
// parts. Run by do-ops.ts's backupProgram.

import { Effect } from "effect";

import { OPS_SNAPSHOT_PART_BYTES, OPS_SNAPSHOT_ROW_PAGE } from "../ops/ops-policy.ts";
import type {
  SnapshotHeader,
  SnapshotRowLine,
  SnapshotTableLine,
  SnapshotTrailer,
} from "./do-snapshot.ts";
import {
  encodeScalar,
  readWatermarks,
  SNAPSHOT_FORMAT,
  SNAPSHOT_FORMAT_VERSION,
  snapshotTableOrder,
} from "./do-snapshot.ts";

/**
 * A sink that writes to R2 while gzip-compressing. Each time one part's
 * worth of compressed output accumulates it is sent as a multipart part;
 * when the total is under the part length, a single put finishes it. On
 * failure the multipart upload is aborted (the bucket lifecycle rule also
 * cleans up incomplete uploads).
 */
class GzipObjectWriter {
  readonly #encoder = new TextEncoder();
  readonly #compressor = new CompressionStream("gzip");
  readonly #writer: WritableStreamDefaultWriter<BufferSource>;
  readonly #drain: Promise<void>;
  #pending: Uint8Array[] = [];
  #pendingBytes = 0;
  #upload: R2MultipartUpload | null = null;
  readonly #parts: R2UploadedPart[] = [];
  #totalBytes = 0;
  #drainError: unknown = null;

  constructor(
    private readonly bucket: R2Bucket,
    private readonly key: string,
    private readonly partBytes: number,
  ) {
    this.#writer = this.#compressor.writable.getWriter();
    this.#drain = this.#drainCompressed().catch((error: unknown) => {
      this.#drainError = error;
    });
  }

  async writeLine(line: string): Promise<void> {
    if (this.#drainError !== null) {
      throw this.#drainError;
    }
    await this.#writer.write(this.#encoder.encode(`${line}\n`));
  }

  async finish(): Promise<{ readonly bytes: number }> {
    await this.#writer.close();
    await this.#drain;
    if (this.#drainError !== null) {
      throw this.#drainError;
    }
    const last = this.#takePending();
    if (this.#upload === null) {
      await this.bucket.put(this.key, last);
    } else {
      // When the compressed total is an exact multiple of partBytes, the
      // remainder is 0 bytes — R2 rejects an empty part, so don't send it
      if (last.byteLength > 0) {
        this.#parts.push(await this.#upload.uploadPart(this.#parts.length + 1, last));
      }
      await this.#upload.complete(this.#parts);
    }
    return { bytes: this.#totalBytes };
  }

  async abort(): Promise<void> {
    if (this.#upload !== null) {
      await this.#upload.abort();
    }
  }

  async #drainCompressed(): Promise<void> {
    const reader = this.#compressor.readable.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        return;
      }
      this.#pending.push(value);
      this.#pendingBytes += value.byteLength;
      this.#totalBytes += value.byteLength;
      // R2 multipart requires **the same size** for every part except the
      // last (r2/api/workers/workers-multipart-usage), so carve out exactly
      // partBytes each time
      while (this.#pendingBytes >= this.partBytes) {
        this.#upload ??= await this.bucket.createMultipartUpload(this.key);
        this.#parts.push(
          await this.#upload.uploadPart(this.#parts.length + 1, this.#takeExact(this.partBytes)),
        );
      }
    }
  }

  #takePending(): Uint8Array {
    return this.#takeExact(this.#pendingBytes);
  }

  /** Carve out n bytes from the front (the remainder goes back to pending). */
  #takeExact(n: number): Uint8Array {
    const merged = new Uint8Array(this.#pendingBytes);
    let offset = 0;
    for (const chunk of this.#pending) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const part = merged.slice(0, n);
    const rest = merged.slice(n);
    this.#pending = rest.byteLength === 0 ? [] : [rest];
    this.#pendingBytes = rest.byteLength;
    return part;
  }
}

export interface WriteSnapshotInput {
  readonly sql: SqlStorage;
  readonly tables: readonly string[];
  readonly schemaVersion: number;
  readonly doIdHex: string;
  readonly takenAtMs: number;
  readonly bucket: R2Bucket;
  readonly key: string;
  /** For tests (default is policy's 16 MiB). */
  readonly partBytes?: number;
}

export interface WriteSnapshotResult {
  readonly bytes: number;
  readonly trailer: SnapshotTrailer;
}

/** The evacuation's key (contains no project ID — image of the DO id + taken-at time). */
export function snapshotObjectKey(prefix: string, doIdHex: string, takenAtMs: number): string {
  const stamp = new Date(takenAtMs).toISOString().replaceAll(":", "-");
  return `${prefix}/${doIdHex}/${stamp}.ndjson.gz`;
}

/**
 * Reads out all tables and writes to R2 (the caller must hold the
 * permit). Reads one page at a time, synchronously, per table via a
 * rowid keyset (no cursor is held across awaits). Every failure is a
 * defect (a rejected write, a failed upload); the in-flight multipart
 * upload is aborted on it (the bucket lifecycle rule also cleans up
 * incomplete uploads).
 */
export function writeSnapshot(input: WriteSnapshotInput): Effect.Effect<WriteSnapshotResult> {
  const { sql } = input;
  const writer = new GzipObjectWriter(
    input.bucket,
    input.key,
    input.partBytes ?? OPS_SNAPSHOT_PART_BYTES,
  );
  return Effect.gen(function* () {
    const header: SnapshotHeader = {
      kind: "header",
      format: SNAPSHOT_FORMAT,
      version: SNAPSHOT_FORMAT_VERSION,
      schemaVersion: input.schemaVersion,
      takenAtMs: input.takenAtMs,
      doIdHex: input.doIdHex,
    };
    yield* Effect.promise(() => writer.writeLine(JSON.stringify(header)));
    const rows: Record<string, number> = {};
    for (const table of snapshotTableOrder(input.tables)) {
      const columns = sql.exec(`SELECT * FROM ${table} LIMIT 0`).columnNames;
      const tableLine: SnapshotTableLine = { kind: "table", table, columns };
      yield* Effect.promise(() => writer.writeLine(JSON.stringify(tableLine)));
      let count = 0;
      let lastRowid = -1;
      for (;;) {
        const page = Array.from(
          sql
            .exec(
              `SELECT rowid AS __rid, * FROM ${table} WHERE rowid > ? ORDER BY rowid LIMIT ?`,
              lastRowid,
              OPS_SNAPSHOT_ROW_PAGE,
            )
            .raw(),
        );
        for (const raw of page) {
          const [rowid, ...values] = raw;
          lastRowid = Number(rowid);
          const rowLine: SnapshotRowLine = {
            kind: "row",
            table,
            values: values.map(encodeScalar),
          };
          yield* Effect.promise(() => writer.writeLine(JSON.stringify(rowLine)));
          count += 1;
        }
        if (page.length < OPS_SNAPSHOT_ROW_PAGE) {
          break;
        }
      }
      rows[table] = count;
    }
    const marks = readWatermarks(sql);
    const trailer: SnapshotTrailer = {
      kind: "trailer",
      rows,
      chainHeadSeq: marks.chainHeadSeq,
      chainHeadHashHex: marks.chainHeadHashHex,
      auditMaxSeq: marks.auditMaxSeq,
      auditHeadHashHex: marks.auditHeadHashHex,
      databaseSizeBytes: sql.databaseSize,
    };
    yield* Effect.promise(() => writer.writeLine(JSON.stringify(trailer)));
    const { bytes } = yield* Effect.promise(() => writer.finish());
    return { bytes, trailer };
  }).pipe(Effect.onError(() => Effect.promise(() => writer.abort())));
}
