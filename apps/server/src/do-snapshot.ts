// Evacuation (DO → R2) and restore of the project DO —
// docs/notes/hosted-ops.md §2-D / §2-E / §4-2.
//
// Shape of an evacuation: an object of gzipped NDJSON. Line kinds:
//   header  … format, schema version, taken-at time, DO id (image of
//           `idFromName` — one-way)
//   table   … table name + column names (the order of `values` in the
//             row lines that follow)
//   row     … table name + value array (number / string / null; a BLOB
//             is { b64 } — the current schema has no BLOB columns, but
//             the value-type coverage is kept)
//   trailer … per-table row counts, chain head, audit seq, audit head
//             hex (only when the column is current — no materialization
//             write is performed), databaseSize
// A missing trailer = an evacuation that failed midway, and the restore
// side refuses it.
//
// Discipline:
// - **Do not put the project ID in the key, header, or metadata**
//   (AUTH_SPEC §11-2 — capability). It is derivable from the chain
//   genesis inside the content (which is the DO's own content)
// - Reads run under the DO's permit (chain-do.ts): rowid keyset + LIMIT,
//   one statement at a time, synchronously `toArray()`. A cursor is not
//   held across awaits (storage-api docs: after an await a cursor can
//   observe later changes). Because the permit stops changes, tables are
//   consistent with each other
// - No additional encryption (CLAUDE.md — do not implement crypto
//   operations not in the spec. The content stays in the same shape it
//   has in the DO: E2EE ciphertext + public metadata)
// - Restore writes **only into an empty DO (empty chain_entries)**.
//   Since chain_entries is the last table in the evacuation, a restore
//   that fails midway holds no chain and stays "uninitialized"; reruns
//   wipe the non-chain tables and redo (no overwrite path exists)

import {
  OPS_RESTORE_BATCH_ROWS,
  OPS_SNAPSHOT_PART_BYTES,
  OPS_SNAPSHOT_ROW_PAGE,
} from "./ops-policy.ts";

export const SNAPSHOT_FORMAT = "maruhi-do-snapshot";
export const SNAPSHOT_FORMAT_VERSION = 1;

/** DO SQLite bound-parameter limit (per statement — durable-objects/platform/limits). */
export const MAX_BOUND_PARAMETERS = 100;

export type SnapshotScalar = number | string | null | { readonly b64: string };

export interface SnapshotHeader {
  readonly kind: "header";
  readonly format: typeof SNAPSHOT_FORMAT;
  readonly version: typeof SNAPSHOT_FORMAT_VERSION;
  readonly schemaVersion: number;
  readonly takenAtMs: number;
  readonly doIdHex: string;
}

export interface SnapshotTableLine {
  readonly kind: "table";
  readonly table: string;
  readonly columns: readonly string[];
}

export interface SnapshotRowLine {
  readonly kind: "row";
  readonly table: string;
  readonly values: readonly SnapshotScalar[];
}

export interface SnapshotTrailer {
  readonly kind: "trailer";
  readonly rows: Readonly<Record<string, number>>;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string | null;
  readonly auditMaxSeq: number;
  /** Only when the cumulative-hash column (audit_head_hashes) has reached MAX(seq). */
  readonly auditHeadHashHex: string | null;
  readonly databaseSizeBytes: number;
}

export type SnapshotLine = SnapshotHeader | SnapshotTableLine | SnapshotRowLine | SnapshotTrailer;

// ---------------------------------------------------------------------------
// Watermarks (input to the skip rules — hosted-ops §2-D)
// ---------------------------------------------------------------------------

export interface DoWatermarks {
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string | null;
  readonly auditMaxSeq: number;
  readonly auditHeadHashHex: string | null;
  /**
   * Latest acceptance time of a head attestation (head_attestations); 0
   * when none. An attestation upsert writes neither chain rows nor audit
   * rows (AUTH_SPEC §16-1), so under a skip rule based on audit / chain
   * seq alone, a project where only attestations move would go unevacuated
   * for up to 7 days.
   */
  readonly attestationMark: number;
  /** The deployment-local mutation counter (mutation_state — every write entry point bumps it). */
  readonly mutationSeq: number;
}

/** The mutation counter (0 before the first write on this deployment). */
function readMutationSeq(sql: SqlStorage): number {
  const row = sql.exec("SELECT seq FROM mutation_state WHERE id = 1").toArray()[0];
  return row === undefined ? 0 : Number(row["seq"]);
}

/**
 * Advances the mutation counter (called by the DO after a write entry
 * point succeeded, by the mint, and inside a replica commit). The
 * counter is what a paged export compares between pages (`ExportMarks`),
 * so every path that changes a snapshot table other than the rate-limit,
 * binding and attestation tables must pass here.
 */
export function bumpMutationSeq(sql: SqlStorage): void {
  sql.exec(
    "INSERT INTO mutation_state (id, seq) VALUES (1, 1) ON CONFLICT(id) DO UPDATE SET seq = seq + 1",
  );
}

function maxSeq(sql: SqlStorage, table: string): number {
  const row = sql.exec(`SELECT COALESCE(MAX(seq), 0) AS m FROM ${table}`).one();
  return Number(row["m"]);
}

export function readWatermarks(sql: SqlStorage): DoWatermarks {
  const chainHeadSeq = maxSeq(sql, "chain_entries");
  const head = sql
    .exec("SELECT entry_hash_hex FROM chain_entries ORDER BY seq DESC LIMIT 1")
    .toArray()[0];
  const auditMaxSeq = maxSeq(sql, "audit_events");
  const headColumnSeq = maxSeq(sql, "audit_head_hashes");
  const auditHead =
    headColumnSeq === auditMaxSeq
      ? sql
          .exec("SELECT head_hash_hex FROM audit_head_hashes ORDER BY seq DESC LIMIT 1")
          .toArray()[0]
      : undefined;
  const attestation = sql
    .exec("SELECT COALESCE(MAX(accepted_at), 0) AS m FROM head_attestations")
    .one();
  return {
    chainHeadSeq,
    chainHeadHashHex: head === undefined ? null : String(head["entry_hash_hex"]),
    auditMaxSeq,
    attestationMark: Number(attestation["m"]),
    auditHeadHashHex:
      auditMaxSeq === 0 ? "" : auditHead === undefined ? null : String(auditHead["head_hash_hex"]),
    mutationSeq: readMutationSeq(sql),
  };
}

/** The audit head at a given seq (the paged export's trailer — the mark, not the live maximum); null when the column has not reached it. */
function auditHeadHashAt(sql: SqlStorage, seq: number): string | null {
  if (seq === 0) {
    return "";
  }
  const row = sql
    .exec("SELECT head_hash_hex FROM audit_head_hashes WHERE seq = ?", seq)
    .toArray()[0];
  return row === undefined ? null : String(row["head_hash_hex"]);
}

/** Whether chain_entries is empty (the restore acceptance condition — creates no overwrite path). */
function isProjectDoEmpty(sql: SqlStorage): boolean {
  return sql.exec(`SELECT 1 FROM ${CHAIN_TABLE} LIMIT 1`).toArray().length === 0;
}

export const CHAIN_TABLE = "chain_entries";
/** The restore staging table for chain_entries. Not listed in `tables`,
 * so it never appears in evacuations; leftovers are DROPped at the start
 * / completion / failure of the next restore.
 */
const CHAIN_STAGING_TABLE = "chain_entries_restore";

// ---------------------------------------------------------------------------
// Evacuation (write-out)
// ---------------------------------------------------------------------------

/** Table order in the evacuation: chain_entries **last** (the basis of restore's "chain comes last" rule). */
function snapshotTableOrder(tables: readonly string[]): readonly string[] {
  return [...tables.filter((t) => t !== CHAIN_TABLE), CHAIN_TABLE];
}

function encodeScalar(value: unknown): SnapshotScalar {
  if (value === null || typeof value === "number" || typeof value === "string") {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    let binary = "";
    for (const byte of new Uint8Array(value)) {
      binary += String.fromCharCode(byte);
    }
    return { b64: btoa(binary) };
  }
  throw new Error("unsupported SQLite value type in snapshot");
}

export function decodeScalar(value: SnapshotScalar): number | string | null | ArrayBuffer {
  if (value !== null && typeof value === "object") {
    const binary = atob(value.b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
  return value;
}

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
 * rowid keyset (no cursor is held across awaits).
 */
export async function writeSnapshot(input: WriteSnapshotInput): Promise<WriteSnapshotResult> {
  const { sql } = input;
  const writer = new GzipObjectWriter(
    input.bucket,
    input.key,
    input.partBytes ?? OPS_SNAPSHOT_PART_BYTES,
  );
  try {
    const header: SnapshotHeader = {
      kind: "header",
      format: SNAPSHOT_FORMAT,
      version: SNAPSHOT_FORMAT_VERSION,
      schemaVersion: input.schemaVersion,
      takenAtMs: input.takenAtMs,
      doIdHex: input.doIdHex,
    };
    await writer.writeLine(JSON.stringify(header));
    const rows: Record<string, number> = {};
    for (const table of snapshotTableOrder(input.tables)) {
      const columns = sql.exec(`SELECT * FROM ${table} LIMIT 0`).columnNames;
      const tableLine: SnapshotTableLine = { kind: "table", table, columns };
      await writer.writeLine(JSON.stringify(tableLine));
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
          await writer.writeLine(JSON.stringify(rowLine));
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
    await writer.writeLine(JSON.stringify(trailer));
    const { bytes } = await writer.finish();
    return { bytes, trailer };
  } catch (error) {
    await writer.abort();
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Paged export (the owner-side transport of PF3 — AUTH_SPEC §11-6,
// docs/notes/pf3-design.md rulings A–D). The same lines as the
// evacuation, read one page at a time under the permit (one synchronous
// call per page — no permit across awaits), with the project's
// watermarks carried in the cursor so a change between pages is refused
// rather than silently exported as a mixed state.
// ---------------------------------------------------------------------------

/**
 * The marks a cursor binds. The chain head, the attestation mark and the
 * mutation counter must not move between pages (the export restarts);
 * `auditMaxSeq` is the **bound** of the exported audit log (rows past it
 * are the reads served while the export ran — they are not exported and
 * do not restart it; ruling C revision, docs/notes/pf3-design.md §8).
 */
export interface ExportMarks {
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string | null;
  readonly auditMaxSeq: number;
  readonly attestationMark: number;
  readonly mutationSeq: number;
}

/** The tables whose rows the export bounds by `auditMaxSeq` (the log and its cumulative-hash column). */
const AUDIT_SEQ_TABLES: ReadonlySet<string> = new Set(["audit_events", "audit_head_hashes"]);

/** The stateless page cursor (opaque to the client — base64url JSON on the wire). */
export interface ExportCursorState {
  /** Index into the evacuation's table order (chain_entries last). */
  readonly table: number;
  /** Whether the current table's `table` line was already emitted. */
  readonly started: boolean;
  /** The last rowid emitted of the current table (-1 = none). */
  readonly rowid: number;
  /** Rows emitted so far per table (the trailer's counts). */
  readonly rows: Readonly<Record<string, number>>;
  readonly marks: ExportMarks;
  /**
   * The seq of the `project.exported` row the first page appended (ruling
   * D revision): a later page is served only to the requester that row
   * names, and only while the row still says what the cursor says.
   */
  readonly exportedSeq: number;
}

function marksOf(sql: SqlStorage): ExportMarks {
  const marks = readWatermarks(sql);
  return {
    chainHeadSeq: marks.chainHeadSeq,
    chainHeadHashHex: marks.chainHeadHashHex,
    auditMaxSeq: marks.auditMaxSeq,
    attestationMark: marks.attestationMark,
    mutationSeq: marks.mutationSeq,
  };
}

/** Whether a cursor's marks still describe the project (`auditMaxSeq` is a bound, not compared). */
function sameMarks(a: ExportMarks, b: ExportMarks): boolean {
  return (
    a.chainHeadSeq === b.chainHeadSeq &&
    a.chainHeadHashHex === b.chainHeadHashHex &&
    a.attestationMark === b.attestationMark &&
    a.mutationSeq === b.mutationSeq
  );
}

function base64UrlEncode(text: string): string {
  // A cursor is well under a kilobyte, so the byte-by-byte binary string is cheap
  const binary = Array.from(new TextEncoder().encode(text), (byte) =>
    String.fromCharCode(byte),
  ).join("");
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function base64UrlDecode(text: string): string | null {
  const padded = text
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(text.length / 4) * 4, "=");
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

export function encodeExportCursor(state: ExportCursorState): string {
  return base64UrlEncode(JSON.stringify(state));
}

function isRecordOfNumbers(value: unknown): value is Readonly<Record<string, number>> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.values(value).every((count) => typeof count === "number")
  );
}

/** null = not a cursor this server produced (the client starts over). */
export function decodeExportCursor(text: string): ExportCursorState | null {
  const json = base64UrlDecode(text);
  if (json === null) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) {
    return null;
  }
  const candidate = parsed as Partial<ExportCursorState>;
  const marks = decodeMarks(candidate.marks);
  // Positions are embedded in SQL (the rowid) or index the table order:
  // only non-negative integers (rowid ≥ -1) pass — anything else is not a
  // cursor this server produced
  if (
    !isIntegerAtLeast(candidate.table, 0) ||
    typeof candidate.started !== "boolean" ||
    !isIntegerAtLeast(candidate.rowid, -1) ||
    !isRecordOfNumbers(candidate.rows) ||
    !isIntegerAtLeast(candidate.exportedSeq, 1) ||
    marks === null
  ) {
    return null;
  }
  return {
    table: candidate.table,
    started: candidate.started,
    rowid: candidate.rowid,
    rows: candidate.rows,
    exportedSeq: candidate.exportedSeq,
    marks,
  };
}

function isIntegerAtLeast(value: unknown, floor: number): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= floor;
}

/** The cursor's marks, each of its declared type (null = not a cursor this server produced). */
function decodeMarks(value: unknown): ExportMarks | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const marks = value as Partial<ExportMarks>;
  const { chainHeadHashHex } = marks;
  const numbers = [marks.chainHeadSeq, marks.attestationMark, marks.mutationSeq];
  if (
    !numbers.every((number) => typeof number === "number") ||
    (chainHeadHashHex !== null && typeof chainHeadHashHex !== "string") ||
    !isIntegerAtLeast(marks.auditMaxSeq, 0)
  ) {
    return null;
  }
  const [chainHeadSeq = 0, attestationMark = 0, mutationSeq = 0] = numbers;
  return {
    chainHeadSeq,
    chainHeadHashHex: chainHeadHashHex ?? null,
    auditMaxSeq: marks.auditMaxSeq,
    attestationMark,
    mutationSeq,
  };
}

export interface ExportPageInput {
  readonly sql: SqlStorage;
  readonly tables: readonly string[];
  readonly schemaVersion: number;
  readonly doIdHex: string;
  readonly takenAtMs: number;
  /** null = the first page (the header is emitted and the marks are taken). */
  readonly cursor: ExportCursorState | null;
  /** The seq of the `project.exported` row of this export (the first page binds it into the cursor). */
  readonly exportedSeq: number;
  readonly maxRows: number;
  readonly maxBytes: number;
}

export type ExportPageResult =
  | {
      readonly kind: "page";
      readonly lines: readonly string[];
      /** null = the trailer was emitted (the export is complete). */
      readonly next: ExportCursorState | null;
      readonly marks: ExportMarks;
    }
  | { readonly kind: "changed" };

/** The lines of one page and their UTF-8 size (newlines included). */
class PageWriter {
  readonly lines: string[] = [];
  bytes = 0;
  readonly #encoder = new TextEncoder();

  emit(line: string): void {
    this.lines.push(line);
    // UTF-8 bytes (display names may be non-ASCII), plus the newline
    this.bytes += this.#encoder.encode(line).length + 1;
  }
}

/** The cursor a page starts from: the given one, or the first page's (the header is emitted). */
function openCursor(
  input: ExportPageInput,
  marks: ExportMarks,
  writer: PageWriter,
): ExportCursorState {
  if (input.cursor !== null) {
    return input.cursor;
  }
  const header: SnapshotHeader = {
    kind: "header",
    format: SNAPSHOT_FORMAT,
    version: SNAPSHOT_FORMAT_VERSION,
    schemaVersion: input.schemaVersion,
    takenAtMs: input.takenAtMs,
    doIdHex: input.doIdHex,
  };
  writer.emit(JSON.stringify(header));
  return { table: 0, started: false, rowid: -1, rows: {}, marks, exportedSeq: input.exportedSeq };
}

/** Emits a table's line; the cursor then points at its first row. */
function openTable(
  sql: SqlStorage,
  table: string,
  state: ExportCursorState,
  writer: PageWriter,
): ExportCursorState {
  const columns = sql.exec(`SELECT * FROM ${table} LIMIT 0`).columnNames;
  const tableLine: SnapshotTableLine = { kind: "table", table, columns };
  writer.emit(JSON.stringify(tableLine));
  return { ...state, started: true, rowid: -1, rows: { ...state.rows, [table]: 0 } };
}

/**
 * Emits one chunk of a table's rows after the cursor's rowid (up to `limit`,
 * stopping after the row that crosses `maxBytes` — a row is up to 64 KiB of
 * hex ciphertext, and a whole chunk past the bound would be tens of MiB).
 * The table is complete only when the whole chunk was consumed and the
 * chunk was short; a cut-short chunk resumes from the last emitted row.
 */
function emitRows(
  sql: SqlStorage,
  table: string,
  state: ExportCursorState,
  writer: PageWriter,
  limit: number,
  maxBytes: number,
): { readonly state: ExportCursorState; readonly consumed: number } {
  // The audit log is exported up to the mark: rows past it are the reads
  // and leases served while the export ran (they belong to the next export)
  const bounded = AUDIT_SEQ_TABLES.has(table);
  const chunk = Array.from(
    sql
      .exec(
        `SELECT rowid AS __rid, * FROM ${table} WHERE rowid > ?${bounded ? " AND seq <= ?" : ""} ORDER BY rowid LIMIT ?`,
        ...(bounded ? [state.rowid, state.marks.auditMaxSeq, limit] : [state.rowid, limit]),
      )
      .raw(),
  );
  let rowid = state.rowid;
  let consumed = 0;
  for (const raw of chunk) {
    const [rid, ...values] = raw;
    rowid = Number(rid);
    const rowLine: SnapshotRowLine = { kind: "row", table, values: values.map(encodeScalar) };
    writer.emit(JSON.stringify(rowLine));
    consumed += 1;
    if (writer.bytes >= maxBytes) {
      break;
    }
  }
  const rows = { ...state.rows, [table]: (state.rows[table] ?? 0) + consumed };
  const tableDone = consumed === chunk.length && chunk.length < limit;
  return {
    consumed,
    state: tableDone
      ? { ...state, table: state.table + 1, started: false, rowid: -1, rows }
      : { ...state, rowid, rows },
  };
}

/**
 * One page of the evacuation's lines (the caller holds the permit and
 * calls synchronously). A page ends after the line that crosses
 * `maxBytes` or at `maxRows`, whichever first (never more than one line
 * past the byte bound); the trailer rides the last page while the bound
 * has room, else a page of its own.
 */
export function exportSnapshotPage(input: ExportPageInput): ExportPageResult {
  const { sql } = input;
  const order = snapshotTableOrder(input.tables);
  const marks = marksOf(sql);
  // A cursor past the table order (another server's, or a forged one) is
  // treated like a changed project: the client starts over
  if (
    input.cursor !== null &&
    (!sameMarks(input.cursor.marks, marks) || input.cursor.table > order.length)
  ) {
    return { kind: "changed" };
  }
  const writer = new PageWriter();
  let state = openCursor(input, marks, writer);
  let emitted = 0;
  while (state.table < order.length && writer.bytes < input.maxBytes && emitted < input.maxRows) {
    const table = order[state.table] ?? "";
    if (!state.started) {
      // The table line may itself cross the bound: the loop condition
      // decides whether its rows follow on this page
      state = openTable(sql, table, state, writer);
      continue;
    }
    const limit = Math.min(input.maxRows - emitted, OPS_SNAPSHOT_ROW_PAGE);
    const step = emitRows(sql, table, state, writer, limit, input.maxBytes);
    state = step.state;
    emitted += step.consumed;
  }
  if (state.table < order.length || writer.bytes >= input.maxBytes) {
    return { kind: "page", lines: writer.lines, next: state, marks };
  }
  const trailer: SnapshotTrailer = {
    kind: "trailer",
    rows: state.rows,
    chainHeadSeq: marks.chainHeadSeq,
    chainHeadHashHex: marks.chainHeadHashHex,
    auditMaxSeq: marks.auditMaxSeq,
    auditHeadHashHex: auditHeadHashAt(sql, marks.auditMaxSeq),
    databaseSizeBytes: sql.databaseSize,
  };
  writer.emit(JSON.stringify(trailer));
  return { kind: "page", lines: writer.lines, next: null, marks };
}

// ---------------------------------------------------------------------------
// Restore (read-in)
// ---------------------------------------------------------------------------

/** Restore refusal reasons (static codes — safe to put in result files and logs). */
export type RestoreFailureCode =
  | "not-empty"
  | "object-missing"
  | "malformed"
  | "schema-mismatch"
  | "trailer-missing"
  | "row-count-mismatch"
  | "unknown-table";

export class RestoreRefusedError extends Error {
  constructor(readonly code: RestoreFailureCode) {
    super(`restore refused: ${code}`);
  }
}

export interface RestoreSnapshotInput {
  /** DO storage with transactionSync (sql is taken from here). */
  readonly storage: DurableObjectStorage;
  readonly tables: readonly string[];
  readonly schemaVersion: number;
  readonly body: ReadableStream;
}

export interface RestoreSnapshotResult {
  readonly header: SnapshotHeader;
  readonly trailer: SnapshotTrailer;
  readonly rows: Readonly<Record<string, number>>;
}

async function* lines(body: ReadableStream): AsyncGenerator<string> {
  const reader = body
    .pipeThrough(new DecompressionStream("gzip"))
    .pipeThrough(new TextDecoderStream())
    .getReader();
  let carry = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      if (carry !== "") {
        yield carry;
      }
      return;
    }
    carry += value;
    let index = carry.indexOf("\n");
    while (index !== -1) {
      yield carry.slice(0, index);
      carry = carry.slice(index + 1);
      index = carry.indexOf("\n");
    }
  }
}

export function parseLine(text: string): SnapshotLine {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    // A non-JSON line = a corrupted evacuation (fold the reason into a
    // static code — the body is not carried)
    throw new RestoreRefusedError("malformed");
  }
  if (typeof parsed !== "object" || parsed === null || !("kind" in parsed)) {
    throw new RestoreRefusedError("malformed");
  }
  return parsed as SnapshotLine;
}

function wipeTables(sql: SqlStorage, tables: readonly string[]): void {
  for (const table of tables) {
    sql.exec(`DELETE FROM ${table}`);
  }
}

/** Buffers one table's rows and inserts each batch in a single transaction. */
class RowInserter {
  #buffer: (readonly SnapshotScalar[])[] = [];
  readonly #rowsPerStatement: number;

  constructor(
    private readonly storage: DurableObjectStorage,
    readonly table: string,
    private readonly columns: readonly string[],
  ) {
    this.#rowsPerStatement = Math.max(1, Math.floor(MAX_BOUND_PARAMETERS / columns.length));
  }

  push(values: readonly SnapshotScalar[]): void {
    if (values.length !== this.columns.length) {
      throw new RestoreRefusedError("malformed");
    }
    this.#buffer.push(values);
    if (this.#buffer.length >= OPS_RESTORE_BATCH_ROWS) {
      this.flush();
    }
  }

  /** Commits the buffered rows in one transaction (transactionSync). */
  flush(): void {
    if (this.#buffer.length === 0) {
      return;
    }
    const rows = this.#buffer;
    this.#buffer = [];
    const columnList = this.columns.join(", ");
    const placeholders = `(${this.columns.map(() => "?").join(", ")})`;
    this.storage.transactionSync(() => {
      for (let start = 0; start < rows.length; start += this.#rowsPerStatement) {
        const chunk = rows.slice(start, start + this.#rowsPerStatement);
        this.storage.sql.exec(
          `INSERT INTO ${this.table} (${columnList}) VALUES ${chunk.map(() => placeholders).join(", ")}`,
          ...chunk.flatMap((values) => values.map(decodeScalar)),
        );
      }
    });
  }
}

/**
 * Validates and returns the column names of an evacuation's table line.
 * Any miss — not an array, a non-string element, or not an exact match
 * including order with the live table's column names — is "malformed"
 * (column names are embedded as SQL identifiers, so only values that
 * pass here are used).
 */
export function acceptColumns(sql: SqlStorage, table: string, columns: unknown): readonly string[] {
  if (!Array.isArray(columns) || !columns.every((column) => typeof column === "string")) {
    throw new RestoreRefusedError("malformed");
  }
  // table is already checked against the set of known tables (a value safe to embed as an identifier)
  const live = sql.exec(`SELECT * FROM ${table} LIMIT 0`).columnNames;
  if (
    columns.length === 0 ||
    columns.length !== live.length ||
    columns.some((column, index) => column !== live[index])
  ) {
    throw new RestoreRefusedError("malformed");
  }
  return live;
}

export function acceptHeader(line: SnapshotLine, schemaVersion: number): SnapshotHeader {
  if (
    line.kind !== "header" ||
    line.format !== SNAPSHOT_FORMAT ||
    line.version !== SNAPSHOT_FORMAT_VERSION
  ) {
    throw new RestoreRefusedError("malformed");
  }
  if (line.schemaVersion !== schemaVersion) {
    throw new RestoreRefusedError("schema-mismatch");
  }
  return line;
}

/** A state machine that consumes an evacuation's lines in order and batch-inserts per table. */
class RestoreReader {
  header: SnapshotHeader | null = null;
  trailer: SnapshotTrailer | null = null;
  readonly rows: Record<string, number> = {};
  #inserter: RowInserter | null = null;
  /** The logical table name under accept; distinct from the insert target (chain_entries is routed to staging). */
  #table: string | null = null;
  #chainColumns: readonly string[] | null = null;

  constructor(
    private readonly storage: DurableObjectStorage,
    private readonly known: ReadonlySet<string>,
    private readonly schemaVersion: number,
  ) {}

  accept(line: SnapshotLine): void {
    if (this.header === null) {
      this.header = acceptHeader(line, this.schemaVersion);
      return;
    }
    if (this.trailer !== null) {
      throw new RestoreRefusedError("malformed");
    }
    switch (line.kind) {
      case "table":
        this.#beginTable(line);
        return;
      case "row":
        this.#acceptRow(line);
        return;
      case "trailer":
        this.#flush();
        this.trailer = line;
        return;
      default:
        throw new RestoreRefusedError("malformed");
    }
  }

  /** Verifies every table's row count against the trailer, promotes the chain to the real table, and returns the result. */
  verify(tables: readonly string[]): RestoreSnapshotResult {
    const { header, trailer } = this;
    if (header === null || trailer === null) {
      throw new RestoreRefusedError("trailer-missing");
    }
    for (const table of tables) {
      if ((trailer.rows[table] ?? 0) !== (this.rows[table] ?? 0)) {
        throw new RestoreRefusedError("row-count-mismatch");
      }
    }
    this.#promoteChainStaging();
    return { header, trailer, rows: this.rows };
  }

  #beginTable(line: SnapshotTableLine): void {
    if (!this.known.has(line.table)) {
      throw new RestoreRefusedError("unknown-table");
    }
    this.#flush();
    // The column names come from the evacuation's line and are embedded
    // as identifiers into the INSERT / CREATE TABLE below. The schema
    // version already matched in the header, so unless they exactly match
    // the live table's column names — taken the same way the writer
    // (writeSnapshot) takes them — including order, refuse as corrupt
    // (never flow identifiers from an evacuation into SQL unverified).
    const columns = acceptColumns(this.storage.sql, line.table, line.columns);
    // chain_entries is written to the staging table and moved to the
    // real table in verify. Since RowInserter commits per batch, if the
    // process dies mid-chain-table a "valid but truncated chain" remains,
    // and the isProjectDoEmpty refusal would make restore impossible
    // forever. Going through staging, an interruption always falls to
    // "chain_entries empty" (= uninitialized).
    const target = line.table === CHAIN_TABLE ? this.#beginChainStaging(columns) : line.table;
    this.#inserter = new RowInserter(this.storage, target, columns);
    this.#table = line.table;
    this.rows[line.table] = 0;
  }

  /** Remembers the chain's column names, creates the staging table, and returns its name. */
  #beginChainStaging(columns: readonly string[]): string {
    const columnList = columns.join(", ");
    this.storage.sql.exec(`DROP TABLE IF EXISTS ${CHAIN_STAGING_TABLE}`);
    this.storage.sql.exec(`CREATE TABLE ${CHAIN_STAGING_TABLE} (${columnList})`);
    this.#chainColumns = columns;
    return CHAIN_STAGING_TABLE;
  }

  /** Moves the verified staging rows to chain_entries in one transaction. */
  #promoteChainStaging(): void {
    const columns = this.#chainColumns;
    if (columns === null) {
      return; // the evacuation had no chain_entries table (empty project)
    }
    const columnList = columns.join(", ");
    this.storage.transactionSync(() => {
      this.storage.sql.exec(
        `INSERT INTO ${CHAIN_TABLE} (${columnList}) SELECT ${columnList} FROM ${CHAIN_STAGING_TABLE}`,
      );
      this.storage.sql.exec(`DROP TABLE ${CHAIN_STAGING_TABLE}`);
    });
    this.#chainColumns = null;
  }

  #acceptRow(line: SnapshotRowLine): void {
    const inserter = this.#inserter;
    if (inserter === null || line.table !== this.#table) {
      throw new RestoreRefusedError("malformed");
    }
    inserter.push(line.values);
    this.rows[line.table] = (this.rows[line.table] ?? 0) + 1;
  }

  /** Commits the in-flight table's buffer (transactions are opened per batch by RowInserter). */
  #flush(): void {
    this.#inserter?.flush();
  }
}

/**
 * Writes an evacuation back into an empty DO (the caller must hold the
 * permit). Each batch is atomically committed with transactionSync; a
 * mid-way failure (exception, missing trailer, row-count mismatch)
 * wipes all tables back to empty before throwing. chain_entries rows go
 * to the staging table and are moved to the real table in one
 * transaction only after verification passes — wherever the process
 * dies, it falls on the "uninitialized" side and restore can be retried.
 */
export async function restoreSnapshot(input: RestoreSnapshotInput): Promise<RestoreSnapshotResult> {
  const { storage, tables } = input;
  if (!isProjectDoEmpty(storage.sql)) {
    throw new RestoreRefusedError("not-empty");
  }
  // Wipe the previous partial restore (leftover non-chain tables) first
  wipeTables(storage.sql, tables);
  storage.sql.exec(`DROP TABLE IF EXISTS ${CHAIN_STAGING_TABLE}`);
  const reader = new RestoreReader(storage, new Set(tables), input.schemaVersion);
  try {
    for await (const text of lines(input.body)) {
      if (text !== "") {
        reader.accept(parseLine(text));
      }
    }
    return reader.verify(tables);
  } catch (error) {
    wipeTables(storage.sql, tables);
    storage.sql.exec(`DROP TABLE IF EXISTS ${CHAIN_STAGING_TABLE}`);
    throw error;
  }
}
