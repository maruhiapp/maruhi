// Paged export (the owner-side transport of PF3 — AUTH_SPEC §11-6,
// docs/notes/pf3-design.md rulings A–D). The same lines as the
// evacuation (do-snapshot.ts), read one page at a time under the permit
// (one synchronous call per page — no permit across awaits), with the
// project's watermarks carried in the cursor so a change between pages
// is refused rather than silently exported as a mixed state. Run by
// programs-export.ts's exportPageProgram.

import { Option, Schema } from "effect";

import { OPS_SNAPSHOT_ROW_PAGE } from "../ops/ops-policy.ts";
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
 * The marks a cursor binds: the chain head, the attestation mark and the
 * mutation counter (kept by the schema's triggers — the mutation triggers
 * the do-schema.ts base step creates)
 * must not move between pages, or the export restarts. The exported audit
 * log is bounded by the cursor's `exportedSeq` (the export's own audit
 * row, the last one before the marks were taken): rows past it are the
 * reads served while the export ran — not exported, and not a restart
 * (ruling C revision, docs/notes/pf3-design.md §8).
 */
export interface ExportMarks {
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string | null;
  /** The mutation counter covers every tracked table, head attestations included (ruling C revision, round 4 — no separate attestation mark). */
  readonly mutationSeq: number;
  /** The DO schema version: an export spanning a deploy that migrates the schema restarts at the source, not at the destination (ruling C revision, round 5). */
  readonly schemaVersion: number;
  /** The line format's version, for the same reason (round 6 — a mixed file would be refused at the destination). */
  readonly formatVersion: number;
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
   * names, and only while the row still says what the cursor says. It is
   * also the bound of the exported audit log (the row is the last one
   * before the marks were taken).
   */
  readonly exportedSeq: number;
}

function marksOf(sql: SqlStorage, schemaVersion: number): ExportMarks {
  const marks = readWatermarks(sql);
  return {
    chainHeadSeq: marks.chainHeadSeq,
    chainHeadHashHex: marks.chainHeadHashHex,
    mutationSeq: marks.mutationSeq,
    schemaVersion,
    formatVersion: SNAPSHOT_FORMAT_VERSION,
  };
}

/** Whether a cursor's marks still describe the project. */
function sameMarks(a: ExportMarks, b: ExportMarks): boolean {
  return (
    a.chainHeadSeq === b.chainHeadSeq &&
    a.chainHeadHashHex === b.chainHeadHashHex &&
    a.mutationSeq === b.mutationSeq &&
    a.schemaVersion === b.schemaVersion &&
    a.formatVersion === b.formatVersion
  );
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

// The cursor's wire shape. Positions are embedded in SQL (the rowid) or
// index the table order: only non-negative integers (rowid ≥ -1,
// exportedSeq ≥ 1) pass — anything else is not a cursor this server
// produced
const exportCursorSchema = Schema.Struct({
  table: Schema.Natural,
  started: Schema.Boolean,
  rowid: Schema.Int.check(Schema.isGreaterThanOrEqualTo(-1)),
  rows: Schema.Record(Schema.String, Schema.Number),
  marks: Schema.Struct({
    chainHeadSeq: Schema.Number,
    chainHeadHashHex: Schema.NullOr(Schema.String),
    mutationSeq: Schema.Number,
    schemaVersion: Schema.Number,
    formatVersion: Schema.Number,
  }),
  exportedSeq: Schema.Int.check(Schema.isGreaterThanOrEqualTo(1)),
});

const decodeExportCursorJson = Schema.decodeUnknownOption(
  Schema.fromJsonString(exportCursorSchema),
);

/** null = not a cursor this server produced (the client starts over). */
export function decodeExportCursor(text: string): ExportCursorState | null {
  const json = base64UrlDecode(text);
  if (json === null) {
    return null;
  }
  return Option.getOrNull(decodeExportCursorJson(json));
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
      /** The bound of the exported audit log (the cursor's `exportedSeq` — the trailer repeats it). */
      readonly auditMaxSeq: number;
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
        ...(bounded ? [state.rowid, state.exportedSeq, limit] : [state.rowid, limit]),
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
  const marks = marksOf(sql, input.schemaVersion);
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
  const auditMaxSeq = state.exportedSeq;
  if (state.table < order.length || writer.bytes >= input.maxBytes) {
    return { kind: "page", lines: writer.lines, next: state, marks, auditMaxSeq };
  }
  // The trailer describes the exported state (the cursor's marks and
  // bound), never the live one: a page after a read in between must say
  // what the rows say
  const trailer: SnapshotTrailer = {
    kind: "trailer",
    rows: state.rows,
    chainHeadSeq: state.marks.chainHeadSeq,
    chainHeadHashHex: state.marks.chainHeadHashHex,
    auditMaxSeq,
    auditHeadHashHex: auditHeadHashAt(sql, auditMaxSeq),
    databaseSizeBytes: sql.databaseSize,
  };
  writer.emit(JSON.stringify(trailer));
  return { kind: "page", lines: writer.lines, next: null, marks, auditMaxSeq };
}
