import { Option, Result, Schema } from "effect";
import { Base64Url } from "effect/encoding";

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

export interface ExportMarks {
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string | null;
  readonly mutationSeq: number;
  readonly schemaVersion: number;
  readonly formatVersion: number;
}

const AUDIT_SEQ_TABLES: ReadonlySet<string> = new Set(["audit_events", "audit_head_hashes"]);

export interface ExportCursorState {
  readonly table: number;
  readonly started: boolean;
  readonly rowid: number;
  readonly rows: Readonly<Record<string, number>>;
  readonly marks: ExportMarks;
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

function sameMarks(a: ExportMarks, b: ExportMarks): boolean {
  return (
    a.chainHeadSeq === b.chainHeadSeq &&
    a.chainHeadHashHex === b.chainHeadHashHex &&
    a.mutationSeq === b.mutationSeq &&
    a.schemaVersion === b.schemaVersion &&
    a.formatVersion === b.formatVersion
  );
}

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
  return Base64Url.encode(text);
}

function base64UrlDecode(text: string): string | null {
  const decoded = Base64Url.decode(text);
  return Result.isSuccess(decoded) ? new TextDecoder().decode(decoded.success) : null;
}

export function encodeExportCursor(state: ExportCursorState): string {
  return base64UrlEncode(JSON.stringify(state));
}

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
  readonly cursor: ExportCursorState | null;
  readonly exportedSeq: number;
  readonly maxRows: number;
  readonly maxBytes: number;
}

export type ExportPageResult =
  | {
      readonly kind: "page";
      readonly lines: readonly string[];
      readonly next: ExportCursorState | null;
      readonly marks: ExportMarks;
      readonly auditMaxSeq: number;
    }
  | { readonly kind: "changed" };

class PageWriter {
  readonly lines: string[] = [];
  bytes = 0;
  readonly #encoder = new TextEncoder();

  emit(line: string): void {
    this.lines.push(line);
    this.bytes += this.#encoder.encode(line).length + 1;
  }
}

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

function emitRows(
  sql: SqlStorage,
  table: string,
  state: ExportCursorState,
  writer: PageWriter,
  limit: number,
  maxBytes: number,
): { readonly state: ExportCursorState; readonly consumed: number } {
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

export function exportSnapshotPage(input: ExportPageInput): ExportPageResult {
  const { sql } = input;
  const order = snapshotTableOrder(input.tables);
  const marks = marksOf(sql, input.schemaVersion);
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
