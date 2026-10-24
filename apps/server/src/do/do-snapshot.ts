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
//
// This file is the line format and what the other three share: the
// watermarks, the table order and the scalar codec. Writing an
// evacuation is do-snapshot-write.ts, the paged export (the same lines,
// read a page at a time) do-snapshot-export.ts, and the restore
// do-snapshot-restore.ts.

import { Schema } from "effect";

export const SNAPSHOT_FORMAT = "maruhi-do-snapshot";
export const SNAPSHOT_FORMAT_VERSION = 1;

// The line formats on the wire — the single source for the SnapshotLine
// types below (the union decode of do-snapshot-restore.ts's parseLine).
// `kind` narrows the union; `format` / `version` stay literal so the
// header keeps its constant type and a wrong one is refused before a
// field is read. The encode side writes these same shapes.
const snapshotScalarSchema = Schema.Union([
  Schema.Number,
  Schema.String,
  Schema.Null,
  Schema.Struct({ b64: Schema.String }),
]);

const snapshotHeaderSchema = Schema.Struct({
  kind: Schema.Literal("header"),
  format: Schema.Literal(SNAPSHOT_FORMAT),
  version: Schema.Literal(SNAPSHOT_FORMAT_VERSION),
  schemaVersion: Schema.Number,
  takenAtMs: Schema.Number,
  doIdHex: Schema.String,
});

const snapshotTableLineSchema = Schema.Struct({
  kind: Schema.Literal("table"),
  table: Schema.String,
  columns: Schema.Array(Schema.String),
});

const snapshotRowLineSchema = Schema.Struct({
  kind: Schema.Literal("row"),
  table: Schema.String,
  values: Schema.Array(snapshotScalarSchema),
});

const snapshotTrailerSchema = Schema.Struct({
  kind: Schema.Literal("trailer"),
  rows: Schema.Record(Schema.String, Schema.Number),
  chainHeadSeq: Schema.Number,
  chainHeadHashHex: Schema.NullOr(Schema.String),
  auditMaxSeq: Schema.Number,
  // Only when the cumulative-hash column (audit_head_hashes) has reached MAX(seq)
  auditHeadHashHex: Schema.NullOr(Schema.String),
  databaseSizeBytes: Schema.Number,
});

const snapshotLineSchema = Schema.Union([
  snapshotHeaderSchema,
  snapshotTableLineSchema,
  snapshotRowLineSchema,
  snapshotTrailerSchema,
]);

export type SnapshotScalar = typeof snapshotScalarSchema.Type;
export type SnapshotHeader = typeof snapshotHeaderSchema.Type;
export type SnapshotTableLine = typeof snapshotTableLineSchema.Type;
export type SnapshotRowLine = typeof snapshotRowLineSchema.Type;
export type SnapshotTrailer = typeof snapshotTrailerSchema.Type;
export type SnapshotLine = typeof snapshotLineSchema.Type;

// Compiled once at module scope: `fromJsonString` composes JSON.parse
// and the schema, and rebuilding it per line makes a new AST every
// call — on a restore every row line runs through this
export const decodeSnapshotLine = Schema.decodeUnknownSync(
  Schema.fromJsonString(snapshotLineSchema),
);

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

// ---------------------------------------------------------------------------
// The table order and the scalar codec (the write-out and the export
// encode with them, the restore and the mirror decode)
// ---------------------------------------------------------------------------

export const CHAIN_TABLE = "chain_entries";

/** Table order in the evacuation: chain_entries **last** (the basis of restore's "chain comes last" rule). */
export function snapshotTableOrder(tables: readonly string[]): readonly string[] {
  return [...tables.filter((t) => t !== CHAIN_TABLE), CHAIN_TABLE];
}

export function encodeScalar(value: unknown): SnapshotScalar {
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
