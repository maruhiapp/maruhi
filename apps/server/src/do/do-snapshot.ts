import { Result, Schema } from "effect";
import { Base64 } from "effect/encoding";

export const SNAPSHOT_FORMAT = "maruhi-do-snapshot";
export const SNAPSHOT_FORMAT_VERSION = 1;

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

export const decodeSnapshotLine = Schema.decodeUnknownSync(
  Schema.fromJsonString(snapshotLineSchema),
);

export interface DoWatermarks {
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string | null;
  readonly auditMaxSeq: number;
  readonly auditHeadHashHex: string | null;
  readonly attestationMark: number;
  readonly mutationSeq: number;
}

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

export const CHAIN_TABLE = "chain_entries";

export function snapshotTableOrder(tables: readonly string[]): readonly string[] {
  return [...tables.filter((t) => t !== CHAIN_TABLE), CHAIN_TABLE];
}

export function encodeScalar(value: unknown): SnapshotScalar {
  if (value === null || typeof value === "number" || typeof value === "string") {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return { b64: Base64.encode(new Uint8Array(value)) };
  }
  throw new Error("unsupported SQLite value type in snapshot");
}

export function decodeScalar(value: SnapshotScalar): number | string | null | ArrayBuffer {
  if (value !== null && typeof value === "object") {
    const decoded = Base64.decode(value.b64);
    if (Result.isFailure(decoded)) {
      throw new Error("invalid base64 in snapshot scalar");
    }
    return Uint8Array.from(decoded.success).buffer;
  }
  return value;
}
