import { Data, Effect } from "effect";

import type { MirrorSyncRejectReason } from "../data.package/index.ts";
import { CHAIN_TABLE, readWatermarks } from "./do-snapshot.ts";

export const MANIFEST_TABLE = "environment_manifests";
export const CHECKPOINT_TABLE = "environment_checkpoints";
export const ENVIRONMENTS_TABLE = "environments";
export const VARIABLES_TABLE = "variables";

export const AUDIT_TABLE = "audit_events";
export const LOCAL_AUDIT_TABLE = "audit_events_mirror_local";
export const AUDIT_HEAD_TABLE = "audit_head_hashes";
export const TRAILER_TABLE = "trailer_mirror";

export const stagingOf = (table: string): string => `${table}_mirror`;

export interface MirrorState {
  readonly sourceOrigin: string;
  readonly markedAtMs: number;
  readonly expectedSequence: number;
  readonly stagingTable: string | null;
  readonly lastSyncedAtMs: number | null;
  readonly lastHeadSeq: number;
  readonly lastHeadHashHex: string;
  readonly lastAuditSeq: number;
  readonly lastAttestationMark: number;
  readonly lastMutationSeq: number | null;
}

export function readMirrorState(sql: SqlStorage): MirrorState | null {
  const row = sql.exec("SELECT * FROM mirror_state WHERE id = 1").toArray()[0];
  if (row === undefined) {
    return null;
  }
  return {
    sourceOrigin: String(row["source_origin"]),
    markedAtMs: Number(row["marked_at"]),
    expectedSequence: Number(row["expected_sequence"]),
    stagingTable: row["staging_table"] === null ? null : String(row["staging_table"]),
    lastSyncedAtMs: row["last_synced_at"] === null ? null : Number(row["last_synced_at"]),
    lastHeadSeq: Number(row["last_head_seq"]),
    lastHeadHashHex: String(row["last_head_hash_hex"]),
    lastAuditSeq: Number(row["last_audit_seq"]),
    lastAttestationMark: Number(row["last_attestation_mark"]),
    lastMutationSeq: row["last_mutation_seq"] === null ? null : Number(row["last_mutation_seq"]),
  };
}

export function remarkMirror(
  storage: DurableObjectStorage,
  tables: readonly string[],
  sourceOrigin: string,
  nowMs: number,
): void {
  storage.transactionSync(() => {
    dropStaging(storage.sql, tables);
    storage.sql.exec(
      "UPDATE mirror_state SET source_origin = ?, marked_at = ?, expected_sequence = 0, staging_table = NULL, last_synced_at = NULL, last_audit_seq = 0, last_mutation_seq = NULL WHERE id = 1",
      sourceOrigin,
      nowMs,
    );
  });
}

export function markMirror(sql: SqlStorage, sourceOrigin: string, nowMs: number): void {
  const marks = readWatermarks(sql);
  sql.exec(
    `INSERT INTO mirror_state (id, source_origin, marked_at, expected_sequence, staging_table, last_synced_at, last_head_seq, last_head_hash_hex, last_audit_seq, last_attestation_mark)
     VALUES (1, ?, ?, 0, NULL, NULL, ?, ?, 0, ?)`,
    sourceOrigin,
    nowMs,
    marks.chainHeadSeq,
    marks.chainHeadHashHex ?? "",
    marks.attestationMark,
  );
}

export function hasTable(sql: SqlStorage, name: string): boolean {
  return (
    sql.exec("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", name).toArray()
      .length > 0
  );
}

export function dropStaging(sql: SqlStorage, tables: readonly string[]): void {
  for (const table of tables) {
    sql.exec(`DROP TABLE IF EXISTS ${stagingOf(table)}`);
  }
  sql.exec(`DROP TABLE IF EXISTS ${LOCAL_AUDIT_TABLE}`);
  sql.exec(`DROP TABLE IF EXISTS ${TRAILER_TABLE}`);
}

export function discardMirrorStaging(
  storage: DurableObjectStorage,
  tables: readonly string[],
): void {
  storage.transactionSync(() => {
    dropStaging(storage.sql, tables);
    storage.sql.exec(
      "UPDATE mirror_state SET expected_sequence = 0, staging_table = NULL WHERE id = 1",
    );
  });
}

export function unmarkMirror(storage: DurableObjectStorage, tables: readonly string[]): void {
  storage.transactionSync(() => {
    dropStaging(storage.sql, tables);
    storage.sql.exec("DELETE FROM mirror_state WHERE id = 1");
  });
}

export class MirrorPageRefusedError extends Data.TaggedError("MirrorPageRefused")<{
  readonly reason: MirrorSyncRejectReason;
}> {}

export const malformed = (): MirrorPageRefusedError =>
  new MirrorPageRefusedError({ reason: "malformed" });

export function stagedCount(sql: SqlStorage, table: string): number {
  return hasTable(sql, stagingOf(table))
    ? Number(sql.exec(`SELECT COUNT(*) AS n FROM ${stagingOf(table)}`).one()["n"])
    : 0;
}

export function stagedMaxSeq(sql: SqlStorage, table: string): number {
  if (!hasTable(sql, stagingOf(table))) {
    return 0;
  }
  const max = Number(
    sql.exec(`SELECT COALESCE(MAX(seq), 0) AS m FROM ${stagingOf(table)}`).one()["m"],
  );
  const min = Number(
    sql.exec(`SELECT COALESCE(MIN(seq), 1) AS m FROM ${stagingOf(table)}`).one()["m"],
  );
  if (!Number.isInteger(max) || max < 0 || !Number.isInteger(min) || min < 1) {
    throw malformed();
  }
  return max;
}

export function stagedRowOf(sql: SqlStorage, table: string, environmentId: string) {
  const staging = stagingOf(table);
  if (!hasTable(sql, staging)) {
    return undefined;
  }
  return sql.exec(`SELECT * FROM ${staging} WHERE environment_id = ?`, environmentId).toArray()[0];
}

export function rowsByKey(
  sql: SqlStorage,
  table: string,
  staged: boolean,
  keyColumns: readonly string[],
): ReadonlyMap<string, Record<string, unknown>> {
  const source = staged ? stagingOf(table) : table;
  const out = new Map<string, Record<string, unknown>>();
  if (staged && !hasTable(sql, source)) {
    return out;
  }
  for (const row of sql.exec(`SELECT * FROM ${source}`).toArray()) {
    const record = row as Record<string, unknown>;
    out.set(keyColumns.map((column) => String(record[column])).join("\n"), record);
  }
  return out;
}

export function columnsOf(sql: SqlStorage, table: string): readonly string[] {
  return sql.exec(`SELECT * FROM ${table} LIMIT 0`).columnNames;
}

export function rowsDiffer(
  columns: readonly string[],
  a: Record<string, unknown>,
  b: Record<string, unknown>,
): boolean {
  return columns.some((column) => a[column] !== b[column]);
}

interface StagedChainRow {
  readonly seq: number;
  readonly entryJson: string;
  readonly entryHashHex: string;
  readonly canonicalBytes: number;
}

export const stagedChainRows = Effect.fn("do-mirror.stagedChainRows")(function* (
  sql: SqlStorage,
): Effect.fn.Return<readonly StagedChainRow[], MirrorPageRefusedError> {
  const staging = stagingOf(CHAIN_TABLE);
  if (!hasTable(sql, staging)) {
    return yield* new MirrorPageRefusedError({ reason: "chain-not-extension" });
  }
  const rows = sql
    .exec(`SELECT seq, entry_json, entry_hash_hex, canonical_bytes FROM ${staging} ORDER BY seq`)
    .toArray();
  const out: StagedChainRow[] = [];
  for (const [index, row] of rows.entries()) {
    const seq = row["seq"];
    const entryJson = row["entry_json"];
    const entryHashHex = row["entry_hash_hex"];
    const canonicalBytes = row["canonical_bytes"];
    if (
      seq !== index + 1 ||
      typeof entryJson !== "string" ||
      typeof entryHashHex !== "string" ||
      typeof canonicalBytes !== "number" ||
      !Number.isInteger(canonicalBytes)
    ) {
      return yield* malformed();
    }
    out.push({ seq, entryJson, entryHashHex, canonicalBytes });
  }
  return out;
});
