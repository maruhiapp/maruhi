import { Effect } from "effect";

import {
  AUDIT_HEAD_TABLE,
  AUDIT_TABLE,
  discardMirrorStaging,
  hasTable,
  LOCAL_AUDIT_TABLE,
  malformed,
  MirrorPageRefusedError,
  type MirrorState,
  stagedMaxSeq,
  stagingOf,
  TRAILER_TABLE,
} from "./do-mirror-state.ts";
import { readWatermarks } from "./do-snapshot.ts";

const MIRROR_KEPT_TABLES: readonly string[] = [
  "lease_windows",
  "lease_bindings",
  "attestation_windows",
];

export interface MirrorCommit {
  readonly atMs: number;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly auditMaxSeq: number;
  readonly attestationMark: number;
  readonly mutationSeq: number;
  readonly ownAuditRows: number;
}

const MERGED_TABLE = "lease_bindings";

function swapTables(
  sql: SqlStorage,
  tables: readonly string[],
  nowMs: number,
  replicatedAuditSeq: number,
): void {
  for (const table of tables) {
    if (table === AUDIT_HEAD_TABLE && replicatedAuditSeq > 0) {
      swapAuditHeads(sql, replicatedAuditSeq);
    } else if (MIRROR_KEPT_TABLES.includes(table)) {
      keepTable(sql, table, nowMs);
    } else {
      replaceTable(sql, table);
    }
  }
}

function swapAuditHeads(sql: SqlStorage, replicatedAuditSeq: number): void {
  const staging = stagingOf(AUDIT_HEAD_TABLE);
  sql.exec(`DELETE FROM ${AUDIT_HEAD_TABLE} WHERE seq > ?`, replicatedAuditSeq);
  if (hasTable(sql, staging)) {
    sql.exec(
      `INSERT INTO ${AUDIT_HEAD_TABLE} (seq, head_hash_hex) SELECT seq, head_hash_hex FROM ${staging} WHERE seq > ? ORDER BY seq`,
      replicatedAuditSeq,
    );
    sql.exec(`DROP TABLE ${staging}`);
  }
}

function keepTable(sql: SqlStorage, table: string, nowMs: number): void {
  const staging = stagingOf(table);
  if (table === MERGED_TABLE) {
    if (hasTable(sql, staging)) {
      const columns = sql.exec(`SELECT * FROM ${staging} LIMIT 0`).columnNames.join(", ");
      sql.exec(
        `INSERT OR IGNORE INTO ${table} (${columns}) SELECT ${columns} FROM ${staging} WHERE expires_at > ?`,
        nowMs,
      );
    }
    sql.exec(`DELETE FROM ${table} WHERE expires_at <= ?`, nowMs);
  }
  sql.exec(`DROP TABLE IF EXISTS ${staging}`);
}

function replaceTable(sql: SqlStorage, table: string): void {
  const staging = stagingOf(table);
  sql.exec(`DELETE FROM ${table}`);
  if (hasTable(sql, staging)) {
    const columns = sql.exec(`SELECT * FROM ${staging} LIMIT 0`).columnNames.join(", ");
    sql.exec(`INSERT INTO ${table} (${columns}) SELECT ${columns} FROM ${staging}`);
    sql.exec(`DROP TABLE ${staging}`);
  }
}

export interface MirrorCommitInput {
  readonly storage: DurableObjectStorage;
  readonly tables: readonly string[];
  readonly state: MirrorState;
  readonly nowMs: number;
  readonly sourceMutationSeq: number;
}

export function commitMirrorReplica(
  input: MirrorCommitInput,
): Effect.Effect<MirrorCommit, MirrorPageRefusedError> {
  const { storage, state } = input;
  const sql = storage.sql;
  return Effect.try({
    try: () =>
      storage.transactionSync(() => {
        if (!hasTable(sql, TRAILER_TABLE)) {
          throw malformed();
        }
        const replicaAuditSeq = stagedMaxSeq(sql, AUDIT_TABLE);
        const auditColumns = sql.exec(`SELECT * FROM ${AUDIT_TABLE} LIMIT 0`).columnNames;
        sql.exec(`DROP TABLE IF EXISTS ${LOCAL_AUDIT_TABLE}`);
        const stagedAudit = stagingOf(AUDIT_TABLE);
        if (hasTable(sql, stagedAudit)) {
          const differs = auditColumns
            .filter((column) => column !== "seq")
            .map((column) => `own.${column} IS NOT staged.${column}`)
            .join(" OR ");
          const rewritten = sql
            .exec(
              `SELECT COUNT(*) AS n FROM ${AUDIT_TABLE} AS own JOIN ${stagedAudit} AS staged ON staged.row_id = own.row_id WHERE own.seq > ? AND (${differs})`,
              state.lastAuditSeq,
            )
            .one()["n"];
          if (Number(rewritten) !== 0) {
            throw malformed();
          }
        }
        const carried = hasTable(sql, stagedAudit)
          ? ` AND row_id NOT IN (SELECT row_id FROM ${stagedAudit})`
          : "";
        sql.exec(
          `CREATE TABLE ${LOCAL_AUDIT_TABLE} AS SELECT * FROM ${AUDIT_TABLE} WHERE seq > ?${carried}`,
          state.lastAuditSeq,
        );
        const ownAuditRows = Number(
          sql.exec(`SELECT COUNT(*) AS n FROM ${LOCAL_AUDIT_TABLE}`).one()["n"],
        );
        swapTables(sql, input.tables, input.nowMs, state.lastAuditSeq);
        const shifted = auditColumns.map((column) =>
          column === "seq" ? "? + ROW_NUMBER() OVER (ORDER BY seq)" : column,
        );
        sql.exec(
          `INSERT INTO ${AUDIT_TABLE} (${auditColumns.join(", ")}) SELECT ${shifted.join(", ")} FROM ${LOCAL_AUDIT_TABLE} ORDER BY seq`,
          replicaAuditSeq,
        );
        sql.exec(`DROP TABLE ${LOCAL_AUDIT_TABLE}`);
        sql.exec(`DROP TABLE ${TRAILER_TABLE}`);
        const marks = readWatermarks(sql);
        const commit: MirrorCommit = {
          atMs: input.nowMs,
          chainHeadSeq: marks.chainHeadSeq,
          chainHeadHashHex: marks.chainHeadHashHex ?? "",
          auditMaxSeq: replicaAuditSeq,
          attestationMark: marks.attestationMark,
          mutationSeq: input.sourceMutationSeq,
          ownAuditRows,
        };
        sql.exec(
          `UPDATE mirror_state SET expected_sequence = 0, staging_table = NULL, last_synced_at = ?, last_head_seq = ?, last_head_hash_hex = ?, last_audit_seq = ?, last_attestation_mark = ?, last_mutation_seq = ? WHERE id = 1`,
          commit.atMs,
          commit.chainHeadSeq,
          commit.chainHeadHashHex,
          commit.auditMaxSeq,
          commit.attestationMark,
          input.sourceMutationSeq,
        );
        return commit;
      }),
    catch: (error) => (error instanceof MirrorPageRefusedError ? error : malformed()),
  }).pipe(Effect.onError(() => Effect.sync(() => discardMirrorStaging(storage, input.tables))));
}
