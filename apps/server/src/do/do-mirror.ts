import { Effect } from "effect";

import { auditRowShapeViolations } from "../audit-store.ts";
import { OPS_RESTORE_BATCH_ROWS } from "../ops/ops-policy.ts";
import { verifyChainAnchoredProjections } from "./do-mirror-chain-verify.ts";
import { verifyProjectionRegression } from "./do-mirror-regression.ts";
import {
  AUDIT_HEAD_TABLE,
  AUDIT_TABLE,
  discardMirrorStaging,
  dropStaging,
  hasTable,
  malformed,
  MirrorPageRefusedError,
  type MirrorState,
  stagedCount,
  stagedMaxSeq,
  stagingOf,
  TRAILER_TABLE,
} from "./do-mirror-state.ts";
import {
  acceptColumns,
  acceptHeader,
  MAX_BOUND_PARAMETERS,
  parseLine,
  RestoreRefusedError,
} from "./do-snapshot-restore.ts";
import {
  CHAIN_TABLE,
  decodeScalar,
  readWatermarks,
  type SnapshotLine,
  type SnapshotRowLine,
  type SnapshotScalar,
  type SnapshotTableLine,
  type SnapshotTrailer,
} from "./do-snapshot.ts";

class PageStager {
  trailer: SnapshotTrailer | null = null;
  table: string | null;
  rows = 0;
  #headerSeen: boolean;
  #columns: readonly string[] | null = null;
  #rowsPerStatement = 1;
  #buffer: (readonly SnapshotScalar[])[] = [];

  constructor(
    private readonly sql: SqlStorage,
    private readonly known: ReadonlySet<string>,
    private readonly schemaVersion: number,
    openTable: string | null,
    firstPage: boolean,
  ) {
    this.table = openTable;
    this.#headerSeen = !firstPage;
    if (openTable !== null) {
      this.#useColumns(this.sql.exec(`SELECT * FROM ${stagingOf(openTable)} LIMIT 0`).columnNames);
    }
  }

  accept(line: SnapshotLine): void {
    if (!this.#headerSeen) {
      acceptHeader(line, this.schemaVersion);
      this.#headerSeen = true;
      return;
    }
    if (this.trailer !== null) {
      throw malformed();
    }
    switch (line.kind) {
      case "table":
        this.#beginTable(line);
        return;
      case "row":
        this.#acceptRow(line);
        return;
      case "trailer":
        this.flush();
        this.trailer = line;
        this.table = null;
        return;
      default:
        throw malformed();
    }
  }

  #useColumns(columns: readonly string[]): void {
    this.#columns = columns;
    this.#rowsPerStatement = Math.max(1, Math.floor(MAX_BOUND_PARAMETERS / columns.length));
  }

  #beginTable(line: SnapshotTableLine): void {
    if (!this.known.has(line.table)) {
      throw new MirrorPageRefusedError({ reason: "unknown-table" });
    }
    this.flush();
    const columns = acceptColumns(this.sql, line.table, line.columns);
    const staging = stagingOf(line.table);
    this.sql.exec(`DROP TABLE IF EXISTS ${staging}`);
    this.sql.exec(
      `CREATE TABLE ${staging} AS SELECT ${columns.join(", ")} FROM ${line.table} LIMIT 0`,
    );
    if (columns.includes("seq")) {
      this.sql.exec(`CREATE INDEX ${staging}_seq ON ${staging} (seq)`);
    }
    this.table = line.table;
    this.#useColumns(columns);
  }

  #acceptRow(line: SnapshotRowLine): void {
    const columns = this.#columns;
    if (
      this.table === null ||
      columns === null ||
      line.table !== this.table ||
      line.values.length !== columns.length
    ) {
      throw malformed();
    }
    this.#buffer.push(line.values);
    this.rows += 1;
    if (this.#buffer.length >= OPS_RESTORE_BATCH_ROWS) {
      this.flush();
    }
  }

  flush(): void {
    const table = this.table;
    const columns = this.#columns;
    if (this.#buffer.length === 0 || table === null || columns === null) {
      return;
    }
    const rows = this.#buffer;
    this.#buffer = [];
    const columnList = columns.join(", ");
    const placeholders = `(${columns.map(() => "?").join(", ")})`;
    for (let start = 0; start < rows.length; start += this.#rowsPerStatement) {
      const chunk = rows.slice(start, start + this.#rowsPerStatement);
      this.sql.exec(
        `INSERT INTO ${stagingOf(table)} (${columnList}) VALUES ${chunk.map(() => placeholders).join(", ")}`,
        ...chunk.flatMap((values) => values.map(decodeScalar)),
      );
    }
  }
}

interface MirrorPageInput {
  readonly storage: DurableObjectStorage;
  readonly tables: readonly string[];
  readonly schemaVersion: number;
  readonly state: MirrorState;
  readonly sequence: number;
  readonly lines: readonly string[];
  readonly nowMs: number;
  readonly maxRows: number;
  readonly maxBytes: number;
}

export type MirrorStageResult =
  | { readonly kind: "staged"; readonly nextSequence: number }
  | { readonly kind: "trailer" };

function verifyAuditContiguity(sql: SqlStorage): void {
  const auditRows = stagedCount(sql, AUDIT_TABLE);
  const headRows = stagedCount(sql, AUDIT_HEAD_TABLE);
  if (
    auditRows !== stagedMaxSeq(sql, AUDIT_TABLE) ||
    headRows !== stagedMaxSeq(sql, AUDIT_HEAD_TABLE) ||
    headRows > auditRows
  ) {
    throw malformed();
  }
}

function verifyCounts(sql: SqlStorage, tables: readonly string[], trailer: SnapshotTrailer): void {
  const known = new Set(tables);
  for (const [table, count] of Object.entries(trailer.rows)) {
    if (!known.has(table) && count !== 0) {
      throw new MirrorPageRefusedError({ reason: "unknown-table" });
    }
  }
  for (const table of tables) {
    if ((trailer.rows[table] ?? 0) !== stagedCount(sql, table)) {
      throw new MirrorPageRefusedError({ reason: "row-count-mismatch" });
    }
  }
}

function verifyChainExtension(sql: SqlStorage): void {
  const staging = stagingOf(CHAIN_TABLE);
  if (!hasTable(sql, staging)) {
    throw new MirrorPageRefusedError({ reason: "chain-not-extension" });
  }
  const diverging = sql
    .exec(
      `SELECT COUNT(*) AS n FROM ${CHAIN_TABLE} AS live
       LEFT JOIN ${staging} AS staged ON staged.seq = live.seq
       WHERE staged.entry_hash_hex IS NULL OR staged.entry_hash_hex <> live.entry_hash_hex`,
    )
    .one()["n"];
  if (
    Number(diverging) !== 0 ||
    stagedMaxSeq(sql, CHAIN_TABLE) < readWatermarks(sql).chainHeadSeq
  ) {
    throw new MirrorPageRefusedError({ reason: "chain-not-extension" });
  }
}

function acceptTrailer(
  sql: SqlStorage,
  input: MirrorPageInput,
  trailer: SnapshotTrailer,
  nextSequence: number,
): void {
  verifyCounts(sql, input.tables, trailer);
  verifyAuditContiguity(sql);
  if (
    hasTable(sql, stagingOf(AUDIT_TABLE)) &&
    auditRowShapeViolations(sql, stagingOf(AUDIT_TABLE)) !== 0
  ) {
    throw malformed();
  }
  verifyChainExtension(sql);
  if (stagedMaxSeq(sql, AUDIT_TABLE) < input.state.lastAuditSeq) {
    throw new MirrorPageRefusedError({ reason: "audit-regression" });
  }
  if (input.state.lastAuditSeq > 0) {
    verifyAuditPrefix(sql, input.state);
  }
  verifyProjectionRegression(sql);
  verifyChainAnchoredProjections(sql);
  sql.exec(`DROP TABLE IF EXISTS ${TRAILER_TABLE}`);
  sql.exec(`CREATE TABLE ${TRAILER_TABLE} (trailer_json TEXT NOT NULL)`);
  sql.exec(`INSERT INTO ${TRAILER_TABLE} (trailer_json) VALUES (?)`, JSON.stringify(trailer));
  sql.exec(
    "UPDATE mirror_state SET expected_sequence = ?, staging_table = NULL WHERE id = 1",
    nextSequence,
  );
}

function verifyAuditPrefix(sql: SqlStorage, state: MirrorState): void {
  const staged = stagingOf(AUDIT_TABLE);
  const stagedHeads = stagingOf(AUDIT_HEAD_TABLE);
  if (!hasTable(sql, staged) || !hasTable(sql, stagedHeads)) {
    throw new MirrorPageRefusedError({ reason: "audit-not-extension" });
  }
  const headsDiffer = sql
    .exec(
      `SELECT COUNT(*) AS n FROM ${AUDIT_HEAD_TABLE} AS own LEFT JOIN ${stagedHeads} AS theirs ON theirs.seq = own.seq WHERE own.seq <= ? AND (theirs.seq IS NULL OR theirs.head_hash_hex IS NOT own.head_hash_hex)`,
      state.lastAuditSeq,
    )
    .one()["n"];
  const ownReaches = sql
    .exec(`SELECT 1 FROM ${AUDIT_HEAD_TABLE} WHERE seq = ?`, state.lastAuditSeq)
    .toArray()[0];
  if (Number(headsDiffer) !== 0 || ownReaches === undefined) {
    throw new MirrorPageRefusedError({ reason: "audit-not-extension" });
  }
  const columns = sql.exec(`SELECT * FROM ${AUDIT_TABLE} LIMIT 0`).columnNames;
  const differs = columns
    .filter((column) => column !== "seq")
    .map((column) => `own.${column} IS NOT theirs.${column}`)
    .join(" OR ");
  const rewritten = sql
    .exec(
      `SELECT COUNT(*) AS n FROM ${AUDIT_TABLE} AS own LEFT JOIN ${staged} AS theirs ON theirs.seq = own.seq WHERE own.seq <= ? AND (theirs.seq IS NULL OR ${differs})`,
      state.lastAuditSeq,
    )
    .one()["n"];
  if (Number(rewritten) !== 0) {
    throw new MirrorPageRefusedError({ reason: "audit-not-extension" });
  }
}

const toMirrorRefusal = (error: unknown): MirrorPageRefusedError => {
  if (error instanceof MirrorPageRefusedError) {
    return error;
  }
  if (error instanceof RestoreRefusedError) {
    return new MirrorPageRefusedError({
      reason: error.code === "schema-mismatch" ? "schema-mismatch" : "malformed",
    });
  }
  throw error;
};

function ensurePageBounds(input: MirrorPageInput): void {
  const encoder = new TextEncoder();
  let bytes = 0;
  for (const line of input.lines) {
    bytes += encoder.encode(line).length + 1;
    if (bytes > input.maxBytes) {
      throw new MirrorPageRefusedError({ reason: "page-too-large" });
    }
  }
}

export function stageMirrorPage(
  input: MirrorPageInput,
): Effect.Effect<MirrorStageResult, MirrorPageRefusedError> {
  const { storage, state } = input;
  const sql = storage.sql;
  return Effect.gen(function* () {
    if (input.sequence !== 0 && input.sequence !== state.expectedSequence) {
      return yield* new MirrorPageRefusedError({ reason: "sequence-mismatch" });
    }
    return yield* Effect.try({
      try: () => {
        ensurePageBounds(input);
        return storage.transactionSync(() => {
          const first = input.sequence === 0;
          if (first) {
            dropStaging(sql, input.tables);
          }
          const stager = new PageStager(
            sql,
            new Set(input.tables),
            input.schemaVersion,
            first ? null : state.stagingTable,
            first,
          );
          for (const text of input.lines) {
            stager.accept(parseLine(text));
            if (stager.rows > input.maxRows) {
              throw new MirrorPageRefusedError({ reason: "page-too-large" });
            }
          }
          stager.flush();
          const nextSequence = input.sequence + 1;
          if (stager.trailer === null) {
            sql.exec(
              "UPDATE mirror_state SET expected_sequence = ?, staging_table = ? WHERE id = 1",
              nextSequence,
              stager.table,
            );
            return { kind: "staged", nextSequence } satisfies MirrorStageResult;
          }
          acceptTrailer(sql, input, stager.trailer, nextSequence);
          return { kind: "trailer" } satisfies MirrorStageResult;
        });
      },
      catch: toMirrorRefusal,
    }).pipe(Effect.onError(() => Effect.sync(() => discardMirrorStaging(storage, input.tables))));
  });
}
