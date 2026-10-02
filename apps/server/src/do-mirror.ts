// Mirror state and replication inside the project DO (AUTH_SPEC §11-7 —
// PF2, docs/notes/pf2-design.md rulings A / D / G).
//
// A mirror is a project whose DO carries a `mirror_state` row (outside the
// snapshot set — do-schema.ts PROJECT_DO_LOCAL_TABLES: a replica never
// carries the mark). The replica arrives as the export's pages (the
// evacuation format of do-snapshot.ts): each page is **staged** into one
// staging table per snapshot table (`<table>_mirror`, created with the
// live table's column list after the same checks the restore reader
// makes) inside one transaction with the position update, so a page the
// client retries after a lost answer is refused as out of sequence
// instead of being staged twice. The page carrying the trailer
// **commits**: the per-table counts against the trailer, the staged chain
// extends the live chain (every live (seq, entry hash) equal at the same
// seq, the staged head not behind — a mirror is monotonic, a stale old
// primary can never be replicated over a newer one), the staged audit log
// not behind the last replicated position, then one transaction replaces
// every snapshot table except the deployment-local ones (lease windows
// and bindings, attestation windows — the mirror's own rate-limit and
// first-come state survives a replication).
//
// The commit is two steps under one permit: the page carrying the trailer
// stages its rows and runs the synchronous checks (counts, the hash
// extension, the audit position) and parks the trailer; the program then
// parses and verifies the staged chain in full (programs-mirror.ts — the
// signatures need the async WebCrypto, so this step sits between two
// transactions, the DO's permit still held) and the swap runs as its own
// transaction. A page retried after the trailer page was staged is out of
// sequence (the client restarts at 0).
//
// The mirror's own audit rows — the reads and leases it served since the
// last replication, `seq` past the last replicated position — are kept:
// they are re-appended after the replica's rows (their `seq` moves; the
// wire row id does not — AUDIT_SPEC §7 ruling C1). So the mirror's log is
// the source's log followed by what the mirror itself did, and the
// derived audit-head column (audit_head_hashes, replaced with the
// replica's) is extended over them by the ordinary lazy materialization.
//
// Every refusal but `sequence-mismatch` discards the staging in progress
// (the next upload starts at sequence 0). No audit row is written for a
// replication (ruling G).

import type { MirrorSyncRejectReason } from "./data-plane.ts";
import {
  acceptColumns,
  acceptHeader,
  CHAIN_TABLE,
  decodeScalar,
  MAX_BOUND_PARAMETERS,
  parseLine,
  readWatermarks,
  RestoreRefusedError,
  type SnapshotLine,
  type SnapshotRowLine,
  type SnapshotScalar,
  type SnapshotTableLine,
  type SnapshotTrailer,
} from "./do-snapshot.ts";
import { OPS_RESTORE_BATCH_ROWS } from "./ops-policy.ts";

/**
 * Snapshot tables a replication never replaces: the deployment's own
 * rate-limit windows and first-come bindings (AUTH_SPEC §14-1 / §14-3 /
 * §16-1). They are carried by the export (the source's) and dropped from
 * the staging at commit.
 */
const MIRROR_KEPT_TABLES: readonly string[] = [
  "lease_windows",
  "lease_bindings",
  "attestation_windows",
];

const AUDIT_TABLE = "audit_events";
/** Where the mirror's own audit rows wait during the swap (dropped afterwards; never exported — not in `tables`). */
const LOCAL_AUDIT_TABLE = "audit_events_mirror_local";
/** Where the staged replica's trailer waits between the trailer page and the commit. */
const TRAILER_TABLE = "trailer_mirror";

const stagingOf = (table: string): string => `${table}_mirror`;

export interface MirrorState {
  readonly sourceOrigin: string;
  readonly markedAtMs: number;
  /** The sequence the next replication page must carry (0 = no replication in progress). */
  readonly expectedSequence: number;
  /** The table whose rows the next page continues (null between tables). */
  readonly stagingTable: string | null;
  /** null = never replicated since the mark (the position is the mark's bootstrap). */
  readonly lastSyncedAtMs: number | null;
  readonly lastHeadSeq: number;
  readonly lastHeadHashHex: string;
  /** The replica's audit seq at the last replication (or the mark): rows past it are the mirror's own. */
  readonly lastAuditSeq: number;
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
  };
}

/** Marks the project (the caller checked it is not marked); the current heads are the bootstrap position. */
export function markMirror(sql: SqlStorage, sourceOrigin: string, nowMs: number): void {
  const marks = readWatermarks(sql);
  sql.exec(
    `INSERT INTO mirror_state (id, source_origin, marked_at, expected_sequence, staging_table, last_synced_at, last_head_seq, last_head_hash_hex, last_audit_seq)
     VALUES (1, ?, ?, 0, NULL, NULL, ?, ?, ?)`,
    sourceOrigin,
    nowMs,
    marks.chainHeadSeq,
    marks.chainHeadHashHex ?? "",
    marks.auditMaxSeq,
  );
}

function hasTable(sql: SqlStorage, name: string): boolean {
  return (
    sql.exec("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", name).toArray()
      .length > 0
  );
}

/** Drops every staging table (a replication left mid-way, a refusal, or the promotion). */
function dropStaging(sql: SqlStorage, tables: readonly string[]): void {
  for (const table of tables) {
    sql.exec(`DROP TABLE IF EXISTS ${stagingOf(table)}`);
  }
  sql.exec(`DROP TABLE IF EXISTS ${LOCAL_AUDIT_TABLE}`);
  sql.exec(`DROP TABLE IF EXISTS ${TRAILER_TABLE}`);
}

/** Drops the staging in progress and resets the position (every refusal but the sequence one). */
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

/** The promotion: the mark and any staging go; the project accepts writes again. */
export function unmarkMirror(storage: DurableObjectStorage, tables: readonly string[]): void {
  storage.transactionSync(() => {
    dropStaging(storage.sql, tables);
    storage.sql.exec("DELETE FROM mirror_state WHERE id = 1");
  });
}

export class MirrorPageRefusedError extends Error {
  constructor(readonly reason: MirrorSyncRejectReason) {
    super(`mirror page refused: ${reason}`);
  }
}

const malformed = (): MirrorPageRefusedError => new MirrorPageRefusedError("malformed");

function isSnapshotScalar(value: unknown): value is SnapshotScalar {
  return (
    value === null ||
    typeof value === "number" ||
    typeof value === "string" ||
    (typeof value === "object" && "b64" in value && typeof value.b64 === "string")
  );
}

/**
 * Consumes one page's lines in order into the staging tables (the same
 * state machine as the restore reader, resumable across pages: the open
 * table comes from `mirror_state`, its columns from the staging table).
 */
class PageStager {
  trailer: SnapshotTrailer | null = null;
  /** The table whose rows are being staged (persists across pages). */
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
        // A header past the first line, or an unknown kind
        throw malformed();
    }
  }

  #useColumns(columns: readonly string[]): void {
    this.#columns = columns;
    this.#rowsPerStatement = Math.max(1, Math.floor(MAX_BOUND_PARAMETERS / columns.length));
  }

  #beginTable(line: SnapshotTableLine): void {
    if (!this.known.has(line.table)) {
      throw new MirrorPageRefusedError("unknown-table");
    }
    this.flush();
    // The column names are embedded as identifiers: only the live
    // table's own list passes (acceptColumns — the restore's rule)
    const columns = acceptColumns(this.sql, line.table, line.columns);
    const staging = stagingOf(line.table);
    // A table line repeated inside one replica restarts that table
    this.sql.exec(`DROP TABLE IF EXISTS ${staging}`);
    this.sql.exec(`CREATE TABLE ${staging} (${columns.join(", ")})`);
    this.table = line.table;
    this.#useColumns(columns);
  }

  #acceptRow(line: SnapshotRowLine): void {
    const columns = this.#columns;
    if (
      this.table === null ||
      columns === null ||
      line.table !== this.table ||
      !Array.isArray(line.values) ||
      line.values.length !== columns.length ||
      !line.values.every(isSnapshotScalar)
    ) {
      throw malformed();
    }
    this.#buffer.push(line.values);
    this.rows += 1;
    if (this.#buffer.length >= OPS_RESTORE_BATCH_ROWS) {
      this.flush();
    }
  }

  /** Inserts the buffered rows (the caller's transaction makes the page atomic). */
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
  /** The export's page bounds (a page past them is refused as too large). */
  readonly maxRows: number;
  readonly maxBytes: number;
}

/** What a committed replication brought (the status's `lastSync`). */
export interface MirrorCommit {
  readonly atMs: number;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly auditMaxSeq: number;
}

/** A page was staged, or the trailer page was staged and the synchronous checks passed (the chain verification and the commit follow). */
export type MirrorStageResult =
  | { readonly kind: "staged"; readonly nextSequence: number }
  | { readonly kind: "trailer" };

function stagedCount(sql: SqlStorage, table: string): number {
  return hasTable(sql, stagingOf(table))
    ? Number(sql.exec(`SELECT COUNT(*) AS n FROM ${stagingOf(table)}`).one()["n"])
    : 0;
}

/** The staged table's highest `seq` (a non-integer value — a replica that is not what the server writes — is malformed). */
function stagedMaxSeq(sql: SqlStorage, table: string): number {
  if (!hasTable(sql, stagingOf(table))) {
    return 0;
  }
  const max = Number(
    sql.exec(`SELECT COALESCE(MAX(seq), 0) AS m FROM ${stagingOf(table)}`).one()["m"],
  );
  if (!Number.isInteger(max) || max < 0) {
    throw malformed();
  }
  return max;
}

/** The trailer's counts against the staged tables (and no count for a table this server has not). */
function verifyCounts(sql: SqlStorage, tables: readonly string[], trailer: SnapshotTrailer): void {
  const rows: unknown = trailer.rows;
  if (typeof rows !== "object" || rows === null) {
    throw malformed();
  }
  const counts = rows as Readonly<Record<string, unknown>>;
  const known = new Set(tables);
  for (const [table, count] of Object.entries(counts)) {
    if (!known.has(table) && count !== 0) {
      throw new MirrorPageRefusedError("unknown-table");
    }
  }
  for (const table of tables) {
    if ((counts[table] ?? 0) !== stagedCount(sql, table)) {
      throw new MirrorPageRefusedError("row-count-mismatch");
    }
  }
}

/** The staged chain extends the live chain (ruling D): every live entry present at the same seq with the same hash, the head not behind. */
function verifyChainExtension(sql: SqlStorage): void {
  const staging = stagingOf(CHAIN_TABLE);
  if (!hasTable(sql, staging)) {
    throw new MirrorPageRefusedError("chain-not-extension");
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
    throw new MirrorPageRefusedError("chain-not-extension");
  }
}

/** Replaces every snapshot table but the kept ones with its staging table (inside the caller's transaction). */
function swapTables(sql: SqlStorage, tables: readonly string[]): void {
  for (const table of tables) {
    const staging = stagingOf(table);
    if (MIRROR_KEPT_TABLES.includes(table)) {
      sql.exec(`DROP TABLE IF EXISTS ${staging}`);
      continue;
    }
    sql.exec(`DELETE FROM ${table}`);
    if (hasTable(sql, staging)) {
      const columns = sql.exec(`SELECT * FROM ${staging} LIMIT 0`).columnNames.join(", ");
      sql.exec(`INSERT INTO ${table} (${columns}) SELECT ${columns} FROM ${staging}`);
      sql.exec(`DROP TABLE ${staging}`);
    }
  }
}

/**
 * The trailer page's synchronous checks (inside the page's transaction):
 * the counts, the hash extension, the audit position; then the trailer is
 * parked and the position advanced, so a retry of this page is out of
 * sequence rather than staged twice.
 */
function acceptTrailer(
  sql: SqlStorage,
  input: MirrorPageInput,
  trailer: SnapshotTrailer,
  nextSequence: number,
): void {
  verifyCounts(sql, input.tables, trailer);
  verifyChainExtension(sql);
  if (stagedMaxSeq(sql, AUDIT_TABLE) < input.state.lastAuditSeq) {
    throw new MirrorPageRefusedError("audit-regression");
  }
  sql.exec(`DROP TABLE IF EXISTS ${TRAILER_TABLE}`);
  sql.exec(`CREATE TABLE ${TRAILER_TABLE} (trailer_json TEXT NOT NULL)`);
  sql.exec(`INSERT INTO ${TRAILER_TABLE} (trailer_json) VALUES (?)`, JSON.stringify(trailer));
  sql.exec(
    "UPDATE mirror_state SET expected_sequence = ?, staging_table = NULL WHERE id = 1",
    nextSequence,
  );
}

/** One staged chain row as the content verification reads it (programs-mirror.ts). */
export interface StagedChainRow {
  readonly seq: number;
  readonly entryJson: string;
  readonly entryHashHex: string;
  readonly canonicalBytes: number;
}

/** The staged chain in seq order (contiguous from 1, every column of the shape the server writes — else malformed). */
export function stagedChainRows(sql: SqlStorage): readonly StagedChainRow[] {
  const staging = stagingOf(CHAIN_TABLE);
  if (!hasTable(sql, staging)) {
    throw new MirrorPageRefusedError("chain-not-extension");
  }
  const rows = sql
    .exec(`SELECT seq, entry_json, entry_hash_hex, canonical_bytes FROM ${staging} ORDER BY seq`)
    .toArray();
  return rows.map((row, index) => {
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
      throw malformed();
    }
    return { seq, entryJson, entryHashHex, canonicalBytes };
  });
}

export interface MirrorCommitInput {
  readonly storage: DurableObjectStorage;
  readonly tables: readonly string[];
  readonly state: MirrorState;
  readonly nowMs: number;
}

/**
 * The commit (its own transaction, after the chain verification): the
 * swap, the mirror's own audit rows re-appended after the replica's, the
 * position. A constraint the live schema refuses (a duplicate key, a NULL
 * where none is allowed) rolls the transaction back and is `malformed`.
 */
export function commitMirrorReplica(input: MirrorCommitInput): MirrorCommit {
  const { storage, state } = input;
  const sql = storage.sql;
  try {
    return storage.transactionSync(() => {
      if (!hasTable(sql, TRAILER_TABLE)) {
        throw malformed();
      }
      const replicaAuditSeq = stagedMaxSeq(sql, AUDIT_TABLE);
      // The mirror's own rows (past the last replicated position) wait aside
      const auditColumns = sql.exec(`SELECT * FROM ${AUDIT_TABLE} LIMIT 0`).columnNames;
      sql.exec(`DROP TABLE IF EXISTS ${LOCAL_AUDIT_TABLE}`);
      sql.exec(
        `CREATE TABLE ${LOCAL_AUDIT_TABLE} AS SELECT * FROM ${AUDIT_TABLE} WHERE seq > ?`,
        state.lastAuditSeq,
      );
      swapTables(sql, input.tables);
      // … and follow the replica's rows (contiguous past the last position,
      // so a shift keeps their order)
      const shifted = auditColumns.map((column) => (column === "seq" ? "seq - ? + ?" : column));
      sql.exec(
        `INSERT INTO ${AUDIT_TABLE} (${auditColumns.join(", ")}) SELECT ${shifted.join(", ")} FROM ${LOCAL_AUDIT_TABLE} ORDER BY seq`,
        state.lastAuditSeq,
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
      };
      sql.exec(
        `UPDATE mirror_state SET expected_sequence = 0, staging_table = NULL, last_synced_at = ?, last_head_seq = ?, last_head_hash_hex = ?, last_audit_seq = ? WHERE id = 1`,
        commit.atMs,
        commit.chainHeadSeq,
        commit.chainHeadHashHex,
        commit.auditMaxSeq,
      );
      return commit;
    });
  } catch (error) {
    discardMirrorStaging(storage, input.tables);
    // A refusal of the checks above, or SQLite refusing the replica's rows
    // against the live schema (its message names a constraint, never a value)
    throw error instanceof MirrorPageRefusedError ? error : malformed();
  }
}

function toRefusal(error: unknown): MirrorPageRefusedError | null {
  if (error instanceof MirrorPageRefusedError) {
    return error;
  }
  if (error instanceof RestoreRefusedError) {
    // The restore reader's vocabulary folded onto the page's (its other codes cannot arise here)
    return new MirrorPageRefusedError(
      error.code === "schema-mismatch" ? "schema-mismatch" : "malformed",
    );
  }
  return null;
}

/** The page bounds (the export's, plus one line of slack): judged before any write. */
function ensurePageBounds(input: MirrorPageInput): void {
  const encoder = new TextEncoder();
  let bytes = 0;
  for (const line of input.lines) {
    bytes += encoder.encode(line).length + 1;
    if (bytes > input.maxBytes) {
      throw new MirrorPageRefusedError("page-too-large");
    }
  }
}

/**
 * Stages one page (the caller holds the permit and verified the mark and
 * the storage guard). Throws {@link MirrorPageRefusedError}; any other
 * throw is a defect (the transaction rolled back either way).
 */
export function stageMirrorPage(input: MirrorPageInput): MirrorStageResult {
  const { storage, state } = input;
  const sql = storage.sql;
  if (input.sequence !== 0 && input.sequence !== state.expectedSequence) {
    throw new MirrorPageRefusedError("sequence-mismatch");
  }
  try {
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
          throw new MirrorPageRefusedError("page-too-large");
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
        return { kind: "staged", nextSequence };
      }
      acceptTrailer(sql, input, stager.trailer, nextSequence);
      return { kind: "trailer" };
    });
  } catch (error) {
    // The page's transaction rolled back; the staging in progress is
    // discarded on every refusal (the sequence refusal above keeps it)
    discardMirrorStaging(storage, input.tables);
    const refusal = toRefusal(error);
    if (refusal === null) {
      throw error;
    }
    throw refusal;
  }
}
