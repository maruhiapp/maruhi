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
// The projection tables are bound the same way (the chain and the audit
// log were, the rest of the snapshot was not): a mirror never writes the
// data plane locally — every such write is refused while the mark stands
// — so the live projection rows are exactly the last replicated (or
// bootstrapped) state, and a replica may only advance them. The trailer
// checks therefore also refuse a replica whose statements or versions
// rewrite a live row, whose per-environment counters, manifest or
// checkpoint regress, or whose manifest / checkpoint state does not
// match the staged chain that the commit is gated on verifying in full
// (the checkpoint tuples and the environment lifecycle the chain
// carries). A deletion is the one legitimate removal, and it is never
// taken on the replica's word: an environment's tombstone must be the
// staged chain's `delete_environment`, a variable's tombstone its latest
// statement's `deleted` form. The same discipline covers the remaining
// snapshot tables: DEK wraps and head attestations are preserved row
// for row against the live rows, with removals excused only by the
// staged-chain entries that cause them on a primary (the environment
// cascade, the stale-wrap sweep of a re-added member, the attestation
// cleanup of a removed member or revoked device) and every staged
// attestation's declared head resolving to the staged chain; the
// manifest version must equal the staged statement count plus the
// staged rotation count (every manifest reissue is bundled with exactly
// one of those); and the project settings and the sealed rotation
// proposals — which no chain entry carries — must fold exactly from the
// staged audit log, the one remaining anchor the replica itself carries
// (see {@link verifyChainAnchoredProjections}).
//
// The mirror's own audit rows — the reads and leases it served since the
// last replication, `seq` past the last replicated position — are kept:
// they are re-appended after the replica's rows (their `seq` moves; the
// wire row id does not — AUDIT_SPEC §7 ruling C1). So the mirror's log is
// the source's log followed by what the mirror itself did, and the
// derived audit-head column (audit_head_hashes — installed from the first
// replica after a mark, the mirror's own derivation from then on: kept up
// to the replicated position, derived past it) is extended over them by
// the ordinary lazy materialization.
//
// Every refusal but `sequence-mismatch` discards the staging in progress
// (the next upload starts at sequence 0). No audit row is written for a
// replication (ruling G).

import { Data, Effect } from "effect";

import { auditRowShapeViolations, deriveAuditHeads, isAuditHeadHex } from "../audit-store.ts";
import type { MirrorSyncRejectReason } from "../data/data-rejection.ts";
import { OPS_RESTORE_BATCH_ROWS } from "../ops/ops-policy.ts";
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

const MANIFEST_TABLE = "environment_manifests";
const CHECKPOINT_TABLE = "environment_checkpoints";
const ENVIRONMENTS_TABLE = "environments";
const VARIABLES_TABLE = "variables";

const AUDIT_TABLE = "audit_events";
/** Where the mirror's own audit rows wait during the swap (dropped afterwards; never exported — not in `tables`). */
const LOCAL_AUDIT_TABLE = "audit_events_mirror_local";
const AUDIT_HEAD_TABLE = "audit_head_hashes";
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
  /** The replica's attestation mark at the last replication (or the mark). */
  readonly lastAttestationMark: number;
  /** The source's mutation counter the replica was exported at (null until the first replication since the mark). */
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

/**
 * Re-points a marked project at another source (ruling C revision, round
 * 4 — the honest path after a failover elsewhere, without a writable
 * window): the staging in progress goes, the source changes, the chain
 * position stays (checked against the new source's chain by the client's
 * mark guard), the audit position resets to 0 (a seq floor compares
 * positions of one source's log only — the new source's log is another;
 * the first replica from it is accepted whatever its audit seq, and the
 * rows it does not carry are re-appended after it — round 5), the
 * mutation counter is forgotten — it is per deployment — and so is the
 * replication record: what the status reports as the last replication is
 * one from the current source, or nothing (ruling H revision, round 9).
 */
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

/**
 * Marks the project (the caller checked it is not marked); the current
 * chain head is the bootstrap position. The audit position starts at 0
 * (ruling C revision, round 5): the first replica is accepted whatever
 * its audit seq, and every row of this project's log that the replica
 * does not carry — a former primary's rows after its last export — is
 * re-appended after it, never replaced.
 */
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

/**
 * The page refusal in the Effect error channel (the reason is the
 * worker-facing MirrorSyncRejectReason). Inside transactionSync
 * closures it is still thrown — the throw is what rolls the page's
 * transaction back — and the boundary's `catch` turns it back into the
 * typed error (the only place an instanceof may remain).
 */
export class MirrorPageRefusedError extends Data.TaggedError("MirrorPageRefused")<{
  readonly reason: MirrorSyncRejectReason;
}> {}

const malformed = (): MirrorPageRefusedError => new MirrorPageRefusedError({ reason: "malformed" });

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
      throw new MirrorPageRefusedError({ reason: "unknown-table" });
    }
    this.flush();
    // The column names are embedded as identifiers: only the live
    // table's own list passes (acceptColumns — the restore's rule)
    const columns = acceptColumns(this.sql, line.table, line.columns);
    const staging = stagingOf(line.table);
    // A table line repeated inside one replica restarts that table. The
    // staging table takes the live table's column affinities (a typeless
    // column cannot drive an index against the live INTEGER `seq`, which
    // made the prefix checks a scan of the staged log per live row — ruling
    // J revision, round 8), and its `seq` is indexed for the joins
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
  /** The replica's attestation mark (the source's latest head-attestation acceptance time). */
  readonly attestationMark: number;
  /** The source's mutation counter the replica was exported at. */
  readonly mutationSeq: number;
  /** The mirror's own audit rows re-appended after the replica's (ruling G revision). */
  readonly ownAuditRows: number;
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
  const min = Number(
    sql.exec(`SELECT COALESCE(MIN(seq), 1) AS m FROM ${stagingOf(table)}`).one()["m"],
  );
  if (!Number.isInteger(max) || max < 0 || !Number.isInteger(min) || min < 1) {
    throw malformed();
  }
  return max;
}

/**
 * The staged audit log is exactly seq 1..N and the staged head column
 * exactly 1..M with M ≤ N (ruling J revision, round 9): a log with a gap or
 * a seq at or below 0 committed, and the post-commit extension then threw
 * the append-only defect on every later page, read and export of this
 * mirror — a replica the mirror cannot hash never replaces the live log
 * (the chain's `chain-invalid` principle). A column longer than the log
 * installed phantom heads nothing derives. Duplicates still die at the
 * swap (the live primary key).
 */
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

/** The trailer's counts against the staged tables (and no count for a table this server has not). */
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

/** The staged chain extends the live chain (ruling D): every live entry present at the same seq with the same hash, the head not behind. */
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

/** Replaces every snapshot table but the kept ones with its staging table (inside the caller's transaction). */
/**
 * The source's first-come bindings are merged into the mirror's own (never
 * replacing one — ruling D revision): a workload whose token was bound on
 * the source cannot bind the same token to another key on the mirror, and
 * the mirror's own bindings stay.
 */
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

/**
 * Past a replicated position the served heads are the mirror's own
 * derivation (ruling J revision, round 8): the rows up to the position were
 * verified identical to the replica's, so their heads are kept; the rest
 * was derived from the staged rows before the swap (verifyStagedAuditHeads
 * — round 10) and is installed from the staging, where it replaced the
 * uploaded claim.
 */
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

/** A deployment-local table keeps its rows; the merged one takes the source's live bindings and drops the expired of either side (ruling D revision, round 3). */
function keepTable(sql: SqlStorage, table: string, nowMs: number): void {
  const staging = stagingOf(table);
  if (table === MERGED_TABLE) {
    // Only live bindings are merged, and the mirror's own expired ones
    // go: a mirror that never issues a lease has no other collection
    // of this table
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

/** Every other snapshot table is replaced by the staged replica's rows. */
function replaceTable(sql: SqlStorage, table: string): void {
  const staging = stagingOf(table);
  sql.exec(`DELETE FROM ${table}`);
  if (hasTable(sql, staging)) {
    const columns = sql.exec(`SELECT * FROM ${staging} LIMIT 0`).columnNames.join(", ");
    sql.exec(`INSERT INTO ${table} (${columns}) SELECT ${columns} FROM ${staging}`);
    sql.exec(`DROP TABLE ${staging}`);
  }
}

/**
 * The trailer page's synchronous checks (inside the page's transaction):
 * the counts, the hash extension, the audit position, the projection
 * regression and chain-anchor checks; then the trailer is parked and
 * the position advanced, so a retry of this page is out of sequence
 * rather than staged twice.
 */
function acceptTrailer(
  sql: SqlStorage,
  input: MirrorPageInput,
  trailer: SnapshotTrailer,
  nextSequence: number,
): void {
  verifyCounts(sql, input.tables, trailer);
  verifyAuditContiguity(sql);
  // Every staged row's numbers in the canonical form's domain (round 11):
  // the rows under an uploaded head column are never derived over, so a
  // row the extension cannot hash would otherwise be installed with them
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
  // The replica's log must extend the one replicated last: every live row
  // up to the replicated position — the mirror's own accepted evidence,
  // the rows it served to its readers — must be in the staged log, row for
  // row (ruling J revision, round 7: the carried cumulative-hash column is
  // an uploaded value, so it proves nothing by itself; it stays as a first
  // check). A mark or a re-point records no position, so the first replica is free
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

/**
 * The replicated prefix, row for row: a live row at or below the position
 * that the staged log lacks or carries differently is `audit-not-extension`;
 * so is a staged head that differs from the mirror's own at or below the
 * position (the mirror's column is its own derivation over those rows —
 * ruling J revision, round 8 — so the uploaded column must agree with it;
 * a staged column that does not reach the position is one such claim too).
 */
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

/** Whether the staged replica tombstones the environment (the staged row exists and carries `deleted_at`). */
function stagedEnvTombstoned(sql: SqlStorage, environmentId: string): boolean {
  const staging = stagingOf(ENVIRONMENTS_TABLE);
  if (!hasTable(sql, staging)) {
    return false;
  }
  const row = sql
    .exec(`SELECT deleted_at FROM ${staging} WHERE environment_id = ?`, environmentId)
    .toArray()[0];
  return row !== undefined && row["deleted_at"] !== null;
}

/**
 * Every live row of an append-only projection table present identically
 * in the staged replica (the {@link verifyAuditPrefix} discipline,
 * applied to the signed statement and value rows): statement rows are
 * never rewritten or removed, and a value version's row never changes
 * once written — the only removals are the deletion cascades, judged by
 * the caller through `exempt` (an SQL predicate over `own`, built from
 * the staged tombstones). A staged table the replica does not carry at
 * all preserves nothing.
 */
function verifyRowsPreserved(
  sql: SqlStorage,
  table: string,
  keyColumns: readonly string[],
  exempt: string,
): void {
  const staging = stagingOf(table);
  const notExempt = exempt === "" ? "" : ` AND NOT (${exempt})`;
  if (!hasTable(sql, staging)) {
    const missing = sql
      .exec(`SELECT COUNT(*) AS n FROM ${table} AS own WHERE 1 = 1${notExempt}`)
      .one()["n"];
    if (Number(missing) !== 0) {
      throw malformed();
    }
    return;
  }
  const columns = sql.exec(`SELECT * FROM ${table} LIMIT 0`).columnNames;
  const join = keyColumns.map((column) => `theirs.${column} = own.${column}`).join(" AND ");
  const differs = columns
    .filter((column) => !keyColumns.includes(column))
    .map((column) => `own.${column} IS NOT theirs.${column}`)
    .join(" OR ");
  const rewritten = sql
    .exec(
      `SELECT COUNT(*) AS n FROM ${table} AS own LEFT JOIN ${staging} AS theirs ON ${join} WHERE (theirs.${keyColumns[0]} IS NULL OR ${differs})${notExempt}`,
    )
    .one()["n"];
  if (Number(rewritten) !== 0) {
    throw malformed();
  }
}

/** The staged-tombstone exemption for a cascade-deleted environment's rows (empty when the replica carries no environments table). */
function envCascadeExempt(sql: SqlStorage): string {
  const staging = stagingOf(ENVIRONMENTS_TABLE);
  return hasTable(sql, staging)
    ? `EXISTS (SELECT 1 FROM ${staging} AS se WHERE se.environment_id = own.environment_id AND se.deleted_at IS NOT NULL)`
    : "";
}

/**
 * The projection tables against the live mirror state: the counters, the
 * latest manifest and the latest checkpoint of every environment may
 * only advance, and the append-only rows are preserved row for row. A
 * mirror takes no data-plane write of its own, so the live rows are the
 * last replicated state — a replica behind them, or rewriting them, is
 * refused as `malformed` (the staged rows are not a replica of the state
 * the mirror holds; no new wire reason is introduced for it). The one
 * legitimate removal is a deletion, and the tombstone that excuses it is
 * itself bound to the staged chain by
 * {@link verifyChainAnchoredProjections}.
 */
// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- the projection-regression checklist over the staged tables; each branch is one refusal condition, and splitting the checklist would obscure it
function verifyProjectionRegression(sql: SqlStorage): void {
  const envExempt = envCascadeExempt(sql);
  verifyRowsPreserved(
    sql,
    "environment_meta_statements",
    ["environment_id", "meta_version"],
    envExempt,
  );
  verifyRowsPreserved(
    sql,
    "variable_meta_statements",
    ["environment_id", "variable_id", "meta_version"],
    envExempt,
  );
  const varStaging = stagingOf(VARIABLES_TABLE);
  const varTomb = hasTable(sql, varStaging)
    ? `EXISTS (SELECT 1 FROM ${varStaging} AS sv WHERE sv.environment_id = own.environment_id AND sv.variable_id = own.variable_id AND sv.deleted_at IS NOT NULL)`
    : "";
  const varExempt = [envExempt, varTomb].filter((part) => part !== "").join(" OR ");
  verifyRowsPreserved(
    sql,
    "variable_versions",
    ["environment_id", "variable_id", "version"],
    varExempt,
  );
  // The derived counters: an environment row is never removed (deletion
  // tombstones it), a variable row only by its environment's cascade
  const envStaging = stagingOf(ENVIRONMENTS_TABLE);
  if (!hasTable(sql, envStaging)) {
    if (stagedCount(sql, ENVIRONMENTS_TABLE) !== 0 || liveCount(sql, ENVIRONMENTS_TABLE) !== 0) {
      throw malformed();
    }
  } else {
    const regressed = sql
      .exec(
        `SELECT COUNT(*) AS n FROM ${ENVIRONMENTS_TABLE} AS own LEFT JOIN ${envStaging} AS theirs ON theirs.environment_id = own.environment_id WHERE theirs.environment_id IS NULL OR theirs.latest_meta_version < own.latest_meta_version`,
      )
      .one()["n"];
    if (Number(regressed) !== 0) {
      throw malformed();
    }
    if (hasTable(sql, varStaging)) {
      const badVars = sql
        .exec(
          `SELECT COUNT(*) AS n FROM ${VARIABLES_TABLE} AS own LEFT JOIN ${varStaging} AS theirs ON theirs.environment_id = own.environment_id AND theirs.variable_id = own.variable_id WHERE (theirs.variable_id IS NULL AND NOT (${envExempt === "" ? "0" : envExempt})) OR theirs.latest_meta_version < own.latest_meta_version OR theirs.latest_version < own.latest_version`,
        )
        .one()["n"];
      if (Number(badVars) !== 0) {
        throw malformed();
      }
    } else if (liveCount(sql, VARIABLES_TABLE) !== 0) {
      throw malformed();
    }
  }
  verifyManifestRegression(sql);
  verifyCheckpointRegression(sql);
}

function liveCount(sql: SqlStorage, table: string): number {
  return Number(sql.exec(`SELECT COUNT(*) AS n FROM ${table}`).one()["n"]);
}

/** One staged row by environment (undefined when the replica carries no such table or row). */
function stagedRowOf(sql: SqlStorage, table: string, environmentId: string) {
  const staging = stagingOf(table);
  if (!hasTable(sql, staging)) {
    return undefined;
  }
  return sql.exec(`SELECT * FROM ${staging} WHERE environment_id = ?`, environmentId).toArray()[0];
}

/**
 * The latest manifest per environment against the live one: the version
 * and the epoch may only advance, and at the live version the staged row
 * must be the live row's manifest — its signed-bytes hash covers the
 * version, the epoch, the variables digest, the environment-meta binding
 * and the declared head, so an equal hash at an equal version is the
 * whole manifest. A missing staged manifest is a deletion's cascade
 * only.
 */
function verifyManifestRegression(sql: SqlStorage): void {
  const live = sql.exec(`SELECT * FROM ${MANIFEST_TABLE}`).toArray();
  for (const row of live) {
    const environmentId = String(row["environment_id"]);
    const staged = stagedRowOf(sql, MANIFEST_TABLE, environmentId);
    if (staged === undefined) {
      if (!stagedEnvTombstoned(sql, environmentId)) {
        throw malformed();
      }
      continue;
    }
    if (
      Number(staged["manifest_version"]) < Number(row["manifest_version"]) ||
      Number(staged["epoch"]) < Number(row["epoch"]) ||
      (Number(staged["manifest_version"]) === Number(row["manifest_version"]) &&
        String(staged["signed_bytes_hash_hex"]) !== String(row["signed_bytes_hash_hex"]))
    ) {
      throw malformed();
    }
  }
}

/**
 * The latest checkpoint per environment against the live one (the same
 * monotonicity), and — where the staged checkpoint carries the live
 * one's values digest — the snapshot enumeration stored with it, exactly
 * row for row in both directions: the enumeration is the one whose
 * digest the row carries, written atomically with the row at acceptance,
 * so at an equal digest the staged enumeration is the live one, neither
 * a subset nor a superset.
 */
// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- the checkpoint half of the projection-regression checklist; each branch is one refusal condition, and splitting the checklist would obscure it
function verifyCheckpointRegression(sql: SqlStorage): void {
  const live = sql.exec(`SELECT * FROM ${CHECKPOINT_TABLE}`).toArray();
  for (const row of live) {
    const environmentId = String(row["environment_id"]);
    const staged = stagedRowOf(sql, CHECKPOINT_TABLE, environmentId);
    if (staged === undefined) {
      if (!stagedEnvTombstoned(sql, environmentId)) {
        throw malformed();
      }
      continue;
    }
    if (
      Number(staged["chain_seq"]) < Number(row["chain_seq"]) ||
      Number(staged["manifest_version"]) < Number(row["manifest_version"]) ||
      Number(staged["epoch"]) < Number(row["epoch"]) ||
      (Number(staged["chain_seq"]) === Number(row["chain_seq"]) &&
        (String(staged["entry_hash_hex"]) !== String(row["entry_hash_hex"]) ||
          Number(staged["epoch"]) !== Number(row["epoch"]) ||
          Number(staged["manifest_version"]) !== Number(row["manifest_version"]) ||
          String(staged["manifest_sig_hash_hex"]) !== String(row["manifest_sig_hash_hex"]) ||
          String(staged["values_digest_hex"]) !== String(row["values_digest_hex"])))
    ) {
      throw malformed();
    }
    if (String(staged["values_digest_hex"]) === String(row["values_digest_hex"])) {
      verifySnapshotValuesPreserved(sql, environmentId);
    }
  }
}

/**
 * The snapshot enumeration of one environment at an equal values digest,
 * exact in both directions: every live row present identically in the
 * staged replica, and no staged row the live enumeration does not carry.
 * The one-directional form let an extra staged row in at an equal digest;
 * installed, it would poison the next checkpoint's cross-check (the
 * stored enumeration would no longer be the one the digest was computed
 * over at acceptance — data-store-write-ops.ts's `upsertCheckpointSnapshot`
 * skips the wholesale replacement when the digest matches).
 */
function verifySnapshotValuesPreserved(sql: SqlStorage, environmentId: string): void {
  const table = "checkpoint_snapshot_values";
  const staging = stagingOf(table);
  if (!hasTable(sql, staging)) {
    const missing = sql
      .exec(`SELECT COUNT(*) AS n FROM ${table} WHERE environment_id = ?`, environmentId)
      .one()["n"];
    if (Number(missing) !== 0) {
      throw malformed();
    }
    return;
  }
  const rewritten = sql
    .exec(
      `SELECT COUNT(*) AS n FROM ${table} AS own LEFT JOIN ${staging} AS theirs ON theirs.environment_id = own.environment_id AND theirs.variable_id = own.variable_id WHERE own.environment_id = ? AND (theirs.variable_id IS NULL OR own.version IS NOT theirs.version OR own.value_sig_hash_hex IS NOT theirs.value_sig_hash_hex)`,
      environmentId,
    )
    .one()["n"];
  if (Number(rewritten) !== 0) {
    throw malformed();
  }
  const extra = sql
    .exec(
      `SELECT COUNT(*) AS n FROM ${staging} AS theirs LEFT JOIN ${table} AS own ON own.environment_id = theirs.environment_id AND own.variable_id = theirs.variable_id WHERE theirs.environment_id = ? AND own.variable_id IS NULL`,
      environmentId,
    )
    .one()["n"];
  if (Number(extra) !== 0) {
    throw malformed();
  }
}

interface CheckpointTuple {
  readonly seq: number;
  readonly entryHashHex: string;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly manifestSigHashHex: string;
  readonly valuesDigestHex: string;
}

const asRecord = (value: unknown): Record<string, unknown> | null =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;

const intField = (record: Record<string, unknown>, key: string): number | null => {
  const value = record[key];
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
};

const strField = (record: Record<string, unknown>, key: string): string | null => {
  const value = record[key];
  return typeof value === "string" ? value : null;
};

/**
 * The projection state the staged chain anchors, derived from the staged
 * entries in seq order (the mirror of chain-history.ts's recorder: a
 * checkpoint entry's tuples, the epoch a create / rotate opens, the
 * deletion that drops an environment's checkpoint baseline, the rotation
 * count behind the manifest-version binding, and the direct membership
 * entries behind the wrap / attestation removal exemptions). An entry
 * whose JSON does not parse, or whose payload fields are not of the
 * shapes read here, is skipped: the staged chain's content verification
 * (programs-mirror.ts, between the trailer and the commit) refuses such
 * a chain before anything is swapped, so a skipped entry can never carry
 * a commit — and the refusal keeps that step's `chain-invalid` /
 * `malformed` reasons rather than pre-empting them here. A skip marks
 * the anchors `complete: false`, and {@link verifyChainAnchoredProjections}
 * defers entirely on incomplete anchors: otherwise the anchors a skipped
 * entry would have contributed read as forged projections, and the
 * trailer would pre-empt the verification's refusal with its own
 * `malformed`.
 */
interface StagedChainAnchors {
  readonly headSeq: number;
  readonly hashBySeq: ReadonlyMap<number, string>;
  /** Ascending [fromSeq, epoch] per environment (create opens epoch 1). */
  readonly epochStarts: ReadonlyMap<string, readonly (readonly [number, number])[]>;
  readonly deletedSeq: ReadonlyMap<string, number>;
  /** Direct `rotate_epoch` entries per environment (the manifest-version count — see {@link verifyStagedManifests}). */
  readonly rotateCounts: ReadonlyMap<string, number>;
  /**
   * Direct `add_member` entries (target + the member's enc key at the
   * add): the stale-wrap sweep's anchor (chain-accept.ts runs
   * `deleteStaleMemberWraps` at every `add_member` acceptance).
   */
  readonly addMemberSweeps: readonly {
    readonly seq: number;
    readonly targetUserId: string;
    readonly encPubHex: string;
  }[];
  /** Direct `remove_member` entries (the head-attestation cleanup's anchor). */
  readonly removedMembers: readonly { readonly seq: number; readonly targetUserId: string }[];
  /** Direct `revoke_device` entries (the per-device attestation cleanup's anchor). */
  readonly revokedDevices: readonly {
    readonly seq: number;
    readonly targetUserId: string;
    readonly fingerprints: readonly string[];
  }[];
  /** Per (environment, manifestVersion): the agreeing tuple, or "conflict" (CRYPTO_SPEC §4.3 (2)). */
  readonly tupleFor: ReadonlyMap<
    string,
    { readonly epoch: number; readonly sig: string } | "conflict"
  >;
  readonly latest: ReadonlyMap<string, CheckpointTuple>;
  /** False when at least one staged entry could not be consumed (see the interface comment). */
  readonly complete: boolean;
}

/**
 * The chain ops {@link stagedChainAnchors} consumes by ignoring them:
 * the closed union of the chain entry schema (packages/api-schema's
 * ChainEntrySchema) minus the ops the anchors read. An `op` outside
 * both sets is an entry that cannot verify.
 */
const ANCHORS_IGNORED_OPS: ReadonlySet<string> = new Set([
  "genesis",
  "change_role",
  "grant_server",
  "revoke_server",
  "set_approval_policy",
  "add_device",
  "propose",
  "approve",
  "withdraw",
]);

// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- a per-op fold over the chain's entry taxonomy in seq order (the mirror of chain-history's recorder); the branches are the entry kinds the anchors are read from
function stagedChainAnchors(sql: SqlStorage): StagedChainAnchors {
  const staging = stagingOf(CHAIN_TABLE);
  const hashBySeq = new Map<number, string>();
  const epochStarts = new Map<string, [number, number][]>();
  const deletedSeq = new Map<string, number>();
  const rotateCounts = new Map<string, number>();
  const addMemberSweeps: { seq: number; targetUserId: string; encPubHex: string }[] = [];
  const removedMembers: { seq: number; targetUserId: string }[] = [];
  const revokedDevices: { seq: number; targetUserId: string; fingerprints: string[] }[] = [];
  const tupleFor = new Map<string, { readonly epoch: number; readonly sig: string } | "conflict">();
  const latest = new Map<string, CheckpointTuple>();
  let headSeq = 0;
  let complete = true;
  const rows = sql
    .exec(`SELECT seq, entry_json, entry_hash_hex FROM ${staging} ORDER BY seq`)
    .toArray();
  for (const row of rows) {
    const seq = Number(row["seq"]);
    const entryHashHex = String(row["entry_hash_hex"]);
    hashBySeq.set(seq, entryHashHex);
    headSeq = Math.max(headSeq, seq);
    let parsed: unknown;
    try {
      parsed = JSON.parse(String(row["entry_json"]));
    } catch {
      complete = false;
      continue;
    }
    const entry = asRecord(parsed);
    const payload = entry === null ? null : asRecord(entry["payload"]);
    if (entry === null || payload === null) {
      complete = false;
      continue;
    }
    const op = strField(entry, "op");
    if (op === null) {
      complete = false;
      continue;
    }
    if (op === "create_environment" || op === "rotate_epoch" || op === "delete_environment") {
      const environmentId = strField(payload, "environmentId");
      if (environmentId === null) {
        complete = false;
        continue;
      }
      if (op === "create_environment") {
        epochStarts.set(environmentId, [[seq, 1]]);
      } else if (op === "rotate_epoch") {
        rotateCounts.set(environmentId, (rotateCounts.get(environmentId) ?? 0) + 1);
        const newEpoch = intField(payload, "newEpoch");
        if (newEpoch === null) {
          complete = false;
        }
        const starts = epochStarts.get(environmentId);
        if (starts === undefined) {
          // A rotation for an environment this chain never created:
          // the entry cannot verify, so the anchors are incomplete
          complete = false;
        }
        if (newEpoch !== null && starts !== undefined) {
          starts.push([seq, newEpoch]);
        }
      } else if (!deletedSeq.has(environmentId)) {
        deletedSeq.set(environmentId, seq);
        latest.delete(environmentId);
      }
      continue;
    }
    // The membership ops the wrap / attestation removal exemptions read.
    // Only direct entries are recorded: on a chain that passes the full
    // verification gating the commit, every direct entry was applied
    // exactly as read (a direct entry the consensus rules refuse — a
    // policy-targeted op submitted directly, for instance — invalidates
    // the whole chain, so it can never carry a commit). A four-eyes
    // proposal is deliberately not resolved here: whether a `propose`
    // completed is a quorum judgment over the policy and the ownership
    // at each `approve`, which is verifyChain's state machine, not a
    // synchronous payload reading — so a removal a completed proposal
    // caused is not excused (the replica is refused, fail-closed; see
    // the residual in {@link verifyChainAnchoredProjections}).
    // `create_environment` / `rotate_epoch` / `delete_environment` /
    // `revoke_device` need no such care: CRYPTO_SPEC §6.2's closed
    // approval-target set excludes them and `evaluatePropose` refuses a
    // proposal carrying a non-target, so they can only ever be direct.
    if (op === "add_member" || op === "remove_member" || op === "revoke_device") {
      const targetUserId = strField(payload, "targetUserId");
      if (targetUserId === null) {
        complete = false;
        continue;
      }
      if (op === "add_member") {
        const encPubHex = strField(payload, "encPubHex");
        if (encPubHex === null) {
          complete = false;
        } else {
          addMemberSweeps.push({ seq, targetUserId, encPubHex });
        }
      } else if (op === "remove_member") {
        removedMembers.push({ seq, targetUserId });
      } else {
        const raw = payload["deviceFingerprintsHex"];
        const fingerprints = Array.isArray(raw)
          ? raw.filter((value): value is string => typeof value === "string")
          : [];
        if (!Array.isArray(raw) || fingerprints.length !== raw.length) {
          // The schema carries only string fingerprints: anything the
          // filter dropped means the entry cannot verify
          complete = false;
        }
        revokedDevices.push({ seq, targetUserId, fingerprints });
      }
      continue;
    }
    if (op !== "checkpoint") {
      if (!ANCHORS_IGNORED_OPS.has(op)) {
        // Outside the chain's closed op union: the entry cannot verify
        complete = false;
      }
      continue;
    }
    if (!Array.isArray(payload["environments"])) {
      complete = false;
      continue;
    }
    for (const raw of payload["environments"]) {
      const tuple = asRecord(raw);
      if (tuple === null) {
        complete = false;
        continue;
      }
      const environmentId = strField(tuple, "environmentId");
      const epoch = intField(tuple, "epoch");
      const manifestVersion = intField(tuple, "manifestVersion");
      const manifestSigHashHex = strField(tuple, "manifestSigHashHex");
      const valuesDigestHex = strField(tuple, "valuesDigestHex");
      if (
        environmentId === null ||
        epoch === null ||
        manifestVersion === null ||
        manifestSigHashHex === null ||
        valuesDigestHex === null
      ) {
        complete = false;
        continue;
      }
      const deletedAt = deletedSeq.get(environmentId);
      if (deletedAt !== undefined && deletedAt < seq) {
        continue;
      }
      const key = `${environmentId}\n${manifestVersion}`;
      const existing = tupleFor.get(key);
      if (existing === undefined) {
        tupleFor.set(key, { epoch, sig: manifestSigHashHex });
      } else if (
        existing !== "conflict" &&
        (existing.epoch !== epoch || existing.sig !== manifestSigHashHex)
      ) {
        tupleFor.set(key, "conflict");
      }
      latest.set(environmentId, {
        seq,
        entryHashHex,
        epoch,
        manifestVersion,
        manifestSigHashHex,
        valuesDigestHex,
      });
    }
  }
  return {
    headSeq,
    hashBySeq,
    epochStarts,
    deletedSeq,
    rotateCounts,
    addMemberSweeps,
    removedMembers,
    revokedDevices,
    tupleFor,
    latest,
    complete,
  };
}

/** The environment's chain epoch at `seq` (undefined when the chain has not created it by then, or has deleted it). */
function epochAt(
  anchors: StagedChainAnchors,
  environmentId: string,
  seq: number,
): number | undefined {
  const deletedAt = anchors.deletedSeq.get(environmentId);
  if (deletedAt !== undefined && deletedAt <= seq) {
    return undefined;
  }
  let epoch: number | undefined;
  for (const [fromSeq, value] of anchors.epochStarts.get(environmentId) ?? []) {
    if (fromSeq > seq) {
      break;
    }
    epoch = value;
  }
  return epoch;
}

/** One table's rows (the live table, or its staging when `staged`), keyed by the given key columns. An absent staging table reads as empty. */
function rowsByKey(
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

/** A table's column list (the live table's — a staging table is created with it). */
function columnsOf(sql: SqlStorage, table: string): readonly string[] {
  return sql.exec(`SELECT * FROM ${table} LIMIT 0`).columnNames;
}

/** Whether two stored rows agree on every column (the row-for-row identity the preservation checks require). */
function rowsDiffer(
  columns: readonly string[],
  a: Record<string, unknown>,
  b: Record<string, unknown>,
): boolean {
  return columns.some((column) => a[column] !== b[column]);
}

/** The staged rows of one environment in a staged table (0 when the replica does not carry the table). */
function stagedEnvCount(sql: SqlStorage, table: string, environmentId: string): number {
  const staging = stagingOf(table);
  if (!hasTable(sql, staging)) {
    return 0;
  }
  return Number(
    sql.exec(`SELECT COUNT(*) AS n FROM ${staging} WHERE environment_id = ?`, environmentId).one()[
      "n"
    ],
  );
}

/**
 * The staged projections against the staged chain (whose full content
 * verification gates the commit — a replica whose chain does not verify
 * never reaches the swap, so the tuples read here are the verified
 * chain's by the time anything is installed):
 *
 * - the staged checkpoint rows are exactly the chain's latest tuple per
 *   environment (the row acceptance writes atomically with the entry —
 *   chain seq, entry hash and every tuple field), in both directions
 * - every staged manifest binds to the chain as at its acceptance
 *   (CRYPTO_SPEC §4.3 / §6.3): its declared head is the staged chain's
 *   entry at that seq; a checkpoint tuple for its (environment,
 *   manifestVersion) coordinate pins its epoch and signed-bytes hash
 *   exactly, and conflicting tuples are equivocation; without a tuple
 *   its epoch is the environment's epoch at its declared head; its
 *   version and epoch are at least the latest checkpoint baseline's;
 *   and its epoch is the environment's epoch at the staged head (a
 *   rotation since its issuance would have bundled a newer manifest)
 * - the manifest's environment-meta binding is the staged environment's
 *   latest statement (the recomputation anchor of AUTH_SPEC §12-5 (7))
 * - the manifest's version is the staged statement-set's size: every
 *   manifest reissue on a primary is bundled with exactly one meta
 *   statement (environment creation, an environment rename, a variable
 *   create / rename / delete / activation / schema reissue) or with a
 *   `rotate_epoch` entry, and nothing else upserts the manifest row
 *   (composite-programs.ts, verify-manifest.ts's `acceptManifestForMetaOp`
 *   write phase, programs-variable.ts, programs-environment.ts), so the
 *   version equals the environment's staged statement-row count plus its
 *   staged rotation count — a manifest paired with a statement set ahead
 *   of it (the splice of an older manifest row into a newer replica) is
 *   refused here, not by the live regression check, which an equal
 *   version passes
 * - an environment row's tombstone is the chain's deletion, a variable
 *   row's tombstone its latest statement's `deleted` form
 * - every live DEK wrap is present identically in the staged replica and
 *   every staged wrap names a chain-admitted (environment, epoch) — the
 *   wrap lifecycle's chain anchors and removal exemptions are
 *   {@link verifyStagedWraps}'s comment
 * - every live head attestation is preserved (at an equal declared seq
 *   the row is identical; an advance keeps its acceptance time monotone)
 *   unless a direct `remove_member` / `revoke_device` in the replicated
 *   delta deleted it, and every staged attestation's declared head
 *   resolves to the staged chain's entry at that seq — an attestation
 *   row therefore cannot mint the attestation mark the commit reads back
 *   (readWatermarks' MAX(accepted_at)) for a head the chain does not
 *   carry at an unchanged position
 * - the project settings and the sealed rotation proposals, which no
 *   chain entry carries, fold from the staged audit log — see
 *   {@link verifyAuditAnchoredState}
 *
 * Residual, stated plainly: the variables digest and the checkpoint
 * values digest are not recomputed here — recomputation is WebCrypto
 * work, which cannot run inside the trailer's transaction (the async
 * form belongs with the staged chain's verification in
 * programs-mirror.ts, as {@link verifyStagedAuditHeads} does for the
 * audit heads). The manifest's digest is therefore bound only where a
 * checkpoint tuple pins the manifest's signed-bytes hash (which covers
 * the digest), where the live manifest pins it at an equal version, and
 * through the statement rows the digest is computed over, which
 * {@link verifyProjectionRegression} preserves row for row. A manifest
 * version no checkpoint has notarized, first replicated past the
 * mirror's live state with statements the mirror never held, is bound
 * by its epoch, head and version-count checks — its digest and
 * signature remain the clients' §6.3 verification, as before.
 * The wrap and attestation residuals are stated at their checks: a
 * staged wrap row that is not a live row (a backfill the mirror never
 * held) is bound only to a chain-admitted (environment, epoch) — its
 * registration signature is not verified synchronously (WebCrypto, the
 * same boundary as the digests; clients verify it under CRYPTO_SPEC
 * §5.1 on receipt, and the epoch's DEK commitment is the chain's); a
 * new or advanced attestation's `accepted_at` is bounded only by
 * monotonicity against the live row it advances, so the mark a forged
 * advancing row carries is limited to that row's (chain-resolved) head,
 * and the mark itself feeds only the sync skip check and the status;
 * and removals caused by a four-eyes-completed `add_member` /
 * `remove_member` are not excused (see {@link stagedChainAnchors}), so
 * a legitimate replica crossing one is refused until the mirror is
 * re-bootstrapped — fail-closed, never fail-open.
 */
function verifyChainAnchoredProjections(sql: SqlStorage): void {
  if (!hasTable(sql, stagingOf(CHAIN_TABLE))) {
    return;
  }
  const anchors = stagedChainAnchors(sql);
  if (!anchors.complete) {
    // The staged chain carries an entry the anchors reader cannot
    // consume: the chain's content verification (programs-mirror.ts,
    // before the commit) refuses it with its own `malformed` /
    // `chain-invalid` reason, so the anchored checks defer rather than
    // read the missing anchors as forged projections and pre-empt that
    // refusal with `malformed` here.
    return;
  }
  verifyStagedCheckpoints(sql, anchors);
  verifyStagedManifests(sql, anchors);
  verifyStagedTombstones(sql, anchors);
  verifyStagedWraps(sql, anchors);
  verifyStagedAttestations(sql, anchors);
  verifyAuditAnchoredState(sql, anchors);
}

/** The staged checkpoint rows are the staged chain's latest tuples, in both directions. */
// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- the checkpoint binding checked in both directions in one pass; each branch is one refusal condition, and splitting the checklist would obscure it
function verifyStagedCheckpoints(sql: SqlStorage, anchors: StagedChainAnchors): void {
  const staging = stagingOf(CHECKPOINT_TABLE);
  const staged = hasTable(sql, staging) ? sql.exec(`SELECT * FROM ${staging}`).toArray() : [];
  const seen = new Set<string>();
  for (const row of staged) {
    const environmentId = String(row["environment_id"]);
    seen.add(environmentId);
    const tuple = anchors.latest.get(environmentId);
    if (
      tuple === undefined ||
      Number(row["chain_seq"]) !== tuple.seq ||
      String(row["entry_hash_hex"]) !== tuple.entryHashHex ||
      Number(row["epoch"]) !== tuple.epoch ||
      Number(row["manifest_version"]) !== tuple.manifestVersion ||
      String(row["manifest_sig_hash_hex"]) !== tuple.manifestSigHashHex ||
      String(row["values_digest_hex"]) !== tuple.valuesDigestHex
    ) {
      throw malformed();
    }
  }
  for (const environmentId of anchors.latest.keys()) {
    if (!seen.has(environmentId)) {
      throw malformed();
    }
  }
}

/** Every staged manifest binds to the staged chain and to its environment's latest statement. */
// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- the manifest binding's checks in the order the manifest's own fields are bound; each branch is one refusal condition, and splitting the checklist would obscure it
function verifyStagedManifests(sql: SqlStorage, anchors: StagedChainAnchors): void {
  const staging = stagingOf(MANIFEST_TABLE);
  const staged = hasTable(sql, staging) ? sql.exec(`SELECT * FROM ${staging}`).toArray() : [];
  const seen = new Set<string>();
  for (const row of staged) {
    const environmentId = String(row["environment_id"]);
    seen.add(environmentId);
    if (anchors.deletedSeq.has(environmentId)) {
      throw malformed();
    }
    const manifestVersion = Number(row["manifest_version"]);
    const epoch = Number(row["epoch"]);
    const chainHeadSeq = Number(row["chain_head_seq"]);
    if (anchors.hashBySeq.get(chainHeadSeq) !== String(row["chain_head_hash_hex"])) {
      throw malformed();
    }
    const tuple = anchors.tupleFor.get(`${environmentId}\n${manifestVersion}`);
    if (tuple === "conflict") {
      throw malformed();
    }
    if (tuple !== undefined) {
      if (tuple.epoch !== epoch || tuple.sig !== String(row["signed_bytes_hash_hex"])) {
        throw malformed();
      }
    } else if (epochAt(anchors, environmentId, chainHeadSeq) !== epoch) {
      throw malformed();
    }
    const baseline = anchors.latest.get(environmentId);
    if (
      baseline !== undefined &&
      (manifestVersion < baseline.manifestVersion || epoch < baseline.epoch)
    ) {
      throw malformed();
    }
    if (epochAt(anchors, environmentId, anchors.headSeq) !== epoch) {
      throw malformed();
    }
    // The version is the staged statement-set's size (see
    // verifyChainAnchoredProjections): creation writes statement 1 with
    // manifest 1, every later meta statement is bundled with exactly one
    // reissue (+1), and a rotation reissues without a statement (+1,
    // counted from the staged chain). No chain entry references a
    // manifest version for a variable mutation — the mutations are
    // data-plane operations, not chain entries — so this count over the
    // staged rows themselves is the binding: a manifest behind the
    // staged statement set (an older manifest row spliced into a newer
    // replica) names a version smaller than the count and is refused,
    // where the live regression check (equal version, equal hash) and
    // the checkpoint-tuple pin (no tuple notarizes that version) both
    // pass it.
    const expectedVersion =
      stagedEnvCount(sql, "environment_meta_statements", environmentId) +
      stagedEnvCount(sql, "variable_meta_statements", environmentId) +
      (anchors.rotateCounts.get(environmentId) ?? 0);
    if (manifestVersion !== expectedVersion) {
      throw malformed();
    }
    // The environment-meta binding is the staged environment's latest
    // statement (its row's counter and that statement's stored hash)
    const environment = stagedRowOf(sql, ENVIRONMENTS_TABLE, environmentId);
    const metaVersion =
      environment === undefined ? null : Number(environment["latest_meta_version"]);
    if (
      environment === undefined ||
      metaVersion !== Number(row["env_meta_version"]) ||
      !hasTable(sql, stagingOf("environment_meta_statements"))
    ) {
      throw malformed();
    }
    const statement = sql
      .exec(
        `SELECT signed_bytes_hash_hex FROM ${stagingOf("environment_meta_statements")} WHERE environment_id = ? AND meta_version = ?`,
        environmentId,
        metaVersion,
      )
      .toArray()[0];
    if (
      statement === undefined ||
      String(statement["signed_bytes_hash_hex"]) !== String(row["env_meta_sig_hash_hex"])
    ) {
      throw malformed();
    }
  }
  // A chain-live environment carries its manifest (the creation and
  // rotation composites write it atomically with the chain entry)
  for (const environmentId of anchors.epochStarts.keys()) {
    if (anchors.deletedSeq.has(environmentId) || seen.has(environmentId)) {
      continue;
    }
    const environment = stagedRowOf(sql, ENVIRONMENTS_TABLE, environmentId);
    if (environment !== undefined && environment["deleted_at"] === null) {
      throw malformed();
    }
  }
}

/** The staged tombstones are the chain's / the statements' deletions, and every chain-created environment has its staged row. */
// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- the tombstone exemptions in one pass over the staged rows; each branch is one refusal condition, and splitting the checklist would obscure it
function verifyStagedTombstones(sql: SqlStorage, anchors: StagedChainAnchors): void {
  const envStaging = stagingOf(ENVIRONMENTS_TABLE);
  if (hasTable(sql, envStaging)) {
    for (const row of sql.exec(`SELECT * FROM ${envStaging}`).toArray()) {
      const environmentId = String(row["environment_id"]);
      const deleted = row["deleted_at"] !== null;
      if (deleted !== anchors.deletedSeq.has(environmentId)) {
        throw malformed();
      }
    }
  }
  for (const environmentId of anchors.epochStarts.keys()) {
    if (stagedRowOf(sql, ENVIRONMENTS_TABLE, environmentId) === undefined) {
      throw malformed();
    }
  }
  const varStaging = stagingOf(VARIABLES_TABLE);
  const stmtStaging = stagingOf("variable_meta_statements");
  if (!hasTable(sql, varStaging) || !hasTable(sql, stmtStaging)) {
    return;
  }
  for (const row of sql
    .exec(`SELECT * FROM ${varStaging} WHERE deleted_at IS NOT NULL`)
    .toArray()) {
    const statement = sql
      .exec(
        `SELECT status FROM ${stmtStaging} WHERE environment_id = ? AND variable_id = ? AND meta_version = ?`,
        String(row["environment_id"]),
        String(row["variable_id"]),
        Number(row["latest_meta_version"]),
      )
      .toArray()[0];
    if (statement === undefined || String(statement["status"]) !== "deleted") {
      throw malformed();
    }
  }
}

/**
 * The DEK wraps against the live rows and the staged chain.
 *
 * The wrap lifecycle, as the codebase writes it: wraps are created only
 * by `insertWrap` (data-store-write-ops.ts), reached from exactly three
 * acceptance paths — the environment-creation composite (the complete
 * epoch-1 set, atomically with the `create_environment` entry), the
 * rotation composite (the complete new-epoch set, atomically with the
 * `rotate_epoch` entry), and the standalone registration of §12-6
 * (backfill / repair re-registration — no chain entry; its only record
 * is the `dek.registered` audit rows). A wrap row declares no chain
 * head: its coordinates are (environment, epoch, recipient, the
 * recipient's device enc key), plus the registration signature and its
 * signer. Wraps are deleted by exactly three paths:
 * `retireEnvironment`'s cascade (the `delete_environment` composite),
 * `deleteStaleMemberWraps` at an `add_member` acceptance (it sweeps a
 * member's `member`-class wraps whose enc key is not the key the add
 * carries, across every environment and epoch), and the §12-6 repair
 * path's `deleteWrap` (an admin's per-tuple deletion — no chain entry,
 * only a `dek.deleted` audit row).
 *
 * The binding, strongest first:
 * - every live wrap row is present identically in the staged replica
 *   (row for row, every column — a same-primary-key rewrite of the
 *   ciphertext or signature is a rewrite, and staging zero rows for an
 *   environment is a deletion), excused only where a staged-chain entry
 *   in the replicated delta (past the live head) explains the removal:
 *   the environment's `delete_environment` (its cascade), or a direct
 *   `add_member` for the row's recipient carrying a different enc key
 *   (the stale sweep — the entry types relied on are chain-signed and,
 *   per {@link stagedChainAnchors}, credited only in their direct form,
 *   which a verified chain applied exactly as read; `delete_environment`
 *   can never be four-eyes-wrapped at all). The repair path's deletions
 *   are deliberately NOT excused: they have no chain anchor, so a
 *   replica crossing one is refused and the mirror is re-bootstrapped —
 *   excusing them on the replica's audit word would reopen exactly the
 *   resurrection this check closes (an older export's genuine rows,
 *   deleted on the source by a sweep or a repair, paired with the
 *   current chain).
 * - every staged wrap row names a chain-admitted coordinate: its
 *   environment is created and not deleted on the staged chain and its
 *   epoch is between 1 and the environment's epoch at the staged head.
 *
 * What remains unbound, plainly: a staged wrap row that is not a live
 * row — a backfill for a member or device the chain admitted after the
 * mirror's last replication, or the composite set of a create / rotate
 * inside the delta — is bound only to that coordinate check. Which rows
 * the recipient set R(E) holds at an epoch is a chain-state derivation
 * (membership, devices, scopes, grants — verifyChain's state, not a
 * synchronous payload reading), and the registration signature is
 * WebCrypto work; neither runs inside the trailer's transaction. A
 * forged additional row therefore survives the trailer with a
 * well-formed coordinate — its signature remains the clients' §5.1
 * verification on receipt, and it can never displace or rewrite a row
 * the mirror already holds, which is the resurrection / deletion /
 * rewrite class this check closes.
 */
// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- the wrap preservation and admission checks in one pass; each branch is one refusal condition, and splitting the checklist would obscure it
function verifyStagedWraps(sql: SqlStorage, anchors: StagedChainAnchors): void {
  const table = "dek_wraps";
  const keyColumns = ["environment_id", "epoch", "recipient_user_id", "recipient_enc_pub_hex"];
  const staged = rowsByKey(sql, table, true, keyColumns);
  for (const row of staged.values()) {
    const current = epochAt(anchors, String(row["environment_id"]), anchors.headSeq);
    const epoch = Number(row["epoch"]);
    if (current === undefined || !Number.isInteger(epoch) || epoch < 1 || epoch > current) {
      throw malformed();
    }
  }
  const liveHeadSeq = readWatermarks(sql).chainHeadSeq;
  const columns = columnsOf(sql, table);
  for (const [key, live] of rowsByKey(sql, table, false, keyColumns)) {
    const stagedRow = staged.get(key);
    if (stagedRow !== undefined) {
      if (rowsDiffer(columns, live, stagedRow)) {
        throw malformed();
      }
      continue;
    }
    if (anchors.deletedSeq.has(String(live["environment_id"]))) {
      continue;
    }
    const swept =
      String(live["recipient_class"]) === "member" &&
      anchors.addMemberSweeps.some(
        (sweep) =>
          sweep.seq > liveHeadSeq &&
          sweep.targetUserId === String(live["recipient_user_id"]) &&
          sweep.encPubHex !== String(live["recipient_enc_pub_hex"]),
      );
    if (!swept) {
      throw malformed();
    }
  }
}

/**
 * The head attestations against the live rows and the staged chain.
 *
 * Attestations are not append-only: the stored row is the latest per
 * device (an upsert on (attester, device key) — attestation-accept.ts),
 * advancing monotonically in `chain_head_seq` per device, and deleted
 * only by the chain acceptance side effects — `remove_member` deletes
 * the member's rows, `revoke_device` the revoked device's row
 * (chain-accept.ts). The row declares its head (seq + hash), which is
 * the anchor the wrap rows lack: every staged row's declared head must
 * resolve to the staged chain's entry at that seq. Against the live
 * rows the discipline is the upsert's own: a staged row behind the live
 * row's seq is a regression; at the same seq the stored row on a primary
 * never changes (the acceptance is idempotent — the same seq is a
 * resend and rewrites nothing), so the rows must be identical in every
 * column, `accepted_at` included; an advancing row keeps `accepted_at`
 * monotone. A live row missing from the replica is excused only by a
 * direct `remove_member` / `revoke_device` in the replicated delta (the
 * same direct-entry discipline as the wraps). Together these keep the
 * commit's post-swap readWatermarks from reading an attestation mark
 * (MAX(accepted_at)) the replica invented for a position the mirror
 * already held: the mark can only move with a row whose head the staged
 * chain carries. A new device's row, and an advancing row's exact
 * `accepted_at`, remain the replica's word — bounded by the declared
 * head's resolution and, for advances, by monotonicity; the signature
 * is the clients' §6.6 verification, as with the wraps.
 */
// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- the attestation preservation and head-resolution checks in one pass; each branch is one refusal condition, and splitting the checklist would obscure it
function verifyStagedAttestations(sql: SqlStorage, anchors: StagedChainAnchors): void {
  const table = "head_attestations";
  const keyColumns = ["attester_user_id", "attester_key_fingerprint"];
  const staged = rowsByKey(sql, table, true, keyColumns);
  for (const row of staged.values()) {
    if (
      anchors.hashBySeq.get(Number(row["chain_head_seq"])) !== String(row["chain_head_hash_hex"])
    ) {
      throw malformed();
    }
  }
  const liveHeadSeq = readWatermarks(sql).chainHeadSeq;
  const columns = columnsOf(sql, table);
  for (const [key, live] of rowsByKey(sql, table, false, keyColumns)) {
    const stagedRow = staged.get(key);
    if (stagedRow === undefined) {
      const userId = String(live["attester_user_id"]);
      const removed = anchors.removedMembers.some(
        (removal) => removal.seq > liveHeadSeq && removal.targetUserId === userId,
      );
      const revoked = anchors.revokedDevices.some(
        (revocation) =>
          revocation.seq > liveHeadSeq &&
          revocation.targetUserId === userId &&
          revocation.fingerprints.includes(String(live["attester_key_fingerprint"])),
      );
      if (!removed && !revoked) {
        throw malformed();
      }
      continue;
    }
    if (Number(stagedRow["chain_head_seq"]) < Number(live["chain_head_seq"])) {
      throw malformed();
    }
    if (Number(stagedRow["chain_head_seq"]) === Number(live["chain_head_seq"])) {
      if (rowsDiffer(columns, live, stagedRow)) {
        throw malformed();
      }
    } else if (Number(stagedRow["accepted_at"]) < Number(live["accepted_at"])) {
      throw malformed();
    }
  }
}

/** One rotation proposal's mint as the staged audit log records it (`rotation.proposed` — programs-proposal.ts). */
interface StagedProposalMint {
  readonly environmentId: string | null;
  readonly claimsDigestHex: string | null;
  readonly grantChainSeq: number | null;
  readonly connector: string | null;
  readonly variableIds: readonly string[];
  /** No closing row (accepted / rejected / expired / cancelled) follows the latest mint of this id. */
  readonly open: boolean;
}

interface StagedAuditAnchors {
  /** The schema policy the staged log's `project.schema_policy_changed` rows fold to, from the default. */
  readonly policy: string;
  readonly proposals: ReadonlyMap<string, StagedProposalMint>;
  /** Proposal ids a closing row names after their latest mint (or without any mint in the staged log). */
  readonly closed: ReadonlySet<string>;
}

/**
 * The staged audit log's word on the state no chain entry carries, read
 * in seq order: the schema-policy fold (each
 * `project.schema_policy_changed` row names its predecessor and its
 * successor — programs-schema-policy.ts writes the row and the setting
 * in one synchronous block, starting from the `enabled` default) and the
 * rotation proposals' mints and closings (every mint writes
 * `rotation.proposed`; every removal — resolution, the expiry sweep, an
 * environment deletion's cascade — writes exactly one closing row:
 * AUDIT_SPEC §3.3's "every proposed row gets exactly one closing row").
 * Null when the replica carries no audit table: the callers then fall
 * back to exact preservation against the live rows. A policy row whose
 * payload does not chain onto the fold is a log no primary wrote:
 * `malformed`, like the log's other shape refusals.
 */
// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- a per-kind fold over the staged audit log's row kinds; the branches are the row kinds the settings and proposal bindings read
function stagedAuditAnchors(sql: SqlStorage): StagedAuditAnchors | null {
  const staging = stagingOf(AUDIT_TABLE);
  if (!hasTable(sql, staging)) {
    return null;
  }
  let policy = "enabled";
  const proposals = new Map<string, StagedProposalMint>();
  const closed = new Set<string>();
  const rows = sql
    .exec(
      `SELECT event, environment_id, payload FROM ${staging} WHERE event IN ('project.schema_policy_changed', 'rotation.proposed', 'rotation.proposal_accepted', 'rotation.proposal_rejected', 'rotation.proposal_expired', 'rotation.proposal_cancelled') ORDER BY seq`,
    )
    .toArray();
  for (const row of rows) {
    const event = String(row["event"]);
    const payload =
      typeof row["payload"] === "string" ? asRecord(safeParseJson(row["payload"])) : null;
    if (event === "project.schema_policy_changed") {
      const next = payload === null ? null : strField(payload, "next");
      if (
        payload === null ||
        strField(payload, "previous") !== policy ||
        (next !== "enabled" && next !== "locked")
      ) {
        throw malformed();
      }
      policy = next;
      continue;
    }
    const proposalId = payload === null ? null : strField(payload, "proposalId");
    if (payload === null || proposalId === null) {
      continue;
    }
    if (event === "rotation.proposed") {
      const rawIds = payload["variableIds"];
      proposals.set(proposalId, {
        environmentId: row["environment_id"] === null ? null : String(row["environment_id"]),
        claimsDigestHex: strField(payload, "claimsDigest"),
        grantChainSeq: intField(payload, "grantChainSeq"),
        connector: strField(payload, "connector"),
        variableIds: Array.isArray(rawIds)
          ? rawIds.filter((value): value is string => typeof value === "string")
          : [],
        open: true,
      });
      closed.delete(proposalId);
    } else {
      const mint = proposals.get(proposalId);
      if (mint !== undefined) {
        proposals.set(proposalId, { ...mint, open: false });
      }
      closed.add(proposalId);
    }
  }
  return { policy, proposals, closed };
}

/** JSON.parse that yields null instead of throwing (a staged row's payload claim). */
function safeParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/**
 * The snapshot state no chain entry carries, bound to the staged audit
 * log: `project_settings` and the sealed rotation proposals
 * (`rotation_proposals` + its variable and wrap rows).
 *
 * Neither has a chain anchor — the investigation is short: schemaPolicy
 * changes are an admin API operation whose only record is its audit row
 * (programs-schema-policy.ts; no chain op names it), and rotation
 * proposals are workload-minted, member-resolved rows whose outcomes
 * are audit events, not chain entries (the chain's `propose` / `approve`
 * are the four-eyes membership proposals — a different object that never
 * names a rotation proposal id; a proposal row's `grant_chain_seq`
 * points at the lease's grant entry, which authorizes the mint but says
 * nothing about the row's contents or its resolution). The staged audit
 * log is the strongest remaining anchor, and it is a real one: the log
 * is prefix-bound to the mirror's own log (verifyAuditPrefix) and its
 * heads are derived before the swap, so a replica that resurrects a
 * resolved proposal or flips the policy must also rewrite the log it is
 * checked against — at or below the replicated position it cannot, and
 * past it the forgery is confined to rows the source's log position has
 * not yet vouched for, the same trust the replica's own new audit rows
 * already carry.
 *
 * - the staged settings' effective policy (no row = the `enabled`
 *   default) is exactly the staged log's fold;
 * - every staged proposal row is its latest mint, still open, field for
 *   field (environment, connector, claims digest, grant seq), with the
 *   staged variable rows naming exactly the mint's variable set;
 * - every live proposal row (and its variable / wrap rows) is present
 *   identically in the staged replica, excused only when the staged log
 *   closes the proposal or its environment's chain deletion cascades
 *   it; staged variable / wrap rows belong to a staged proposal.
 *
 * Residual: a proposal first replicated past the mirror's live state is
 * bound to the log the same replica carries (above), not to the chain;
 * its `created_at` / `expires_at` and its sealed wraps' contents have no
 * anchor beyond the mint's claims digest, which covers the facts the
 * workload sealed under, not the stored rows' bytes.
 */
function verifyAuditAnchoredState(sql: SqlStorage, anchors: StagedChainAnchors): void {
  const audit = stagedAuditAnchors(sql);
  verifyStagedSettings(sql, audit);
  verifyStagedProposals(sql, anchors, audit);
}

/** The staged project settings are the staged audit log's policy fold. */
function verifyStagedSettings(sql: SqlStorage, audit: StagedAuditAnchors | null): void {
  const table = "project_settings";
  const liveRow = sql.exec(`SELECT * FROM ${table} WHERE id = 1`).toArray()[0];
  if (!hasTable(sql, stagingOf(table))) {
    if (liveRow !== undefined) {
      throw malformed();
    }
    return;
  }
  const stagedRow = sql.exec(`SELECT * FROM ${stagingOf(table)} WHERE id = 1`).toArray()[0];
  const stagedPolicy = stagedRow === undefined ? "enabled" : String(stagedRow["schema_policy"]);
  const expected =
    audit === null
      ? liveRow === undefined
        ? "enabled"
        : String(liveRow["schema_policy"])
      : audit.policy;
  if (stagedPolicy !== expected) {
    throw malformed();
  }
}

/** The staged rotation proposals are the staged audit log's open mints, and the live ones are preserved. */
// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- the proposal binding and preservation checks in one pass; each branch is one refusal condition, and splitting the checklist would obscure it
function verifyStagedProposals(
  sql: SqlStorage,
  anchors: StagedChainAnchors,
  audit: StagedAuditAnchors | null,
): void {
  const proposalKey = ["proposal_id"] as const;
  const variableKey = ["proposal_id", "variable_id"] as const;
  const wrapKey = [
    "proposal_id",
    "variable_id",
    "recipient_user_id",
    "recipient_enc_pub_hex",
  ] as const;
  const liveProposals = rowsByKey(sql, "rotation_proposals", false, proposalKey);
  const stagedProposals = rowsByKey(sql, "rotation_proposals", true, proposalKey);
  const liveVariables = rowsByKey(sql, "rotation_proposal_variables", false, variableKey);
  const stagedVariables = rowsByKey(sql, "rotation_proposal_variables", true, variableKey);
  const liveWraps = rowsByKey(sql, "rotation_proposal_wraps", false, wrapKey);
  const stagedWraps = rowsByKey(sql, "rotation_proposal_wraps", true, wrapKey);
  // The staged proposals bind to their mints, and their variable rows
  // name the mint's variable set exactly. With no staged audit log there
  // is no mint to bind to: a staged proposal is then admitted only as
  // the live row itself (exact preservation, judged below)
  const bound = new Set<string>();
  for (const [proposalId, row] of stagedProposals) {
    if (audit === null) {
      if (liveProposals.has(proposalId)) {
        bound.add(proposalId);
      }
      continue;
    }
    const mint = audit.proposals.get(proposalId);
    if (
      mint === undefined ||
      !mint.open ||
      mint.claimsDigestHex !== String(row["claims_digest_hex"]) ||
      mint.grantChainSeq !== Number(row["grant_chain_seq"]) ||
      mint.connector !== String(row["connector"]) ||
      (mint.environmentId !== null && mint.environmentId !== String(row["environment_id"]))
    ) {
      throw malformed();
    }
    const stagedIds = [...stagedVariables.keys()]
      .filter((key) => key.startsWith(`${proposalId}\n`))
      .map((key) => key.slice(proposalId.length + 1))
      .sort();
    if (JSON.stringify(stagedIds) !== JSON.stringify([...mint.variableIds].sort())) {
      throw malformed();
    }
    bound.add(proposalId);
  }
  // No staged variable or wrap row hangs off a proposal the replica does
  // not carry (the store inserts and deletes the three tables together)
  for (const key of [...stagedVariables.keys(), ...stagedWraps.keys()]) {
    if (!bound.has(key.split("\n")[0] ?? "")) {
      throw malformed();
    }
  }
  const excused = (live: Record<string, unknown>): boolean => {
    const proposalId = String(live["proposal_id"]);
    if (audit !== null && audit.closed.has(proposalId)) {
      return true;
    }
    const parent = liveProposals.get(proposalId);
    return parent !== undefined && anchors.deletedSeq.has(String(parent["environment_id"]));
  };
  // fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
  // fallow-ignore-next-line complexity -- the proposal tables' preservation pass in both directions (a live row survives identically or is excused; a staged row is admitted only under a mint-bound proposal); each branch is one refusal condition
  const preserved = (
    table: string,
    liveRows: ReadonlyMap<string, Record<string, unknown>>,
    stagedRows: ReadonlyMap<string, Record<string, unknown>>,
    // A staged row the live table does not carry is admitted only under
    // a mint-bound proposal — and only when a staged log exists to bind
    // it (with no log, `bound` holds live ids by construction, which
    // must not admit new sub-rows under a live proposal)
    boundAdmitsExtra: boolean,
  ): void => {
    const columns = columnsOf(sql, table);
    for (const [key, live] of liveRows) {
      const stagedRow = stagedRows.get(key);
      if (stagedRow !== undefined) {
        if (rowsDiffer(columns, live, stagedRow)) {
          throw malformed();
        }
      } else if (!excused(live)) {
        throw malformed();
      }
    }
    for (const key of stagedRows.keys()) {
      if (!liveRows.has(key) && !(boundAdmitsExtra && bound.has(key.split("\n")[0] ?? ""))) {
        throw malformed();
      }
    }
  };
  preserved("rotation_proposals", liveProposals, stagedProposals, true);
  preserved("rotation_proposal_variables", liveVariables, stagedVariables, audit !== null);
  preserved("rotation_proposal_wraps", liveWraps, stagedWraps, audit !== null);
}

/**
 * The derivation's start head: at the replicated position the mirror's
 * own column (the position's head — the mirror derived it over the
 * verified-identical rows), or — a first replica — the staged column's
 * tail (an uploaded claim, checked to be a head hash by the caller).
 * null = no such row (refused as malformed).
 */
function stagedAuditHeadStart(
  sql: SqlStorage,
  state: MirrorState,
  stagedHeads: string,
): { readonly from: number; readonly start: string | null } {
  const firstReplica = state.lastAuditSeq === 0;
  const from = firstReplica ? stagedMaxSeq(sql, AUDIT_HEAD_TABLE) : state.lastAuditSeq;
  const table = firstReplica ? stagedHeads : AUDIT_HEAD_TABLE;
  const head =
    from === 0
      ? ""
      : sql.exec(`SELECT head_hash_hex FROM ${table} WHERE seq = ?`, from).toArray()[0]?.[
          "head_hash_hex"
        ];
  return { from, start: head === undefined ? null : String(head) };
}

/**
 * The heads over the staged audit log, derived before the swap (ruling J
 * revision, round 10): from the mirror's own head at the replicated
 * position, or — on a first replica — from the uploaded column's tail
 * (which must be a head hash); a row the canonical form refuses, or a gap,
 * is `malformed` with the live log untouched (the extension after the
 * commit would have thrown the append-only defect on every later read).
 * The derived heads replace the uploaded claim past the start in the
 * staging, so the swap installs a column that is a prefix-contiguous
 * derivation over the rows it covers. Runs between the two transactions,
 * under the permit, like the staged chain's content verification.
 */
export const verifyStagedAuditHeads = Effect.fn("do-mirror.verifyStagedAuditHeads")(function* (
  sql: SqlStorage,
  state: MirrorState,
): Effect.fn.Return<void, MirrorPageRefusedError> {
  const stagedHeads = stagingOf(AUDIT_HEAD_TABLE);
  const stagedLog = stagingOf(AUDIT_TABLE);
  if (!hasTable(sql, stagedLog)) {
    return;
  }
  // A replica without the head column's table line is derived from seq 1
  // into a staged column created for it (round 11: an absent column
  // installed an empty one, and the extension after the commit met the
  // replica's rows unchecked)
  if (!hasTable(sql, stagedHeads)) {
    sql.exec(
      `CREATE TABLE ${stagedHeads} AS SELECT seq, head_hash_hex FROM ${AUDIT_HEAD_TABLE} LIMIT 0`,
    );
    sql.exec(`CREATE INDEX ${stagedHeads}_seq ON ${stagedHeads} (seq)`);
  }
  const { from, start } = stagedAuditHeadStart(sql, state, stagedHeads);
  if (from !== 0 && !isAuditHeadHex(start)) {
    return yield* malformed();
  }
  // The uploaded claim past the start goes first; the derivation then
  // writes chunk by chunk into the staged column (one chunk of memory)
  sql.exec(`DELETE FROM ${stagedHeads} WHERE seq > ?`, from);
  const derived = yield* Effect.promise(() =>
    deriveAuditHeads(sql, stagedLog, stagedHeads, from, from === 0 ? "" : String(start)),
  );
  if (derived === null) {
    return yield* malformed();
  }
});

/** One staged chain row as the content verification reads it (programs-mirror.ts). */
interface StagedChainRow {
  readonly seq: number;
  readonly entryJson: string;
  readonly entryHashHex: string;
  readonly canonicalBytes: number;
}

/** The staged chain in seq order (contiguous from 1, every column of the shape the server writes — else malformed). */
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

export interface MirrorCommitInput {
  readonly storage: DurableObjectStorage;
  readonly tables: readonly string[];
  readonly state: MirrorState;
  readonly nowMs: number;
  /** The source's mutation counter the trailer page carried. */
  readonly sourceMutationSeq: number;
}

/**
 * The commit (its own transaction, after the chain verification): the
 * swap, the mirror's own audit rows re-appended after the replica's, the
 * position. A constraint the live schema refuses (a duplicate key, a NULL
 * where none is allowed) rolls the transaction back and is `malformed`.
 */
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
        // The mirror's own rows (past the last replicated position) wait
        // aside — minus the ones the replica carries by their wire row id
        // (AUDIT_SPEC §7 C1): a frozen former primary's rows between its mark
        // and its export came back through the destination, and re-appending
        // them would collide on the row id (ruling J revision, round 4)
        const auditColumns = sql.exec(`SELECT * FROM ${AUDIT_TABLE} LIMIT 0`).columnNames;
        sql.exec(`DROP TABLE IF EXISTS ${LOCAL_AUDIT_TABLE}`);
        const stagedAudit = stagingOf(AUDIT_TABLE);
        if (hasTable(sql, stagedAudit)) {
          // A carried row is the mirror's own row, byte for byte (its seq may
          // differ): the replica cannot rewrite the evidence the mirror
          // itself witnessed under the same row id (ruling J revision, round 5)
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
        // … and follow the replica's rows, renumbered densely in their order
        // (the rows the replica carried left holes)
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
    // Inside transactionSync the refusal is a throw (the throw is what
    // rolls the swap back); the boundary turns it back into the typed
    // error — the only place an instanceof may remain. Any other throw
    // is SQLite refusing the replica's rows against the live schema (its
    // message names a constraint, never a value): also malformed
    catch: (error) => (error instanceof MirrorPageRefusedError ? error : malformed()),
  }).pipe(Effect.onError(() => Effect.sync(() => discardMirrorStaging(storage, input.tables))));
}

/**
 * The thrown value crossing a transactionSync boundary — inside the
 * closure the refusal is a throw (that is what rolls the transaction
 * back); here it is turned back into the typed error. The only place an
 * instanceof may remain. The restore reader's vocabulary is folded onto
 * the page's (its other codes cannot arise here); any other throw is a
 * defect.
 */
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

/** The page bounds (the export's, plus one line of slack): judged before any write. */
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

/**
 * Stages one page (the caller holds the permit and verified the mark and
 * the storage guard). Fails with {@link MirrorPageRefusedError}; any
 * other throw is a defect (the transaction rolled back either way).
 */
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
    }).pipe(
      // The page's transaction rolled back; the staging in progress is
      // discarded on every refusal (the sequence refusal above keeps it)
      Effect.onError(() => Effect.sync(() => discardMirrorStaging(storage, input.tables))),
    );
  });
}
