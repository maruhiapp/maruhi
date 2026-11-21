import { Data, Effect } from "effect";

import { auditRowShapeViolations, deriveAuditHeads, isAuditHeadHex } from "../audit-store.ts";
import type { MirrorSyncRejectReason } from "../data.package/index.ts";
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
const LOCAL_AUDIT_TABLE = "audit_events_mirror_local";
const AUDIT_HEAD_TABLE = "audit_head_hashes";
const TRAILER_TABLE = "trailer_mirror";

const stagingOf = (table: string): string => `${table}_mirror`;

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

function hasTable(sql: SqlStorage, name: string): boolean {
  return (
    sql.exec("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", name).toArray()
      .length > 0
  );
}

function dropStaging(sql: SqlStorage, tables: readonly string[]): void {
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

const malformed = (): MirrorPageRefusedError => new MirrorPageRefusedError({ reason: "malformed" });

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

export interface MirrorCommit {
  readonly atMs: number;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly auditMaxSeq: number;
  readonly attestationMark: number;
  readonly mutationSeq: number;
  readonly ownAuditRows: number;
}

export type MirrorStageResult =
  | { readonly kind: "staged"; readonly nextSequence: number }
  | { readonly kind: "trailer" };

function stagedCount(sql: SqlStorage, table: string): number {
  return hasTable(sql, stagingOf(table))
    ? Number(sql.exec(`SELECT COUNT(*) AS n FROM ${stagingOf(table)}`).one()["n"])
    : 0;
}

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

function envCascadeExempt(sql: SqlStorage): string {
  const staging = stagingOf(ENVIRONMENTS_TABLE);
  return hasTable(sql, staging)
    ? `EXISTS (SELECT 1 FROM ${staging} AS se WHERE se.environment_id = own.environment_id AND se.deleted_at IS NOT NULL)`
    : "";
}

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

function stagedRowOf(sql: SqlStorage, table: string, environmentId: string) {
  const staging = stagingOf(table);
  if (!hasTable(sql, staging)) {
    return undefined;
  }
  return sql.exec(`SELECT * FROM ${staging} WHERE environment_id = ?`, environmentId).toArray()[0];
}

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

interface StagedChainAnchors {
  readonly headSeq: number;
  readonly hashBySeq: ReadonlyMap<number, string>;
  readonly epochStarts: ReadonlyMap<string, readonly (readonly [number, number])[]>;
  readonly deletedSeq: ReadonlyMap<string, number>;
  readonly rotateCounts: ReadonlyMap<string, number>;
  readonly addMemberSweeps: readonly {
    readonly seq: number;
    readonly targetUserId: string;
    readonly encPubHex: string;
  }[];
  readonly removedMembers: readonly { readonly seq: number; readonly targetUserId: string }[];
  readonly revokedDevices: readonly {
    readonly seq: number;
    readonly targetUserId: string;
    readonly fingerprints: readonly string[];
  }[];
  readonly tupleFor: ReadonlyMap<
    string,
    { readonly epoch: number; readonly sig: string } | "conflict"
  >;
  readonly latest: ReadonlyMap<string, CheckpointTuple>;
  readonly complete: boolean;
}

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
          complete = false;
        }
        revokedDevices.push({ seq, targetUserId, fingerprints });
      }
      continue;
    }
    if (op !== "checkpoint") {
      if (!ANCHORS_IGNORED_OPS.has(op)) {
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

function columnsOf(sql: SqlStorage, table: string): readonly string[] {
  return sql.exec(`SELECT * FROM ${table} LIMIT 0`).columnNames;
}

function rowsDiffer(
  columns: readonly string[],
  a: Record<string, unknown>,
  b: Record<string, unknown>,
): boolean {
  return columns.some((column) => a[column] !== b[column]);
}

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

function verifyChainAnchoredProjections(sql: SqlStorage): void {
  if (!hasTable(sql, stagingOf(CHAIN_TABLE))) {
    return;
  }
  const anchors = stagedChainAnchors(sql);
  if (!anchors.complete) {
    return;
  }
  verifyStagedCheckpoints(sql, anchors);
  verifyStagedManifests(sql, anchors);
  verifyStagedTombstones(sql, anchors);
  verifyStagedWraps(sql, anchors);
  verifyStagedAttestations(sql, anchors);
  verifyAuditAnchoredState(sql, anchors);
}

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
    const expectedVersion =
      stagedEnvCount(sql, "environment_meta_statements", environmentId) +
      stagedEnvCount(sql, "variable_meta_statements", environmentId) +
      (anchors.rotateCounts.get(environmentId) ?? 0);
    if (manifestVersion !== expectedVersion) {
      throw malformed();
    }
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

interface StagedProposalMint {
  readonly environmentId: string | null;
  readonly claimsDigestHex: string | null;
  readonly grantChainSeq: number | null;
  readonly connector: string | null;
  readonly variableIds: readonly string[];
  readonly open: boolean;
}

interface StagedAuditAnchors {
  readonly policy: string;
  readonly proposals: ReadonlyMap<string, StagedProposalMint>;
  readonly closed: ReadonlySet<string>;
}

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

function safeParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function verifyAuditAnchoredState(sql: SqlStorage, anchors: StagedChainAnchors): void {
  const audit = stagedAuditAnchors(sql);
  verifyStagedSettings(sql, audit);
  verifyStagedProposals(sql, anchors, audit);
}

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

export const verifyStagedAuditHeads = Effect.fn("do-mirror.verifyStagedAuditHeads")(function* (
  sql: SqlStorage,
  state: MirrorState,
): Effect.fn.Return<void, MirrorPageRefusedError> {
  const stagedHeads = stagingOf(AUDIT_HEAD_TABLE);
  const stagedLog = stagingOf(AUDIT_TABLE);
  if (!hasTable(sql, stagedLog)) {
    return;
  }
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
  sql.exec(`DELETE FROM ${stagedHeads} WHERE seq > ?`, from);
  const derived = yield* Effect.promise(() =>
    deriveAuditHeads(sql, stagedLog, stagedHeads, from, from === 0 ? "" : String(start)),
  );
  if (derived === null) {
    return yield* malformed();
  }
});

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
