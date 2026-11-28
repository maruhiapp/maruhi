import { Data, Effect } from "effect";

import { auditRowShapeViolations, deriveAuditHeads, isAuditHeadHex } from "../audit-store.ts";
import { OPS_RESTORE_BATCH_ROWS } from "../ops/ops-policy.ts";
import {
  type ChainRow,
  type CheckpointTuple,
  checkpointRowsMatchLatest,
  foldChainAnchors,
} from "./chain-anchors.ts";
import type {
  SnapshotHeader,
  SnapshotLine,
  SnapshotRowLine,
  SnapshotScalar,
  SnapshotTableLine,
  SnapshotTrailer,
} from "./do-snapshot.ts";
import { CHAIN_TABLE, decodeScalar, decodeSnapshotLine } from "./do-snapshot.ts";

export const MAX_BOUND_PARAMETERS = 100;

function isProjectDoEmpty(sql: SqlStorage): boolean {
  return sql.exec(`SELECT 1 FROM ${CHAIN_TABLE} LIMIT 1`).toArray().length === 0;
}

const CHAIN_STAGING_TABLE = "chain_entries_restore";

export type RestoreFailureCode =
  | "not-empty"
  | "object-missing"
  | "object-changed"
  | "malformed"
  | "schema-mismatch"
  | "trailer-missing"
  | "row-count-mismatch"
  | "trailer-mismatch"
  | "unknown-table";

export class RestoreRefusedError extends Data.TaggedError("RestoreRefused")<{
  readonly code: RestoreFailureCode;
}> {}

export interface RestoreSnapshotInput {
  readonly storage: DurableObjectStorage;
  readonly tables: readonly string[];
  readonly schemaVersion: number;
  readonly body: ReadableStream;
  readonly storesAuditHeads: () => boolean;
}

export interface RestoreSnapshotResult {
  readonly header: SnapshotHeader;
  readonly trailer: SnapshotTrailer;
  readonly rows: Readonly<Record<string, number>>;
  readonly auditHeadHashHex: string;
}

async function* lines(body: ReadableStream): AsyncGenerator<string> {
  const reader = body
    .pipeThrough(new DecompressionStream("gzip"))
    .pipeThrough(new TextDecoderStream())
    .getReader();
  let carry = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      if (carry !== "") {
        yield carry;
      }
      return;
    }
    carry += value;
    let index = carry.indexOf("\n");
    while (index !== -1) {
      yield carry.slice(0, index);
      carry = carry.slice(index + 1);
      index = carry.indexOf("\n");
    }
  }
}

export function parseLine(text: string): SnapshotLine {
  try {
    return decodeSnapshotLine(text);
  } catch {
    throw new RestoreRefusedError({ code: "malformed" });
  }
}

const toRestoreRefusal = (error: unknown): RestoreRefusedError => {
  if (error instanceof RestoreRefusedError) {
    return error;
  }
  throw error;
};

function wipeTables(sql: SqlStorage, tables: readonly string[]): void {
  for (const table of tables) {
    sql.exec(`DELETE FROM ${table}`);
  }
}

class RowInserter {
  #buffer: (readonly SnapshotScalar[])[] = [];
  readonly #rowsPerStatement: number;

  constructor(
    private readonly storage: DurableObjectStorage,
    readonly table: string,
    private readonly columns: readonly string[],
  ) {
    this.#rowsPerStatement = Math.max(1, Math.floor(MAX_BOUND_PARAMETERS / columns.length));
  }

  push(values: readonly SnapshotScalar[]): void {
    if (values.length !== this.columns.length) {
      throw new RestoreRefusedError({ code: "malformed" });
    }
    this.#buffer.push(values);
    if (this.#buffer.length >= OPS_RESTORE_BATCH_ROWS) {
      this.flush();
    }
  }

  flush(): void {
    if (this.#buffer.length === 0) {
      return;
    }
    const rows = this.#buffer;
    this.#buffer = [];
    const columnList = this.columns.join(", ");
    const placeholders = `(${this.columns.map(() => "?").join(", ")})`;
    this.storage.transactionSync(() => {
      for (let start = 0; start < rows.length; start += this.#rowsPerStatement) {
        const chunk = rows.slice(start, start + this.#rowsPerStatement);
        this.storage.sql.exec(
          `INSERT INTO ${this.table} (${columnList}) VALUES ${chunk.map(() => placeholders).join(", ")}`,
          ...chunk.flatMap((values) => values.map(decodeScalar)),
        );
      }
    });
  }
}

export function acceptColumns(
  sql: SqlStorage,
  table: string,
  columns: readonly string[],
): readonly string[] {
  const live = sql.exec(`SELECT * FROM ${table} LIMIT 0`).columnNames;
  if (
    columns.length === 0 ||
    columns.length !== live.length ||
    columns.some((column, index) => column !== live[index])
  ) {
    throw new RestoreRefusedError({ code: "malformed" });
  }
  return live;
}

interface StagedChainAnchors {
  readonly created: ReadonlySet<string>;
  readonly live: ReadonlySet<string>;
  readonly deleted: ReadonlySet<string>;
  readonly currentEpoch: ReadonlyMap<string, number>;
  readonly latest: ReadonlyMap<string, CheckpointTuple>;
  readonly grantScopes: ReadonlyMap<number, readonly string[]>;
}

function stagedChainAnchors(sql: SqlStorage): StagedChainAnchors {
  const rows: ChainRow[] = [];
  for (const row of sql
    .exec(`SELECT seq, entry_json, entry_hash_hex FROM ${CHAIN_STAGING_TABLE} ORDER BY seq`)
    .toArray()) {
    const seq = row["seq"];
    if (typeof seq !== "number" || !Number.isSafeInteger(seq)) {
      continue;
    }
    const entryHashHex = row["entry_hash_hex"];
    rows.push({
      seq,
      entryJson: String(row["entry_json"]),
      entryHashHex: typeof entryHashHex === "string" ? entryHashHex : null,
    });
  }
  const { epochStarts, deletedSeq, latest, grantScopes } = foldChainAnchors(rows);
  const created = new Set(epochStarts.keys());
  const deleted = new Set(deletedSeq.keys());
  const live = new Set([...created].filter((environmentId) => !deleted.has(environmentId)));
  const currentEpoch = new Map<string, number>();
  for (const environmentId of live) {
    const starts = epochStarts.get(environmentId) ?? [];
    const last = starts[starts.length - 1];
    if (last !== undefined) {
      currentEpoch.set(environmentId, last[1]);
    }
  }
  return { created, live, deleted, currentEpoch, latest, grantScopes };
}

export function acceptHeader(line: SnapshotLine, schemaVersion: number): SnapshotHeader {
  if (line.kind !== "header") {
    throw new RestoreRefusedError({ code: "malformed" });
  }
  if (line.schemaVersion !== schemaVersion) {
    throw new RestoreRefusedError({ code: "schema-mismatch" });
  }
  return line;
}

class RestoreReader {
  header: SnapshotHeader | null = null;
  trailer: SnapshotTrailer | null = null;
  readonly rows: Record<string, number> = {};
  #inserter: RowInserter | null = null;
  #table: string | null = null;
  readonly #begunTables = new Set<string>();
  #chainColumns: readonly string[] | null = null;

  constructor(
    private readonly storage: DurableObjectStorage,
    private readonly known: ReadonlySet<string>,
    private readonly schemaVersion: number,
    private readonly storesAuditHeads: () => boolean,
  ) {}

  accept(line: SnapshotLine): void {
    if (this.header === null) {
      this.header = acceptHeader(line, this.schemaVersion);
      return;
    }
    if (this.trailer !== null) {
      throw new RestoreRefusedError({ code: "malformed" });
    }
    switch (line.kind) {
      case "table":
        this.#beginTable(line);
        return;
      case "row":
        this.#acceptRow(line);
        return;
      case "trailer":
        this.#flush();
        this.trailer = line;
        return;
      default:
        throw new RestoreRefusedError({ code: "malformed" });
    }
  }

  async verify(tables: readonly string[]): Promise<RestoreSnapshotResult> {
    const { header, trailer } = this;
    if (header === null || trailer === null) {
      throw new RestoreRefusedError({ code: "trailer-missing" });
    }
    for (const table of tables) {
      if ((trailer.rows[table] ?? 0) !== (this.rows[table] ?? 0)) {
        throw new RestoreRefusedError({ code: "row-count-mismatch" });
      }
    }
    this.#verifyAuditContiguity();
    this.#verifyTrailerWatermarks(trailer);
    this.#verifyDeclaredChainHeads();
    this.#verifyChainAnchoredState();
    const auditHeadHashHex = await this.#deriveAuditHeads();
    if (trailer.auditHeadHashHex !== null && trailer.auditHeadHashHex !== auditHeadHashHex) {
      throw new RestoreRefusedError({ code: "trailer-mismatch" });
    }
    this.#promoteChainStaging();
    return { header, trailer, rows: this.rows, auditHeadHashHex };
  }

  #verifyTrailerWatermarks(trailer: SnapshotTrailer): void {
    const sql = this.storage.sql;
    let chainHeadSeq = 0;
    let chainHeadHashHex: string | null = null;
    if (this.#chainColumns !== null) {
      const head = sql
        .exec(`SELECT seq, entry_hash_hex FROM ${CHAIN_STAGING_TABLE} ORDER BY seq DESC LIMIT 1`)
        .toArray()[0];
      if (head !== undefined) {
        chainHeadSeq = Number(head["seq"]);
        const heads = sql
          .exec(`SELECT entry_hash_hex FROM ${CHAIN_STAGING_TABLE} WHERE seq = ?`, chainHeadSeq)
          .toArray();
        if (heads.length !== 1) {
          throw new RestoreRefusedError({ code: "trailer-mismatch" });
        }
        chainHeadHashHex = String(heads[0]?.["entry_hash_hex"]);
      }
    }
    const auditMaxSeq = Number(
      sql.exec("SELECT COALESCE(MAX(seq), 0) AS m FROM audit_events").one()["m"],
    );
    if (
      trailer.chainHeadSeq !== chainHeadSeq ||
      trailer.chainHeadHashHex !== chainHeadHashHex ||
      trailer.auditMaxSeq !== auditMaxSeq
    ) {
      throw new RestoreRefusedError({ code: "trailer-mismatch" });
    }
  }

  #verifyDeclaredChainHeads(): void {
    const sql = this.storage.sql;
    const declared: readonly (readonly [string, string, string])[] = [
      ["environment_meta_statements", "chain_head_seq", "chain_head_hash_hex"],
      ["variable_meta_statements", "chain_head_seq", "chain_head_hash_hex"],
      ["variable_versions", "chain_head_seq", "chain_head_hash_hex"],
      ["environment_manifests", "chain_head_seq", "chain_head_hash_hex"],
      ["head_attestations", "chain_head_seq", "chain_head_hash_hex"],
      ["environment_checkpoints", "chain_seq", "entry_hash_hex"],
    ];
    for (const [table, seqColumn, hashColumn] of declared) {
      const violations =
        this.#chainColumns === null
          ? Number(sql.exec(`SELECT COUNT(*) AS n FROM ${table}`).one()["n"])
          : Number(
              sql
                .exec(
                  `SELECT COUNT(*) AS n FROM ${table} AS p
                   LEFT JOIN ${CHAIN_STAGING_TABLE} AS c ON c.seq = p.${seqColumn}
                   WHERE c.entry_hash_hex IS NULL OR c.entry_hash_hex <> p.${hashColumn}`,
                )
                .one()["n"],
            );
      if (violations !== 0) {
        throw new RestoreRefusedError({ code: "malformed" });
      }
    }
  }

  #verifyChainAnchoredState(): void {
    if (this.#chainColumns === null) {
      return;
    }
    const anchors = stagedChainAnchors(this.storage.sql);
    this.#verifyEnvironmentPresence(anchors);
    this.#verifyRestoredCheckpoints(anchors);
    this.#verifyRestoredWrapEpochs(anchors);
    this.#verifyRestoredCheckpointValues();
    this.#verifyRestoredSettings();
    this.#verifyRestoredProposals(anchors);
  }

  #verifyEnvironmentPresence(anchors: StagedChainAnchors): void {
    const sql = this.storage.sql;
    const tombstoned = new Map<string, boolean>();
    for (const row of sql.exec("SELECT environment_id, deleted_at FROM environments").toArray()) {
      tombstoned.set(String(row["environment_id"]), row["deleted_at"] !== null);
    }
    for (const environmentId of anchors.created) {
      if (tombstoned.get(environmentId) !== anchors.deleted.has(environmentId)) {
        throw new RestoreRefusedError({ code: "malformed" });
      }
    }
    const manifests = new Set(
      sql
        .exec("SELECT environment_id FROM environment_manifests")
        .toArray()
        .map((row) => String(row["environment_id"])),
    );
    for (const environmentId of anchors.live) {
      if (!manifests.has(environmentId)) {
        throw new RestoreRefusedError({ code: "malformed" });
      }
    }
    for (const environmentId of manifests) {
      if (anchors.deleted.has(environmentId)) {
        throw new RestoreRefusedError({ code: "malformed" });
      }
    }
  }

  #verifyRestoredCheckpoints(anchors: StagedChainAnchors): void {
    const rows = this.storage.sql.exec("SELECT * FROM environment_checkpoints").toArray();
    if (!checkpointRowsMatchLatest(rows, anchors.latest)) {
      throw new RestoreRefusedError({ code: "malformed" });
    }
  }

  #verifyRestoredWrapEpochs(anchors: StagedChainAnchors): void {
    const rows = this.storage.sql
      .exec("SELECT DISTINCT environment_id, epoch FROM dek_wraps")
      .toArray();
    for (const row of rows) {
      const current = anchors.currentEpoch.get(String(row["environment_id"]));
      const epoch = row["epoch"];
      if (
        current === undefined ||
        typeof epoch !== "number" ||
        !Number.isSafeInteger(epoch) ||
        epoch < 1 ||
        epoch > current
      ) {
        throw new RestoreRefusedError({ code: "malformed" });
      }
    }
  }

  #verifyRestoredCheckpointValues(): void {
    const orphaned = Number(
      this.storage.sql
        .exec(
          `SELECT COUNT(*) AS n FROM checkpoint_snapshot_values AS v
           LEFT JOIN environment_checkpoints AS c ON c.environment_id = v.environment_id
           WHERE c.environment_id IS NULL`,
        )
        .one()["n"],
    );
    if (orphaned !== 0) {
      throw new RestoreRefusedError({ code: "malformed" });
    }
  }

  #verifyRestoredSettings(): void {
    const row = this.storage.sql.exec("SELECT schema_policy FROM project_settings").toArray()[0];
    if (
      row !== undefined &&
      row["schema_policy"] !== "enabled" &&
      row["schema_policy"] !== "locked"
    ) {
      throw new RestoreRefusedError({ code: "malformed" });
    }
  }

  #verifyRestoredProposals(anchors: StagedChainAnchors): void {
    const sql = this.storage.sql;
    const proposals = sql
      .exec("SELECT environment_id, grant_chain_seq FROM rotation_proposals")
      .toArray();
    for (const row of proposals) {
      const environmentId = String(row["environment_id"]);
      const grantSeq = row["grant_chain_seq"];
      const scope =
        typeof grantSeq === "number" && Number.isSafeInteger(grantSeq)
          ? anchors.grantScopes.get(grantSeq)
          : undefined;
      if (
        !anchors.live.has(environmentId) ||
        scope === undefined ||
        !scope.includes(environmentId)
      ) {
        throw new RestoreRefusedError({ code: "malformed" });
      }
    }
    for (const table of ["rotation_proposal_variables", "rotation_proposal_wraps"] as const) {
      const orphaned = Number(
        sql
          .exec(
            `SELECT COUNT(*) AS n FROM ${table} AS child
             LEFT JOIN rotation_proposals AS p ON p.proposal_id = child.proposal_id
             WHERE p.proposal_id IS NULL`,
          )
          .one()["n"],
      );
      if (orphaned !== 0) {
        throw new RestoreRefusedError({ code: "malformed" });
      }
    }
  }

  async #deriveAuditHeads(): Promise<string> {
    const sql = this.storage.sql;
    const tail = sql
      .exec("SELECT seq, head_hash_hex FROM audit_head_hashes ORDER BY seq DESC LIMIT 1")
      .toArray()[0];
    const from = tail === undefined ? 0 : Number(tail["seq"]);
    const start = tail === undefined ? "" : tail["head_hash_hex"];
    if (tail !== undefined && !isAuditHeadHex(start)) {
      throw new RestoreRefusedError({ code: "malformed" });
    }
    if (auditRowShapeViolations(sql, "audit_events") !== 0) {
      throw new RestoreRefusedError({ code: "malformed" });
    }
    const derived = await deriveAuditHeads(
      sql,
      "audit_events",
      "audit_head_hashes",
      from,
      String(start),
      this.storesAuditHeads,
    );
    if (derived === null) {
      throw new RestoreRefusedError({ code: "malformed" });
    }
    return derived;
  }

  #verifyAuditContiguity(): void {
    const sql = this.storage.sql;
    const shape = (table: string) => {
      const row = sql
        .exec(
          `SELECT COUNT(*) AS c, COALESCE(MAX(seq), 0) AS mx, COALESCE(MIN(seq), 1) AS mn FROM ${table}`,
        )
        .one();
      return { count: Number(row["c"]), max: Number(row["mx"]), min: Number(row["mn"]) };
    };
    const audit = shape("audit_events");
    const heads = shape("audit_head_hashes");
    if (
      audit.count !== audit.max ||
      audit.min < 1 ||
      heads.count !== heads.max ||
      heads.min < 1 ||
      heads.count > audit.count
    ) {
      throw new RestoreRefusedError({ code: "malformed" });
    }
  }

  #beginTable(line: SnapshotTableLine): void {
    if (!this.known.has(line.table)) {
      throw new RestoreRefusedError({ code: "unknown-table" });
    }
    if (this.#begunTables.has(line.table)) {
      throw new RestoreRefusedError({ code: "malformed" });
    }
    this.#begunTables.add(line.table);
    this.#flush();
    const columns = acceptColumns(this.storage.sql, line.table, line.columns);
    const target = line.table === CHAIN_TABLE ? this.#beginChainStaging(columns) : line.table;
    this.#inserter = new RowInserter(this.storage, target, columns);
    this.#table = line.table;
    this.rows[line.table] = 0;
  }

  #beginChainStaging(columns: readonly string[]): string {
    const columnList = columns.join(", ");
    this.storage.sql.exec(`DROP TABLE IF EXISTS ${CHAIN_STAGING_TABLE}`);
    this.storage.sql.exec(`CREATE TABLE ${CHAIN_STAGING_TABLE} (${columnList})`);
    this.#chainColumns = columns;
    return CHAIN_STAGING_TABLE;
  }

  #promoteChainStaging(): void {
    const columns = this.#chainColumns;
    if (columns === null) {
      return;
    }
    const columnList = columns.join(", ");
    this.storage.transactionSync(() => {
      this.storage.sql.exec(
        `INSERT INTO ${CHAIN_TABLE} (${columnList}) SELECT ${columnList} FROM ${CHAIN_STAGING_TABLE}`,
      );
      this.storage.sql.exec(`DROP TABLE ${CHAIN_STAGING_TABLE}`);
    });
    this.#chainColumns = null;
  }

  #acceptRow(line: SnapshotRowLine): void {
    const inserter = this.#inserter;
    if (inserter === null || line.table !== this.#table) {
      throw new RestoreRefusedError({ code: "malformed" });
    }
    inserter.push(line.values);
    this.rows[line.table] = (this.rows[line.table] ?? 0) + 1;
  }

  #flush(): void {
    this.#inserter?.flush();
  }
}

export function restoreSnapshot(
  input: RestoreSnapshotInput,
): Effect.Effect<RestoreSnapshotResult, RestoreRefusedError> {
  const { storage, tables } = input;
  return Effect.gen(function* () {
    if (!isProjectDoEmpty(storage.sql)) {
      return yield* new RestoreRefusedError({ code: "not-empty" });
    }
    wipeTables(storage.sql, tables);
    storage.sql.exec(`DROP TABLE IF EXISTS ${CHAIN_STAGING_TABLE}`);
    const reader = new RestoreReader(
      storage,
      new Set(tables),
      input.schemaVersion,
      input.storesAuditHeads,
    );
    return yield* Effect.tryPromise({
      try: async () => {
        for await (const text of lines(input.body)) {
          if (text !== "") {
            reader.accept(parseLine(text));
          }
        }
        return await reader.verify(tables);
      },
      catch: toRestoreRefusal,
    }).pipe(
      Effect.onError(() =>
        Effect.sync(() => {
          wipeTables(storage.sql, tables);
          storage.sql.exec(`DROP TABLE IF EXISTS ${CHAIN_STAGING_TABLE}`);
        }),
      ),
    );
  });
}
