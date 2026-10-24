// The restore of an evacuation into an empty project DO
// (docs/notes/hosted-ops.md §2-E / §5-2): the lines (do-snapshot.ts's
// format) are checked in order and batch-inserted table by table,
// chain_entries through a staging table that is promoted only after the
// row counts and the audit log are verified. Run by do-ops.ts's
// restoreProgram; the mirror (do-mirror.ts) shares the line and column
// checks.

import { Data, Effect } from "effect";

import { auditRowShapeViolations, deriveAuditHeads, isAuditHeadHex } from "../audit-store.ts";
import { OPS_RESTORE_BATCH_ROWS } from "../ops/ops-policy.ts";
import type {
  SnapshotHeader,
  SnapshotLine,
  SnapshotRowLine,
  SnapshotScalar,
  SnapshotTableLine,
  SnapshotTrailer,
} from "./do-snapshot.ts";
import { CHAIN_TABLE, decodeScalar, decodeSnapshotLine } from "./do-snapshot.ts";

/** DO SQLite bound-parameter limit (per statement — durable-objects/platform/limits). */
export const MAX_BOUND_PARAMETERS = 100;

/** Whether chain_entries is empty (the restore acceptance condition — creates no overwrite path). */
function isProjectDoEmpty(sql: SqlStorage): boolean {
  return sql.exec(`SELECT 1 FROM ${CHAIN_TABLE} LIMIT 1`).toArray().length === 0;
}

/** The restore staging table for chain_entries. Not listed in `tables`,
 * so it never appears in evacuations; leftovers are DROPped at the start
 * / completion / failure of the next restore.
 */
const CHAIN_STAGING_TABLE = "chain_entries_restore";

/** Restore refusal reasons (static codes — safe to put in result files and logs). */
export type RestoreFailureCode =
  | "not-empty"
  | "object-missing"
  /** The object's etag is not the one the import's pre-check verified (replaced between the two reads). */
  | "object-changed"
  | "malformed"
  | "schema-mismatch"
  | "trailer-missing"
  | "row-count-mismatch"
  | "unknown-table";

/**
 * The refusal in the Effect error channel (the code is the static
 * RestoreFailureCode — safe to put in result files and logs). Inside
 * transactionSync closures and the stream loop it is still thrown — the
 * throw is what rolls a batch back and stops the read — and the
 * boundary's `catch` turns it back into the typed error (the only place
 * an instanceof may remain).
 */
export class RestoreRefusedError extends Data.TaggedError("RestoreRefused")<{
  readonly code: RestoreFailureCode;
}> {}

export interface RestoreSnapshotInput {
  /** DO storage with transactionSync (sql is taken from here). */
  readonly storage: DurableObjectStorage;
  readonly tables: readonly string[];
  readonly schemaVersion: number;
  readonly body: ReadableStream;
  /**
   * Asked before each chunk of the audit-head derivation: false = hash and
   * check, but store no further head (the storage guard's rejection line —
   * AUTH_SPEC §11-7 / §12-8; do-ops.ts's restoreProgram measures it).
   */
  readonly storesAuditHeads: () => boolean;
}

export interface RestoreSnapshotResult {
  readonly header: SnapshotHeader;
  readonly trailer: SnapshotTrailer;
  readonly rows: Readonly<Record<string, number>>;
  /** The audit head at the restored log's end, as the derivation computed it (stored or not — AUTH_SPEC §11-7). */
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
    // Decoded against the wire union: a non-JSON line, or a shape no
    // line kind writes, is a corrupted evacuation (fold the reason into
    // a static code — the body is not carried)
    return decodeSnapshotLine(text);
  } catch {
    throw new RestoreRefusedError({ code: "malformed" });
  }
}

/**
 * The thrown value crossing the async boundary — inside the reader and
 * its transactionSync batches the refusal is a throw (that is what
 * rolls a batch back); here it is turned back into the typed error. The
 * only place an instanceof may remain; any other throw is a defect.
 */
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

/** Buffers one table's rows and inserts each batch in a single transaction. */
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

  /** Commits the buffered rows in one transaction (transactionSync). */
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

/**
 * Validates and returns the column names of an evacuation's table line
 * (the wire schema has already decoded them as strings). Any miss — not
 * an exact match including order with the live table's column names —
 * is "malformed" (column names are embedded as SQL identifiers, so only
 * values that pass here are used).
 */
export function acceptColumns(
  sql: SqlStorage,
  table: string,
  columns: readonly string[],
): readonly string[] {
  // table is already checked against the set of known tables (a value safe to embed as an identifier)
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

export function acceptHeader(line: SnapshotLine, schemaVersion: number): SnapshotHeader {
  // A non-header line in the header's slot (the wire schema has already
  // refused a bad format/version at decode)
  if (line.kind !== "header") {
    throw new RestoreRefusedError({ code: "malformed" });
  }
  if (line.schemaVersion !== schemaVersion) {
    throw new RestoreRefusedError({ code: "schema-mismatch" });
  }
  return line;
}

/** A state machine that consumes an evacuation's lines in order and batch-inserts per table. */
class RestoreReader {
  header: SnapshotHeader | null = null;
  trailer: SnapshotTrailer | null = null;
  readonly rows: Record<string, number> = {};
  #inserter: RowInserter | null = null;
  /** The logical table name under accept; distinct from the insert target (chain_entries is routed to staging). */
  #table: string | null = null;
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

  /** Verifies every table's row count against the trailer, derives the audit heads, promotes the chain to the real table, and returns the result. */
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
    const auditHeadHashHex = await this.#deriveAuditHeads();
    this.#promoteChainStaging();
    return { header, trailer, rows: this.rows, auditHeadHashHex };
  }

  /**
   * The audit heads past the snapshot's column, derived from its tail (a
   * head hash, or the empty string with no column) before the chain is
   * promoted (ruling J revision, round 10): a row the canonical form
   * refuses is `malformed` and the DO stays empty — restored, it threw the
   * append-only defect on every later read, with the DO `not-empty` for a
   * re-run. The convergence after the restore then has nothing to do.
   * Heads are stored only below the storage guard's rejection threshold
   * (AUTH_SPEC §11-7 / §12-8): past it every row is still hashed and
   * checked, and the head is returned from memory.
   */
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
    // Every row's numbers in the canonical form's domain, the rows under
    // the snapshot's column included (round 11); then the heads past the
    // column, chunk by chunk into the live column (wiped on a failure)
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

  /**
   * The audit log is exactly seq 1..N and the head column exactly 1..M with
   * M ≤ N (the append-only invariant the lazy extension relies on — a
   * restored log with a gap threw the defect on every later read; the
   * mirror's trailer applies the same rule — ruling J revision, round 9).
   */
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
    this.#flush();
    // The column names come from the evacuation's line and are embedded
    // as identifiers into the INSERT / CREATE TABLE below. The schema
    // version already matched in the header, so unless they exactly match
    // the live table's column names — taken the same way the writer
    // (writeSnapshot) takes them — including order, refuse as corrupt
    // (never flow identifiers from an evacuation into SQL unverified).
    const columns = acceptColumns(this.storage.sql, line.table, line.columns);
    // chain_entries is written to the staging table and moved to the
    // real table in verify. Since RowInserter commits per batch, if the
    // process dies mid-chain-table a "valid but truncated chain" remains,
    // and the isProjectDoEmpty refusal would make restore impossible
    // forever. Going through staging, an interruption always falls to
    // "chain_entries empty" (= uninitialized).
    const target = line.table === CHAIN_TABLE ? this.#beginChainStaging(columns) : line.table;
    this.#inserter = new RowInserter(this.storage, target, columns);
    this.#table = line.table;
    this.rows[line.table] = 0;
  }

  /** Remembers the chain's column names, creates the staging table, and returns its name. */
  #beginChainStaging(columns: readonly string[]): string {
    const columnList = columns.join(", ");
    this.storage.sql.exec(`DROP TABLE IF EXISTS ${CHAIN_STAGING_TABLE}`);
    this.storage.sql.exec(`CREATE TABLE ${CHAIN_STAGING_TABLE} (${columnList})`);
    this.#chainColumns = columns;
    return CHAIN_STAGING_TABLE;
  }

  /** Moves the verified staging rows to chain_entries in one transaction. */
  #promoteChainStaging(): void {
    const columns = this.#chainColumns;
    if (columns === null) {
      return; // the evacuation had no chain_entries table (empty project)
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

  /** Commits the in-flight table's buffer (transactions are opened per batch by RowInserter). */
  #flush(): void {
    this.#inserter?.flush();
  }
}

/**
 * Writes an evacuation back into an empty DO (the caller must hold the
 * permit). Each batch is atomically committed with transactionSync; a
 * mid-way failure (a refusal, a defect) wipes all tables back to empty
 * before it propagates. chain_entries rows go to the staging table and
 * are moved to the real table in one transaction only after
 * verification passes — wherever the process dies, it falls on the
 * "uninitialized" side and restore can be retried.
 */
export function restoreSnapshot(
  input: RestoreSnapshotInput,
): Effect.Effect<RestoreSnapshotResult, RestoreRefusedError> {
  const { storage, tables } = input;
  return Effect.gen(function* () {
    if (!isProjectDoEmpty(storage.sql)) {
      return yield* new RestoreRefusedError({ code: "not-empty" });
    }
    // Wipe the previous partial restore (leftover non-chain tables) first
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
      // On every mid-way failure the DO is wiped back to empty (the
      // not-empty refusal above does not reach this — there is nothing
      // of this restore's to wipe)
      Effect.onError(() =>
        Effect.sync(() => {
          wipeTables(storage.sql, tables);
          storage.sql.exec(`DROP TABLE IF EXISTS ${CHAIN_STAGING_TABLE}`);
        }),
      ),
    );
  });
}
