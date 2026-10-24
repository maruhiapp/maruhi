// The audit log's append store (AUDIT_SPEC §5.1) and the AuditStore service
// over it. The service also serves two read surfaces, each in its own file:
// the generic read (§7 — C1, audit-store-query.ts) and the reads for
// rotation-needed detection (§4.1 / §4.2, audit-store-rotation-read.ts). The
// stored-row decoders the head derivation shares with them are
// audit-store-rows.ts.
//
// - append-only: this service exposes only appends and reads (no update
//   or delete entry point is created — AUDIT_SPEC §1-4)
// - seq is monotonic and gapless. The next seq is held in DO instance
//   memory (MAX(seq) is read once at initialization; re-read on a DO
//   restart), and never crosses an await boundary because the SQL is
//   synchronous
// - Identity rule (§1-2): actor / target carry only the internal
//   user_id and the key FP. Never bring provider IDs or emails into this
//   layer
// - The chain-mirror mapping (§3.4) shares its implementation with
//   @maruhi/core's chainMirrorEvents (the same implementation the CLI's
//   mirror verification — `maruhi audit verify` — uses)

import type { AuditEventRecord } from "@maruhi/core";
import {
  assertProjectAuditPayload,
  auditPayloadWith,
  CHAIN_MIRROR_EVENT_PREFIX,
  cryptoEffect,
} from "@maruhi/core";
import { computeAuditHeadHash, computeAuditRowDigest, SUITE_ID } from "@maruhi/crypto";
import { Context, Data, Effect, Layer } from "effect";

import type { AuditEventsQuery, StoredAuditEventRow } from "./audit-store-query.ts";
import { queryEvents } from "./audit-store-query.ts";
import type { AuditRotationRead } from "./audit-store-rotation-read.ts";
import { makeRotationRead } from "./audit-store-rotation-read.ts";
import { AUDIT_ROW_COLUMNS, toAuditHeadRow } from "./audit-store-rows.ts";
import { randomHex } from "./ids.ts";
import { ServerLoggerLive } from "./server-logger.ts";

/**
 * The input of one audit-event row (columns per AUDIT_SPEC §5.1;
 * unspecified = NULL). An alias of the shared record type
 * (@maruhi/core — colocated with the chain-mirror mapping).
 */
export type AuditEventInput = AuditEventRecord;

/**
 * The result of ensureHeadCurrent: "current" = the column has reached
 * MAX(seq) (the head may be read); "more-remains" = hit the bounded
 * extension limit before reaching it (do not read; answer with a
 * retryable rejection).
 */
export type AuditHeadExtensionOutcome = "current" | "more-remains";

interface AuditStoreShape {
  /**
   * A synchronous append. Called inside the same synchronous block (= the
   * same event-loop task) as the data write, the inconsistency "the data
   * was written but the event is missing" on a crash is prevented
   * structurally (a DO SQLite write commits atomically per task).
   */
  readonly appendSync: (event: AuditEventInput) => void;
  /**
   * A bulk synchronous append of multiple events (a multi-row INSERT).
   * The path that keeps the per-returned-variable / per-cascade-variable
   * / per-wrap loop appends (up to 10,000 rows per request) from being
   * one INSERT statement per row. Atomicity is held by the same "inside
   * one synchronous block" as appendSync (the statements are split into
   * chunks but commit in the same task).
   */
  readonly appendManySync: (events: readonly AuditEventInput[]) => void;
  /**
   * Discard the sequence cache. On a task failure the storage rolls back
   * per task while only the in-memory sequencing stays advanced, making
   * the next append produce a gap (an AUDIT_SPEC §5.1 violation), so the
   * DO always calls this on the failure path (the defect hook of
   * chain-do.ts) and the next append continues from a fresh MAX(seq)
   * read.
   */
  readonly resetSeqCacheSync: () => void;
  /** The reads for rotation-needed detection and flag derivation (§4.1; adds no append entry point). */
  readonly readRotationSync: AuditRotationRead;
  /**
   * The generic read (§7 — C1): seq-descending (newest first) + filters
   * + visibility class. Since visibility is enforced by the WHERE
   * clause, a sub-admin page is a gapless `limit` rows that skipped
   * class-2 rows (nothing leaks via counts or the cursor — §7).
   */
  readonly queryEventsSync: (query: AuditEventsQuery) => readonly StoredAuditEventRow[];
  /**
   * Extend the audit-head cumulative hash column (AUDIT_SPEC §5.1 —
   * audit_head_hashes) toward MAX(seq). The hash column is a
   * deterministic derivation from the append-only rows, and
   * materialization happens right before a read path (GET /audit-head,
   * checkpoint acceptance verification) — SHA-256 is async (WebCrypto)
   * so it cannot sit in the synchronous append block, and lazy extension
   * keeps the hash computation off the var.read bulk-append hot path.
   * The first call computes from all existing rows (no separate
   * initialization step — §5.1). Since no reader observes anything but
   * the fully extended column, a disagreement between rows and the
   * column is unobservable (the design ruling is docs/notes/session-35.
   * md). Call under the DO permit.
   *
   * **Bounded contract**: one call's extension is bounded in chunks
   * ({@link MAX_HEAD_EXTENSION_CHUNKS_PER_CALL}). On a call that
   * returned `"more-remains"` the column has not reached MAX(seq), so
   * the caller must answer with a retryable rejection (AuditHeadNotReady
   * — AUTH_SPEC §16-2) **without reading the head** (never calling
   * currentHeadHexSync / headPositionSync). Never judge
   * audit-head-unknown / stale on a stale column (fail-closed). Progress
   * is persisted per chunk, so a retry always advances and converges.
   */
  readonly ensureHeadCurrent: Effect.Effect<AuditHeadExtensionOutcome>;
  /**
   * Whether the cumulative hash column is behind MAX(seq) (= whether the
   * next ensureHeadCurrent involves materialization writes). The input
   * of the DO storage total guard (AUTH_SPEC §12-8): materialization is
   * a write proportional to the audit row count (one hash row + index
   * per row), and a DO at or over the rejection threshold must not write
   * an unmaterialized backlog (storage-guard.ts). Read-only (two indexed
   * MAX / existence checks).
   */
  readonly headColumnBehindSync: () => boolean;
  /**
   * The current cumulative hash (empty string when there are no audit
   * rows). Call only after ensureHeadCurrent returned "current" (the
   * bounded contract — above).
   */
  readonly currentHeadHexSync: () => string;
  /**
   * The position inside the cumulative hash column (= the audit seq; the
   * membership check — CRYPTO_SPEC §6.4). null when absent from the
   * column. Call only after ensureHeadCurrent returned "current" (the
   * bounded contract — above).
   */
  readonly headPositionSync: (headHashHex: string) => number | null;
  /**
   * The audit seq of the mirror row of the previous checkpoint
   * (chain.checkpointed — with or without notarization; the basis of the
   * position-lower-bound check — CRYPTO_SPEC §6.4). null when absent
   * (the project's first checkpoint — no lower bound applies).
   */
  readonly latestCheckpointMirrorSeqSync: () => number | null;
}

export class AuditStore extends Context.Service<AuditStore, AuditStoreShape>()("AuditStore") {}

const INSERT_COLUMNS = `INSERT INTO audit_events (
    seq, row_id, server_ts, client_ts, event, actor_type, actor_user_id,
    actor_key_fingerprint, actor_api_token_id, target_user_id,
    target_key_fingerprint, environment_id, variable_id, epoch, version,
    chain_seq, payload
  ) VALUES `;

/** The placeholders of one row (seq + row_id + the 15 values of eventBindings = 17 columns). */
const VALUES_ROW = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

/**
 * The per-statement row count of a multi-row INSERT. 17 columns × 5
 * rows = 85 bindings, staying under SQLite's bound-variable limit
 * (conservatively taken as 100).
 */
const APPEND_CHUNK_ROWS = 5;

function orNull(value: string | number | undefined): string | number | null {
  return value === undefined ? null : value;
}

/**
 * chain_seq is reserved for chain.* mirrors (AUDIT_SPEC §5.1).
 *
 * Since the read side promotes a row carrying chain_seq to class 1 as
 * tamper evidence, not stopping an honest writer's misuse here could
 * disclose a future class-2 row to every member. Nulling only the
 * column would hide a producer bug and lose the audit cross-check
 * material, so it is a defect. The call sits ahead of sequencing and
 * SQL execution so a violation creates neither a gap nor a partial
 * append.
 */
function assertChainSeqInvariant(event: AuditEventInput): void {
  if (event.chainSeq !== undefined && !event.event.startsWith(CHAIN_MIRROR_EVENT_PREFIX)) {
    throw new Error("audit invariant violation: chain_seq is reserved for chain.* events");
  }
}

/**
 * The checks every row passes ahead of sequencing and SQL execution: the
 * chain_seq reservation above, and the payload against its event's AUDIT_SPEC
 * §3 schema (no key the spec does not list — the identity rule's gate on the
 * payload, packages/core audit-payloads.ts). Both are defects.
 */
function assertAppendable(event: AuditEventInput): void {
  assertChainSeqInvariant(event);
  assertProjectAuditPayload(event);
}

/** The stored payload: the event's payload plus a session actor's auth method (§2 / §5.1). NULL when empty. */
function storedPayload(event: AuditEventInput): string | null {
  const payload = auditPayloadWith(
    event.actorAuthMethod === undefined ? {} : { authMethod: event.actorAuthMethod },
    event.payload,
  );
  return Object.keys(payload).length === 0 ? null : JSON.stringify(payload);
}

/** The insert bindings (same order as INSERT_EVENT's SELECT columns). Unspecified = NULL. */
function eventBindings(event: AuditEventInput): (string | number | null)[] {
  return [
    event.serverTs,
    orNull(event.clientTs),
    event.event,
    event.actorType,
    orNull(event.actorUserId),
    orNull(event.actorKeyFingerprintHex),
    orNull(event.actorApiTokenId),
    orNull(event.targetUserId),
    orNull(event.targetKeyFingerprintHex),
    orNull(event.environmentId),
    orNull(event.variableId),
    orNull(event.epoch),
    orNull(event.version),
    orNull(event.chainSeq),
    storedPayload(event),
  ];
}

/** The options of makeAuditStore (so a test can pin a smaller bounded-extension limit). */
export interface AuditStoreOptions {
  /** ensureHeadCurrent's per-call chunk limit (defaults to the production value). */
  readonly maxHeadExtensionChunks?: number;
}

/**
 * The AuditStore implementation (exposed separately from the Layer so
 * tests can build it directly).
 *
 * The next seq (monotonic, gapless — AUDIT_SPEC §5.1) is held in DO
 * instance memory, replacing a per-row `SELECT COALESCE(MAX(seq),0)+1`
 * aggregate with a single read at initialization. null = cache invalid
 * (right after a DO restart or a failure); the next append re-reads
 * MAX(seq). On an insert failure the sequence cache is discarded
 * immediately — chunk success ≠ task success, and if only the in-memory
 * sequencing stayed advanced against the per-task storage rollback on
 * task failure, the next append would produce a gap (for the same
 * reason the DO's failure path calls resetSeqCacheSync — chain-do.ts).
 * Assumes every append goes through this implementation under the DO's
 * permit serialization.
 */
export const makeAuditStore = (sql: SqlStorage, options?: AuditStoreOptions): AuditStoreShape => {
  let nextSeqCache: number | null = null;
  const nextSeq = (): number => {
    if (nextSeqCache === null) {
      const row = sql
        .exec("SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM audit_events")
        .toArray()[0];
      nextSeqCache = Number(row?.["next_seq"] ?? 1);
    }
    return nextSeqCache;
  };
  return {
    appendSync: (event) => {
      assertAppendable(event);
      const seq = nextSeq();
      try {
        // row_id = the wire row identifier (16 bytes random — AUDIT_SPEC §5.1 / §7)
        sql.exec(INSERT_COLUMNS + VALUES_ROW, seq, randomHex(16), ...eventBindings(event));
      } catch (error) {
        nextSeqCache = null;
        throw error;
      }
      nextSeqCache = seq + 1;
    },
    appendManySync: (events) => {
      // Check every event ahead of the SQL so a violation in a later
      // chunk never leaves only the earlier chunks written
      for (const event of events) {
        assertAppendable(event);
      }
      try {
        for (let offset = 0; offset < events.length; offset += APPEND_CHUNK_ROWS) {
          const chunk = events.slice(offset, offset + APPEND_CHUNK_ROWS);
          const seq = nextSeq();
          sql.exec(
            INSERT_COLUMNS + chunk.map(() => VALUES_ROW).join(", "),
            ...chunk.flatMap((event, index) => [
              seq + index,
              randomHex(16),
              ...eventBindings(event),
            ]),
          );
          nextSeqCache = seq + chunk.length;
        }
      } catch (error) {
        nextSeqCache = null;
        throw error;
      }
    },
    resetSeqCacheSync: () => {
      nextSeqCache = null;
    },
    readRotationSync: makeRotationRead(sql),
    queryEventsSync: (query) => queryEvents(sql, query),
    ensureHeadCurrent: extendHeadHashes(
      sql,
      options?.maxHeadExtensionChunks ?? MAX_HEAD_EXTENSION_CHUNKS_PER_CALL,
    ),
    headColumnBehindSync: () => {
      const row = sql
        .exec(
          `SELECT 1 FROM audit_events
           WHERE seq > (SELECT COALESCE(MAX(seq), 0) FROM audit_head_hashes)
           LIMIT 1`,
        )
        .toArray()[0];
      return row !== undefined;
    },
    currentHeadHexSync: () => {
      const row = sql
        .exec("SELECT head_hash_hex FROM audit_head_hashes ORDER BY seq DESC LIMIT 1")
        .toArray()[0];
      return row === undefined ? "" : String(row["head_hash_hex"]);
    },
    headPositionSync: (headHashHex) => {
      const row = sql
        .exec("SELECT seq FROM audit_head_hashes WHERE head_hash_hex = ? LIMIT 1", headHashHex)
        .toArray()[0];
      return row === undefined ? null : Number(row["seq"]);
    },
    latestCheckpointMirrorSeqSync: () => {
      const row = sql
        .exec("SELECT MAX(seq) AS seq FROM audit_events WHERE event = 'chain.checkpointed'")
        .toArray()[0];
      return row === undefined || row["seq"] === null ? null : Number(row["seq"]);
    },
  };
};

// ---------------------------------------------------------------------------
// Lazy extension of the audit-head cumulative hash (AUDIT_SPEC §5.1 —
// the implementation-shape ruling is docs/notes/session-35.md). The
// canonical form is @maruhi/crypto (pinned by audit-head.json).
// ---------------------------------------------------------------------------

/** The rows read and written per chunk (2 columns × 50 rows = 100 bindings, inside the SQLite limit). */
const HEAD_CHUNK_ROWS = 50;

/**
 * ensureHeadCurrent's per-call chunk limit (session 38's ruling AF).
 * 200 chunks × 50 rows = 10,000 rows — taken equal to §12-8's maximum
 * audit rows per request (the appendManySync cap): the steady-state
 * backlog (extended on each read) is at most "the appends since the
 * previous read", and even the largest single burst clears in one call.
 * The limit can only be hit by a backlog larger than that (a large log
 * whose column has not been materialized yet), in which case it is
 * "more-remains" → AuditHeadNotReady
 * (503) → the client's bounded retries (progress is persisted per chunk
 * — each call advances up to 10,000 rows).
 */
export const MAX_HEAD_EXTENSION_CHUNKS_PER_CALL = 200;

/**
 * Extend audit_head_hashes toward audit_events's MAX(seq) (up to
 * maxChunks chunks per call — see the bounded contract in the service
 * declaration's doc).
 *
 * The persistence granularity is the task (as in the head of
 * chain-do.ts, a DO SQLite write commits atomically per task, and what
 * a failure rolls back is only the **current** task's writes). This
 * loop proceeds across tasks with an await (SHA-256) between chunks, so
 * a completed chunk's INSERT is already committed in a prior task, and
 * a mid-flight failure can lose at most the single INSERT of the
 * in-flight chunk (the one sql.exec issued after that chunk's hashes
 * all computed). At any failure or limit-hit point the column remains a
 * contiguous prefix from seq 1, and the next call resumes from the
 * persisted tail and converges — the first pass over a huge existing
 * log is split into bounded retries of "more-remains" (→
 * AuditHeadNotReady), each call always making progress. A seq gap is a
 * §5.1 invariant violation (append-only storage corruption), so it is a
 * defect.
 */
const extendHeadHashes = Effect.fn("audit-store.extendHeadHashes")(function* (
  sql: SqlStorage,
  maxChunks: number,
): Effect.fn.Return<AuditHeadExtensionOutcome> {
  const state = { hashedUpTo: 0, head: "" };
  const tail = sql
    .exec(`SELECT seq, head_hash_hex FROM audit_head_hashes ORDER BY seq DESC LIMIT 1`)
    .toArray()[0];
  if (tail !== undefined) {
    state.hashedUpTo = Number(tail["seq"]);
    state.head = String(tail["head_hash_hex"]);
  }
  for (let chunk = 0; chunk < maxChunks; chunk += 1) {
    if (yield* hashNextChunk(sql, state)) {
      return "current";
    }
  }
  // The chunk limit was reached. Settle whether rows remain with a
  // light existence check (so a call that finished exactly at the
  // limit does not return a spurious "more-remains")
  const remains = sql
    .exec(`SELECT 1 FROM audit_events WHERE seq > ? LIMIT 1`, state.hashedUpTo)
    .toArray()[0];
  return remains === undefined ? "current" : "more-remains";
});

/**
 * Hash the next chunk (up to HEAD_CHUNK_ROWS rows) and commit it in a
 * single INSERT. The return value = whether this chunk brought the
 * column to MAX(seq) (an empty chunk or a short chunk).
 */
const hashNextChunk = (
  sql: SqlStorage,
  state: { hashedUpTo: number; head: string },
): Effect.Effect<boolean> =>
  deriveChunk(sql, "audit_events", "audit_head_hashes", state, true).pipe(
    Effect.map((outcome) => outcome === "done"),
    // A structural invalidity on input derived from a stored row is an
    // implementation bug (the error value carries no secrets): the staged
    // and restored logs are refused before they are installed (ruling J
    // revision, rounds 9–11), so a live log never carries one
    Effect.catchTag("AuditHeadChunkInvalid", (error) =>
      Effect.die(new Error(`audit log cannot be hashed at seq ${error.seq}: ${error.reason}`)),
    ),
  );

/**
 * One row failed the canonical form — the row at `seq` is not the next
 * one, or the digest / head computation refused it. `reason` is a
 * debugging label only: a structural reason string that carries no row
 * content (the same discipline as CryptoError's kind-only values —
 * never a fragment of the log).
 */
class AuditHeadChunkInvalidError extends Data.TaggedError("AuditHeadChunkInvalid")<{
  readonly seq: number;
  readonly reason: string;
}> {}

/**
 * Hashes the next chunk (up to HEAD_CHUNK_ROWS rows) of `source` past
 * `state.hashedUpTo`, from `state.head`, and writes its heads into
 * `target` in one INSERT — the one loop body of the lazy extension (the
 * live log into the live column) and of the derivation over a staged or
 * restored log (ruling J revision, rounds 10 and 11): memory stays at one
 * chunk whatever the log's size. `persist` false hashes and checks the
 * chunk without writing it (a restore past the storage guard's line —
 * AUTH_SPEC §11-7).
 */
const deriveChunk = Effect.fnUntraced(function* (
  sql: SqlStorage,
  source: string,
  target: string,
  state: { hashedUpTo: number; head: string },
  persist: boolean,
): Effect.fn.Return<"done" | "more", AuditHeadChunkInvalidError> {
  const rows = sql
    .exec(
      `SELECT ${AUDIT_ROW_COLUMNS} FROM ${source} WHERE seq > ? ORDER BY seq LIMIT ?`,
      state.hashedUpTo,
      HEAD_CHUNK_ROWS,
    )
    .toArray()
    .map(toAuditHeadRow);
  if (rows.length === 0) {
    return "done";
  }
  const inserts: (string | number)[] = [];
  for (const row of rows) {
    if (row.seq !== state.hashedUpTo + 1) {
      return yield* new AuditHeadChunkInvalidError({
        seq: state.hashedUpTo + 1,
        reason: "seq gap",
      });
    }
    const digest = yield* cryptoEffect(() => computeAuditRowDigest(row)).pipe(
      Effect.mapError(
        (error) =>
          new AuditHeadChunkInvalidError({
            seq: row.seq,
            reason: `row digest: ${error["_tag"]}`,
          }),
      ),
    );
    const next = yield* cryptoEffect(() =>
      computeAuditHeadHash(SUITE_ID, state.head, row.seq, digest),
    ).pipe(
      Effect.mapError(
        (error) =>
          new AuditHeadChunkInvalidError({
            seq: row.seq,
            reason: `head hash: ${error["_tag"]}`,
          }),
      ),
    );
    state.head = next;
    state.hashedUpTo = row.seq;
    inserts.push(row.seq, state.head);
  }
  if (persist) {
    sql.exec(
      `INSERT INTO ${target} (seq, head_hash_hex) VALUES ${rows.map(() => "(?, ?)").join(", ")}`,
      ...inserts,
    );
  }
  // A short chunk = this chunk reached MAX(seq) (no extra SELECT needed)
  return rows.length < HEAD_CHUNK_ROWS ? "done" : "more";
});

/** Whether a stored head hash is one the chaining accepts (64 lowercase hex). */
export function isAuditHeadHex(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
}

/**
 * Derives the audit-head column over `source`'s rows past `fromSeq`, from
 * `prevHead` (the empty string before seq 1), into `target`, chunk by
 * chunk (one chunk of memory — round 11): the rows must be exactly
 * `fromSeq + 1 …` and every one must pass the canonical form. Returns the
 * head at the log's end; null = a gap, or a row the canonical form refuses
 * — what a replica or a snapshot must never install (ruling J revision,
 * round 10: such a log committed, and the extension afterwards threw the
 * append-only defect on every later read). The target's rows written
 * before a failure are the caller's to discard (a staging, or a restore
 * that is wiped). `stores` is asked before each chunk: once it says no,
 * the rest is hashed and checked but not written, so the target stays a
 * contiguous prefix.
 */
export async function deriveAuditHeads(
  sql: SqlStorage,
  source: string,
  target: string,
  fromSeq: number,
  prevHead: string,
  stores: () => boolean = () => true,
): Promise<string | null> {
  const state = { hashedUpTo: fromSeq, head: prevHead };
  let persist = true;
  for (;;) {
    persist = persist && stores();
    const outcome = await Effect.runPromise(
      deriveChunk(sql, source, target, state, persist).pipe(
        // A log that fails the canonical form is refused (null) — the
        // staging / restore paths treat it as untrusted input, not as a
        // defect (a storage fault inside the fiber still rejects the
        // promise, same as a throw did)
        Effect.catchTag("AuditHeadChunkInvalid", () => Effect.succeed("invalid" as const)),
        Effect.provide(ServerLoggerLive),
      ),
    );
    if (outcome !== "more") {
      return outcome === "done" ? state.head : null;
    }
  }
}

/**
 * The shape the audit canonical form requires of a row's numbers, as SQL
 * over a table with the live affinities (ruling J revision, round 11):
 * `seq` and `server_ts` safe non-negative integers (`seq` ≥ 1; round 12 —
 * a fractional `seq` passed the aggregates and died at the swap's rowid
 * instead), the nullable `client_ts`, `epoch`, `version` and `chain_seq`
 * the same when present. The one statement of the acceptance
 * the derivation applies row by row, so every row of a replica or a
 * snapshot is checked — including the rows under an uploaded head column,
 * which the derivation never touches — before anything is installed.
 */
export function auditRowShapeViolations(sql: SqlStorage, table: string): number {
  return Number(
    sql
      .exec(
        `SELECT COUNT(*) AS n FROM ${table} WHERE ${notCounting("seq")} OR seq < 1 OR ${notCounting("server_ts")} OR ${nullableNotCounting("client_ts")} OR ${nullableNotCounting("epoch")} OR ${nullableNotCounting("version")} OR ${nullableNotCounting("chain_seq")}`,
      )
      .one()["n"],
  );
}

/** SQL: the column is not a safe non-negative integer (the canonical form's `isCountingNumber`). */
function notCounting(column: string): string {
  return `(typeof(${column}) <> 'integer' OR ${column} < 0 OR ${column} > 9007199254740991)`;
}

function nullableNotCounting(column: string): string {
  return `(${column} IS NOT NULL AND ${notCounting(column)})`;
}

export const auditStoreLayer = (sql: SqlStorage): Layer.Layer<AuditStore> =>
  Layer.sync(AuditStore, () => makeAuditStore(sql));
