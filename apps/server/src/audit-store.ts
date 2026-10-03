// The audit log's append store (AUDIT_SPEC §5.1) and read surface (§7 —
// C1).
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
//   @maruhi/core's chainMirrorEvent (the same implementation the CLI's
//   mirror verification — `maruhi audit verify` — uses)

import type { AuditEventRecord } from "@maruhi/core";
import { auditReadVariablesOf, CHAIN_MIRROR_EVENT_PREFIX, VAR_READ_EVENT } from "@maruhi/core";
import type { AuditHeadRow } from "@maruhi/crypto";
import { computeAuditHeadHash, computeAuditRowDigest, SUITE_ID } from "@maruhi/crypto";
import { Context, Effect, Layer } from "effect";

import { randomHex } from "./ids.ts";

/**
 * The input of one audit-event row (columns per AUDIT_SPEC §5.1;
 * unspecified = NULL). An alias of the shared record type
 * (@maruhi/core — colocated with the chain-mirror mapping).
 */
export type AuditEventInput = AuditEventRecord;

// ---------------------------------------------------------------------------
// The read surface for rotation-needed detection (AUDIT_SPEC §4.1 /
// §4.2's Q1-Q6). Only appends and reads are exposed (§1-4) — the
// update/delete entry points stay uncreated. Everything synchronous:
// detection runs inside the write phase of a chain acceptance (a single
// task) and writes rotation.recommended in the same transaction as the
// mirror append (§4.1).
// ---------------------------------------------------------------------------

/**
 * The scope read out of a mirror payload (AUDIT_SPEC §3.4's scopeKind /
 * scopeEnvironmentIds — the input of §4.1 step 2's per-environment
 * access windows).
 */
export type ScopeSnapshot =
  | { readonly kind: "all" }
  | { readonly kind: "listed"; readonly environmentIds: readonly string[] };

/**
 * Q1: the membership-interval events of the target user_id
 * (chain.genesis / member_added / role_changed / member_removed —
 * role_changed was added at 2026-09-15 ES K3). scope / role come from
 * the mirror payload (genesis = owner / all; removed = null; a row
 * unreadable from the payload is null = the window derivation treats it
 * as `all`, fail-safe).
 */
export interface MembershipEventRow {
  readonly seq: number;
  readonly event: string;
  readonly role: string | null;
  readonly scope: ScopeSnapshot | null;
}

/**
 * The device axis of Q1 (2026-09-19 DK — the `revoke_device` variant of
 * AUDIT_SPEC §4.1): the target user_id's chain.device_added (one
 * deviceKeyFingerprint in the payload + the device scope) /
 * chain.device_revoked (the payload's deviceKeyFingerprints). scope
 * comes from the device_added payload (an unreadable row is null = the
 * window derivation treats it as `all`, fail-safe).
 */
export interface DeviceEventRow {
  readonly seq: number;
  readonly event: string;
  readonly fingerprintsHex: readonly string[];
  readonly scope: ScopeSnapshot | null;
}

/** Q6: the grant-interval events of a server key FP (chain.server_granted / revoked). */
export interface GrantEventRow {
  readonly seq: number;
  readonly event: string;
  /**
   * From a chain.server_granted payload. A revoked row is the empty
   * array. null = a broken row unreadable from the payload (the window
   * derivation treats it as every environment, fail-safe — design
   * record §9 K3-F).
   */
  readonly scopeEnvironmentIds: readonly string[] | null;
}

/** Q2: a variable's existence-interval events (var.created / var.deleted). */
export interface VariableLifecycleRow {
  readonly seq: number;
  readonly event: string;
  readonly environmentId: string;
  readonly variableId: string;
}

/** Q3: the target user_id's var.read (expansion of the aggregate form's payload — §3.3). */
export interface VariableReadRow {
  readonly seq: number;
  readonly environmentId: string;
  readonly variableId: string;
}

/**
 * The seq range of Q3 (both ends are **open** — `afterSeq < seq <
 * beforeSeq`). The caller (detectForMember of rotation-detect.ts)
 * supplies the envelope of the detection window so rows that would be
 * discarded outside the window are never read. A non-finite value
 * means "unbounded on that side".
 */
export interface SeqRange {
  readonly afterSeq: number;
  readonly beforeSeq: number;
}

/** Q6: a server key FP's disclosure exercises (server.lease_issued / value_decrypted [reserved]). */
export interface ServerAccessRow {
  readonly seq: number;
  readonly event: string;
  readonly environmentId: string;
  /** server.lease_issued is per-environment distribution, so null (§3.5). */
  readonly variableId: string | null;
}

/** One epoch transition of an environment, from the chain mirror (§4.1-5 — VH). */
export interface EnvironmentEpochRow {
  readonly seq: number;
  readonly environmentId: string;
  readonly epoch: number;
}

/** Q5: the input rows of flag derivation (rotation.recommended / dismissed / var.version_pushed). */
export interface RotationFlagSourceRow {
  readonly seq: number;
  readonly serverTs: number;
  readonly event: string;
  readonly environmentId: string;
  readonly variableId: string;
  /** The version column (var.version_pushed only — the lineage fold's key; NULL otherwise). */
  readonly version: number | null;
  /**
   * The epoch column: a var.version_pushed's epoch, or a rotation.recommended's
   * exposure bound (the environment's epoch at detection — VH). NULL otherwise.
   */
  readonly epoch: number | null;
  readonly targetUserId: string | null;
  readonly targetKeyFingerprintHex: string | null;
  readonly payload: Readonly<Record<string, unknown>> | null;
}

/** The synchronous read surface used by detection and flag derivation (indexes in §4.2 / do-schema.ts). */
export interface AuditRotationRead {
  readonly membershipEventsFor: (targetUserId: string) => readonly MembershipEventRow[];
  readonly deviceEventsFor: (targetUserId: string) => readonly DeviceEventRow[];
  readonly serverGrantEventsFor: (fpHex: string) => readonly GrantEventRow[];
  readonly variableLifecycles: () => readonly VariableLifecycleRow[];
  readonly variableReadsBy: (actorUserId: string, range?: SeqRange) => readonly VariableReadRow[];
  readonly serverAccessEventsBy: (actorFpHex: string) => readonly ServerAccessRow[];
  /**
   * Every environment's epoch transitions from the chain mirror
   * (`chain.environment_created` = epoch 1, `chain.epoch_rotated` = the new
   * epoch — ae_event), ascending by seq: the input of each flag's exposure
   * bound (the epoch at the end of the subject's window — §4.1-5, VH).
   */
  readonly environmentEpochEvents: () => readonly EnvironmentEpochRow[];
  readonly rotationFlagEvents: () => readonly RotationFlagSourceRow[];
  /** The same rows narrowed to one (variable × environment) pair (the history's flagsIfCurrent — ae_var). */
  readonly rotationFlagEventsFor: (
    environmentId: string,
    variableId: string,
  ) => readonly RotationFlagSourceRow[];
}

// ---------------------------------------------------------------------------
// The generic read surface (AUDIT_SPEC §7 — C1). seq-cursor paging +
// filters. Visibility classes (§6) are enforced by the SQL WHERE: a
// class-2 row appears nowhere in a sub-admin's results, counts, or
// paging ("behaves as if it did not exist").
// ---------------------------------------------------------------------------

/**
 * The **non-chain** event names of class 1 (chain role reader or above =
 * every member) (§6). The `chain.` namespace and the provenance claim
 * `chain_seq IS NOT NULL` are covered by SQL predicates rather than a
 * name enumeration ({@link visibilityCondition}) — §6 classifies the
 * **whole** namespace and the verification material of chain provenance
 * as class 1, and permitting only the mapped names would break in two
 * directions:
 *
 * 1. If a future op addition is missed by the enumeration, that mirror
 *    row becomes invisible to sub-admins and `maruhi audit verify`,
 *    which every member should be able to run, falsely convicts a
 *    healthy server of "missing = deletion concealed"
 * 2. A forged row claiming a `chain.*` name that is **not** in the
 *    mapping is dropped on the server side and not a single row reaches
 *    a sub-admin's verify — a coverage hole in the forgery direction
 *    would remain for non-admins
 * 3. If a forged row claiming `chain_seq` outside `chain.*` fell into
 *    class 2, verify could not inspect a provenance claim one step
 *    outside the namespace. Since no honest writer produces that shape,
 *    promoting the presence of chain_seq to class 1 discloses no
 *    legitimate class-2 row and only delivers tamper evidence to every
 *    member
 *
 * **Outside chain.* it is an explicit allowlist with default-deny**: an
 * event absent here (var.read / dek.registered / dek.deleted, and any
 * non-chain event added in the future) is treated as class 2 and
 * invisible to sub-admins — new events fall to the safe side.
 */
const CLASS1_EVENTS: readonly string[] = [
  "env.created",
  "env.renamed",
  "env.deleted",
  "var.created",
  "var.renamed",
  "var.schema_reissued",
  "var.deleted",
  "var.version_pushed",
  "server.dek_unwrapped",
  "server.lease_issued",
  "server.lease_denied",
  "server.value_decrypted",
  "rotation.recommended",
  "rotation.dismissed",
  // Sealed value proposals (AUDIT_SPEC §3.3 — PF7b): members must see what
  // was proposed to them and how it was resolved
  "rotation.proposed",
  "rotation.proposal_accepted",
  "rotation.proposal_rejected",
  "rotation.proposal_expired",
  // Class 1 because the setting itself is advisory-distributed to every
  // member in pull responses (AUDIT_SPEC §3.3 — AUTH_SPEC §12-11)
  "project.schema_policy_changed",
];

/**
 * Whether an event is class 1 (§6): the whole `chain.` namespace +
 * {@link CLASS1_EVENTS}. The same judgment as the SQL-side visibility
 * predicate ({@link visibilityCondition}); changing only one makes the
 * response and the tests' claims disagree.
 */
export function isClass1Event(event: string): boolean {
  return event.startsWith(CHAIN_MIRROR_EVENT_PREFIX) || CLASS1_EVENTS.includes(event);
}

/**
 * The visibility specification (§6). admin = every row (the caller has
 * already confirmed "chain role admin-or-above × token scope admin"),
 * class1-or-self = class-1 rows + the rows where the caller is the
 * actor (self is readable regardless of class).
 */
type AuditVisibility =
  | { readonly kind: "admin" }
  | { readonly kind: "class1-or-self"; readonly selfUserId: string };

/** The generic-read query (only the §7 filter vocabulary; null = no filter). */
interface AuditEventsQuery {
  /**
   * The paging cursor = the row_id of the last row of the previous page
   * (§7 — opaque). Resolution happens under the viewer's visibility
   * predicate; an invisible or unknown id behaves as an empty page
   * (does not become an existence oracle).
   */
  readonly beforeRowId: string | null;
  readonly limit: number;
  readonly event: string | null;
  /** A prefix match on the event namespace (§7). A substr comparison, not LIKE. */
  readonly eventPrefix: string | null;
  /** Return only rows whose chain_seq is not NULL (§7). */
  readonly chainSeqPresent: boolean;
  readonly actorUserId: string | null;
  readonly targetUserId: string | null;
  readonly variableId: string | null;
  readonly environmentId: string | null;
  readonly visibility: AuditVisibility;
}

/**
 * The read shape of a stored row (all §5.1 columns; NULL is null). The
 * column set is identical to the audit-head computation's input shape
 * (AuditHeadRow — the fixed 17 columns of §5.1); only the non-NULL
 * constraint on row_id and the defensive parse of payload (an object,
 * not the raw TEXT) differ.
 */
export interface StoredAuditEventRow extends Omit<AuditHeadRow, "rowId" | "payloadText"> {
  /** The wire row identifier (§5.1 row_id — 16 bytes random hex). */
  readonly rowId: string;
  readonly payload: Readonly<Record<string, unknown>> | null;
}

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
   * The first call recomputing from all existing rows doubles as the
   * §5.1 introduction migration. Since no reader observes anything but
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
    event.payload === undefined ? null : JSON.stringify(event.payload),
  ];
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
/** The options of makeAuditStore (so a test can pin a smaller bounded-extension limit). */
export interface AuditStoreOptions {
  /** ensureHeadCurrent's per-call chunk limit (defaults to the production value). */
  readonly maxHeadExtensionChunks?: number;
}

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
      assertChainSeqInvariant(event);
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
        assertChainSeqInvariant(event);
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
 * The limit can only be hit by the first materialization of a huge
 * existing log, in which case it is "more-remains" → AuditHeadNotReady
 * (503) → the client's bounded retries (progress is persisted per chunk
 * — each call advances up to 10,000 rows).
 */
export const MAX_HEAD_EXTENSION_CHUNKS_PER_CALL = 200;

/** The columns read by the extension (the fixed 17 columns of row_digest — the column order of AUDIT_SPEC §5.1). */
const HEAD_ROW_COLUMNS = `seq, row_id, server_ts, client_ts, event, actor_type, actor_user_id,
  actor_key_fingerprint, actor_api_token_id, target_user_id, target_key_fingerprint,
  environment_id, variable_id, epoch, version, chain_seq, payload`;

function toAuditHeadRow(row: Record<string, unknown>): AuditHeadRow {
  return {
    seq: Number(row["seq"]),
    rowId: textOrNull(row["row_id"]),
    serverTs: Number(row["server_ts"]),
    clientTs: numberOrNull(row["client_ts"]),
    event: String(row["event"]),
    actorType: String(row["actor_type"]),
    actorUserId: textOrNull(row["actor_user_id"]),
    actorKeyFingerprintHex: textOrNull(row["actor_key_fingerprint"]),
    actorApiTokenId: textOrNull(row["actor_api_token_id"]),
    targetUserId: textOrNull(row["target_user_id"]),
    targetKeyFingerprintHex: textOrNull(row["target_key_fingerprint"]),
    environmentId: textOrNull(row["environment_id"]),
    variableId: textOrNull(row["variable_id"]),
    epoch: numberOrNull(row["epoch"]),
    version: numberOrNull(row["version"]),
    chainSeq: numberOrNull(row["chain_seq"]),
    // payload is the stored TEXT bytes verbatim (no JSON normalization — §5.1)
    payloadText: textOrNull(row["payload"]),
  };
}

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
const extendHeadHashes = (
  sql: SqlStorage,
  maxChunks: number,
): Effect.Effect<AuditHeadExtensionOutcome> =>
  Effect.promise(async () => {
    const state = { hashedUpTo: 0, head: "" };
    const tail = sql
      .exec(`SELECT seq, head_hash_hex FROM audit_head_hashes ORDER BY seq DESC LIMIT 1`)
      .toArray()[0];
    if (tail !== undefined) {
      state.hashedUpTo = Number(tail["seq"]);
      state.head = String(tail["head_hash_hex"]);
    }
    for (let chunk = 0; chunk < maxChunks; chunk += 1) {
      if (await hashNextChunk(sql, state)) {
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
async function hashNextChunk(
  sql: SqlStorage,
  state: { hashedUpTo: number; head: string },
): Promise<boolean> {
  const outcome = await deriveChunk(sql, "audit_events", "audit_head_hashes", state);
  if (outcome.kind === "invalid") {
    // A structural invalidity on input derived from a stored row is an
    // implementation bug (the error value carries no secrets): the staged
    // and restored logs are refused before they are installed (ruling J
    // revision, rounds 9–11), so a live log never carries one
    throw new Error(`audit log cannot be hashed at seq ${outcome.seq}: ${outcome.reason}`);
  }
  return outcome.kind === "done";
}

type DeriveChunkOutcome =
  /** The chunk reached the source's end (empty or short). */
  | { readonly kind: "done" }
  /** A full chunk was written; more may remain. */
  | { readonly kind: "more" }
  /** The row at `seq` is not the next one, or the canonical form refuses it. */
  | { readonly kind: "invalid"; readonly seq: number; readonly reason: string };

/**
 * Hashes the next chunk (up to HEAD_CHUNK_ROWS rows) of `source` past
 * `state.hashedUpTo`, from `state.head`, and writes its heads into
 * `target` in one INSERT — the one loop body of the lazy extension (the
 * live log into the live column) and of the derivation over a staged or
 * restored log (ruling J revision, rounds 10 and 11): memory stays at one
 * chunk whatever the log's size.
 */
async function deriveChunk(
  sql: SqlStorage,
  source: string,
  target: string,
  state: { hashedUpTo: number; head: string },
): Promise<DeriveChunkOutcome> {
  const rows = sql
    .exec(
      `SELECT ${HEAD_ROW_COLUMNS} FROM ${source} WHERE seq > ? ORDER BY seq LIMIT ?`,
      state.hashedUpTo,
      HEAD_CHUNK_ROWS,
    )
    .toArray()
    .map(toAuditHeadRow);
  if (rows.length === 0) {
    return { kind: "done" };
  }
  const inserts: (string | number)[] = [];
  for (const row of rows) {
    if (row.seq !== state.hashedUpTo + 1) {
      return { kind: "invalid", seq: state.hashedUpTo + 1, reason: "seq gap" };
    }
    const digest = await computeAuditRowDigest(row);
    if (!digest.ok) {
      return { kind: "invalid", seq: row.seq, reason: `row digest: ${digest.error.kind}` };
    }
    const next = await computeAuditHeadHash(SUITE_ID, state.head, row.seq, digest.value);
    if (!next.ok) {
      return { kind: "invalid", seq: row.seq, reason: `head hash: ${next.error.kind}` };
    }
    state.head = next.value;
    state.hashedUpTo = row.seq;
    inserts.push(row.seq, state.head);
  }
  sql.exec(
    `INSERT INTO ${target} (seq, head_hash_hex) VALUES ${rows.map(() => "(?, ?)").join(", ")}`,
    ...inserts,
  );
  // A short chunk = this chunk reached MAX(seq) (no extra SELECT needed)
  return rows.length < HEAD_CHUNK_ROWS ? { kind: "done" } : { kind: "more" };
}

/** Whether a stored head hash is one the chaining accepts (64 lowercase hex). */
export function isAuditHeadHex(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
}

/**
 * Derives the audit-head column over `source`'s rows past `fromSeq`, from
 * `prevHead` (the empty string before seq 1), into `target`, chunk by
 * chunk (one chunk of memory — round 11): the rows must be exactly
 * `fromSeq + 1 …` and every one must pass the canonical form. false = a
 * gap, or a row the canonical form refuses — what a replica or a snapshot
 * must never install (ruling J revision, round 10: such a log committed,
 * and the extension afterwards threw the append-only defect on every
 * later read). The target's rows written before a failure are the
 * caller's to discard (a staging, or a restore that is wiped).
 */
export async function deriveAuditHeads(
  sql: SqlStorage,
  source: string,
  target: string,
  fromSeq: number,
  prevHead: string,
): Promise<boolean> {
  const state = { hashedUpTo: fromSeq, head: prevHead };
  for (;;) {
    const outcome = await deriveChunk(sql, source, target, state);
    if (outcome.kind !== "more") {
      return outcome.kind === "done";
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

/** The SELECT columns of queryEventsSync (same order as StoredAuditEventRow). */
const EVENT_ROW_COLUMNS = `seq, row_id, server_ts, client_ts, event, actor_type, actor_user_id,
  actor_key_fingerprint, actor_api_token_id, target_user_id, target_key_fingerprint,
  environment_id, variable_id, epoch, version, chain_seq, payload`;

/** The WHERE condition of the visibility class (§6) (shared by this query and cursor resolution). */
function visibilityCondition(
  visibility: AuditVisibility,
): { readonly clause: string; readonly bindings: readonly (string | number)[] } | null {
  if (visibility.kind === "admin") {
    return null;
  }
  // §6 / §7: a class-2 row behaves as if it did not exist for a
  // sub-admin. A row where the viewer is the actor is readable by them
  // regardless of class.
  // chain.* is covered by a prefix match, not a name enumeration (the
  // same judgment as isClass1Event — see the doc of CLASS1_EVENTS for
  // the reasons). Additionally, a row carrying chain_seq becomes class 1
  // regardless of the event name, as a provenance claim = tamper
  // evidence every member must verify. The prefix comparison uses substr
  // rather than LIKE, so no wildcard semantics apply
  return {
    clause: `(event IN (${CLASS1_EVENTS.map(() => "?").join(", ")}) OR substr(event, 1, ?) = ? OR chain_seq IS NOT NULL OR actor_user_id = ?)`,
    bindings: [
      ...CLASS1_EVENTS,
      CHAIN_MIRROR_EVENT_PREFIX.length,
      CHAIN_MIRROR_EVENT_PREFIX,
      visibility.selfUserId,
    ],
  };
}

/**
 * Cursor (row_id) → internal seq resolution. Resolved **under the
 * viewer's visibility predicate**: an invisible row's id used as a
 * cursor behaves identically to an unknown id (null), so cursor probing
 * is not an existence oracle (§7; the id is a 128-bit random and
 * unguessable anyway).
 */
function resolveCursorSeq(
  sql: SqlStorage,
  rowId: string,
  visibility: AuditVisibility,
): number | null {
  const condition = visibilityCondition(visibility);
  const where = condition === null ? "" : ` AND ${condition.clause}`;
  const row = sql
    .exec(
      `SELECT seq FROM audit_events WHERE row_id = ?${where}`,
      rowId,
      ...(condition?.bindings ?? []),
    )
    .toArray()[0];
  return row === undefined ? null : Number(row["seq"]);
}

/** A fragment of the WHERE clause (conditions + bindings). */
interface SqlConditions {
  readonly conditions: readonly string[];
  readonly bindings: readonly (string | number)[];
}

function withCondition(
  base: SqlConditions,
  clause: string,
  bindings: readonly (string | number)[],
): SqlConditions {
  return {
    conditions: [...base.conditions, clause],
    bindings: [...base.bindings, ...bindings],
  };
}

/** One page of seq-descending + LIMIT. */
function selectPage(
  sql: SqlStorage,
  where: SqlConditions,
  limit: number,
): readonly StoredAuditEventRow[] {
  const clause = where.conditions.length === 0 ? "" : ` WHERE ${where.conditions.join(" AND ")}`;
  return sql
    .exec(
      `SELECT ${EVENT_ROW_COLUMNS} FROM audit_events${clause} ORDER BY seq DESC LIMIT ?`,
      ...where.bindings,
      limit,
    )
    .toArray()
    .map(toStoredRow);
}

/**
 * The condition selecting, among the aggregate-form `var.read` rows
 * (AUDIT_SPEC §3.3 — variable_id IS NULL, a `variables` enumeration in
 * the payload), the rows containing the given variable (the §7
 * variable_id filter / §4.2 Q4). Since the variable ID is not a column
 * the payload is inspected, but the inspection set is narrowed to **the
 * value's existence interval (the seq range from the first
 * var.version_pushed to the last var.deleted)**: a value-bearing pull
 * returns every active variable of the environment, so the aggregate
 * rows inside the interval almost all contain the variable and stop at
 * the page limit. Rows outside the interval (pulls before the value's
 * first appearance or after deletion) are never inspected — a deleted
 * variable's filter never creates a form that JSON-scans the
 * environment's whole pull history. The lower bound is the value's
 * first appearance, not var.created, because a declared variable that
 * never held a value never appears in a pull (in that case null = the
 * aggregate-side query is skipped). **The interval is taken per
 * environment and bounds by their union**: variable IDs are
 * client-issued and the server's uniqueness is per (environment,
 * variable), so the same ID can exist in several environments (with the
 * shape "deleted in A, alive in B", a per-variable MAX(deleted) upper
 * bound would drop B's aggregate rows). An `environmentId` filter uses
 * only that environment's interval. Below admin (class1-or-self), only
 * the viewer's own rows among the aggregate rows are visible (§6 —
 * var.read is class 2), so `actor_user_id = self` is stated explicitly
 * and the inspected set is bound to the viewer's rows via ae_actor
 * (independent of the visibility predicate's evaluation order, so
 * another person's pull history is never scanned). json_valid precedes
 * EXISTS (a stored row is server-written JSON, but a broken row must
 * not crash the read API).
 */
function aggregatedReadContains(
  sql: SqlStorage,
  variableId: string,
  environmentId: string | null,
  visibility: AuditVisibility,
): SqlConditions | null {
  // Per-environment (first-value seq, last-deleted seq). Grouped per
  // environment in the index order of ae_var (variable_id,
  // environment_id, seq)
  const windows = sql
    .exec(
      `SELECT
         MIN(CASE WHEN event = 'var.version_pushed' THEN seq END) AS first_value_seq,
         MAX(CASE WHEN event = 'var.deleted' THEN seq END) AS deleted_seq
       FROM audit_events
       WHERE variable_id = ?${environmentId === null ? "" : " AND environment_id = ?"}
         AND event IN ('var.version_pushed', 'var.deleted')
       GROUP BY environment_id`,
      variableId,
      ...(environmentId === null ? [] : [environmentId]),
    )
    .toArray()
    .map((row) => ({
      firstValueSeq: numberOrNull(row["first_value_seq"] ?? null),
      deletedSeq: numberOrNull(row["deleted_seq"] ?? null),
    }))
    .filter(
      (window): window is { firstValueSeq: number; deletedSeq: number | null } =>
        window.firstValueSeq !== null,
    );
  if (windows.length === 0) {
    return null;
  }
  // The union's envelope: the lower bound is the earliest first
  // appearance; the upper bound is the last deletion, only when deleted
  // in every environment
  const firstValueSeq = Math.min(...windows.map((window) => window.firstValueSeq));
  const deletedSeq = windows.every((window) => window.deletedSeq !== null)
    ? Math.max(...windows.map((window) => window.deletedSeq as number))
    : null;
  const self = visibility.kind === "class1-or-self" ? [visibility.selfUserId] : [];
  return {
    conditions: [
      ...self.map(() => "actor_user_id = ?"),
      "variable_id IS NULL",
      "event = ?",
      "seq > ?",
      ...(deletedSeq === null ? [] : ["seq < ?"]),
      "json_valid(payload)",
      "EXISTS (SELECT 1 FROM json_each(audit_events.payload, '$.variables') WHERE json_extract(json_each.value, '$.variableId') = ?)",
    ],
    bindings: [
      ...self,
      VAR_READ_EVENT,
      firstValueSeq,
      ...(deletedSeq === null ? [] : [deletedSeq]),
      variableId,
    ],
  };
}

/** Merge two seq-descending lists staying seq-descending, and return the first `limit` rows. */
function mergeDescending(
  left: readonly StoredAuditEventRow[],
  right: readonly StoredAuditEventRow[],
  limit: number,
): readonly StoredAuditEventRow[] {
  const merged: StoredAuditEventRow[] = [];
  let i = 0;
  let j = 0;
  while (merged.length < limit && (i < left.length || j < right.length)) {
    const a = left[i];
    const b = right[j];
    if (b === undefined || (a !== undefined && a.seq > b.seq)) {
      merged.push(a as StoredAuditEventRow);
      i += 1;
    } else {
      merged.push(b);
      j += 1;
    }
  }
  return merged;
}

function queryEvents(sql: SqlStorage, query: AuditEventsQuery): readonly StoredAuditEventRow[] {
  let where: SqlConditions = { conditions: [], bindings: [] };
  const filter = (clause: string, value: string | number | null): void => {
    if (value !== null) {
      where = withCondition(where, clause, [value]);
    }
  };
  if (query.beforeRowId !== null) {
    const beforeSeq = resolveCursorSeq(sql, query.beforeRowId, query.visibility);
    if (beforeSeq === null) {
      // An unknown or invisible cursor is an empty page (same shape as
      // the end of paging — §7)
      return [];
    }
    filter("seq < ?", beforeSeq);
  }
  filter("event = ?", query.event);
  if (query.eventPrefix !== null) {
    // A prefix match never uses LIKE: under LIKE the input's % / _
    // would act as wildcards and the filter would stop being a namespace
    // specification. A substr comparison costs only the two bindings
    // (length and value) and has no special characters
    where = withCondition(where, "substr(event, 1, ?) = ?", [
      query.eventPrefix.length,
      query.eventPrefix,
    ]);
  }
  if (query.chainSeqPresent) {
    where = withCondition(where, "chain_seq IS NOT NULL", []);
  }
  filter("actor_user_id = ?", query.actorUserId);
  filter("target_user_id = ?", query.targetUserId);
  filter("environment_id = ?", query.environmentId);
  const visibility = visibilityCondition(query.visibility);
  if (visibility !== null) {
    where = withCondition(where, visibility.clause, visibility.bindings);
  }
  if (query.variableId === null) {
    return selectPage(sql, where, query.limit);
  }
  // The variable_id filter (§7 / Q4): the column match (var.created /
  // var.version_pushed etc. — stops at `limit` rows in ae_var's index
  // order) and the aggregate-form var.read (payload inspection —
  // aggregatedReadContains) run as separate queries and merge in
  // seq-descending order. Fused into one OR, SQLite would gather all
  // matching rows of both sides before sorting, degrading the column
  // match's paging from "index order + early stop" to "proportional to
  // the match count". The cursor, visibility, and the other filters
  // apply identically to both queries
  const byColumn = selectPage(
    sql,
    withCondition(where, "variable_id = ?", [query.variableId]),
    query.limit,
  );
  const aggregated = aggregatedReadContains(
    sql,
    query.variableId,
    query.environmentId,
    query.visibility,
  );
  if (aggregated === null) {
    // A variable that never held a value never appears in aggregate
    // rows — do not run the payload inspection
    return byColumn;
  }
  const listed = selectPage(
    sql,
    withCondition(where, aggregated.conditions.join(" AND "), aggregated.bindings),
    query.limit,
  );
  return mergeDescending(byColumn, listed, query.limit);
}

const textOrNull = (value: unknown): string | null => (value === null ? null : String(value));
const numberOrNull = (value: unknown): number | null => (value === null ? null : Number(value));

function toStoredRow(row: Record<string, unknown>): StoredAuditEventRow {
  // The column mapping is shared with the audit-head computation's
  // input shape (identical column set — the 17 columns of §5.1). Only
  // the non-NULL coercion of row_id and the defensive parse of payload
  // are this read shape's difference
  const { payloadText: _payloadText, ...shared } = toAuditHeadRow(row);
  return {
    ...shared,
    rowId: String(row["row_id"]),
    payload: parsePayload(row["payload"]),
  };
}

/** Defensive parse of the payload column (JSON) (a broken row is treated as null — detection is never made a defect). */
function parsePayload(value: unknown): Readonly<Record<string, unknown>> | null {
  if (typeof value !== "string") {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(value);
    return typeof parsed === "object" && parsed !== null
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/**
 * Read the payload's scopeEnvironmentIds. A broken row — not an array,
 * or containing non-string elements — is null (a silently narrowed
 * enumeration would create a missed window — design record §9 K3-F).
 */
function scopeOf(payload: Readonly<Record<string, unknown>> | null): readonly string[] | null {
  const scope = payload?.["scopeEnvironmentIds"];
  return Array.isArray(scope) && scope.every((id) => typeof id === "string")
    ? (scope as readonly string[])
    : null;
}

/**
 * Read the scope of a mirror payload. A broken row with kind listed but
 * a non-array id list falls to null (= the window derivation treats it
 * as all, fail-safe), never listed{} (zero windows = a miss) (design
 * record §9 K3-F).
 */
function scopeSnapshotOf(payload: Readonly<Record<string, unknown>> | null): ScopeSnapshot | null {
  const kind = payload?.["scopeKind"];
  if (kind === "all") {
    return { kind: "all" };
  }
  const ids = kind === "listed" ? scopeOf(payload) : null;
  return ids === null ? null : { kind: "listed", environmentIds: ids };
}

/**
 * Read one Q1 row with (role, scope) attached (the payloads of
 * member_added / role_changed in AUDIT_SPEC §3.4). genesis is
 * structurally owner / all (CRYPTO_SPEC §6.2); removed is null on both.
 * A row whose scopeKind is unreadable gets scope = null (detection is
 * never made a defect on a broken row — the window derivation treats it
 * as all).
 */
function membershipRowOf(row: Record<string, SqlStorageValue>): MembershipEventRow {
  const seq = Number(row["seq"]);
  const event = String(row["event"]);
  if (event === "chain.genesis") {
    return { seq, event, role: "owner", scope: { kind: "all" } };
  }
  if (event === "chain.member_removed") {
    return { seq, event, role: null, scope: null };
  }
  const payload = parsePayload(row["payload"]);
  const role = payload?.[event === "chain.role_changed" ? "newRole" : "role"];
  return {
    seq,
    event,
    role: typeof role === "string" ? role : null,
    scope: scopeSnapshotOf(payload),
  };
}

const makeRotationRead = (sql: SqlStorage): AuditRotationRead => ({
  // Q1: the (target_user_id, seq) index (ae_target). The scope in a
  // role_changed payload is the open/close point of the per-environment
  // access window (§4.1 step 2 — 2026-09-15 ES K3)
  membershipEventsFor: (targetUserId) =>
    sql
      .exec(
        `SELECT seq, event, payload FROM audit_events
         WHERE target_user_id = ?
           AND event IN ('chain.genesis', 'chain.member_added', 'chain.role_changed', 'chain.member_removed')
         ORDER BY seq`,
        targetUserId,
      )
      .toArray()
      .map(membershipRowOf),
  // The device axis of Q1 (the same ae_target index — device_added /
  // device_revoked of AUDIT_SPEC §3.4 carry target_user_id = the
  // subject). FPs are read from the payload (the §4.1 revoke_device
  // variant)
  deviceEventsFor: (targetUserId) =>
    sql
      .exec(
        `SELECT seq, event, payload FROM audit_events
         WHERE target_user_id = ?
           AND event IN ('chain.device_added', 'chain.device_revoked')
         ORDER BY seq`,
        targetUserId,
      )
      .toArray()
      .map((row): DeviceEventRow => {
        const event = String(row["event"]);
        const payload = parsePayload(row["payload"]);
        if (event === "chain.device_revoked") {
          const fps = payload?.["deviceKeyFingerprints"];
          return {
            seq: Number(row["seq"]),
            event,
            fingerprintsHex:
              Array.isArray(fps) && fps.every((fp) => typeof fp === "string")
                ? (fps as readonly string[])
                : [],
            scope: null,
          };
        }
        const fp = payload?.["deviceKeyFingerprint"];
        return {
          seq: Number(row["seq"]),
          event,
          fingerprintsHex: typeof fp === "string" ? [fp] : [],
          scope: scopeSnapshotOf(payload),
        };
      }),
  // Q6: the (target_key_fingerprint, seq) index (ae_target_fp)
  serverGrantEventsFor: (fpHex) =>
    sql
      .exec(
        `SELECT seq, event, payload FROM audit_events
         WHERE target_key_fingerprint = ?
           AND event IN ('chain.server_granted', 'chain.server_revoked')
         ORDER BY seq`,
        fpHex,
      )
      .toArray()
      .map((row) => ({
        seq: Number(row["seq"]),
        event: String(row["event"]),
        scopeEnvironmentIds:
          String(row["event"]) === "chain.server_revoked"
            ? []
            : scopeOf(parsePayload(row["payload"])),
      })),
  // Q2: the (event, seq) index (ae_event)
  variableLifecycles: () =>
    sql
      .exec(
        `SELECT seq, event, environment_id, variable_id FROM audit_events
         WHERE event IN ('var.created', 'var.deleted') ORDER BY seq`,
      )
      .toArray()
      .map((row) => ({
        seq: Number(row["seq"]),
        event: String(row["event"]),
        environmentId: String(row["environment_id"]),
        variableId: String(row["variable_id"]),
      })),
  // Q3: the (actor_user_id, seq) index (ae_actor). Expands the
  // aggregate-form var.read (the payload's variables enumeration — §3.3)
  // (the expansion is a defensive parse — a broken row never makes
  // detection a defect). The variables of one pull share the same seq
  // (§4.1 step 3's interval judgment is per seq). range becomes a range
  // scan over ae_actor's seq component (omitted = every seq).
  // `+event` is the unary + that disqualifies the event column from
  // index candidacy (a standard SQLite idiom): the DO SQLite planner has
  // no statistics and would pick ae_event (event, seq) for the `event =
  // ?` equality, scanning the whole project's var.read (the dominant
  // row kind). The predicate's meaning is unchanged and ae_actor,
  // narrowed by actor, is chosen instead (test/audit-index.test.ts pins
  // it via EXPLAIN)
  variableReadsBy: (actorUserId, range) =>
    sql
      .exec(
        `SELECT seq, environment_id, payload FROM audit_events
         WHERE actor_user_id = ? AND +event = ? AND seq > ? AND seq < ? ORDER BY seq`,
        actorUserId,
        VAR_READ_EVENT,
        range !== undefined && Number.isFinite(range.afterSeq)
          ? range.afterSeq
          : Number.MIN_SAFE_INTEGER,
        range !== undefined && Number.isFinite(range.beforeSeq)
          ? range.beforeSeq
          : Number.MAX_SAFE_INTEGER,
      )
      .toArray()
      .flatMap((row): VariableReadRow[] => {
        const seq = Number(row["seq"]);
        const environmentId = String(row["environment_id"]);
        return (auditReadVariablesOf(parsePayload(row["payload"])) ?? []).map((variable) => ({
          seq,
          environmentId,
          variableId: variable.variableId,
        }));
      }),
  // The (a) input of Q6: the (actor_key_fingerprint, seq) index (ae_actor_fp)
  serverAccessEventsBy: (actorFpHex) =>
    sql
      .exec(
        `SELECT seq, event, environment_id, variable_id FROM audit_events
         WHERE actor_key_fingerprint = ?
           AND event IN ('server.lease_issued', 'server.value_decrypted')
         ORDER BY seq`,
        actorFpHex,
      )
      .toArray()
      .map((row) => ({
        seq: Number(row["seq"]),
        event: String(row["event"]),
        environmentId: String(row["environment_id"]),
        variableId: row["variable_id"] === null ? null : String(row["variable_id"]),
      })),
  // Q5: the (event, seq) index (ae_event)
  environmentEpochEvents: () =>
    sql
      .exec(
        `SELECT seq, environment_id, epoch FROM audit_events
         WHERE event IN ('chain.environment_created', 'chain.epoch_rotated')
           AND environment_id IS NOT NULL AND epoch IS NOT NULL
         ORDER BY seq`,
      )
      .toArray()
      .map((row) => ({
        seq: Number(row["seq"]),
        environmentId: String(row["environment_id"]),
        epoch: Number(row["epoch"]),
      })),
  rotationFlagEvents: () =>
    sql
      .exec(
        `SELECT seq, server_ts, event, environment_id, variable_id, version, epoch,
                target_user_id, target_key_fingerprint, payload
         FROM audit_events
         WHERE event IN ('rotation.recommended', 'rotation.dismissed', 'var.version_pushed')
         ORDER BY seq`,
      )
      .toArray()
      .map(rotationFlagSourceRow),
  rotationFlagEventsFor: (environmentId: string, variableId: string) =>
    sql
      .exec(
        `SELECT seq, server_ts, event, environment_id, variable_id, version, epoch,
                target_user_id, target_key_fingerprint, payload
         FROM audit_events
         WHERE variable_id = ? AND environment_id = ?
           AND event IN ('rotation.recommended', 'rotation.dismissed', 'var.version_pushed')
         ORDER BY seq`,
        variableId,
        environmentId,
      )
      .toArray()
      .map(rotationFlagSourceRow),
});

function rotationFlagSourceRow(row: Record<string, SqlStorageValue>): RotationFlagSourceRow {
  return {
    seq: Number(row["seq"]),
    serverTs: Number(row["server_ts"]),
    event: String(row["event"]),
    environmentId: String(row["environment_id"]),
    variableId: String(row["variable_id"]),
    version: row["version"] === null ? null : Number(row["version"]),
    epoch: row["epoch"] === null ? null : Number(row["epoch"]),
    targetUserId: row["target_user_id"] === null ? null : String(row["target_user_id"]),
    targetKeyFingerprintHex:
      row["target_key_fingerprint"] === null ? null : String(row["target_key_fingerprint"]),
    payload: parsePayload(row["payload"]),
  };
}

export const auditStoreLayer = (sql: SqlStorage): Layer.Layer<AuditStore> =>
  Layer.sync(AuditStore, () => makeAuditStore(sql));
