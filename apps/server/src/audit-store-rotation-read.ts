// The audit log's read surface for rotation-needed detection (AUDIT_SPEC
// §4.1 / §4.2's Q1-Q6), served by AuditStore's readRotationSync
// (audit-store.ts). Read-only (§1-4: AuditStore creates no update/delete
// entry point). Everything synchronous: detection runs inside the write
// phase of a chain acceptance (a single task) and writes
// rotation.recommended in the same transaction as the mirror append
// (§4.1).

import type { EnvironmentId, KeyFingerprintHex, UserId, VariableId } from "@maruhi/core";
import { decodeKeyFingerprintHex, decodeUserId } from "@maruhi/core";
import { auditReadVariablesOf, rotationRecommendedVariablesOf, VAR_READ_EVENT } from "@maruhi/core";

import { brandOrNull, numberOrNull, parsePayload } from "./audit-store-rows.ts";

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
  readonly targetUserId: UserId | null;
  readonly targetKeyFingerprintHex: KeyFingerprintHex | null;
  readonly payload: Readonly<Record<string, unknown>> | null;
}

/** The synchronous read surface used by detection and flag derivation (indexes in §4.2 / do-schema.ts). */
export interface AuditRotationRead {
  readonly membershipEventsFor: (targetUserId: UserId) => readonly MembershipEventRow[];
  readonly deviceEventsFor: (targetUserId: UserId) => readonly DeviceEventRow[];
  readonly serverGrantEventsFor: (fpHex: string) => readonly GrantEventRow[];
  readonly variableLifecycles: () => readonly VariableLifecycleRow[];
  readonly variableReadsBy: (actorUserId: UserId, range?: SeqRange) => readonly VariableReadRow[];
  readonly serverAccessEventsBy: (actorFpHex: string) => readonly ServerAccessRow[];
  /**
   * Every environment's epoch transitions from the chain mirror
   * (`chain.environment_created` = epoch 1, `chain.epoch_rotated` = the new
   * epoch — ae_event), ascending by seq: the input of each flag's exposure
   * bound (the epoch at the end of the subject's window — §4.1-5, VH).
   */
  readonly environmentEpochEvents: () => readonly EnvironmentEpochRow[];
  readonly rotationFlagEvents: () => readonly RotationFlagSourceRow[];
  /**
   * The same rows narrowed to the given (variable × environment) pairs (the
   * history's flagsIfCurrent, a dismissal's live check — ae_var). The pairs
   * are typed with the id brands so a caller cannot swap the two
   * same-shaped ids; they are only bound as a query parameter, so nothing
   * is minted here.
   */
  readonly rotationFlagEventsFor: (
    pairs: readonly {
      readonly environmentId: EnvironmentId;
      readonly variableId: VariableId;
    }[],
  ) => readonly RotationFlagSourceRow[];
}

/**
 * Read the payload's scopeEnvironmentIds. A broken row — not an array,
 * or containing non-string elements — is null (a silently narrowed
 * enumeration would create a missed window — design record §9 K3-F).
 */
function scopeOf(payload: Readonly<Record<string, unknown>> | null): readonly string[] | null {
  const scope = payload?.["scopeEnvironmentIds"];
  return Array.isArray(scope) && scope.every((id) => typeof id === "string")
    ? scope.map((id) => String(id))
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

export const makeRotationRead = (sql: SqlStorage): AuditRotationRead => ({
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
  // Q5: the aggregate rotation.recommended rows (ae_event — one row per
  // environment, §3.3's aggregate form), each expanded to its per-pair flag
  // rows so the lineage fold (rotation-detect.ts) stays per pair. The flagged
  // pairs then drive the per-pair resolution read (ae_var — rotation.dismissed
  // / var.version_pushed), so a pair never flagged is never touched. Reading
  // all recommended rows is bounded by removals × environments (2026-10-11
  // Sc-5 — it replaces #392's pair-unit narrowing, which the aggregate form
  // cannot use since a recommended row carries no variable_id column).
  // test/audit-index.test.ts pins the two plans via EXPLAIN.
  rotationFlagEvents: () => {
    const expanded = sql
      .exec(
        `SELECT ${RECOMMENDED_COLUMNS} FROM audit_events WHERE event = 'rotation.recommended' ORDER BY seq`,
      )
      .toArray()
      .flatMap((row) => expandRecommendedRow(row));
    const pairs = distinctPairs(expanded);
    if (pairs.length === 0) {
      return [];
    }
    return mergeFlagRowsBySeq(expanded, resolutionRowsFor(sql, pairs));
  },
  // The given pairs only: the aggregate recommended rows that cover a
  // requested pair, expanded to just those pairs, plus their resolution rows
  // (ae_var). The dismissal live check and the reader-callable history GET
  // pass specific pairs, so the recommended rows are narrowed in SQL
  // (environment_id IN … and the payload enumeration containing a requested
  // variableId) before the JS expansion — it does not read and parse every
  // recommended row in the project (the #392-style narrowing, restored for the
  // aggregate form). `wanted` is the precise pair set that drops a row's
  // non-requested variables (the `IN` predicates over-match within a mixed
  // row).
  rotationFlagEventsFor: (pairs) => {
    if (pairs.length === 0) {
      return [];
    }
    const wanted = new Set(pairs.map((pair) => pairKeyOf(pair.environmentId, pair.variableId)));
    const environments = [...new Set(pairs.map((pair) => String(pair.environmentId)))];
    const variables = [...new Set(pairs.map((pair) => String(pair.variableId)))];
    const expanded = sql
      .exec(
        `SELECT ${RECOMMENDED_COLUMNS} FROM audit_events
         WHERE event = 'rotation.recommended'
           AND environment_id IN (SELECT value FROM json_each(?))
           AND json_valid(payload)
           AND EXISTS (SELECT 1 FROM json_each(audit_events.payload, '$.variables') AS v
                       WHERE json_extract(v.value, '$.variableId') IN (SELECT value FROM json_each(?)))
         ORDER BY seq`,
        JSON.stringify(environments),
        JSON.stringify(variables),
      )
      .toArray()
      .flatMap((row) => expandRecommendedRow(row, wanted));
    return mergeFlagRowsBySeq(
      expanded,
      resolutionRowsFor(
        sql,
        pairs.map((pair) => ({ environmentId: pair.environmentId, variableId: pair.variableId })),
      ),
    );
  },
});

/** The columns read from an aggregate rotation.recommended row (variable_id is NULL — the enumeration is in the payload). */
const RECOMMENDED_COLUMNS = `seq, server_ts, environment_id, epoch, target_user_id, target_key_fingerprint, payload`;

const pairKeyOf = (environmentId: string, variableId: string): string =>
  `${environmentId}\u0000${variableId}`;

/**
 * Expand one aggregate `rotation.recommended` row (§3.3 — 2026-10-11 Sc-5)
 * into the per-pair flag rows the lineage fold consumes: one row per enumerated
 * variable, carrying that variable's basis and the row's (shared) trigger,
 * triggerChainSeq and exposure bound. The reconstructed per-pair payload
 * `{ basis, trigger, triggerChainSeq }` is byte-for-byte the shape the fold
 * read before aggregation, so `flagOf` / `originEpochOf` / `foldPairs` are
 * untouched. `restrict` (when given) keeps only the requested pairs. A broken
 * payload (no enumeration) yields nothing — a read is never made a defect.
 */
function expandRecommendedRow(
  row: Record<string, SqlStorageValue>,
  restrict?: ReadonlySet<string>,
): RotationFlagSourceRow[] {
  const environmentId = String(row["environment_id"]);
  const payload = parsePayload(row["payload"]);
  // The columns shared by every expanded pair of this aggregate row
  const shared = {
    seq: Number(row["seq"]),
    serverTs: Number(row["server_ts"]),
    event: "rotation.recommended" as const,
    environmentId,
    version: null,
    epoch: numberOrNull(row["epoch"]),
    targetUserId: brandOrNull(row["target_user_id"], decodeUserId),
    targetKeyFingerprintHex: brandOrNull(row["target_key_fingerprint"], decodeKeyFingerprintHex),
  };
  const scalars = { trigger: payload?.["trigger"], triggerChainSeq: payload?.["triggerChainSeq"] };
  return (rotationRecommendedVariablesOf(payload) ?? [])
    .filter(
      (variable) =>
        restrict === undefined || restrict.has(pairKeyOf(environmentId, variable.variableId)),
    )
    .map((variable): RotationFlagSourceRow => ({
      ...shared,
      variableId: variable.variableId,
      payload: { basis: variable.basis, ...scalars },
    }));
}

/** The distinct (environment, variable) pairs an expanded flag-row list covers. */
function distinctPairs(
  rows: readonly RotationFlagSourceRow[],
): { environmentId: string; variableId: string }[] {
  const seen = new Set<string>();
  const pairs: { environmentId: string; variableId: string }[] = [];
  for (const row of rows) {
    const key = pairKeyOf(row.environmentId, row.variableId);
    if (!seen.has(key)) {
      seen.add(key);
      pairs.push({ environmentId: row.environmentId, variableId: row.variableId });
    }
  }
  return pairs;
}

/**
 * Each pair's resolution rows (rotation.dismissed / var.version_pushed —
 * ae_var), in one statement however many pairs: json_each expands the bound
 * list, DISTINCT keeps a repeated pair from repeating its rows, and CROSS JOIN
 * fixes the join order (SQLite never reorders it — without statistics the
 * planner could otherwise drive from ae_event's whole var.version_pushed
 * range).
 */
function resolutionRowsFor(
  sql: SqlStorage,
  pairs: readonly { readonly environmentId: string; readonly variableId: string }[],
): readonly RotationFlagSourceRow[] {
  if (pairs.length === 0) {
    return [];
  }
  return sql
    .exec(
      `SELECT a.seq, a.server_ts, a.event, a.environment_id, a.variable_id, a.version,
              a.epoch, a.target_user_id, a.target_key_fingerprint, a.payload
       FROM (SELECT DISTINCT json_extract(value, '$.variableId') AS variable_id,
                             json_extract(value, '$.environmentId') AS environment_id
             FROM json_each(?)) AS target
       CROSS JOIN audit_events AS a
       WHERE a.variable_id = target.variable_id AND a.environment_id = target.environment_id
         AND a.event IN ('rotation.dismissed', 'var.version_pushed')
       ORDER BY a.seq`,
      JSON.stringify(
        pairs.map((pair) => ({ variableId: pair.variableId, environmentId: pair.environmentId })),
      ),
    )
    .toArray()
    .map(rotationFlagSourceRow);
}

/** Merge the expanded recommended rows with the resolution rows into one seq-ascending list (the fold's input order). */
function mergeFlagRowsBySeq(
  recommended: readonly RotationFlagSourceRow[],
  resolution: readonly RotationFlagSourceRow[],
): readonly RotationFlagSourceRow[] {
  return [...recommended, ...resolution].toSorted((a, b) => a.seq - b.seq);
}

function rotationFlagSourceRow(row: Record<string, SqlStorageValue>): RotationFlagSourceRow {
  return {
    seq: Number(row["seq"]),
    serverTs: Number(row["server_ts"]),
    event: String(row["event"]),
    environmentId: String(row["environment_id"]),
    variableId: String(row["variable_id"]),
    version: row["version"] === null ? null : Number(row["version"]),
    epoch: row["epoch"] === null ? null : Number(row["epoch"]),
    targetUserId:
      row["target_user_id"] === null ? null : decodeUserId(String(row["target_user_id"])),
    targetKeyFingerprintHex:
      row["target_key_fingerprint"] === null
        ? null
        : decodeKeyFingerprintHex(String(row["target_key_fingerprint"])),
    payload: parsePayload(row["payload"]),
  };
}
