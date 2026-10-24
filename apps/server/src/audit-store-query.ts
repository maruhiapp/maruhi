// The audit log's generic read surface (AUDIT_SPEC §7 — C1), served by
// AuditStore's queryEventsSync (audit-store.ts). seq-cursor paging +
// filters. Visibility classes (§6) are enforced by the SQL WHERE: a
// class-2 row appears nowhere in a sub-admin's results, counts, or
// paging ("behaves as if it did not exist").

import type { KeyFingerprintHex, UserId } from "@maruhi/core";
import { decodeKeyFingerprintHex, decodeUserId } from "@maruhi/core";
import { CHAIN_MIRROR_EVENT_PREFIX, VAR_READ_EVENT } from "@maruhi/core";
import type { AuditHeadRow } from "@maruhi/crypto";

import {
  AUDIT_ROW_COLUMNS,
  brandOrNull,
  numberOrNull,
  parsePayload,
  toAuditHeadRow,
} from "./audit-store-rows.ts";

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
  "rotation.proposal_cancelled",
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
export interface AuditEventsQuery {
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
  readonly actorUserId: UserId | null;
  readonly targetUserId: UserId | null;
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
  readonly actorUserId: UserId | null;
  readonly actorKeyFingerprintHex: KeyFingerprintHex | null;
  readonly targetUserId: UserId | null;
  readonly targetKeyFingerprintHex: KeyFingerprintHex | null;
}

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
      `SELECT ${AUDIT_ROW_COLUMNS} FROM audit_events${clause} ORDER BY seq DESC LIMIT ?`,
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

/**
 * The condition selecting, among the aggregate `rotation.recommended` rows
 * (§3.3 — 2026-10-11 Sc-5; variable_id IS NULL, a `variables` enumeration in
 * the payload), the rows whose enumeration contains the given variable (the §7
 * variable_id filter / §4.2 Q4). Unlike {@link aggregatedReadContains} there is
 * no value-existence-interval narrowing (rotation.recommended is low-frequency,
 * bounded by removals × environments) and no self restriction (it is class 1 —
 * §6; every member sees it, so the base visibility clause already admits it,
 * and the environment / cursor / other filters ride the base WHERE).
 * json_valid precedes EXISTS (a server-written row is JSON, but a broken row
 * must not crash the read API).
 */
function aggregatedRecommendedContains(sql: SqlStorage, variableId: string): SqlConditions | null {
  // Skip the payload scan entirely when the project has no recommended row
  // (ae_event existence probe — the common case; a declared-only or never-flagged
  // variable then runs no json_each inspection)
  const any = sql
    .exec(`SELECT 1 FROM audit_events WHERE event = 'rotation.recommended' LIMIT 1`)
    .toArray()[0];
  if (any === undefined) {
    return null;
  }
  return {
    // `+variable_id` disqualifies variable_id from index candidacy (the unary-+
    // idiom): without it the planner could pick ae_var (variable_id IS NULL)
    // and scan every var.read row (also NULL). `event = ?` then drives ae_event
    // (test/audit-index.test.ts pins the plan).
    conditions: [
      "+variable_id IS NULL",
      "event = ?",
      "json_valid(payload)",
      "EXISTS (SELECT 1 FROM json_each(audit_events.payload, '$.variables') WHERE json_extract(json_each.value, '$.variableId') = ?)",
    ],
    bindings: ["rotation.recommended", variableId],
  };
}

/**
 * Merge several seq-descending pages into one seq-descending page, up to
 * `limit` rows. The sources are disjoint (byColumn is `variable_id = ?`; the
 * aggregate pages are `variable_id IS NULL` with distinct `event`s), so no
 * dedup is needed; each page is already its source's top `limit`, so the union
 * holds the global top `limit`.
 */
function mergeDescendingAll(
  pages: readonly (readonly StoredAuditEventRow[])[],
  limit: number,
): readonly StoredAuditEventRow[] {
  return pages
    .flat()
    .toSorted((a, b) => b.seq - a.seq)
    .slice(0, limit);
}

export function queryEvents(
  sql: SqlStorage,
  query: AuditEventsQuery,
): readonly StoredAuditEventRow[] {
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
  // var.version_pushed / rotation.dismissed etc. — stops at `limit` rows in
  // ae_var's index order) and the aggregate-form rows (payload inspection)
  // run as separate queries and merge in seq-descending order. Fused into one
  // OR, SQLite would gather all matching rows of every side before sorting,
  // degrading the column match's paging from "index order + early stop" to
  // "proportional to the match count". The cursor, visibility, and the other
  // filters apply identically to every query.
  const pages: (readonly StoredAuditEventRow[])[] = [
    selectPage(sql, withCondition(where, "variable_id = ?", [query.variableId]), query.limit),
  ];
  // Aggregate var.read (class 2 — bound to the value-existence interval and
  // to the viewer's own rows). Null = the variable never held a value, so it
  // never appears in a pull — skip the inspection.
  const readAggregated = aggregatedReadContains(
    sql,
    query.variableId,
    query.environmentId,
    query.visibility,
  );
  if (readAggregated !== null) {
    pages.push(
      selectPage(
        sql,
        withCondition(where, readAggregated.conditions.join(" AND "), readAggregated.bindings),
        query.limit,
      ),
    );
  }
  // Aggregate rotation.recommended (§3.3 — 2026-10-11 Sc-5; class 1, no
  // interval narrowing). Null = the project has no recommended row yet.
  const recommendedAggregated = aggregatedRecommendedContains(sql, query.variableId);
  if (recommendedAggregated !== null) {
    pages.push(
      selectPage(
        sql,
        withCondition(
          where,
          recommendedAggregated.conditions.join(" AND "),
          recommendedAggregated.bindings,
        ),
        query.limit,
      ),
    );
  }
  return mergeDescendingAll(pages, query.limit);
}

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
    actorUserId: brandOrNull(shared.actorUserId, decodeUserId),
    actorKeyFingerprintHex: brandOrNull(shared.actorKeyFingerprintHex, decodeKeyFingerprintHex),
    targetUserId: brandOrNull(shared.targetUserId, decodeUserId),
    targetKeyFingerprintHex: brandOrNull(shared.targetKeyFingerprintHex, decodeKeyFingerprintHex),
  };
}
