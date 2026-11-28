import { DEFAULT_AUDIT_EVENTS_PAGE_LIMIT, MAX_AUDIT_EVENTS_PAGE_LIMIT } from "@maruhi/api-schema";
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
  "rotation.proposed",
  "rotation.proposal_accepted",
  "rotation.proposal_rejected",
  "rotation.proposal_expired",
  "rotation.proposal_cancelled",
  "project.schema_policy_changed",
];

export function isClass1Event(event: string): boolean {
  return event.startsWith(CHAIN_MIRROR_EVENT_PREFIX) || CLASS1_EVENTS.includes(event);
}

type AuditVisibility =
  | { readonly kind: "admin" }
  | { readonly kind: "class1-or-self"; readonly selfUserId: string };

export interface AuditEventsQuery {
  readonly beforeRowId: string | null;
  readonly limit: number;
  readonly event: string | null;
  readonly eventPrefix: string | null;
  readonly chainSeqPresent: boolean;
  readonly actorUserId: UserId | null;
  readonly targetUserId: UserId | null;
  readonly variableId: string | null;
  readonly environmentId: string | null;
  readonly visibility: AuditVisibility;
}

export interface StoredAuditEventRow extends Omit<AuditHeadRow, "rowId" | "payloadText"> {
  readonly rowId: string;
  readonly payload: Readonly<Record<string, unknown>> | null;
  readonly actorUserId: UserId | null;
  readonly actorKeyFingerprintHex: KeyFingerprintHex | null;
  readonly targetUserId: UserId | null;
  readonly targetKeyFingerprintHex: KeyFingerprintHex | null;
}

function visibilityCondition(
  visibility: AuditVisibility,
): { readonly clause: string; readonly bindings: readonly (string | number)[] } | null {
  if (visibility.kind === "admin") {
    return null;
  }
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

function aggregatedReadContains(
  sql: SqlStorage,
  variableId: string,
  environmentId: string | null,
  visibility: AuditVisibility,
): SqlConditions | null {
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

function aggregatedRecommendedContains(sql: SqlStorage, variableId: string): SqlConditions | null {
  const any = sql
    .exec(`SELECT 1 FROM audit_events WHERE event = 'rotation.recommended' LIMIT 1`)
    .toArray()[0];
  if (any === undefined) {
    return null;
  }
  return {
    conditions: [
      "+variable_id IS NULL",
      "event = ?",
      "json_valid(payload)",
      "EXISTS (SELECT 1 FROM json_each(audit_events.payload, '$.variables') WHERE json_extract(json_each.value, '$.variableId') = ?)",
    ],
    bindings: ["rotation.recommended", variableId],
  };
}

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
      return [];
    }
    filter("seq < ?", beforeSeq);
  }
  filter("event = ?", query.event);
  if (query.eventPrefix !== null) {
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
  const pages: (readonly StoredAuditEventRow[])[] = [
    selectPage(sql, withCondition(where, "variable_id = ?", [query.variableId]), query.limit),
  ];
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

export function resolvePageLimit(limit: number | undefined): number {
  const requested = limit ?? DEFAULT_AUDIT_EVENTS_PAGE_LIMIT;
  return Math.max(1, Math.min(requested, MAX_AUDIT_EVENTS_PAGE_LIMIT));
}
