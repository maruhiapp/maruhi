import type { EnvironmentId, KeyFingerprintHex, UserId, VariableId } from "@maruhi/core";
import { decodeKeyFingerprintHex, decodeUserId } from "@maruhi/core";
import { auditReadVariablesOf, rotationRecommendedVariablesOf, VAR_READ_EVENT } from "@maruhi/core";

import { brandOrNull, numberOrNull, parsePayload } from "./audit-store-rows.ts";

export type ScopeSnapshot =
  | { readonly kind: "all" }
  | { readonly kind: "listed"; readonly environmentIds: readonly string[] };

export interface MembershipEventRow {
  readonly seq: number;
  readonly event: string;
  readonly role: string | null;
  readonly scope: ScopeSnapshot | null;
}

export interface DeviceEventRow {
  readonly seq: number;
  readonly event: string;
  readonly fingerprintsHex: readonly string[];
  readonly scope: ScopeSnapshot | null;
}

export interface GrantEventRow {
  readonly seq: number;
  readonly event: string;
  readonly scopeEnvironmentIds: readonly string[] | null;
}

export interface VariableLifecycleRow {
  readonly seq: number;
  readonly event: string;
  readonly environmentId: string;
  readonly variableId: string;
}

export interface VariableReadRow {
  readonly seq: number;
  readonly environmentId: string;
  readonly variableId: string;
}

export interface SeqRange {
  readonly afterSeq: number;
  readonly beforeSeq: number;
}

export interface ServerAccessRow {
  readonly seq: number;
  readonly event: string;
  readonly environmentId: string;
  readonly variableId: string | null;
}

export interface EnvironmentEpochRow {
  readonly seq: number;
  readonly environmentId: string;
  readonly epoch: number;
}

export interface RotationFlagSourceRow {
  readonly seq: number;
  readonly serverTs: number;
  readonly event: string;
  readonly environmentId: string;
  readonly variableId: string;
  readonly version: number | null;
  readonly epoch: number | null;
  readonly targetUserId: UserId | null;
  readonly targetKeyFingerprintHex: KeyFingerprintHex | null;
  readonly payload: Readonly<Record<string, unknown>> | null;
}

export interface AuditRotationRead {
  readonly membershipEventsFor: (targetUserId: UserId) => readonly MembershipEventRow[];
  readonly deviceEventsFor: (targetUserId: UserId) => readonly DeviceEventRow[];
  readonly serverGrantEventsFor: (fpHex: string) => readonly GrantEventRow[];
  readonly variableLifecycles: () => readonly VariableLifecycleRow[];
  readonly variableReadsBy: (actorUserId: UserId, range?: SeqRange) => readonly VariableReadRow[];
  readonly serverAccessEventsBy: (actorFpHex: string) => readonly ServerAccessRow[];
  readonly environmentEpochEvents: () => readonly EnvironmentEpochRow[];
  readonly rotationFlagEvents: () => readonly RotationFlagSourceRow[];
  readonly rotationFlagEventsFor: (
    pairs: readonly {
      readonly environmentId: EnvironmentId;
      readonly variableId: VariableId;
    }[],
  ) => readonly RotationFlagSourceRow[];
}

function scopeOf(payload: Readonly<Record<string, unknown>> | null): readonly string[] | null {
  const scope = payload?.["scopeEnvironmentIds"];
  return Array.isArray(scope) && scope.every((id) => typeof id === "string")
    ? scope.map((id) => String(id))
    : null;
}

function scopeSnapshotOf(payload: Readonly<Record<string, unknown>> | null): ScopeSnapshot | null {
  const kind = payload?.["scopeKind"];
  if (kind === "all") {
    return { kind: "all" };
  }
  const ids = kind === "listed" ? scopeOf(payload) : null;
  return ids === null ? null : { kind: "listed", environmentIds: ids };
}

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

const RECOMMENDED_COLUMNS = `seq, server_ts, environment_id, epoch, target_user_id, target_key_fingerprint, payload`;

const pairKeyOf = (environmentId: string, variableId: string): string =>
  `${environmentId}\u0000${variableId}`;

function expandRecommendedRow(
  row: Record<string, SqlStorageValue>,
  restrict?: ReadonlySet<string>,
): RotationFlagSourceRow[] {
  const environmentId = String(row["environment_id"]);
  const payload = parsePayload(row["payload"]);
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
    targetKeyFingerprintHex: brandOrNull(row["target_key_fingerprint"], decodeKeyFingerprintHex),
    payload: parsePayload(row["payload"]),
  };
}
