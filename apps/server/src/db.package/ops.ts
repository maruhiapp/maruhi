// The operations repository — docs/notes/hosted-ops.md §2-A / §2-B /
// §4-2 / §6.
//
// Operator-only mutable state that is not the audit log (ops_counters /
// ops_backups / ops_state), plus windowed aggregation over the existing
// audit rows (auth.* in user_audit_events — AUDIT_SPEC §3.1 prescribes
// that "operations tripwires count these rows"). Drizzle types never
// leave this boundary.

import { and, asc, count, eq, gt, gte, isNull, lt, or, type SQL, sql } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import {
  OPS_BACKUP_CONSECUTIVE_FAILURES_THRESHOLD,
  OPS_BACKUP_STALE_MS,
  OPS_COUNTER_RETENTION_MS,
  OPS_COUNTER_WINDOW_MS,
} from "../ops/ops-policy.ts";
import { tryD1 } from "./errors.ts";
import { opsBackups, opsCounters, opsState, projects, userAuditEvents } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

// D1 access goes through the shared tryD1 adapter (errors.ts —
// ADR-0006). Every method pipes `Effect.orDie` at its boundary: the
// public repository types keep an empty error channel because the
// handlers turning D1FailureError into typed errors belong to other
// lanes. An unexpected D1 failure stays a defect = a 500, as before

/** Operations counter metric names (hosted-ops §2-A). */
export type OpsCounterMetric = "github_token_requests" | "cli_flow_capacity";

/** Census values of the DO storage-total guard (same vocabulary as storage-guard.ts's checks). */
export type OpsStorageLevel = "admit" | "warn" | "reject";

/** Evacuation failure codes (static — safe to put in logs and results). */
export type OpsBackupFailureCode = "oversize" | "rpc-failed" | "upload-failed";

export interface OpsBackupRecord {
  readonly projectId: string;
  readonly doIdHex: string;
  readonly lastAttemptAt: number;
  readonly lastSuccessAt: number | null;
  readonly lastObjectKey: string | null;
  readonly lastBytes: number | null;
  readonly lastAuditSeq: number | null;
  readonly lastChainSeq: number | null;
  readonly lastAttestationMark: number | null;
  readonly storageLevel: OpsStorageLevel | null;
  readonly consecutiveFailures: number;
  readonly lastFailureCode: OpsBackupFailureCode | null;
}

export type OpsBackupAttempt =
  | {
      readonly kind: "success";
      readonly objectKey: string;
      readonly bytes: number;
      readonly auditSeq: number;
      readonly chainSeq: number;
      readonly attestationMark: number;
      readonly storageLevel: OpsStorageLevel;
    }
  | {
      /** Evacuation omitted because content is unchanged (not counted as success — last_success kept as-is). */
      readonly kind: "skipped";
      readonly storageLevel: OpsStorageLevel;
    }
  | {
      /**
       * Not evacuated due to the size cap (hosted-ops §4-2). Not a
       * failure — the consecutive-failure counter is untouched; only
       * `backup_oversize_projects` is lit.
       */
      readonly kind: "oversize";
      readonly storageLevel: OpsStorageLevel;
    }
  | {
      readonly kind: "failure";
      readonly code: OpsBackupFailureCode;
      readonly storageLevel: OpsStorageLevel | null;
    };

/** Aggregates for hosted-ops §3 row 2 / row 7 (contains no identifiers). */
export interface OpsBackupSummary {
  readonly trackedProjects: number;
  readonly storageWarnProjects: number;
  readonly storageRejectProjects: number;
  readonly staleProjects: number;
  readonly failingProjects: number;
  readonly oversizeProjects: number;
}

export interface OpsRepoShape {
  /** +1 on the fixed-window counter (a single UPSERT). */
  readonly incrementCounter: (metric: OpsCounterMetric, nowMs: number) => Effect.Effect<void>;
  /** Counts of windows starting at or after `sinceMs` (ascending by window start). */
  readonly counterWindows: (
    metric: OpsCounterMetric,
    sinceMs: number,
  ) => Effect.Effect<readonly { readonly windowStart: number; readonly count: number }[]>;
  /** Deletes windows past the retention period (bounding). */
  readonly pruneCounters: (nowMs: number) => Effect.Effect<void>;
  /** Count of user_audit_events since `sinceMs` (by event name). */
  readonly auditEventCountSince: (event: string, sinceMs: number) => Effect.Effect<number>;
  /** Sweep enumeration (`projects` in id order, exclusive cursor). */
  readonly listProjectIdsAfter: (
    afterProjectId: string | null,
    limit: number,
  ) => Effect.Effect<readonly string[]>;
  readonly backupRecord: (projectId: string) => Effect.Effect<OpsBackupRecord | null>;
  readonly recordBackupAttempt: (
    projectId: string,
    doIdHex: string,
    attempt: OpsBackupAttempt,
    nowMs: number,
  ) => Effect.Effect<void>;
  readonly backupSummary: (nowMs: number) => Effect.Effect<OpsBackupSummary>;
  readonly getState: (key: string) => Effect.Effect<string | null>;
  readonly setState: (key: string, value: string, nowMs: number) => Effect.Effect<void>;
}

export class OpsRepo extends Context.Service<OpsRepo, OpsRepoShape>()("OpsRepo") {}

/** Fixed-window start time (1-hour boundary). */
export function opsWindowStart(nowMs: number): number {
  return Math.floor(nowMs / OPS_COUNTER_WINDOW_MS) * OPS_COUNTER_WINDOW_MS;
}

/** Number of rows satisfying a condition (conditional sum). */
const flag = (condition: SQL): SQL<number> =>
  sql<number>`coalesce(sum(case when ${condition} then 1 else 0 end), 0)`;

/** A D1 aggregate value (number / string / missing) → non-negative integer. */
function toCount(value: unknown): number {
  const n = Number(value ?? 0);
  return Number.isFinite(n) ? n : 0;
}

function toStorageLevel(value: string | null): OpsStorageLevel | null {
  return value === "admit" || value === "warn" || value === "reject" ? value : null;
}

function toFailureCode(value: string | null): OpsBackupFailureCode | null {
  return value === "oversize" || value === "rpc-failed" || value === "upload-failed" ? value : null;
}

/** An evacuation attempt → ops_backups columns (at insert / at update of an existing row). */
function backupAttemptColumns(
  attempt: OpsBackupAttempt,
  nowMs: number,
): { readonly insert: Record<string, unknown>; readonly update: Record<string, unknown> } {
  switch (attempt.kind) {
    case "success": {
      const columns = {
        lastSuccessAt: nowMs,
        lastObjectKey: attempt.objectKey,
        lastBytes: attempt.bytes,
        lastAuditSeq: attempt.auditSeq,
        lastChainSeq: attempt.chainSeq,
        lastAttestationMark: attempt.attestationMark,
        storageLevel: attempt.storageLevel,
        consecutiveFailures: 0,
        lastFailureCode: null,
      };
      return { insert: columns, update: columns };
    }
    case "oversize": {
      // The consecutive-failure counter resets to 0 (while oversize no
      // success can occur, so the rpc-failed / upload-failed already
      // accumulated must not keep backup_failing_projects lit forever)
      const columns = {
        storageLevel: attempt.storageLevel,
        consecutiveFailures: 0,
        lastFailureCode: "oversize",
      };
      return { insert: columns, update: columns };
    }
    case "skipped": {
      const columns = {
        storageLevel: attempt.storageLevel,
        consecutiveFailures: 0,
        lastFailureCode: null,
      };
      return { insert: columns, update: columns };
    }
    case "failure": {
      // census is updated only when measured (kept as-is on RPC failure)
      const level = attempt.storageLevel === null ? {} : { storageLevel: attempt.storageLevel };
      return {
        insert: { ...level, consecutiveFailures: 1, lastFailureCode: attempt.code },
        update: {
          ...level,
          consecutiveFailures: sql`${opsBackups.consecutiveFailures} + 1`,
          lastFailureCode: attempt.code,
        },
      };
    }
  }
}

export function makeOpsRepo(db: Db): OpsRepoShape {
  return {
    incrementCounter: (metric, nowMs) =>
      tryD1(async () => {
        await db
          .insert(opsCounters)
          .values({ metric, windowStart: opsWindowStart(nowMs), count: 1 })
          .onConflictDoUpdate({
            target: [opsCounters.metric, opsCounters.windowStart],
            set: { count: sql`${opsCounters.count} + 1` },
          });
      }).pipe(Effect.orDie),
    counterWindows: (metric, sinceMs) =>
      tryD1(async () =>
        db
          .select({ windowStart: opsCounters.windowStart, count: opsCounters.count })
          .from(opsCounters)
          .where(and(eq(opsCounters.metric, metric), gte(opsCounters.windowStart, sinceMs)))
          .orderBy(asc(opsCounters.windowStart))
          .all(),
      ).pipe(Effect.orDie),
    pruneCounters: (nowMs) =>
      tryD1(async () => {
        await db
          .delete(opsCounters)
          .where(lt(opsCounters.windowStart, nowMs - OPS_COUNTER_RETENTION_MS));
      }).pipe(Effect.orDie),
    auditEventCountSince: (event, sinceMs) =>
      tryD1(async () => {
        const row = await db
          .select({ n: count() })
          .from(userAuditEvents)
          .where(and(eq(userAuditEvents.event, event), gte(userAuditEvents.serverTs, sinceMs)))
          .get();
        return row?.n ?? 0;
      }).pipe(Effect.orDie),
    listProjectIdsAfter: (afterProjectId, limit) =>
      tryD1(async () => {
        const rows = await db
          .select({ id: projects.id })
          .from(projects)
          .where(afterProjectId === null ? undefined : gt(projects.id, afterProjectId))
          .orderBy(asc(projects.id))
          .limit(limit)
          .all();
        return rows.map((row) => row.id);
      }).pipe(Effect.orDie),
    backupRecord: (projectId) =>
      tryD1(async () => {
        const row = await db
          .select()
          .from(opsBackups)
          .where(eq(opsBackups.projectId, projectId))
          .get();
        if (row === undefined) {
          return null;
        }
        return {
          projectId: row.projectId,
          doIdHex: row.doIdHex,
          lastAttemptAt: row.lastAttemptAt,
          lastSuccessAt: row.lastSuccessAt,
          lastObjectKey: row.lastObjectKey,
          lastBytes: row.lastBytes,
          lastAuditSeq: row.lastAuditSeq,
          lastChainSeq: row.lastChainSeq,
          lastAttestationMark: row.lastAttestationMark,
          storageLevel: toStorageLevel(row.storageLevel),
          consecutiveFailures: row.consecutiveFailures,
          lastFailureCode: toFailureCode(row.lastFailureCode),
        };
      }).pipe(Effect.orDie),
    recordBackupAttempt: (projectId, doIdHex, attempt, nowMs) =>
      tryD1(async () => {
        const columns = backupAttemptColumns(attempt, nowMs);
        await db
          .insert(opsBackups)
          .values({ projectId, doIdHex, lastAttemptAt: nowMs, ...columns.insert })
          .onConflictDoUpdate({
            target: opsBackups.projectId,
            set: { doIdHex, lastAttemptAt: nowMs, ...columns.update },
          });
      }).pipe(Effect.orDie),
    backupSummary: (nowMs) =>
      tryD1(async () => {
        const staleBefore = nowMs - OPS_BACKUP_STALE_MS;
        // Aggregates in a single query (conditional sum — row count is at most the project count)
        const row = await db
          .select({
            tracked: count(),
            warn: flag(eq(opsBackups.storageLevel, "warn")),
            reject: flag(eq(opsBackups.storageLevel, "reject")),
            stale: flag(
              or(
                and(isNull(opsBackups.lastSuccessAt), lt(opsBackups.lastAttemptAt, staleBefore)),
                lt(opsBackups.lastSuccessAt, staleBefore),
              ) as SQL,
            ),
            failing: flag(
              gte(opsBackups.consecutiveFailures, OPS_BACKUP_CONSECUTIVE_FAILURES_THRESHOLD),
            ),
            oversize: flag(eq(opsBackups.lastFailureCode, "oversize")),
          })
          .from(opsBackups)
          .get();
        return {
          trackedProjects: toCount(row?.tracked),
          storageWarnProjects: toCount(row?.warn),
          storageRejectProjects: toCount(row?.reject),
          staleProjects: toCount(row?.stale),
          failingProjects: toCount(row?.failing),
          oversizeProjects: toCount(row?.oversize),
        };
      }).pipe(Effect.orDie),
    getState: (key) =>
      tryD1(async () => {
        const row = await db
          .select({ value: opsState.value })
          .from(opsState)
          .where(eq(opsState.key, key))
          .get();
        return row?.value ?? null;
      }).pipe(Effect.orDie),
    setState: (key, value, nowMs) =>
      tryD1(async () => {
        await db
          .insert(opsState)
          .values({ key, value, updatedAt: nowMs })
          .onConflictDoUpdate({ target: opsState.key, set: { value, updatedAt: nowMs } });
      }).pipe(Effect.orDie),
  };
}
