// 運用(H3)のリポジトリ — docs/notes/hosted-ops.md §2-A / §2-B / §4-2 / §6。
//
// 監査ログではない運営限定の可変状態(ops_counters / ops_backups / ops_state)と、
// 既存の監査行(user_audit_events の auth.* — AUDIT_SPEC §3.1 が「H3 のトリップ
// ワイヤはこの行を数える」と規定)の窓集計。Drizzle の型はこの境界の外に出さない。

import { and, asc, count, eq, gt, gte, isNull, lt, or, type SQL, sql } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import {
  OPS_BACKUP_CONSECUTIVE_FAILURES_THRESHOLD,
  OPS_BACKUP_STALE_MS,
  OPS_COUNTER_RETENTION_MS,
  OPS_COUNTER_WINDOW_MS,
} from "../ops-policy.ts";
import { opsBackups, opsCounters, opsState, projects, userAuditEvents } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

const run = <T>(evaluate: () => Promise<T>): Effect.Effect<T> => Effect.promise(evaluate);

/** 運用カウンタの metric 名(hosted-ops §2-A)。 */
export type OpsCounterMetric = "github_token_requests" | "cli_flow_capacity";

/** DO ストレージ総量ガードの census 値(storage-guard.ts の判定と同じ語彙)。 */
export type OpsStorageLevel = "admit" | "warn" | "reject";

/** 退避の失敗コード(静的 — ログ・結果に載せてよい)。 */
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
      /** 内容不変で退避を省略(成功として扱わない — last_success は据え置き)。 */
      readonly kind: "skipped";
      readonly storageLevel: OpsStorageLevel;
    }
  | {
      /**
       * 上限超過で退避しない(hosted-ops §4-2)。失敗ではない — 連続失敗カウンタを
       * 触らず、`backup_oversize_projects` だけを点灯させる(PR #137 レビュー)。
       */
      readonly kind: "oversize";
      readonly storageLevel: OpsStorageLevel;
    }
  | {
      readonly kind: "failure";
      readonly code: OpsBackupFailureCode;
      readonly storageLevel: OpsStorageLevel | null;
    };

/** hosted-ops §3 行 2 / 行 7 の集計値(識別子を含まない)。 */
export interface OpsBackupSummary {
  readonly trackedProjects: number;
  readonly storageWarnProjects: number;
  readonly storageRejectProjects: number;
  readonly staleProjects: number;
  readonly failingProjects: number;
  readonly oversizeProjects: number;
}

export interface OpsRepoShape {
  /** 固定窓カウンタの +1(UPSERT 1 文)。 */
  readonly incrementCounter: (metric: OpsCounterMetric, nowMs: number) => Effect.Effect<void>;
  /** `sinceMs` 以降に始まる窓の件数(窓開始昇順)。 */
  readonly counterWindows: (
    metric: OpsCounterMetric,
    sinceMs: number,
  ) => Effect.Effect<readonly { readonly windowStart: number; readonly count: number }[]>;
  /** 保持期間を過ぎた窓の削除(有界化)。 */
  readonly pruneCounters: (nowMs: number) => Effect.Effect<void>;
  /** `sinceMs` 以降の user_audit_events の件数(event 名で)。 */
  readonly auditEventCountSince: (event: string, sinceMs: number) => Effect.Effect<number>;
  /** スイープの列挙(`projects` を id 昇順・排他カーソル)。 */
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

/** 固定窓の開始時刻(1 時間境界)。 */
export function opsWindowStart(nowMs: number): number {
  return Math.floor(nowMs / OPS_COUNTER_WINDOW_MS) * OPS_COUNTER_WINDOW_MS;
}

/** 条件を満たす行数(条件付き sum)。 */
const flag = (condition: SQL): SQL<number> =>
  sql<number>`coalesce(sum(case when ${condition} then 1 else 0 end), 0)`;

/** D1 の集計値(数値 / 文字列 / 欠損)→ 非負整数。 */
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

/** 退避の試行 → ops_backups の列(挿入時 / 既存行の更新時)。 */
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
      // 連続失敗カウンタは 0 に戻す(oversize の間は success が起きないため、先に積んだ
      // rpc-failed / upload-failed が backup_failing_projects を永久点灯させないように)
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
      // census は測れたときだけ更新する(RPC 失敗時は据え置き)
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
      run(async () => {
        await db
          .insert(opsCounters)
          .values({ metric, windowStart: opsWindowStart(nowMs), count: 1 })
          .onConflictDoUpdate({
            target: [opsCounters.metric, opsCounters.windowStart],
            set: { count: sql`${opsCounters.count} + 1` },
          });
      }),
    counterWindows: (metric, sinceMs) =>
      run(async () =>
        db
          .select({ windowStart: opsCounters.windowStart, count: opsCounters.count })
          .from(opsCounters)
          .where(and(eq(opsCounters.metric, metric), gte(opsCounters.windowStart, sinceMs)))
          .orderBy(asc(opsCounters.windowStart))
          .all(),
      ),
    pruneCounters: (nowMs) =>
      run(async () => {
        await db
          .delete(opsCounters)
          .where(lt(opsCounters.windowStart, nowMs - OPS_COUNTER_RETENTION_MS));
      }),
    auditEventCountSince: (event, sinceMs) =>
      run(async () => {
        const row = await db
          .select({ n: count() })
          .from(userAuditEvents)
          .where(and(eq(userAuditEvents.event, event), gte(userAuditEvents.serverTs, sinceMs)))
          .get();
        return row?.n ?? 0;
      }),
    listProjectIdsAfter: (afterProjectId, limit) =>
      run(async () => {
        const rows = await db
          .select({ id: projects.id })
          .from(projects)
          .where(afterProjectId === null ? undefined : gt(projects.id, afterProjectId))
          .orderBy(asc(projects.id))
          .limit(limit)
          .all();
        return rows.map((row) => row.id);
      }),
    backupRecord: (projectId) =>
      run(async () => {
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
      }),
    recordBackupAttempt: (projectId, doIdHex, attempt, nowMs) =>
      run(async () => {
        const columns = backupAttemptColumns(attempt, nowMs);
        await db
          .insert(opsBackups)
          .values({ projectId, doIdHex, lastAttemptAt: nowMs, ...columns.insert })
          .onConflictDoUpdate({
            target: opsBackups.projectId,
            set: { doIdHex, lastAttemptAt: nowMs, ...columns.update },
          });
      }),
    backupSummary: (nowMs) =>
      run(async () => {
        const staleBefore = nowMs - OPS_BACKUP_STALE_MS;
        // 1 クエリで集計(条件付き sum — 行数は最大でプロジェクト数)
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
      }),
    getState: (key) =>
      run(async () => {
        const row = await db
          .select({ value: opsState.value })
          .from(opsState)
          .where(eq(opsState.key, key))
          .get();
        return row?.value ?? null;
      }),
    setState: (key, value, nowMs) =>
      run(async () => {
        await db
          .insert(opsState)
          .values({ key, value, updatedAt: nowMs })
          .onConflictDoUpdate({ target: opsState.key, set: { value, updatedAt: nowMs } });
      }),
  };
}
