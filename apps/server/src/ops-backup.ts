// DO → R2 退避スイープ(worker 側) — docs/notes/hosted-ops.md §2-D / §4-2 / §4-3。
//
// 毎時 cron(index.ts)から呼ばれ、D1 `projects` を id 昇順に列挙して各プロジェクト
// DO の `opsBackup` RPC を呼ぶ。読み出し・書き込みは DO 自身が permit 下で行い
// (do-snapshot.ts)、ここへ戻るのは集計値だけ(識別子は D1 の運用記録に閉じる)。
//
// 有界化(§4-3): 壁時計予算・訪問数上限・カーソル継続。skip 規則(§2-D):
// 前回成功のウォーターマーク(監査 seq・チェーン seq)と一致し、かつ前回成功から
// OPS_BACKUP_REFRESH_MS 以内なら退避しない(census の size は毎回読む)。
//
// バインディング(`OPS_BACKUP_BUCKET`)が無いデプロイ(セルフホストの既定)では
// 何もしない — ただし無言にはせず isolate ごと 1 回の静的行を残す。

import { Effect } from "effect";

import type { Env, OpsBackupOutcome } from "./chain-do.ts";
import type { OpsBackupAttempt } from "./db.package/index.ts";
import { OpsRepo } from "./db.package/index.ts";
import {
  OPS_BACKUP_MAX_BYTES,
  OPS_BACKUP_REFRESH_MS,
  OPS_SWEEP_BUDGET_MS,
  OPS_SWEEP_MAX_PROJECTS,
  OPS_SWEEP_PAGE_SIZE,
} from "./ops-policy.ts";
import { projectStub, rpcCall } from "./worker-env.ts";

const SWEEP_CURSOR_KEY = "backup_sweep_cursor";
const SNAPSHOT_KEY_PREFIX = "do";

export interface BackupSweepResult {
  readonly enabled: boolean;
  readonly visited: number;
  readonly uploaded: number;
  readonly skipped: number;
  readonly oversize: number;
  readonly failed: number;
  /** 予算・上限で打ち切った(カーソルは途中を指す)。 */
  readonly truncated: boolean;
}

export interface BackupSweepOptions {
  readonly nowMs?: () => number;
  readonly budgetMs?: number;
  readonly maxProjects?: number;
  readonly maxBytes?: number;
  /** テスト用: multipart のパート長(既定は policy)。 */
  readonly partBytes?: number;
}

let warnedMissingBucket = false;

function toAttempt(outcome: OpsBackupOutcome): OpsBackupAttempt {
  switch (outcome.kind) {
    case "uploaded":
      return {
        kind: "success",
        objectKey: outcome.objectKey,
        bytes: outcome.bytes,
        auditSeq: outcome.auditSeq,
        chainSeq: outcome.chainSeq,
        storageLevel: outcome.storageLevel,
      };
    case "skipped":
      return { kind: "skipped", storageLevel: outcome.storageLevel };
    case "oversize":
      return { kind: "failure", code: "oversize", storageLevel: outcome.storageLevel };
    case "upload-failed":
      return { kind: "failure", code: "upload-failed", storageLevel: outcome.storageLevel };
    case "no-bucket":
      // DO 側にバインディングが無い(worker 側にはある)= 構成の不整合。RPC 失敗と同じ扱い
      return { kind: "failure", code: "rpc-failed", storageLevel: null };
  }
}

/** 1 プロジェクトの退避(RPC 失敗は failure として記録 — 次回再試行)。 */
function backupOne(
  env: Env,
  projectId: string,
  nowMs: number,
  options: BackupSweepOptions,
): Effect.Effect<OpsBackupAttempt, never, OpsRepo> {
  return Effect.gen(function* () {
    const ops = yield* OpsRepo;
    const record = yield* ops.backupRecord(projectId);
    const skipIfUnchanged =
      record !== null &&
      record.lastSuccessAt !== null &&
      record.lastAuditSeq !== null &&
      record.lastChainSeq !== null &&
      nowMs - record.lastSuccessAt < OPS_BACKUP_REFRESH_MS
        ? { auditSeq: record.lastAuditSeq, chainSeq: record.lastChainSeq }
        : null;
    const stub = projectStub(env, projectId);
    const outcome = yield* rpcCall<OpsBackupOutcome>(() =>
      stub.opsBackup({
        keyPrefix: SNAPSHOT_KEY_PREFIX,
        nowMs,
        maxBytes: options.maxBytes ?? OPS_BACKUP_MAX_BYTES,
        skipIfUnchanged,
        ...(options.partBytes === undefined ? {} : { partBytes: options.partBytes }),
      }),
    ).pipe(
      Effect.map(toAttempt),
      Effect.catchCause(() =>
        Effect.sync((): OpsBackupAttempt => {
          // 静的メッセージのみ(プロジェクト ID は書かない — 記録は D1 側)
          console.warn("project backup RPC failed; the project is retried on the next sweep");
          return { kind: "failure", code: "rpc-failed", storageLevel: null };
        }),
      ),
    );
    return outcome;
  });
}

interface MutableSweepResult {
  enabled: boolean;
  visited: number;
  uploaded: number;
  skipped: number;
  oversize: number;
  failed: number;
  truncated: boolean;
}

function tally(result: MutableSweepResult, attempt: OpsBackupAttempt): void {
  result.visited += 1;
  if (attempt.kind === "success") {
    result.uploaded += 1;
  } else if (attempt.kind === "skipped") {
    result.skipped += 1;
  } else if (attempt.code === "oversize") {
    result.oversize += 1;
  } else {
    result.failed += 1;
  }
}

/** 1 ページ分を訪ねる。戻り値 = 最後に訪ねたプロジェクト(予算切れなら途中)。 */
function sweepPage(
  env: Env,
  page: readonly string[],
  result: MutableSweepResult,
  limits: { readonly now: () => number; readonly deadline: number; readonly maxProjects: number },
  options: BackupSweepOptions,
): Effect.Effect<string | null, never, OpsRepo> {
  return Effect.gen(function* () {
    const ops = yield* OpsRepo;
    let last: string | null = null;
    for (const projectId of page) {
      if (result.visited >= limits.maxProjects || limits.now() >= limits.deadline) {
        result.truncated = true;
        return last;
      }
      const attemptAt = limits.now();
      const attempt = yield* backupOne(env, projectId, attemptAt, options);
      const doIdHex = env.PROJECT_CHAIN.idFromName(projectId).toString();
      yield* ops.recordBackupAttempt(projectId, doIdHex, attempt, attemptAt);
      tally(result, attempt);
      last = projectId;
    }
    return last;
  });
}

interface SweepLimits {
  readonly now: () => number;
  readonly deadline: number;
  readonly maxProjects: number;
}

/** カーソルから終端(または予算切れ)まで進み、次回のカーソルを保存する。 */
function sweepFromCursor(
  env: Env,
  result: MutableSweepResult,
  limits: SweepLimits,
  options: BackupSweepOptions,
): Effect.Effect<void, never, OpsRepo> {
  return Effect.gen(function* () {
    const ops = yield* OpsRepo;
    let cursor = yield* ops.getState(SWEEP_CURSOR_KEY);
    for (;;) {
      const page = yield* ops.listProjectIdsAfter(
        cursor === "" ? null : cursor,
        OPS_SWEEP_PAGE_SIZE,
      );
      const last = yield* sweepPage(env, page, result, limits, options);
      cursor = last ?? cursor;
      if (result.truncated) {
        break;
      }
      if (page.length < OPS_SWEEP_PAGE_SIZE) {
        // 終端: 次回は先頭から
        cursor = null;
        break;
      }
    }
    yield* ops.setState(SWEEP_CURSOR_KEY, cursor ?? "", limits.now());
  });
}

function warnMissingBucketOnce(): void {
  if (!warnedMissingBucket) {
    warnedMissingBucket = true;
    console.warn(
      "backup bucket binding is not configured; project snapshots are not exported (see docs/SELF_HOSTING.md, Backups)",
    );
  }
}

/**
 * スイープ本体。予算内でカーソルから進み、終端に達したらカーソルを先頭へ戻す。
 */
export function runBackupSweep(
  env: Env,
  options: BackupSweepOptions = {},
): Effect.Effect<BackupSweepResult, never, OpsRepo> {
  return Effect.gen(function* () {
    const result: MutableSweepResult = {
      enabled: env.OPS_BACKUP_BUCKET !== undefined,
      visited: 0,
      uploaded: 0,
      skipped: 0,
      oversize: 0,
      failed: 0,
      truncated: false,
    };
    if (!result.enabled) {
      warnMissingBucketOnce();
      return result;
    }
    const now = options.nowMs ?? Date.now;
    yield* sweepFromCursor(
      env,
      result,
      {
        now,
        deadline: now() + (options.budgetMs ?? OPS_SWEEP_BUDGET_MS),
        maxProjects: options.maxProjects ?? OPS_SWEEP_MAX_PROJECTS,
      },
      options,
    );
    return result;
  });
}
