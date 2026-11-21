import type { ProjectId } from "@maruhi/core";
import { ProjectIdSchema } from "@maruhi/core";
import { Clock, Effect, Ref, Schema } from "effect";

import type { OpsBackupAttempt } from "../db.package/index.ts";
import { OpsRepo } from "../db.package/index.ts";
import type { Env } from "../do/chain-do.ts";
import type { OpsBackupOutcome } from "../do/do-ops.ts";
import { projectStub, rpcCall } from "../worker-env.ts";
import {
  OPS_BACKUP_MAX_BYTES,
  OPS_BACKUP_REFRESH_MS,
  OPS_SWEEP_BUDGET_MS,
  OPS_SWEEP_MAX_PROJECTS,
  OPS_SWEEP_PAGE_SIZE,
} from "./ops-policy.ts";

const SWEEP_CURSOR_KEY = "backup_sweep_cursor";
const SNAPSHOT_KEY_PREFIX = "do";

interface BackupSweepResult {
  readonly enabled: boolean;
  readonly visited: number;
  readonly uploaded: number;
  readonly skipped: number;
  readonly oversize: number;
  readonly failed: number;
  readonly truncated: boolean;
}

interface BackupSweepOptions {
  readonly budgetMs?: number;
  readonly maxProjects?: number;
  readonly maxBytes?: number;
  readonly partBytes?: number;
}

const warnedMissingBucket = Ref.makeUnsafe(false);

function toAttempt(outcome: OpsBackupOutcome): OpsBackupAttempt {
  switch (outcome.kind) {
    case "uploaded":
      return {
        kind: "success",
        objectKey: outcome.objectKey,
        bytes: outcome.bytes,
        auditSeq: outcome.auditSeq,
        chainSeq: outcome.chainSeq,
        attestationMark: outcome.attestationMark,
        storageLevel: outcome.storageLevel,
      };
    case "skipped":
      return { kind: "skipped", storageLevel: outcome.storageLevel };
    case "oversize":
      return { kind: "oversize", storageLevel: outcome.storageLevel };
    case "upload-failed":
      return { kind: "failure", code: "upload-failed", storageLevel: outcome.storageLevel };
    case "no-bucket":
      return { kind: "failure", code: "rpc-failed", storageLevel: null };
  }
}

const backupOne = Effect.fn("ops-backup.backupOne")(function* (
  env: Env,
  projectId: ProjectId,
  nowMs: number,
  options: BackupSweepOptions,
): Effect.fn.Return<OpsBackupAttempt, never, OpsRepo> {
  const ops = yield* OpsRepo;
  const record = yield* ops.backupRecord(projectId);
  const skipIfUnchanged =
    record !== null &&
    record.lastSuccessAt !== null &&
    record.lastAuditSeq !== null &&
    record.lastChainSeq !== null &&
    record.lastAttestationMark !== null &&
    nowMs - record.lastSuccessAt < OPS_BACKUP_REFRESH_MS
      ? {
          auditSeq: record.lastAuditSeq,
          chainSeq: record.lastChainSeq,
          attestationMark: record.lastAttestationMark,
        }
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
    Effect.catchTag("RpcCallError", () =>
      Effect.logWarning("project backup RPC failed; the project is retried on the next sweep").pipe(
        Effect.as<OpsBackupAttempt>({ kind: "failure", code: "rpc-failed", storageLevel: null }),
      ),
    ),
  );
  return outcome;
});

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
  } else if (attempt.kind === "oversize") {
    result.oversize += 1;
  } else {
    result.failed += 1;
  }
}

const sweepPage = Effect.fn("ops-backup.sweepPage")(function* (
  env: Env,
  page: readonly ProjectId[],
  result: MutableSweepResult,
  limits: SweepLimits,
  options: BackupSweepOptions,
): Effect.fn.Return<ProjectId | null, never, OpsRepo> {
  const ops = yield* OpsRepo;
  let last: ProjectId | null = null;
  for (const projectId of page) {
    if (
      result.visited >= limits.maxProjects ||
      (yield* Clock.currentTimeMillis) >= limits.deadline
    ) {
      result.truncated = true;
      return last;
    }
    const attemptAt = yield* Clock.currentTimeMillis;
    const attempt = yield* backupOne(env, projectId, attemptAt, options);
    const doIdHex = env.PROJECT_CHAIN.idFromName(projectId).toString();
    yield* ops.recordBackupAttempt(projectId, doIdHex, attempt, attemptAt);
    tally(result, attempt);
    last = projectId;
  }
  return last;
});

interface SweepLimits {
  readonly deadline: number;
  readonly maxProjects: number;
}

function parseSweepCursor(stored: string | null): Effect.Effect<ProjectId | null> {
  if (stored === null || stored === "") {
    return Effect.succeed(null);
  }
  return Schema.decodeUnknownEffect(ProjectIdSchema)(stored).pipe(
    Effect.catchTag("SchemaError", () =>
      Effect.logWarning(
        "backup sweep cursor is not a valid project id; restarting the sweep from the beginning",
      ).pipe(Effect.as<ProjectId | null>(null)),
    ),
  );
}

const sweepFromCursor = Effect.fn("ops-backup.sweepFromCursor")(function* (
  env: Env,
  result: MutableSweepResult,
  limits: SweepLimits,
  options: BackupSweepOptions,
): Effect.fn.Return<void, never, OpsRepo> {
  const ops = yield* OpsRepo;
  const stored = yield* ops.getState(SWEEP_CURSOR_KEY);
  let cursor = yield* parseSweepCursor(stored);
  for (;;) {
    const page = yield* ops.listProjectIdsAfter(cursor, OPS_SWEEP_PAGE_SIZE);
    const last = yield* sweepPage(env, page, result, limits, options);
    cursor = last ?? cursor;
    if (result.truncated) {
      break;
    }
    if (page.length < OPS_SWEEP_PAGE_SIZE) {
      cursor = null;
      break;
    }
  }
  yield* ops.setState(SWEEP_CURSOR_KEY, cursor ?? "", yield* Clock.currentTimeMillis);
});

const warnMissingBucketOnce: Effect.Effect<void> = Effect.flatMap(
  Ref.getAndSet(warnedMissingBucket, true),
  (warned) =>
    warned
      ? Effect.void
      : Effect.logWarning(
          "backup bucket binding is not configured; project snapshots are not exported (see docs/SELF_HOSTING.md, Backups)",
        ),
);

export const runBackupSweep = Effect.fn("ops-backup.runBackupSweep")(function* (
  env: Env,
  options: BackupSweepOptions = {},
): Effect.fn.Return<BackupSweepResult, never, OpsRepo> {
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
    yield* warnMissingBucketOnce;
    return result;
  }
  yield* sweepFromCursor(
    env,
    result,
    {
      deadline: (yield* Clock.currentTimeMillis) + (options.budgetMs ?? OPS_SWEEP_BUDGET_MS),
      maxProjects: options.maxProjects ?? OPS_SWEEP_MAX_PROJECTS,
    },
    options,
  );
  return result;
});
