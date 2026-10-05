// The DO → R2 evacuation sweep (worker side) —
// docs/notes/hosted-ops.md §2-D / §4-2 / §4-3.
//
// Called from the hourly cron (index.ts); enumerates D1 `projects` in
// id order and calls each project DO's `opsBackup` RPC. Reads and
// writes are performed by the DO itself under the permit
// (do-snapshot.ts); only aggregates come back here (identifiers stay
// inside D1's ops records).
//
// Bounding (§4-3): a wall-clock budget, a visit-count cap, and cursor
// continuation. The skip rule (§2-D): a project whose watermarks
// (audit seq, chain seq) match its last success and whose last success
// is within OPS_BACKUP_REFRESH_MS is not evacuated (the census size is
// still read every time).
//
// On a deployment without the binding (`OPS_BACKUP_BUCKET`) — the
// self-hosted default — it does nothing, but not silently: it leaves
// one static line per isolate.

import { Effect } from "effect";

import type { OpsBackupAttempt } from "../db.package/index.ts";
import { OpsRepo } from "../db.package/index.ts";
import type { Env, OpsBackupOutcome } from "../do/chain-do.ts";
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

export interface BackupSweepResult {
  readonly enabled: boolean;
  readonly visited: number;
  readonly uploaded: number;
  readonly skipped: number;
  readonly oversize: number;
  readonly failed: number;
  /** Cut short by the budget or the cap (the cursor points mid-way). */
  readonly truncated: boolean;
}

export interface BackupSweepOptions {
  readonly nowMs?: () => number;
  readonly budgetMs?: number;
  readonly maxProjects?: number;
  readonly maxBytes?: number;
  /** For tests: the multipart part length (default is policy). */
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
      // No binding on the DO side (the worker side has one) = a
      // configuration inconsistency; treated the same as an RPC
      // failure
      return { kind: "failure", code: "rpc-failed", storageLevel: null };
  }
}

/** Evacuation of one project (an RPC failure is recorded as failure — retried next sweep). */
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
        Effect.sync((): OpsBackupAttempt => {
          // Static message only (no project ID — the record lives on
          // the D1 side)
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
  } else if (attempt.kind === "oversize") {
    result.oversize += 1;
  } else {
    result.failed += 1;
  }
}

/** Visits one page's worth. Return value = the last project visited (mid-page when the budget ran out). */
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

/** Advances from the cursor to the end (or until the budget runs out), then saves the next cursor. */
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
        // The end: next time starts from the beginning
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
 * The sweep body. Advances from the cursor within the budget; on
 * reaching the end, resets the cursor to the beginning.
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
