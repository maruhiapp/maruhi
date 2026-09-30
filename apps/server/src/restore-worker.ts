// The restore worker (operator-only, non-HTTP, non-permanent) —
// docs/notes/hosted-ops.md §2-E / §5-2.
//
// Deployed only during a restore operation via
// `cf deploy --mode restore`, and deleted afterward
// via `cf workers delete maruhi-restore`. It has no HTTP
// handler: it is driven by an every-minute cron, and its only work is
// enumerating `restore/jobs/<name>.json` in the evacuation bucket,
// executing them, and writing results (static code + verified values)
// to `restore/results/<name>.json`. Only an operator with write
// access to R2 can place a job.
//
// target:
// - `production`: the production worker's DO namespace (bound via
//   `script_name`). The receiving RPC (opsRestore in chain-do.ts)
//   writes **only into an empty DO** — no overwrite path exists
// - `drill`: this worker's own DO class (RestoreDrillDO — the same
//   implementation as ProjectChainDO). Drills (hosted-ops.md §5-3)
//   never touch the production namespace
//
// The DO name (= the project ID) is not written in the job; it is
// derived from the evacuated chain's genesis (the seq-1
// entry_hash_hex) (no capability is carried on keys, jobs, or
// results).

import type { OpsRestoreOutcome, ProjectChainDO } from "./chain-do.ts";
import { ProjectChainDO as ProjectChainDOClass } from "./chain-do.ts";

/** The drill namespace (a distinct class name inside this worker — never intersects the production namespace). */
export class RestoreDrillDO extends ProjectChainDOClass {}

export interface RestoreEnv {
  readonly OPS_BACKUP_BUCKET: R2Bucket;
  /** The production worker's namespace (the scriptName binding in the restore mode of cloudflare.config.ts). */
  readonly PRODUCTION_PROJECT_CHAIN?: DurableObjectNamespace<ProjectChainDO>;
  readonly DRILL_PROJECT_CHAIN?: DurableObjectNamespace<RestoreDrillDO>;
}

const JOBS_PREFIX = "restore/jobs/";
/** Jobs in flight (claimed — the next cron will not pick up the same job). */
const RUNNING_PREFIX = "restore/running/";
const RESULTS_PREFIX = "restore/results/";

interface RestoreJob {
  readonly objectKey: string;
  readonly target: "production" | "drill";
}

export type RestoreJobResult =
  | {
      readonly status: "ok";
      readonly target: RestoreJob["target"];
      readonly verification: Extract<OpsRestoreOutcome, { kind: "restored" }>;
    }
  | {
      readonly status: "failed";
      /** Static codes only (exception messages are never written) */
      readonly code:
        | "job-malformed"
        | "target-unavailable"
        | "snapshot-missing"
        | "snapshot-malformed"
        | "genesis-missing"
        | "rpc-failed"
        | "unexpected"
        | Extract<OpsRestoreOutcome, { kind: "refused" }>["code"]
        | "no-bucket";
    };

function parseJob(text: string): RestoreJob | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) {
    return null;
  }
  const job = parsed as { objectKey?: unknown; target?: unknown };
  if (
    typeof job.objectKey !== "string" ||
    (job.target !== "production" && job.target !== "drill")
  ) {
    return null;
  }
  return { objectKey: job.objectKey, target: job.target };
}

/**
 * Reads the project ID (the genesis entry's hash) out of an
 * evacuation. Streams the gzipped NDJSON from the top and stops at
 * the seq-1 row of chain_entries (chain_entries is the last table,
 * so this is effectively a full scan — the restore itself is a full
 * scan, and this is accepted as a one-off operational operation).
 */
export async function projectIdFromSnapshot(body: ReadableStream): Promise<string | null> {
  const reader = body
    .pipeThrough(new DecompressionStream("gzip"))
    .pipeThrough(new TextDecoderStream())
    .getReader();
  const scanner = new GenesisScanner();
  let carry = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      return carry === "" ? null : scanner.consider(carry);
    }
    carry += value;
    let index = carry.indexOf("\n");
    while (index !== -1) {
      const found = scanner.consider(carry.slice(0, index));
      if (found !== null) {
        await reader.cancel();
        return found;
      }
      carry = carry.slice(index + 1);
      index = carry.indexOf("\n");
    }
  }
}

interface ScannedLine {
  readonly kind: string;
  readonly table?: string;
  readonly columns?: readonly string[];
  readonly values?: readonly unknown[];
}

class SnapshotMalformedError extends Error {
  constructor() {
    super("snapshot malformed");
  }
}

/** Reads one line as JSON (non-JSON = a corrupted evacuation — folded into a static code). */
function parseScannedLine(line: string): ScannedLine {
  try {
    return JSON.parse(line) as ScannedLine;
  } catch {
    throw new SnapshotMalformedError();
  }
}

/** Remembers the chain_entries column names and picks up the seq-1 row's entry_hash_hex (= the project ID). */
class GenesisScanner {
  #chainColumns: readonly string[] | null = null;

  consider(line: string): string | null {
    if (line === "") {
      return null;
    }
    const parsed = parseScannedLine(line);
    if (parsed.table !== "chain_entries") {
      return null;
    }
    if (parsed.kind === "table") {
      this.#chainColumns = parsed.columns ?? null;
      return null;
    }
    return parsed.kind === "row" && this.#chainColumns !== null
      ? genesisHashOf(parsed.values ?? [], this.#chainColumns)
      : null;
  }
}

function genesisHashOf(values: readonly unknown[], columns: readonly string[]): string | null {
  const hash = values[columns.indexOf("entry_hash_hex")];
  return values[columns.indexOf("seq")] === 1 && typeof hash === "string" ? hash : null;
}

function toJobResult(outcome: OpsRestoreOutcome, target: RestoreJob["target"]): RestoreJobResult {
  switch (outcome.kind) {
    case "restored":
      return { status: "ok", target, verification: outcome };
    case "refused":
      return { status: "failed", code: outcome.code };
    case "no-bucket":
      return { status: "failed", code: "no-bucket" };
  }
}

async function runJob(env: RestoreEnv, job: RestoreJob): Promise<RestoreJobResult> {
  const namespace =
    job.target === "production" ? env.PRODUCTION_PROJECT_CHAIN : env.DRILL_PROJECT_CHAIN;
  if (namespace === undefined) {
    return { status: "failed", code: "target-unavailable" };
  }
  const object = await env.OPS_BACKUP_BUCKET.get(job.objectKey);
  if (object === null) {
    return { status: "failed", code: "snapshot-missing" };
  }
  // A corrupted evacuation (non-gzip, truncated gzip, non-JSON
  // lines) is returned as a static code — letting the exception
  // escape leaves the job in place and the every-minute cron would
  // repeat the same failure forever
  let projectId: string | null;
  try {
    projectId = await projectIdFromSnapshot(object.body);
  } catch (error) {
    console.warn("snapshot scan failed", error instanceof Error ? error.name : "unknown");
    return { status: "failed", code: "snapshot-malformed" };
  }
  if (projectId === null) {
    return { status: "failed", code: "genesis-missing" };
  }
  const stub = namespace.get(namespace.idFromName(projectId));
  try {
    // The workers-types RPC stub types distribute over union return
    // values, so this converts back to the declared type (the same
    // reason as rpcCall in worker-env.ts; the restore worker has no
    // Effect runtime)
    return toJobResult(
      await (stub.opsRestore(job.objectKey) as Promise<OpsRestoreOutcome>),
      job.target,
    );
  } catch (error) {
    console.warn("restore RPC failed", error instanceof Error ? error.name : "unknown");
    return { status: "failed", code: "rpc-failed" };
  }
}

/**
 * Enumerates the jobs, runs them in order, writes the results, and
 * deletes the jobs (1 job = 1 result).
 *
 * A job is claimed before execution by moving it from
 * `restore/jobs/` to `restore/running/`: a restore can take minutes
 * while the cron runs every minute, so running with the job left in
 * place would let the next invocation pick the same job up, and a
 * second RPC (against an already-restored, non-empty DO) would write
 * `not-empty` and overwrite the success result. A job whose worker
 * died mid-execution remains under `restore/running/` = the operator
 * reconciles it against the result and resubmits it
 * (hosted-ops.md §5-2).
 */
export async function processRestoreJobs(env: RestoreEnv): Promise<readonly string[]> {
  const listed = await env.OPS_BACKUP_BUCKET.list({ prefix: JOBS_PREFIX });
  const processed: string[] = [];
  for (const object of listed.objects) {
    // Job name = the key's basename minus .json (the result uses the
    // same name + .json)
    const name = object.key.slice(JOBS_PREFIX.length).replace(/\.json$/, "");
    if (name === "") {
      continue;
    }
    const body = await env.OPS_BACKUP_BUCKET.get(object.key);
    const text = body === null ? null : await body.text();
    // claim: move to running/ before executing (later crons do not
    // look in jobs/)
    const runningKey = `${RUNNING_PREFIX}${name}.json`;
    await env.OPS_BACKUP_BUCKET.put(runningKey, text ?? "");
    await env.OPS_BACKUP_BUCKET.delete(object.key);
    const job = text === null ? null : parseJob(text);
    // Preserve the "one job → one result" invariant even on an
    // unexpected exception (the claim has already removed the job
    // from jobs/ — throwing without writing a result would leave it
    // stranded in running/ awaiting manual reconciliation)
    let result: RestoreJobResult;
    try {
      result = job === null ? { status: "failed", code: "job-malformed" } : await runJob(env, job);
    } catch (error) {
      console.warn(
        "restore job failed unexpectedly",
        error instanceof Error ? error.name : "unknown",
      );
      result = { status: "failed", code: "unexpected" };
    }
    await env.OPS_BACKUP_BUCKET.put(
      `${RESULTS_PREFIX}${name}.json`,
      JSON.stringify(result, null, 2),
      {
        httpMetadata: { contentType: "application/json" },
      },
    );
    await env.OPS_BACKUP_BUCKET.delete(runningKey);
    processed.push(name);
  }
  return processed;
}

export default {
  // No HTTP handler (fetch is undefined = 404). Driven by cron only
  async scheduled(_controller, env, _ctx): Promise<void> {
    await processRestoreJobs(env);
  },
} satisfies ExportedHandler<RestoreEnv>;
