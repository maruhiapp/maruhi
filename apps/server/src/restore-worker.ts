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

import { decodeProviderUserId, decodeUserId, type UserId } from "@maruhi/core";

import type {
  ImportClassification,
  ImportedIdentity,
  ImportProvisionResult,
} from "./db.package/index.ts";
import { classifyImportedProject, provisionImportedProject } from "./db.package/index.ts";
import type { OpsRestoreOutcome, ProjectChainDO } from "./do/chain-do.ts";
import { ProjectChainDO as ProjectChainDOClass } from "./do/chain-do.ts";
import {
  chainOwners,
  identitiesOnChain,
  type SnapshotChainOutcome,
  verifySnapshotChain,
} from "./import-check.ts";

/** The drill namespace (a distinct class name inside this worker — never intersects the production namespace). */
export class RestoreDrillDO extends ProjectChainDOClass {}

export interface RestoreEnv {
  readonly OPS_BACKUP_BUCKET: R2Bucket;
  /**
   * The production worker's D1 (PF3 — AUTH_SPEC §11-6). An import job
   * (`identitiesKey`) provisions the imported project's members and the
   * projects row here after the DO restore; absent on a deployment that
   * only restores its own snapshots.
   */
  readonly DB?: D1Database;
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
  /**
   * An import (PF3): the key of the identities companion the exporting
   * owner's `maruhi project export` wrote next to the snapshot. When
   * present, the members and the projects row are provisioned in D1
   * after the DO holds the project (restored by this job, or already —
   * a `not-empty` refusal on the same genesis is the retry of a job whose
   * D1 step failed).
   */
  readonly identitiesKey?: string;
}

/**
 * The identities side of an import job (static codes only). `db-unavailable`
 * = no `DB` binding; `db-error` = D1 threw (a unique-key race with a
 * concurrent first login, or an infrastructure failure — resubmit the
 * job); `identity-not-member` / `exporter-not-owner` = the companion names
 * ids the snapshot's verified chain does not confirm (an import binds
 * GitHub accounts only to ids that are current members, and only an owner
 * may export). `rehearsed` = a drill: the checks passed and this is what a
 * production import would do; nothing was provisioned.
 */
export type ImportOutcome =
  | ImportProvisionResult
  | {
      readonly kind: "rehearsed";
      readonly existing: number;
      readonly created: number;
      readonly members: number;
      readonly project: "absent" | "exporter";
    }
  | {
      readonly kind: "refused";
      readonly code:
        | "identities-missing"
        | "identities-malformed"
        | "identities-stale"
        | "identity-not-member"
        | "exporter-not-owner"
        | "db-unavailable"
        | "db-error"
        | "project-not-restored";
    };

export type RestoreJobResult =
  | {
      readonly status: "ok";
      readonly target: RestoreJob["target"];
      readonly verification: Extract<OpsRestoreOutcome, { kind: "restored" }>;
      /** Only on an import job (identitiesKey). */
      readonly identities?: ImportOutcome;
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
        /** An import job whose snapshot carries a chain the DO would not load (checked before the DO is touched). */
        | "snapshot-chain-invalid"
        /** An import job refused by its pre-checks (`identities` says why); the DO was not touched. */
        | "import-refused"
        | "rpc-failed"
        | "unexpected"
        | Extract<OpsRestoreOutcome, { kind: "refused" }>["code"]
        | "no-bucket";
      /** Only on an import job (identitiesKey). */
      readonly identities?: ImportOutcome;
    };

/** JSON text → an object, or null (non-JSON and non-objects are "malformed" — never thrown). */
function parseObject(text: string): Record<string, unknown> | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : null;
}

/** An optional string field: undefined when absent, null when present with another type. */
function optionalString(value: unknown): string | undefined | null {
  return value === undefined || typeof value === "string" ? value : null;
}

function parseJob(text: string): RestoreJob | null {
  const job = parseObject(text);
  if (job === null) {
    return null;
  }
  const { objectKey, target } = job;
  const identitiesKey = optionalString(job["identitiesKey"]);
  if (
    typeof objectKey !== "string" ||
    (target !== "production" && target !== "drill") ||
    identitiesKey === null
  ) {
    return null;
  }
  return { objectKey, target, ...(identitiesKey === undefined ? {} : { identitiesKey }) };
}

/** The identities companion as `maruhi project export` writes it (api-schema's ExportIdentitiesSchema). */
interface IdentitiesFile {
  readonly exportedBy: UserId;
  /** The chain head the companion was read at (the pre-check binds it to the file's). */
  readonly chainHeadHashHex: string;
  readonly identities: readonly ImportedIdentity[];
}

/** One entry of the companion's `identities` (null = malformed). */
function parseIdentity(entry: unknown): ImportedIdentity | null {
  if (typeof entry !== "object" || entry === null) {
    return null;
  }
  const identity = entry as Record<string, unknown>;
  const { userId, provider, providerUserId } = identity;
  const providerLogin = optionalString(identity["providerLogin"]);
  if (
    typeof userId !== "string" ||
    provider !== "github" ||
    typeof providerUserId !== "string" ||
    providerLogin === null
  ) {
    return null;
  }
  // The companion is a wire input: its ids are minted here, where they are parsed
  return {
    userId: decodeUserId(userId),
    provider: "github",
    providerUserId: decodeProviderUserId(providerUserId),
    providerLogin: providerLogin ?? null,
  };
}

function parseIdentities(text: string): IdentitiesFile | null {
  const file = parseObject(text);
  if (file === null) {
    return null;
  }
  const { exportedBy } = file;
  const chainHeadHashHex = file["chainHeadHashHex"];
  const entries = file["identities"];
  if (
    typeof exportedBy !== "string" ||
    typeof chainHeadHashHex !== "string" ||
    !Array.isArray(entries)
  ) {
    return null;
  }
  const identities: ImportedIdentity[] = [];
  for (const entry of entries as unknown[]) {
    const identity = parseIdentity(entry);
    if (identity === null) {
      return null;
    }
    identities.push(identity);
  }
  return { exportedBy: decodeUserId(exportedBy), chainHeadHashHex, identities };
}

type ImportJob = RestoreJob & { readonly identitiesKey: string };

/** What the pre-checks established (the restore and the D1 step build on it). */
interface CheckedImport {
  readonly file: IdentitiesFile;
  /** The genesis hash of the verified chain (the DO's name — no second scan of the file). */
  readonly projectId: string;
  /** The verified chain's owners (a re-run is accepted under any of their project rows). */
  readonly owners: readonly string[];
  readonly classification: Extract<ImportClassification, { kind: "ok" }>;
  /** The etag of the snapshot object the chain was verified from (the DO restores that body or refuses). */
  readonly etag: string;
}

type PrecheckOutcome =
  | { readonly kind: "ok"; readonly checked: CheckedImport }
  | { readonly kind: "failed"; readonly result: Extract<RestoreJobResult, { status: "failed" }> };

function importRefused(code: Extract<ImportOutcome, { kind: "refused" }>["code"]): PrecheckOutcome {
  return {
    kind: "failed",
    result: { status: "failed", code: "import-refused", identities: { kind: "refused", code } },
  };
}

/**
 * The pre-checks of an import (ruling H revision): the companion's shape,
 * the snapshot's chain (verified as the DO verifies it on load), every
 * listed id against that chain's members, and D1 read-only. All of it
 * before the DO is touched, so a refusal leaves the destination as it was
 * and a drill reports what a production import would do.
 */
async function precheckImport(env: RestoreEnv, job: ImportJob): Promise<PrecheckOutcome> {
  const object = await env.OPS_BACKUP_BUCKET.get(job.identitiesKey);
  if (object === null) {
    return importRefused("identities-missing");
  }
  const file = parseIdentities(await object.text());
  if (file === null) {
    return importRefused("identities-malformed");
  }
  const snapshot = await env.OPS_BACKUP_BUCKET.get(job.objectKey);
  if (snapshot === null) {
    return { kind: "failed", result: { status: "failed", code: "snapshot-missing" } };
  }
  const chain: SnapshotChainOutcome = await verifySnapshotChain(snapshot.body);
  if (chain.kind !== "ok") {
    return { kind: "failed", result: { status: "failed", code: chain.kind } };
  }
  // The chain, not the file, decides who is a member
  const onChain = identitiesOnChain(chain.state, file);
  if (onChain !== null) {
    return importRefused(onChain);
  }
  if (env.DB === undefined) {
    return importRefused("db-unavailable");
  }
  const owners = chainOwners(chain.state);
  const classification = await classifyImportedProject(
    env.DB,
    { projectId: chain.projectId, exportedBy: file.exportedBy, identities: file.identities },
    owners,
  );
  if (classification.kind === "refused") {
    return importRefused(classification.code);
  }
  return {
    kind: "ok",
    // The DO restores this body and no other (its etag — ruling H revision, round 4)
    checked: { file, projectId: chain.projectId, owners, classification, etag: snapshot.etag },
  };
}

/** A drill's report of the pre-checks (nothing is provisioned). */
function rehearsal(checked: CheckedImport): ImportOutcome {
  const { classification, file } = checked;
  return {
    kind: "rehearsed",
    existing: classification.existing,
    created: classification.toCreate.length,
    members: file.identities.length,
    project: classification.project,
  };
}

/**
 * The D1 step of a production import: provisions the members and the
 * projects row (db.package/import.ts) once the DO holds the project —
 * restored by this job, or already (`not-empty`), which is the retry of a
 * job whose D1 step failed, or a re-run that provisions the members
 * missing since (ruling I revision).
 */
async function importIdentities(
  db: D1Database,
  checked: CheckedImport,
  restored: RestoredProject,
): Promise<ImportOutcome> {
  const { outcome } = restored;
  if (
    outcome.kind !== "restored" &&
    !(outcome.kind === "refused" && outcome.code === "not-empty")
  ) {
    return { kind: "refused", code: "project-not-restored" };
  }
  const { file } = checked;
  return provisionImportedProject(
    db,
    { projectId: restored.projectId, exportedBy: file.exportedBy, identities: file.identities },
    Date.now(),
    checked.owners,
  );
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

interface RestoredProject {
  readonly projectId: string;
  readonly outcome: OpsRestoreOutcome;
  readonly stub: DurableObjectStub<ProjectChainDO>;
}

/** The restore RPC against the DO named by the snapshot's genesis (the failure codes of the pre-RPC stages are static). */
async function restoreFromSnapshot(
  env: RestoreEnv,
  job: RestoreJob,
  /** The project id the import's pre-check established from the verified chain (no second scan — ruling H revision). */
  verifiedProjectId?: string,
  /** The etag of the snapshot the pre-check verified: the DO restores that body or refuses `object-changed`. */
  etag?: string,
): Promise<RestoredProject | Extract<RestoreJobResult, { status: "failed" }>> {
  const namespace =
    job.target === "production" ? env.PRODUCTION_PROJECT_CHAIN : env.DRILL_PROJECT_CHAIN;
  if (namespace === undefined) {
    return { status: "failed", code: "target-unavailable" };
  }
  const scanned =
    verifiedProjectId === undefined
      ? await scannedProjectId(env, job.objectKey)
      : { projectId: verifiedProjectId, etag };
  if ("status" in scanned) {
    return scanned;
  }
  const { projectId } = scanned;
  const stub = namespace.get(namespace.idFromName(projectId));
  try {
    // The workers-types RPC stub types distribute over union return
    // values, so this converts back to the declared type (the same
    // reason as rpcCall in worker-env.ts; the restore worker has no
    // Effect runtime)
    const outcome = await (stub.opsRestore(
      job.objectKey,
      scanned.etag,
    ) as Promise<OpsRestoreOutcome>);
    return { projectId, outcome, stub };
  } catch (error) {
    console.warn("restore RPC failed", error instanceof Error ? error.name : "unknown");
    return { status: "failed", code: "rpc-failed" };
  }
}

/**
 * The project id from the snapshot's genesis (a plain restore has no
 * verified chain to take it from), with the etag of the object it was
 * read from: the DO restores that body or refuses (a re-put between the
 * scan and the restore would land another file under the DO this one's
 * genesis names — ruling H revision, round 5).
 */
async function scannedProjectId(
  env: RestoreEnv,
  objectKey: string,
): Promise<
  | { readonly projectId: string; readonly etag: string }
  | Extract<RestoreJobResult, { status: "failed" }>
> {
  const object = await env.OPS_BACKUP_BUCKET.get(objectKey);
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
  return projectId === null
    ? { status: "failed", code: "genesis-missing" }
    : { projectId, etag: object.etag };
}

async function runJob(env: RestoreEnv, job: RestoreJob): Promise<RestoreJobResult> {
  if (job.identitiesKey === undefined) {
    const restored = await restoreFromSnapshot(env, job);
    return "status" in restored ? restored : toJobResult(restored.outcome, job.target);
  }
  return runImportJob(env, { ...job, identitiesKey: job.identitiesKey });
}

/** An import job: the pre-checks, then the DO restore, then (production only) the D1 step. */
async function runImportJob(env: RestoreEnv, job: ImportJob): Promise<RestoreJobResult> {
  const prechecked = await precheckImport(env, job);
  if (prechecked.kind === "failed") {
    return prechecked.result;
  }
  const { checked } = prechecked;
  const restored = await restoreFromSnapshot(env, job, checked.projectId, checked.etag);
  if (job.target === "drill") {
    // A drill rehearses the import: the DO half is the drill's own result,
    // the identities half what production would do
    const half = "status" in restored ? restored : toJobResult(restored.outcome, job.target);
    return { ...half, identities: rehearsal(checked) };
  }
  if ("status" in restored) {
    return restored;
  }
  const result = toJobResult(restored.outcome, job.target);
  // The D1 step after the DO holds the project. A D1 failure is folded into
  // a static code like every other failure of the job
  let identities: ImportOutcome;
  try {
    identities =
      env.DB === undefined
        ? { kind: "refused", code: "db-unavailable" }
        : await importIdentities(env.DB, checked, restored);
  } catch (error) {
    console.warn("import provisioning failed", error instanceof Error ? error.name : "unknown");
    identities = { kind: "refused", code: "db-error" };
  }
  return { ...result, identities };
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
