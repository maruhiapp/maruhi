import type { ProjectId } from "@maruhi/core";
import { decodeProjectId, decodeProviderUserId, decodeUserId, type UserId } from "@maruhi/core";

import type {
  ImportClassification,
  ImportedIdentity,
  ImportProvisionResult,
} from "./db.package/index.ts";
import { classifyImportedProject, provisionImportedProject } from "./db.package/index.ts";
import type { ProjectChainDO } from "./do/chain-do.ts";
import { ProjectChainDO as ProjectChainDOClass } from "./do/chain-do.ts";
import type { OpsRestoreOutcome } from "./do/do-ops.ts";
import {
  chainOwners,
  identitiesOnChain,
  type SnapshotChainOutcome,
  verifySnapshotChain,
} from "./import-check.ts";

export class RestoreDrillDO extends ProjectChainDOClass {}

export interface RestoreEnv {
  readonly OPS_BACKUP_BUCKET: R2Bucket;
  readonly DB?: D1Database;
  readonly PRODUCTION_PROJECT_CHAIN?: DurableObjectNamespace<ProjectChainDO>;
  readonly DRILL_PROJECT_CHAIN?: DurableObjectNamespace<RestoreDrillDO>;
}

const JOBS_PREFIX = "restore/jobs/";
const RUNNING_PREFIX = "restore/running/";
const RESULTS_PREFIX = "restore/results/";

interface RestoreJob {
  readonly objectKey: string;
  readonly target: "production" | "drill";
  readonly identitiesKey?: string;
}

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
      readonly identities?: ImportOutcome;
    }
  | {
      readonly status: "failed";
      readonly code:
        | "job-malformed"
        | "target-unavailable"
        | "snapshot-missing"
        | "snapshot-malformed"
        | "genesis-missing"
        | "snapshot-chain-invalid"
        | "import-refused"
        | "rpc-failed"
        | "unexpected"
        | Extract<OpsRestoreOutcome, { kind: "refused" }>["code"]
        | "no-bucket";
      readonly identities?: ImportOutcome;
    };

function parseObject(text: string): Record<string, unknown> | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : null;
}

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

interface IdentitiesFile {
  readonly exportedBy: UserId;
  readonly chainHeadHashHex: string;
  readonly identities: readonly ImportedIdentity[];
}

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

interface CheckedImport {
  readonly file: IdentitiesFile;
  readonly projectId: ProjectId;
  readonly owners: readonly UserId[];
  readonly classification: Extract<ImportClassification, { kind: "ok" }>;
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
    checked: { file, projectId: chain.projectId, owners, classification, etag: snapshot.etag },
  };
}

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

export async function projectIdFromSnapshot(body: ReadableStream): Promise<ProjectId | null> {
  const reader = body
    .pipeThrough(new DecompressionStream("gzip"))
    .pipeThrough(new TextDecoderStream())
    .getReader();
  const scanner = new GenesisScanner();
  let carry = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      if (carry === "") {
        return null;
      }
      const hit = scanner.consider(carry);
      return hit === null ? null : decodeProjectId(hit);
    }
    carry += value;
    let index = carry.indexOf("\n");
    while (index !== -1) {
      const found = scanner.consider(carry.slice(0, index));
      if (found !== null) {
        await reader.cancel();
        return decodeProjectId(found);
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

function parseScannedLine(line: string): ScannedLine {
  try {
    return JSON.parse(line) as ScannedLine;
  } catch {
    throw new SnapshotMalformedError();
  }
}

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
  readonly projectId: ProjectId;
  readonly outcome: OpsRestoreOutcome;
  readonly stub: DurableObjectStub<ProjectChainDO>;
}

async function restoreFromSnapshot(
  env: RestoreEnv,
  job: RestoreJob,
  verifiedProjectId?: ProjectId,
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

async function scannedProjectId(
  env: RestoreEnv,
  objectKey: string,
): Promise<
  | { readonly projectId: ProjectId; readonly etag: string }
  | Extract<RestoreJobResult, { status: "failed" }>
> {
  const object = await env.OPS_BACKUP_BUCKET.get(objectKey);
  if (object === null) {
    return { status: "failed", code: "snapshot-missing" };
  }
  let projectId: ProjectId | null;
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

async function runImportJob(env: RestoreEnv, job: ImportJob): Promise<RestoreJobResult> {
  const prechecked = await precheckImport(env, job);
  if (prechecked.kind === "failed") {
    return prechecked.result;
  }
  const { checked } = prechecked;
  const restored = await restoreFromSnapshot(env, job, checked.projectId, checked.etag);
  if (job.target === "drill") {
    const half = "status" in restored ? restored : toJobResult(restored.outcome, job.target);
    return { ...half, identities: rehearsal(checked) };
  }
  if ("status" in restored) {
    return restored;
  }
  const result = toJobResult(restored.outcome, job.target);
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

export async function processRestoreJobs(env: RestoreEnv): Promise<readonly string[]> {
  const listed = await env.OPS_BACKUP_BUCKET.list({ prefix: JOBS_PREFIX });
  const processed: string[] = [];
  for (const object of listed.objects) {
    const name = object.key.slice(JOBS_PREFIX.length).replace(/\.json$/, "");
    if (name === "") {
      continue;
    }
    const body = await env.OPS_BACKUP_BUCKET.get(object.key);
    const text = body === null ? null : await body.text();
    const runningKey = `${RUNNING_PREFIX}${name}.json`;
    await env.OPS_BACKUP_BUCKET.put(runningKey, text ?? "");
    await env.OPS_BACKUP_BUCKET.delete(object.key);
    const job = text === null ? null : parseJob(text);
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
  async scheduled(_controller, env, _ctx): Promise<void> {
    await processRestoreJobs(env);
  },
} satisfies ExportedHandler<RestoreEnv>;
