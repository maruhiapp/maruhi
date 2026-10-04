// Drift check for the Workers deploy configuration
// (docs/notes/hosted-ops.md §2-F).
//
// The repo now carries the deploy config twice:
//   - cloudflare.config.ts — what `cf deploy` / `cf dev` evaluate (the real
//     deploy source; `wrangler.config.ts` supplies the bundler-side
//     assetsDirectory)
//   - wrangler.jsonc — the mirror the test harness still reads
//     (@cloudflare/vitest-plugin only understands wrangler.* config files, and
//     vitest.config.ts / spa-topology.test.ts call unstable_readConfig on it)
// Any drift between the two means tests validate a different worker than the
// one that deploys, so this script normalizes both into one shape and diffs
// them field by field.
//
// It also keeps the original invariant: wrangler/cf "hosted" mode does not
// inherit durable_objects / d1_databases / ratelimits / r2_buckets (they are
// re-declared per mode). If a re-declared copy drifts from the self-host
// default, inconsistencies like stale rate-limit values only in hosted happen
// silently, so CI (8c) checks that "hosted's declarations include the top-level
// declarations, and same-named declarations are equal" — on both config files.
//
// Run: `bun scripts/check-hosted-config.ts` (in apps/server. Node side — reads
// the effective config of both environments via wrangler's unstable_readConfig
// and evaluates cloudflare.config.ts / wrangler.config.ts directly).

import { dirname, relative } from "node:path";

import { unstable_readConfig } from "wrangler";

import cfConfig from "../cloudflare.config.ts";
import { OPS_HOURLY_CRON } from "../src/ops/ops-policy.ts";
import bundlerConfig from "../wrangler.config.ts";

const configPath = new URL("../wrangler.jsonc", import.meta.url).pathname;
const configDir = dirname(configPath);
const base = unstable_readConfig({ config: configPath });
const hosted = unstable_readConfig({ config: configPath, env: "hosted" });

// The ops-only restore worker exists only in cf form (`cf deploy --mode
// restore`): no test spins it up, so it has no wrangler mirror to check

const cfCtx = { isPreview: false };
const cfSelf = cfConfig({ ...cfCtx, mode: undefined }).worker;
const cfHosted = cfConfig({ ...cfCtx, mode: "hosted" }).worker;
const cfRestore = cfConfig({ ...cfCtx, mode: "restore" }).worker;
const bundlerSelf = bundlerConfig({ ...cfCtx, mode: undefined });
const bundlerHosted = bundlerConfig({ ...cfCtx, mode: "hosted" });
const bundlerRestore = bundlerConfig({ ...cfCtx, mode: "restore" });

// ---------------------------------------------------------------------------
// Normalization. Both config formats are folded into one shape so every
// invariant can be asserted identically (wrangler snake_case / named arrays
// vs. cf camelCase / per-binding objects keyed by binding name).
// ---------------------------------------------------------------------------

interface NormBinding {
  readonly binding: string;
  readonly name: string;
  readonly id?: string;
}

interface Norm {
  readonly name: string;
  readonly entrypoint?: string;
  readonly compatibilityDate?: string;
  readonly workersDev?: boolean;
  readonly previewUrls?: boolean;
  readonly cpuMs?: number;
  /** binding -> { className, scriptName (absent for same-worker bindings) } */
  readonly doBindings: Record<string, { className: string; scriptName?: string }>;
  /** binding -> { namespace, limit, period } */
  readonly rateLimits: Record<string, { namespace: string; limit: number; period: number }>;
  readonly d1?: NormBinding;
  /** binding -> bucket name */
  readonly r2: Record<string, string>;
  readonly crons: readonly string[];
  readonly routes: readonly string[];
  readonly observability?: {
    enabled?: boolean;
    redactQueryString?: boolean;
    invocationLogs?: boolean;
    headSamplingRate?: number;
  };
  readonly assets?: {
    directory?: string;
    htmlHandling?: string;
    notFoundHandling?: string;
    runWorkerFirst?: readonly string[];
  };
  /** DO class names exported with sqlite storage */
  readonly doExports: readonly string[];
}

// `unstable_readConfig` returns wrangler's loosely-typed config; this file only
// touches the fields mirrored into the cf config. Structural reads go through
// these small typed views instead of blanket `any`.
interface WranglerLike {
  name?: string;
  main?: string;
  compatibility_date?: string;
  workers_dev?: boolean;
  preview_urls?: boolean;
  limits?: { cpu_ms?: number };
  durable_objects?: {
    bindings?: ReadonlyArray<{
      name: string;
      class_name: string;
      script_name?: string;
    }>;
  };
  ratelimits?: ReadonlyArray<{
    name: string;
    namespace_id: string;
    simple: { limit: number; period: number };
  }>;
  d1_databases?: ReadonlyArray<{
    binding: string;
    database_name: string;
    database_id: string;
  }>;
  r2_buckets?: ReadonlyArray<{ binding: string; bucket_name: string }>;
  triggers?: { crons?: readonly string[] };
  routes?: ReadonlyArray<{ pattern: string; custom_domain?: boolean }>;
  observability?: {
    enabled?: boolean;
    redact_query_string?: boolean;
    logs?: { invocation_logs?: boolean; head_sampling_rate?: number };
  };
  assets?: {
    directory?: string;
    html_handling?: string;
    not_found_handling?: string;
    run_worker_first?: readonly string[];
  };
  exports?: Record<string, { type?: string; storage?: string }>;
  migrations?: ReadonlyArray<{ new_sqlite_classes?: readonly string[] }>;
}

interface CfWorkerLike {
  name?: string;
  entrypoint?: string;
  compatibilityDate?: string;
  workersDev?: boolean;
  previewUrls?: boolean;
  limits?: { cpuMs?: number };
  domains?: readonly string[];
  triggers?: ReadonlyArray<{ type: string; schedule?: string }>;
  env?: Record<
    string,
    | { type: "d1"; name: string; id: string }
    | { type: "durable-object"; worker: string; exportName: string }
    | {
        type: "rate-limit";
        namespace: string;
        simple: { limit: number; period: number };
      }
    | { type: "r2"; name: string }
    | Record<string, never>
  >;
  exports?: Record<string, { type: string; storage?: string }>;
  assets?: {
    htmlHandling?: string;
    notFoundHandling?: string;
    runWorkerFirst?: readonly string[];
  };
  observability?: {
    enabled?: boolean;
    redactQueryString?: boolean;
    logs?: {
      enabled?: boolean;
      invocationLogs?: boolean;
      headSamplingRate?: number;
    };
  };
}

interface BundlerLike {
  assetsDirectory?: string;
}

// fallow-ignore-next-line complexity -- mechanical field-by-field normalization of the two config shapes
function normWrangler(config: WranglerLike): Norm {
  const doBindings: Norm["doBindings"] = {};
  for (const binding of config.durable_objects?.bindings ?? []) {
    doBindings[binding.name] = {
      className: binding.class_name,
      ...(binding.script_name === undefined ? {} : { scriptName: binding.script_name }),
    };
  }
  const rateLimits: Norm["rateLimits"] = {};
  for (const limit of config.ratelimits ?? []) {
    rateLimits[limit.name] = {
      namespace: limit.namespace_id,
      limit: limit.simple.limit,
      period: limit.simple.period,
    };
  }
  const r2: Norm["r2"] = {};
  for (const bucket of config.r2_buckets ?? []) {
    r2[bucket.binding] = bucket.bucket_name;
  }
  const db = config.d1_databases?.[0];
  // Legacy `migrations` (restore) and new-style `exports` both declare sqlite
  // DO classes; normalize to the class-name list either way
  const doExports = [
    ...Object.entries(config.exports ?? {})
      .filter(([, v]) => v.type === "durable-object" && v.storage === "sqlite")
      .map(([k]) => k),
    ...(config.migrations ?? []).flatMap((m) => m.new_sqlite_classes ?? []),
  ].toSorted();
  return {
    name: config.name ?? "",
    // unstable_readConfig absolutizes `main`; the cf side is config-relative
    entrypoint: config.main === undefined ? undefined : relative(configDir, config.main),
    compatibilityDate: config.compatibility_date,
    workersDev: config.workers_dev,
    previewUrls: config.preview_urls,
    cpuMs: config.limits?.cpu_ms,
    doBindings,
    rateLimits,
    d1:
      db === undefined
        ? undefined
        : { binding: db.binding, name: db.database_name, id: db.database_id },
    r2,
    crons: config.triggers?.crons ?? [],
    routes: (config.routes ?? []).map((r) => r.pattern),
    observability: config.observability && {
      enabled: config.observability.enabled,
      redactQueryString: config.observability.redact_query_string,
      invocationLogs: config.observability.logs?.invocation_logs,
      headSamplingRate: config.observability.logs?.head_sampling_rate,
    },
    assets: config.assets && {
      directory: config.assets.directory,
      htmlHandling: config.assets.html_handling,
      notFoundHandling: config.assets.not_found_handling,
      runWorkerFirst: config.assets.run_worker_first,
    },
    doExports,
  };
}

// fallow-ignore-next-line complexity -- mechanical field-by-field normalization of the two config shapes
function normCf(worker: CfWorkerLike, bundler: BundlerLike): Norm {
  const doBindings: Norm["doBindings"] = {};
  const rateLimits: Norm["rateLimits"] = {};
  const r2: Norm["r2"] = {};
  let d1: NormBinding | undefined;
  for (const [binding, value] of Object.entries(worker.env ?? {})) {
    switch (value.type) {
      case "durable-object":
        doBindings[binding] = {
          className: value.exportName,
          // a cf binding always names its worker; a same-worker reference is
          // wrangler's "no script_name" case
          ...(value.worker === worker.name ? {} : { scriptName: value.worker }),
        };
        break;
      case "rate-limit":
        rateLimits[binding] = {
          namespace: value.namespace,
          limit: value.simple.limit,
          period: value.simple.period,
        };
        break;
      case "d1":
        d1 = { binding, name: value.name, id: value.id };
        break;
      case "r2":
        r2[binding] = value.name;
        break;
    }
  }
  const doExports = Object.entries(worker.exports ?? {})
    .filter(([, v]) => v.type === "durable-object" && v.storage === "sqlite")
    .map(([k]) => k)
    .toSorted();
  return {
    name: worker.name ?? "",
    entrypoint: worker.entrypoint,
    compatibilityDate: worker.compatibilityDate,
    workersDev: worker.workersDev,
    previewUrls: worker.previewUrls,
    cpuMs: worker.limits?.cpuMs,
    doBindings,
    rateLimits,
    d1,
    r2,
    crons: (worker.triggers ?? [])
      .filter((t) => t.type === "scheduled")
      .map((t) => t.schedule ?? ""),
    routes: worker.domains ?? [],
    observability: worker.observability && {
      enabled: worker.observability.enabled,
      redactQueryString: worker.observability.redactQueryString,
      invocationLogs: worker.observability.logs?.invocationLogs,
      headSamplingRate: worker.observability.logs?.headSamplingRate,
    },
    assets: worker.assets && {
      // cloudflare.config.ts has no assets.directory — it lives in the
      // bundler shim (wrangler.config.ts)
      directory: bundler.assetsDirectory,
      htmlHandling: worker.assets.htmlHandling,
      notFoundHandling: worker.assets.notFoundHandling,
      runWorkerFirst: worker.assets.runWorkerFirst,
    },
    doExports,
  };
}

const failures: string[] = [];

function expectSame(label: string, a: unknown, b: unknown): void {
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    failures.push(`${label}: ${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
  }
}

// ---------------------------------------------------------------------------
// cf <-> wrangler parity, per environment.
// ---------------------------------------------------------------------------

const wBase = normWrangler(base);
const wHosted = normWrangler(hosted);
const cSelf = normCf(cfSelf, bundlerSelf);
const cHosted = normCf(cfHosted, bundlerHosted);
const cRestore = normCf(cfRestore, bundlerRestore);

expectSame("self-host worker (wrangler.jsonc vs cloudflare.config.ts)", wBase, cSelf);
expectSame("hosted worker (env.hosted vs --mode hosted)", wHosted, cHosted);

// The invariants below are checked on the wrangler mirror as before; the
// parity assertions above carry them to the cf config transitively.

// fallow-ignore-next-line complexity -- sequential invariant assertions; splitting them would obscure the checklist
function checkHostedInvariants(prefix: string, self: Norm, env: Norm): void {
  // DO bindings (name and class) are identical
  expectSame(`${prefix}: durable_objects.bindings`, self.doBindings, env.doBindings);

  // ratelimits: each top-level binding exists in hosted with the same value
  for (const [name, limit] of Object.entries(self.rateLimits)) {
    const counterpart = env.rateLimits[name];
    if (counterpart === undefined) {
      failures.push(`${prefix}: ratelimits.${name}: missing in hosted`);
      continue;
    }
    expectSame(`${prefix}: ratelimits.${name}`, limit, counterpart);
  }

  // D1: binding name and database_name are identical (operations substitutes
  // database_id)
  if (self.d1 === undefined || env.d1 === undefined) {
    failures.push(
      `${prefix}: d1_databases: both the self-host default and hosted must declare the DB binding`,
    );
  } else {
    expectSame(`${prefix}: d1_databases.binding`, self.d1.binding, env.d1.binding);
    expectSame(`${prefix}: d1_databases.database_name`, self.d1.name, env.d1.name);
  }

  // hosted-only: the evacuation bucket's binding name matches Env in
  // src/do/chain-do.ts
  if (!("OPS_BACKUP_BUCKET" in env.r2)) {
    failures.push(`${prefix}: r2_buckets: hosted must bind OPS_BACKUP_BUCKET`);
  }
  // The self-host default must not require R2 (so deploy does not break on
  // accounts without an R2 subscription)
  if (Object.keys(self.r2).length !== 0) {
    failures.push(`${prefix}: r2_buckets: the self-host config must not declare R2 buckets`);
  }

  // crons are identical. The hourly cron string is the branch condition in
  // index.ts itself (OPS_HOURLY_CRON): if it drifts, the hourly job falls to
  // the daily side and evacuation and evaluation silently stop, so cross-check
  // it against the real config
  expectSame(`${prefix}: triggers.crons`, self.crons, env.crons);

  // Workers Logs invocation logs contain the request URL (path + query =
  // capability / OAuth code) in their body, so they must be disabled in the
  // hosted environment (hosted-design.md §5-1 — aggregated metrics only)
  if (env.observability?.invocationLogs !== false) {
    failures.push(
      `${prefix}: observability: hosted must set logs.invocation_logs to false (request URLs carry capabilities)`,
    );
  }
  // Defense in depth: always drop the query string (OAuth code etc.) from the
  // URL in logs and traces
  if (env.observability?.redactQueryString !== true) {
    failures.push(
      `${prefix}: observability: hosted must set redact_query_string to true (query strings carry OAuth codes)`,
    );
  }

  // Single-origin invariant (owner ruling — hosted-ops.md §7): the origin of
  // the auth endpoints (OAuth callback, __Host- cookie, CLI server URL) is
  // pinned to one custom domain; workers.dev must not survive as a second
  // origin
  if (env.workersDev !== false) {
    failures.push(
      `${prefix}: workers_dev: hosted must set workers_dev to false (auth endpoints must have a single origin)`,
    );
  }
  if (env.routes.length === 0) {
    failures.push(`${prefix}: routes: hosted must declare the product route (custom domain)`);
  }
}

checkHostedInvariants("wrangler", wBase, wHosted);
checkHostedInvariants("cf", cSelf, cHosted);

for (const [label, norm] of [
  ["wrangler", wBase],
  ["cf", cSelf],
] as const) {
  if (!norm.crons.includes(OPS_HOURLY_CRON)) {
    failures.push(`${label}: triggers.crons: OPS_HOURLY_CRON (${OPS_HOURLY_CRON}) is not declared`);
  }
}

// The restore worker binds to the production (hosted) DO namespace across
// workers (cf: the binding's `worker` field). The bind target must equal the
// hosted worker's effective name (a mismatch is the worst place — it only
// surfaces during an incident)
const cProductionBinding = cRestore.doBindings["PRODUCTION_PROJECT_CHAIN"];
if (cProductionBinding?.scriptName !== cHosted.name) {
  failures.push(
    `cloudflare.config.ts (mode restore): PRODUCTION_PROJECT_CHAIN worker (${String(cProductionBinding?.scriptName)}) must equal the hosted worker name (${cHosted.name})`,
  );
}

// The restore worker's own shape: no HTTP handler surface, the per-minute
// drill cron, and the drill DO export
if (cRestore.workersDev !== false || cRestore.routes.length > 0) {
  failures.push("cf restore: must not expose a serving origin (workers.dev/route)");
}
expectSame("cf restore: doExports", cRestore.doExports, ["RestoreDrillDO"]);
if (cRestore.doBindings["DRILL_PROJECT_CHAIN"] === undefined) {
  failures.push("cf restore: must bind DRILL_PROJECT_CHAIN");
}
// The restore worker is also the import path (PF3 — pf3-design.md ruling H):
// after the DO restore it provisions the imported project's rows in D1, so
// it must bind the production database — the hosted worker's, under the same
// binding name (`DB` in src/restore-worker.ts) and the same id. Any other
// database would provision the import somewhere the product never reads
expectSame("cf restore: d1 (must equal the hosted worker's)", cRestore.d1, cHosted.d1);

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`check-hosted-config: ${failure}`);
  }
  process.exit(1);
}
console.log(
  "check-hosted-config: hosted mirrors the top-level bindings and cloudflare.config.ts matches wrangler.jsonc",
);
