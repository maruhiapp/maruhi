import { readFileSync } from "node:fs";
import { dirname, relative } from "node:path";

import type { UnwrapConfig } from "cf/config";
import { unstable_readConfig } from "wrangler";

import cfConfig from "../cloudflare.config.ts";
import { OPS_HOURLY_CRON } from "../src/ops/ops-policy.ts";
import bundlerConfig from "../wrangler.config.ts";

const configPath = new URL("../wrangler.jsonc", import.meta.url).pathname;
const configDir = dirname(configPath);
const base = unstable_readConfig({ config: configPath });
const hosted = unstable_readConfig({ config: configPath, env: "hosted" });

const cfCtx = { isPreview: false };
const cfSelf = cfConfig({ ...cfCtx, mode: undefined }).worker;
const cfHosted = cfConfig({ ...cfCtx, mode: "hosted" }).worker;
const cfRestore = cfConfig({ ...cfCtx, mode: "restore" }).worker;
if (typeof bundlerConfig !== "function") {
  throw new Error("wrangler.config.ts must export a function of the cf mode");
}
const bundlerSelf = await bundlerConfig({ ...cfCtx, mode: undefined });
const bundlerHosted = await bundlerConfig({ ...cfCtx, mode: "hosted" });
const bundlerRestore = await bundlerConfig({ ...cfCtx, mode: "restore" });

interface NormBinding {
  readonly binding: string;
  readonly name: string;
  readonly id?: string | undefined;
}

interface Norm {
  readonly name: string;
  readonly entrypoint?: string | undefined;
  readonly compatibilityDate?: string | undefined;
  readonly compatibilityFlags: readonly string[];
  readonly workersDev?: boolean | undefined;
  readonly previewUrls?: boolean | undefined;
  readonly cpuMs?: number | undefined;
  readonly doBindings: Record<string, { className: string; scriptName?: string | undefined }>;
  readonly rateLimits: Record<string, { namespace: string; limit: number; period: number }>;
  readonly storeSecrets: Record<string, { storeId: string; secretName: string }>;
  readonly d1?: NormBinding | undefined;
  readonly r2: Record<string, string>;
  readonly crons: readonly string[];
  readonly routes: readonly string[];
  readonly observability?:
    | {
        enabled?: boolean | undefined;
        redactQueryString?: boolean | undefined;
        invocationLogs?: boolean | undefined;
        headSamplingRate?: number | undefined;
      }
    | undefined;
  readonly assets?:
    | {
        directory?: string | undefined;
        htmlHandling?: string | undefined;
        notFoundHandling?: string | undefined;
        runWorkerFirst?: readonly string[] | undefined;
      }
    | undefined;
  readonly doExports: readonly string[];
}

interface WranglerLike {
  name?: string | undefined;
  main?: string | undefined;
  compatibility_date?: string | undefined;
  compatibility_flags?: readonly string[] | undefined;
  workers_dev?: boolean | undefined;
  preview_urls?: boolean | undefined;
  limits?: { cpu_ms?: number } | undefined;
  durable_objects?:
    | {
        bindings?: ReadonlyArray<{
          name: string;
          class_name: string;
          script_name?: string | undefined;
        }>;
      }
    | undefined;
  ratelimits?:
    | ReadonlyArray<{
        name: string;
        namespace_id: string;
        simple: { limit: number; period: number };
      }>
    | undefined;
  secrets_store_secrets?:
    | ReadonlyArray<{
        binding: string;
        store_id: string;
        secret_name: string;
      }>
    | undefined;
  d1_databases?:
    | ReadonlyArray<{
        binding: string;
        database_name?: string | undefined;
        database_id?: string | undefined;
      }>
    | undefined;
  r2_buckets?: ReadonlyArray<{ binding: string; bucket_name?: string | undefined }>;
  triggers?: { crons?: readonly string[] } | undefined;
  routes?:
    | ReadonlyArray<string | { pattern: string; custom_domain?: boolean | undefined }>
    | undefined;
  observability?:
    | {
        enabled?: boolean | undefined;
        redact_query_string?: boolean | undefined;
        logs?: { invocation_logs?: boolean; head_sampling_rate?: number } | undefined;
      }
    | undefined;
  assets?:
    | {
        directory?: string | undefined;
        html_handling?: string | undefined;
        not_found_handling?: string | undefined;
        run_worker_first?: boolean | readonly string[] | undefined;
      }
    | undefined;
  exports?: Record<string, { type?: string; storage?: string }> | undefined;
  migrations?: ReadonlyArray<{ new_sqlite_classes?: readonly string[] }> | undefined;
}

type CfWorker = UnwrapConfig<typeof cfConfig>["worker"];
type KeysOfAny<U> = U extends unknown ? keyof U : never;
type ValueIn<U, K extends PropertyKey> = U extends Readonly<Record<K, infer V>> ? V : undefined;
type CfWorkerLike = { readonly [K in KeysOfAny<CfWorker>]?: ValueIn<CfWorker, K> };

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
    r2[bucket.binding] = bucket.bucket_name ?? "";
  }
  const storeSecrets: Norm["storeSecrets"] = {};
  for (const secret of config.secrets_store_secrets ?? []) {
    storeSecrets[secret.binding] = { storeId: secret.store_id, secretName: secret.secret_name };
  }
  const db = config.d1_databases?.[0];
  const doExports = [
    ...Object.entries(config.exports ?? {})
      .filter(([, v]) => v.type === "durable-object" && v.storage === "sqlite")
      .map(([k]) => k),
    ...(config.migrations ?? []).flatMap((m) => m.new_sqlite_classes ?? []),
  ].toSorted();
  return {
    name: config.name ?? "",
    entrypoint: config.main === undefined ? undefined : relative(configDir, config.main),
    compatibilityDate: config.compatibility_date,
    compatibilityFlags: [...(config.compatibility_flags ?? [])].toSorted(),
    workersDev: config.workers_dev,
    previewUrls: config.preview_urls,
    cpuMs: config.limits?.cpu_ms,
    doBindings,
    rateLimits,
    storeSecrets,
    d1:
      db === undefined
        ? undefined
        : { binding: db.binding, name: db.database_name ?? "", id: db.database_id },
    r2,
    crons: config.triggers?.crons ?? [],
    routes: (config.routes ?? []).map((r) => (typeof r === "string" ? r : r.pattern)),
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
      runWorkerFirst:
        typeof config.assets.run_worker_first === "boolean"
          ? config.assets.run_worker_first
            ? ["/*"]
            : []
          : config.assets.run_worker_first,
    },
    doExports,
  };
}

// fallow-ignore-next-line complexity -- mechanical field-by-field normalization of the two config shapes
function normCf(worker: CfWorkerLike, bundler: BundlerLike): Norm {
  const doBindings: Norm["doBindings"] = {};
  const rateLimits: Norm["rateLimits"] = {};
  const storeSecrets: Norm["storeSecrets"] = {};
  const r2: Norm["r2"] = {};
  let d1: NormBinding | undefined;
  for (const [binding, value] of Object.entries(worker.env ?? {})) {
    switch (value.type) {
      case "durable-object":
        doBindings[binding] = {
          className: value.exportName,
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
      case "secrets-store-secret":
        storeSecrets[binding] = { storeId: value.storeId, secretName: value.secretName };
        break;
      case "d1":
        d1 = { binding, name: value.name ?? "", id: value.id };
        break;
      case "r2":
        r2[binding] = value.name ?? "";
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
    compatibilityFlags: [...(worker.compatibilityFlags ?? [])].toSorted(),
    workersDev: worker.workersDev,
    previewUrls: worker.previewUrls,
    cpuMs: worker.limits?.cpuMs,
    doBindings,
    rateLimits,
    storeSecrets,
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

const wBase = normWrangler(base);
const wHosted = normWrangler(hosted);
const cSelf = normCf(cfSelf, bundlerSelf);
const cHosted = normCf(cfHosted, bundlerHosted);
const cRestore = normCf(cfRestore, bundlerRestore);

expectSame(
  "self-host worker (wrangler.jsonc vs cloudflare.config.ts)",
  { ...wBase, storeSecrets: undefined },
  { ...cSelf, storeSecrets: undefined },
);
expectSame(
  "hosted worker (env.hosted vs --mode hosted)",
  { ...wHosted, storeSecrets: undefined },
  { ...cHosted, storeSecrets: undefined },
);

const HOSTED_SECRET_NAMES = [
  "GITHUB_CLIENT_ID",
  "GITHUB_CLIENT_SECRET",
  "SERVER_ENC_KEY_IKM",
  "OPS_ALERT_WEBHOOK_URL",
];
expectSame(
  "cf hosted: secrets store bindings (names)",
  Object.keys(cHosted.storeSecrets).toSorted(),
  [...HOSTED_SECRET_NAMES].toSorted(),
);
for (const name of HOSTED_SECRET_NAMES) {
  expectSame(
    `cf hosted: secrets store binding ${name} (secret name)`,
    cHosted.storeSecrets[name]?.secretName,
    name,
  );
}
const hostedStoreIds = new Set(Object.values(cHosted.storeSecrets).map((s) => s.storeId));
if (hostedStoreIds.size !== 1 || hostedStoreIds.has("")) {
  failures.push(
    `cf hosted: secrets store bindings must share exactly one non-empty store id (got ${[...hostedStoreIds].join(", ")})`,
  );
}
for (const [label, norm] of [
  ["wrangler self-host", wBase],
  ["wrangler hosted", wHosted],
  ["cf self-host", cSelf],
  ["cf restore", cRestore],
] as const) {
  expectSame(`${label}: no secrets store bindings`, norm.storeSecrets, {});
}

// fallow-ignore-next-line complexity -- sequential invariant assertions; splitting them would obscure the checklist
function checkHostedInvariants(prefix: string, self: Norm, env: Norm): void {
  expectSame(`${prefix}: durable_objects.bindings`, self.doBindings, env.doBindings);

  for (const [name, limit] of Object.entries(self.rateLimits)) {
    const counterpart = env.rateLimits[name];
    if (counterpart === undefined) {
      failures.push(`${prefix}: ratelimits.${name}: missing in hosted`);
      continue;
    }
    expectSame(`${prefix}: ratelimits.${name}`, limit, counterpart);
  }

  if (self.d1 === undefined || env.d1 === undefined) {
    failures.push(
      `${prefix}: d1_databases: both the self-host default and hosted must declare the DB binding`,
    );
  } else {
    expectSame(`${prefix}: d1_databases.binding`, self.d1.binding, env.d1.binding);
    expectSame(`${prefix}: d1_databases.database_name`, self.d1.name, env.d1.name);
  }

  if (!("OPS_BACKUP_BUCKET" in env.r2)) {
    failures.push(`${prefix}: r2_buckets: hosted must bind OPS_BACKUP_BUCKET`);
  }
  if (Object.keys(self.r2).length !== 0) {
    failures.push(`${prefix}: r2_buckets: the self-host config must not declare R2 buckets`);
  }

  expectSame(`${prefix}: triggers.crons`, self.crons, env.crons);

  if (env.observability?.invocationLogs !== false) {
    failures.push(
      `${prefix}: observability: hosted must set logs.invocation_logs to false (request URLs carry capabilities)`,
    );
  }
  if (env.observability?.redactQueryString !== true) {
    failures.push(
      `${prefix}: observability: hosted must set redact_query_string to true (query strings carry OAuth codes)`,
    );
  }

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

const cProductionBinding = cRestore.doBindings["PRODUCTION_PROJECT_CHAIN"];
if (cProductionBinding?.scriptName !== cHosted.name) {
  failures.push(
    `cloudflare.config.ts (mode restore): PRODUCTION_PROJECT_CHAIN worker (${String(cProductionBinding?.scriptName)}) must equal the hosted worker name (${cHosted.name})`,
  );
}

for (const [label, worker] of [
  ["cf self-host", cSelf],
  ["cf hosted", cHosted],
  ["cf restore", cRestore],
] as const) {
  expectSame(`${label}: compatibilityDate`, worker.compatibilityDate, cSelf.compatibilityDate);
  expectSame(`${label}: compatibilityFlags`, worker.compatibilityFlags, [
    "no_nodejs_compat",
    "no_nodejs_compat_v2",
  ]);
}

if (cRestore.workersDev !== false || cRestore.routes.length > 0) {
  failures.push("cf restore: must not expose a serving origin (workers.dev/route)");
}
expectSame("cf restore: doExports", cRestore.doExports, ["RestoreDrillDO"]);
if (cRestore.doBindings["DRILL_PROJECT_CHAIN"] === undefined) {
  failures.push("cf restore: must bind DRILL_PROJECT_CHAIN");
}
expectSame("cf restore: d1 (must equal the hosted worker's)", cRestore.d1, cHosted.d1);

const alchemySource = readFileSync(new URL("../../../alchemy.run.ts", import.meta.url), "utf8");

function alchemyLiteral(label: string, pattern: RegExp): string {
  const match = alchemySource.match(pattern);
  if (match?.[1] === undefined) {
    failures.push(`alchemy.run.ts: ${label}: pattern not found (extraction fails closed)`);
    return "";
  }
  return match[1];
}

function normalizeRepoPath(path: string): string {
  const segments = path.split("/").filter((segment) => segment !== "" && segment !== ".");
  const out: string[] = [];
  for (const segment of segments) {
    if (segment === "..") {
      out.pop();
    } else {
      out.push(segment);
    }
  }
  return out.join("/");
}

function alchemyStrings(label: string, pattern: RegExp): string[] {
  const match = alchemySource.match(pattern);
  if (match?.[1] === undefined) {
    failures.push(`alchemy.run.ts: ${label}: pattern not found (extraction fails closed)`);
    return [];
  }
  return [...match[1].matchAll(/"([^"]+)"/g)].map((m) => m[1] ?? "");
}

expectSame(
  "alchemy: hosted worker name",
  alchemyLiteral("hosted worker name", /Cloudflare\.Worker\("HostedServer", \{\s*name: "([^"]+)"/),
  cHosted.name,
);
expectSame(
  "alchemy: site worker name",
  alchemyLiteral("site worker name", /Cloudflare\.Worker\("Site", \{\s*name: "([^"]+)"/),
  "maruhi-site",
);
expectSame(
  "alchemy: worker domains",
  [...alchemySource.matchAll(/domain: "([^"]+)"/g)].map((m) => m[1]),
  [cHosted.routes[0], "maruhi.app"],
);
expectSame(
  "alchemy: stack name",
  alchemyLiteral("stack name", /Alchemy\.Stack\(\s*"([^"]+)"/),
  "maruhi",
);
expectSame(
  "alchemy: hosted main",
  alchemyLiteral("hosted main", /main: "([^"]+)"/),
  `apps/server/${cHosted.entrypoint ?? ""}`,
);
expectSame(
  "alchemy: assets directories (hosted, then site)",
  [...alchemySource.matchAll(/directory: "([^"]+)"/g)].map((m) => m[1]),
  [normalizeRepoPath(`apps/server/${cHosted.assets?.directory ?? ""}`), "apps/site/dist"],
);
expectSame(
  "alchemy: D1 database name",
  alchemyLiteral("D1 database name", /D1\.Database\("Database", \{\s*name: "([^"]+)"/),
  cHosted.d1?.name,
);
expectSame(
  "alchemy: R2 bucket name",
  alchemyLiteral("R2 bucket name", /R2\.Bucket\("OpsBackupBucket", \{\s*name: "([^"]+)"/),
  cHosted.r2["OPS_BACKUP_BUCKET"],
);
if (/D1\.Database\.lookup|R2\.Bucket\.lookup/.test(alchemySource)) {
  failures.push(
    "alchemy.run.ts: D1 / R2 must be managed declarations, not lookups (ADR-0012 revision 2)",
  );
}
expectSame(
  "alchemy: D1 migrations directory",
  alchemyLiteral("D1 migrations", /migrations: "([^"]+)"/),
  "apps/server/drizzle",
);
const alchemyLifecycleText = alchemyLiteral(
  "lifecycle rules",
  /lifecycleRules: \[([\s\S]*?)\],\s*cors:/,
);
function alchemyAgeSeconds(chunk: string, transition: string): number | undefined {
  const match = chunk.match(
    new RegExp(`${transition}: \\{ condition: \\{ type: "Age", maxAge: ([\\d_]+) \\} \\}`),
  );
  return match?.[1] === undefined ? undefined : Number(match[1].replaceAll("_", ""));
}
const alchemyLifecycleRules = alchemyLifecycleText
  .split(/\{\s*id: "/)
  .slice(1)
  .map((chunk) => {
    const deleteMaxAge = alchemyAgeSeconds(chunk, "deleteObjectsTransition");
    const abortMaxAge = alchemyAgeSeconds(chunk, "abortMultipartUploadsTransition");
    return {
      id: chunk.slice(0, chunk.indexOf('"')),
      enabled: /enabled: true/.test(chunk),
      hasPrefix: /prefix:/.test(chunk),
      hasStorageClassTransitions: /storageClassTransitions/.test(chunk),
      ...(deleteMaxAge === undefined ? {} : { deleteMaxAge }),
      ...(abortMaxAge === undefined ? {} : { abortMaxAge }),
    };
  });
expectSame("alchemy: R2 lifecycle rules", alchemyLifecycleRules, [
  {
    id: "Default Multipart Abort Rule",
    enabled: true,
    hasPrefix: false,
    hasStorageClassTransitions: false,
    abortMaxAge: 604_800,
  },
  {
    id: "retain-35d",
    enabled: true,
    hasPrefix: false,
    hasStorageClassTransitions: false,
    deleteMaxAge: 3_024_000,
    abortMaxAge: 86_400,
  },
]);
if (!/cors: \[\],\s*domains: \[\],\s*publicAccess: false,/.test(alchemySource)) {
  failures.push(
    "alchemy.run.ts: R2 bucket must declare cors: [], domains: [], publicAccess: false explicitly",
  );
}
function alchemySection(label: string, start: string, end: string): string {
  const startIdx = alchemySource.indexOf(start);
  const endIdx = startIdx === -1 ? -1 : alchemySource.indexOf(end, startIdx + start.length);
  if (startIdx === -1 || endIdx === -1) {
    failures.push(
      `alchemy.run.ts: ${label}: declaration anchors not found (extraction fails closed)`,
    );
    return "";
  }
  return alchemySource.slice(startIdx, endIdx);
}
const alchemyD1Section = alchemySection(
  "D1 declaration",
  "Cloudflare.D1.Database(",
  "Cloudflare.R2.Bucket(",
);
const alchemyR2Section = alchemySection(
  "R2 declaration",
  "Cloudflare.R2.Bucket(",
  "Cloudflare.RateLimit(",
);
if (!alchemyD1Section.includes(".pipe(Alchemy.RemovalPolicy.protect())")) {
  failures.push(
    "alchemy.run.ts: D1 database must be piped through Alchemy.RemovalPolicy.protect()",
  );
}
if (!alchemyR2Section.includes(".pipe(Alchemy.RemovalPolicy.protect())")) {
  failures.push("alchemy.run.ts: R2 bucket must be piped through Alchemy.RemovalPolicy.protect()");
}
function alchemyDeclaration(label: string, start: string): string {
  const startIdx = alchemySource.indexOf(start);
  const pipe = ".pipe(Alchemy.RemovalPolicy.protect())";
  const endIdx = startIdx === -1 ? -1 : alchemySource.indexOf(pipe, startIdx);
  if (startIdx === -1 || endIdx === -1) {
    failures.push(
      `alchemy.run.ts: ${label}: declaration anchors not found (extraction fails closed)`,
    );
    return "";
  }
  return alchemySource.slice(startIdx, endIdx + pipe.length);
}
const alchemyD1Declaration = alchemyDeclaration("D1 declaration", "Cloudflare.D1.Database(");
const alchemyR2Declaration = alchemyDeclaration("R2 declaration", "Cloudflare.R2.Bucket(");
for (const prop of ["jurisdiction", "primaryLocationHint", "readReplication"]) {
  if (alchemyD1Declaration.includes(`${prop}:`)) {
    failures.push(`alchemy.run.ts: D1 database must not declare ${prop} (ADR-0012 revision 2)`);
  }
}
for (const prop of [
  "locationHint",
  "jurisdiction",
  "storageClass",
  "locks",
  "localUploads",
  "forceDestroy",
]) {
  if (alchemyR2Declaration.includes(`${prop}:`)) {
    failures.push(`alchemy.run.ts: R2 bucket must not declare ${prop} (ADR-0012 revision 2)`);
  }
}
if (!alchemySource.includes('kind: "Cloudflare.DurableObject"')) {
  failures.push('alchemy.run.ts: PROJECT_CHAIN: kind "Cloudflare.DurableObject" not found');
}
const alchemyDoClass = alchemyLiteral("DO className", /className: "([^"]+)"/);
expectSame(
  "alchemy: PROJECT_CHAIN class",
  alchemyDoClass,
  cHosted.doBindings["PROJECT_CHAIN"]?.className,
);
expectSame(
  "alchemy: PROJECT_CHAIN storage",
  alchemyLiteral("DO storage", /storage: "([^"]+)"/),
  "sqlite",
);
if (!cHosted.doExports.includes(alchemyDoClass)) {
  failures.push(
    `alchemy.run.ts: PROJECT_CHAIN class (${alchemyDoClass}) must be a sqlite export of the cf hosted worker`,
  );
}
const alchemyRateLimitDecls = new Map<
  string,
  { namespace: string; limit: number; period: number }
>();
for (const m of alchemySource.matchAll(
  /const (\w+) = Cloudflare\.RateLimit\("[^"]+", \{\s*namespaceId: (\d+),\s*simple: \{ limit: (\d+), period: (\d+) \}/g,
)) {
  alchemyRateLimitDecls.set(m[1] ?? "", {
    namespace: m[2] ?? "",
    limit: Number(m[3]),
    period: Number(m[4]),
  });
}
const alchemyRateLimits: Record<string, { namespace: string; limit: number; period: number }> = {};
for (const m of alchemySource.matchAll(/([A-Z][A-Z_]+): (\w+),/g)) {
  const decl = alchemyRateLimitDecls.get(m[2] ?? "");
  if (decl !== undefined) {
    alchemyRateLimits[m[1] ?? ""] = decl;
  }
}
if (Object.keys(alchemyRateLimits).length !== alchemyRateLimitDecls.size) {
  failures.push(
    "alchemy.run.ts: rate limits: every RateLimit declaration must be bound under an env name (extraction fails closed)",
  );
}
expectSame("alchemy: rate limits", alchemyRateLimits, cHosted.rateLimits);
expectSame("alchemy: crons", alchemyStrings("crons", /crons: \[([^\]]+)\]/), [...cHosted.crons]);
expectSame(
  "alchemy: compatibility dates",
  [...alchemySource.matchAll(/date: "([^"]+)"/g)].map((m) => m[1]),
  [cHosted.compatibilityDate, cHosted.compatibilityDate],
);
expectSame(
  "alchemy: compatibility flags",
  alchemyStrings("compatibility flags", /flags: \[([^\]]+)\]/),
  [...cHosted.compatibilityFlags],
);
expectSame(
  "alchemy: cpuMs",
  Number(alchemyLiteral("cpuMs", /cpuMs: ([\d_]+)/).replaceAll("_", "")),
  cHosted.cpuMs,
);
expectSame(
  "alchemy: hosted runWorkerFirst",
  alchemyStrings("runWorkerFirst", /runWorkerFirst: \[([^\]]+)\]/),
  [...(cHosted.assets?.runWorkerFirst ?? [])],
);
expectSame(
  "alchemy: assets htmlHandling (hosted, then site)",
  [...alchemySource.matchAll(/htmlHandling: "([^"]+)"/g)].map((m) => m[1]),
  [cHosted.assets?.htmlHandling, "drop-trailing-slash"],
);
expectSame(
  "alchemy: assets notFoundHandling (hosted, then site)",
  [...alchemySource.matchAll(/notFoundHandling: "([^"]+)"/g)].map((m) => m[1]),
  [cHosted.assets?.notFoundHandling, "404-page"],
);
expectSame(
  "alchemy: observability.enabled",
  alchemyLiteral("observability enabled", /observability: \{\s*enabled: (true|false)/),
  String(cHosted.observability?.enabled),
);
expectSame(
  "alchemy: observability.redactQueryString",
  alchemyLiteral("redactQueryString", /redactQueryString: (true|false)/),
  String(cHosted.observability?.redactQueryString),
);
expectSame(
  "alchemy: observability.logs.invocationLogs",
  alchemyLiteral("invocationLogs", /invocationLogs: (true|false)/),
  String(cHosted.observability?.invocationLogs),
);
expectSame(
  "alchemy: observability.logs.headSamplingRate",
  Number(alchemyLiteral("headSamplingRate", /headSamplingRate: ([\d.]+)/)),
  cHosted.observability?.headSamplingRate,
);
if (!/logs: \{ enabled: true,/.test(alchemySource)) {
  failures.push("alchemy.run.ts: observability.logs.enabled must be true (cf hosted parity)");
}
expectSame(
  "alchemy: workersDev (hosted, then site)",
  [...alchemySource.matchAll(/workersDev: (true|false)/g)].map((m) => m[1]),
  ["false", "false"],
);
expectSame(
  "alchemy: secrets store lookup (store name)",
  alchemyLiteral("secrets store lookup", /SecretsStore\.Store\.lookup\(\{\s*name: "([^"]+)"/),
  "default_secrets_store",
);
if (/Config\.Redacted/.test(alchemySource)) {
  failures.push(
    "alchemy.run.ts: no Config.Redacted entries may remain — hosted secrets are Secrets Store lookups (ADR-0012 revision 3)",
  );
}
if (/SecretsStore\.(?:Store|Secret)\("/.test(alchemySource)) {
  failures.push(
    "alchemy.run.ts: the Secrets Store and its secrets must be looked up, not declared as managed resources (ADR-0012 revision 3)",
  );
}
const alchemySecretLookups = new Map<string, string>();
for (const m of alchemySource.matchAll(
  /const (\w+) = Cloudflare\.SecretsStore\.Secret\.lookup\(\{\s*storeId: secretsStore\.storeId,\s*name: "([^"]+)"/g,
)) {
  alchemySecretLookups.set(m[2] ?? "", m[1] ?? "");
}
expectSame(
  "alchemy: secrets store lookups (secret names)",
  [...alchemySecretLookups.keys()].toSorted(),
  [...HOSTED_SECRET_NAMES].toSorted(),
);
expectSame(
  "alchemy <-> cf hosted: store-bound secret names agree",
  [...alchemySecretLookups.keys()].toSorted(),
  Object.keys(cHosted.storeSecrets).toSorted(),
);
const alchemyHostedSection = alchemySection(
  "hosted worker declaration",
  'Cloudflare.Worker("HostedServer"',
  'Cloudflare.Worker("Site"',
);
const alchemyHostedEnv = alchemyHostedSection.match(/env: \{([\s\S]*?)\n      \}/)?.[1] ?? "";
if (alchemyHostedEnv === "") {
  failures.push("alchemy.run.ts: hosted worker env block not found (extraction fails closed)");
}
for (const [secretName, variable] of alchemySecretLookups) {
  if (!new RegExp(`${secretName}: ${variable},`).test(alchemyHostedEnv)) {
    failures.push(
      `alchemy.run.ts: hosted secret ${secretName} must be bound in the hosted worker env as ${secretName}: ${variable}`,
    );
  }
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`check-hosted-config: ${failure}`);
  }
  process.exit(1);
}
console.log(
  "check-hosted-config: hosted mirrors the top-level bindings, cloudflare.config.ts matches wrangler.jsonc, and alchemy.run.ts matches the hosted worker",
);
