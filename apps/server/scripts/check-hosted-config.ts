// Drift check for the hosted environment of wrangler.jsonc
// (docs/notes/hosted-ops.md §2-F).
//
// wrangler named environments do not inherit durable_objects / d1_databases /
// ratelimits / r2_buckets (they are re-declared per environment). If a
// re-declared copy drifts from the top level (the self-host default),
// inconsistencies like stale rate-limit values only in hosted happen silently,
// so CI (8c) checks that "hosted's declarations include the top-level
// declarations, and same-named declarations are equal".
//
// Run: `bun scripts/check-hosted-config.ts` (in apps/server. Node side — reads
// the effective config of both environments via wrangler's unstable_readConfig).

import { unstable_readConfig } from "wrangler";

import { OPS_HOURLY_CRON } from "../src/ops-policy.ts";

const configPath = new URL("../wrangler.jsonc", import.meta.url).pathname;
const base = unstable_readConfig({ config: configPath });
const hosted = unstable_readConfig({ config: configPath, env: "hosted" });
const restore = unstable_readConfig({
  config: new URL("../wrangler.restore.jsonc", import.meta.url).pathname,
});

const failures: string[] = [];

function expectSame(label: string, a: unknown, b: unknown): void {
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    failures.push(`${label}: hosted differs from the top-level declaration`);
  }
}

// DO bindings (name and class) are identical
expectSame(
  "durable_objects.bindings",
  base.durable_objects.bindings,
  hosted.durable_objects.bindings,
);

// ratelimits: each top-level binding exists in hosted with the same value
const hostedLimits = new Map(hosted.ratelimits.map((limit) => [limit.name, limit]));
for (const limit of base.ratelimits) {
  const counterpart = hostedLimits.get(limit.name);
  if (counterpart === undefined) {
    failures.push(`ratelimits.${limit.name}: missing in env.hosted`);
    continue;
  }
  expectSame(`ratelimits.${limit.name}`, limit, counterpart);
}

// D1: binding name, database_name, and migrations placement are identical
// (operations substitutes database_id)
const baseDb = base.d1_databases[0];
const hostedDb = hosted.d1_databases[0];
if (baseDb === undefined || hostedDb === undefined) {
  failures.push("d1_databases: both the top level and env.hosted must declare the DB binding");
} else {
  expectSame("d1_databases.binding", baseDb.binding, hostedDb.binding);
  expectSame("d1_databases.database_name", baseDb.database_name, hostedDb.database_name);
  expectSame("d1_databases.migrations_dir", baseDb.migrations_dir, hostedDb.migrations_dir);
  expectSame(
    "d1_databases.migrations_pattern",
    baseDb.migrations_pattern,
    hostedDb.migrations_pattern,
  );
}

// hosted-only: the evacuation bucket's binding name matches Env in
// src/chain-do.ts
if (!hosted.r2_buckets.some((bucket) => bucket.binding === "OPS_BACKUP_BUCKET")) {
  failures.push("r2_buckets: env.hosted must bind OPS_BACKUP_BUCKET");
}
// The top level (self-host default) must not require R2 (so deploy does not
// break on accounts without an R2 subscription)
if (base.r2_buckets.length !== 0) {
  failures.push(
    "r2_buckets: the top-level config must not declare R2 buckets (self-hosting default)",
  );
}

// crons are inherited. The hourly cron string is the branch condition in
// index.ts itself (OPS_HOURLY_CRON): if it drifts, the hourly job falls to the
// daily side and evacuation and evaluation silently stop, so cross-check it
// against the real config
expectSame("triggers.crons", base.triggers.crons, hosted.triggers.crons);
if (!(base.triggers.crons as readonly string[]).includes(OPS_HOURLY_CRON)) {
  failures.push(
    `triggers.crons: OPS_HOURLY_CRON (${OPS_HOURLY_CRON}) is not declared in triggers.crons`,
  );
}

// Workers Logs invocation logs contain the request URL (path + query =
// capability / OAuth code) in their body, so they must be disabled in the
// hosted environment (hosted-design.md §5-1 — aggregated metrics only)
if (hosted.observability?.logs?.invocation_logs !== false) {
  failures.push(
    "observability: env.hosted must set observability.logs.invocation_logs to false (request URLs carry capabilities)",
  );
}
// Defense in depth: always drop the query string (OAuth code etc.) from the
// URL in logs and traces (wrangler 4.128)
if (hosted.observability?.redact_query_string !== true) {
  failures.push(
    "observability: env.hosted must set observability.redact_query_string to true (query strings carry OAuth codes)",
  );
}

// Single-origin invariant (owner ruling — hosted-ops.md §7): the origin of
// the auth endpoints (OAuth callback, __Host- cookie, CLI server URL) is
// pinned to one custom domain; workers.dev must not survive as a second
// origin. If it drifts, `maruhi-server-hosted.<sub>.workers.dev` silently
// comes back (pinned by this config check)

if (hosted.workers_dev !== false) {
  failures.push(
    "workers_dev: env.hosted must set workers_dev to false (auth endpoints must have a single origin)",
  );
}
const hostedRoutes = hosted.routes ?? [];
if (hostedRoutes.length === 0) {
  failures.push("routes: env.hosted must declare the product route (custom domain)");
}

// The restore worker binds to the production (hosted) DO namespace via
// script_name. Because a named environment publishes a separate Worker called
// `<name>-<env>`, the bind target must equal the effective name of env.hosted
// (a mismatch is the worst place — it only surfaces during an incident)
const productionBinding = restore.durable_objects.bindings.find(
  (binding) => binding.name === "PRODUCTION_PROJECT_CHAIN",
);
if (productionBinding === undefined) {
  failures.push("wrangler.restore.jsonc: PRODUCTION_PROJECT_CHAIN binding is missing");
} else if (productionBinding.script_name !== hosted.name) {
  failures.push(
    `wrangler.restore.jsonc: PRODUCTION_PROJECT_CHAIN.script_name (${String(productionBinding.script_name)}) must equal the hosted worker name (${String(hosted.name)})`,
  );
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`check-hosted-config: ${failure}`);
  }
  process.exit(1);
}
console.log("check-hosted-config: env.hosted mirrors the top-level bindings");
