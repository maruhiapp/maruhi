// wrangler.jsonc の hosted 環境(docs/notes/hosted-ops.md §2-F)の drift 検査。
//
// wrangler の名前付き環境は durable_objects / d1_databases / ratelimits / r2_buckets を
// 継承しない(環境ごとに再宣言)。再宣言の写しが最上位(セルフホストの既定)から
// ずれると、hosted だけレート制限の値が古い等の不整合が黙って起きるため、
// 「hosted の宣言は最上位の宣言を包含し、同名の宣言は等しい」ことを CI(8c)で検査する。
//
// 実行: `bun scripts/check-hosted-config.ts`(apps/server で。Node 側 — wrangler の
// unstable_readConfig で両環境の実効設定を読む)。

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

// DO binding(名前・クラス)は同一
expectSame(
  "durable_objects.bindings",
  base.durable_objects.bindings,
  hosted.durable_objects.bindings,
);

// ratelimits: 最上位の各 binding が hosted に同じ値で存在する
const hostedLimits = new Map(hosted.ratelimits.map((limit) => [limit.name, limit]));
for (const limit of base.ratelimits) {
  const counterpart = hostedLimits.get(limit.name);
  if (counterpart === undefined) {
    failures.push(`ratelimits.${limit.name}: missing in env.hosted`);
    continue;
  }
  expectSame(`ratelimits.${limit.name}`, limit, counterpart);
}

// D1: binding 名・database_name・migrations の配置は同一(database_id は運営が差し替える)
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

// hosted 固有: 退避バケットの binding 名は src/chain-do.ts の Env と一致
if (!hosted.r2_buckets.some((bucket) => bucket.binding === "OPS_BACKUP_BUCKET")) {
  failures.push("r2_buckets: env.hosted must bind OPS_BACKUP_BUCKET");
}
// 最上位(セルフホストの既定)は R2 を要求しない(R2 未契約のアカウントの deploy を壊さない)
if (base.r2_buckets.length !== 0) {
  failures.push(
    "r2_buckets: the top-level config must not declare R2 buckets (self-hosting default)",
  );
}

// cron は継承される。毎時 cron の文字列は index.ts の分岐条件そのもの(OPS_HOURLY_CRON):
// ずれると毎時ジョブが日次側へ落ちて退避と評価が無言で止まるため、実設定と突き合わせる
expectSame("triggers.crons", base.triggers.crons, hosted.triggers.crons);
if (!(base.triggers.crons as readonly string[]).includes(OPS_HOURLY_CRON)) {
  failures.push(
    `triggers.crons: OPS_HOURLY_CRON (${OPS_HOURLY_CRON}) is not declared in triggers.crons`,
  );
}

// Workers Logs の invocation log はリクエスト URL(パス + クエリ = capability・OAuth code)を
// 本文に含むため、hosted 環境では必ず無効にする(hosted-design.md §5-1 — 集計メトリクスのみ)
if (hosted.observability?.logs?.invocation_logs !== false) {
  failures.push(
    "observability: env.hosted must set observability.logs.invocation_logs to false (request URLs carry capabilities)",
  );
}
// 二重化: クエリ(OAuth code 等)はログ・トレースの URL から常に落とす(wrangler 4.128)
if (hosted.observability?.redact_query_string !== true) {
  failures.push(
    "observability: env.hosted must set observability.redact_query_string to true (query strings carry OAuth codes)",
  );
}

// 復元 worker は本番(hosted)の DO 名前空間へ script_name で束縛する。名前付き環境は
// `<name>-<env>` の別 Worker を公開するため、束縛先は env.hosted の実効 name と一致
// していなければならない(不一致はインシデント時にだけ発覚する最悪の場所)
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
