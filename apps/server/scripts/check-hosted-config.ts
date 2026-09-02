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

const configPath = new URL("../wrangler.jsonc", import.meta.url).pathname;
const base = unstable_readConfig({ config: configPath });
const hosted = unstable_readConfig({ config: configPath, env: "hosted" });

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

// cron は継承される(毎時 cron の文字列は src/ops-policy.ts の OPS_HOURLY_CRON と一致 —
// そちらは vitest が固定する)。ここでは両環境で同じであることだけ見る
expectSame("triggers.crons", base.triggers.crons, hosted.triggers.crons);

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`check-hosted-config: ${failure}`);
  }
  process.exit(1);
}
console.log("check-hosted-config: env.hosted mirrors the top-level bindings");
