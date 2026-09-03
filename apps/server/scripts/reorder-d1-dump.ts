// `wrangler d1 export` のダンプを import 可能な順に並べ替える(運用 runbook —
// docs/notes/hosted-ops.md §5-1 (3) / docs/SELF_HOSTING.md "Restoring a D1 export")。
//
// 2026-09-03 のリストア演習(hosted-ops.md §5-3)で判明した実機の挙動:
// - export はテーブルを作成順に「CREATE TABLE → その表の INSERT」の塊で並べるため、
//   外部キーの親表(users)より先に子表(api_tokens 等)の INSERT が現れる
// - 先頭の `PRAGMA defer_foreign_keys=TRUE` は `wrangler d1 execute --file` の
//   import 経路では効かず、`no such table: main.users` / `FOREIGN KEY constraint
//   failed` で止まる
// よって (1) 全 CREATE TABLE → (2) INSERT を外部キー依存の親→子順 → (3) CREATE INDEX
// に並べ替える。BEGIN / COMMIT は落とす(D1 の import は文単位で実行する)。
//
// 前提: 文の切り出しは「行末が `;` の行で 1 文が終わる」(export の INSERT は 1 行、
// CREATE TABLE は複数行で `);` で終わる)。TEXT 値に改行を含む行があると分割が崩れるが、
// 現行スキーマの値は base64 / ハッシュ / 制約付き識別子で改行を含まず、崩れた場合も
// 後片が未分類の文として拒否される(fail-closed)。改行を含む列を足すときはここを見直す。
//
// 使い方(apps/server から): bun scripts/reorder-d1-dump.ts <in.sql> <out.sql>
// 秘密は扱わない(SQL テキストの並べ替えのみ)。復号済みダンプは作業後に削除すること。

import { reorderD1Dump, UnclassifiedStatementsError } from "./reorder-d1-dump.lib.ts";

const [input, output] = process.argv.slice(2);
if (input === undefined || output === undefined) {
  console.error("usage: bun scripts/reorder-d1-dump.ts <in.sql> <out.sql>");
  process.exit(2);
}
try {
  const { sql, summary } = reorderD1Dump(await Bun.file(input).text());
  await Bun.write(output, sql);
  console.log(
    `reordered ${String(summary.statements)} statements: ${String(summary.tables)} tables, ${String(summary.inserts)} inserts, ${String(summary.indexes)} indexes (dropped ${String(summary.dropped)} BEGIN/COMMIT)`,
  );
  console.log(`insert order: ${summary.insertOrder.join(" > ")}`);
} catch (error) {
  if (error instanceof UnclassifiedStatementsError) {
    console.error(error.message);
    for (const statement of error.statements) {
      console.error(`  ${statement.slice(0, 80)}`);
    }
    process.exit(1);
  }
  throw error;
}
