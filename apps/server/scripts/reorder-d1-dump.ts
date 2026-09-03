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
// 使い方(apps/server から): bun scripts/reorder-d1-dump.ts <in.sql> <out.sql>
// 秘密は扱わない(SQL テキストの並べ替えのみ)。復号済みダンプは作業後に削除すること。

const [input, output] = process.argv.slice(2);
if (input === undefined || output === undefined) {
  console.error("usage: bun scripts/reorder-d1-dump.ts <in.sql> <out.sql>");
  process.exit(2);
}

const text = await Bun.file(input).text();

// 文の切り出し: 行末が `;` で終わる行までを 1 文とする(export の INSERT は 1 行、
// CREATE TABLE は複数行で `);` で終わる)
const statements: string[] = [];
let buffer = "";
for (const line of text.split("\n")) {
  if (line.trim() === "" && buffer === "") {
    continue;
  }
  buffer += (buffer === "" ? "" : "\n") + line;
  if (line.trimEnd().endsWith(";")) {
    statements.push(buffer);
    buffer = "";
  }
}
if (buffer.trim() !== "") {
  statements.push(buffer);
}

const matches = (pattern: RegExp) => (statement: string) => pattern.test(statement);
const pragmas = statements.filter(matches(/^PRAGMA/i));
const tables = statements.filter(matches(/^CREATE TABLE/i));
// `DELETE FROM sqlite_sequence;` は sqlite_sequence の INSERT の直前に置かれる
const inserts = statements.filter(matches(/^(?:INSERT|DELETE FROM sqlite_sequence)/i));
const indexes = statements.filter(matches(/^CREATE (?:UNIQUE )?INDEX/i));
const dropped = statements.filter(matches(/^(?:BEGIN|COMMIT)/i));
const unknown = statements.filter(
  (statement) =>
    !/^(?:PRAGMA|CREATE TABLE|INSERT|DELETE FROM sqlite_sequence|CREATE (?:UNIQUE )?INDEX|BEGIN|COMMIT)/i.test(
      statement,
    ),
);
if (unknown.length > 0) {
  console.error("unclassified statements (refusing to guess an order):");
  for (const statement of unknown) {
    console.error(`  ${statement.slice(0, 80)}`);
  }
  process.exit(1);
}

// 外部キー依存の解決: CREATE TABLE の REFERENCES から 親表の集合を作り、深さ優先で
// 親→子の順に並べる(自己参照は無視。循環は拒否 — 現行スキーマには無い)
function tableNameOf(createStatement: string): string {
  const match = /^CREATE TABLE (?:IF NOT EXISTS )?[`"]?(\w+)[`"]?/i.exec(createStatement);
  if (match?.[1] === undefined) {
    throw new Error(`cannot read the table name: ${createStatement.slice(0, 60)}`);
  }
  return match[1];
}
const parentsOf = new Map<string, ReadonlySet<string>>();
for (const statement of tables) {
  const name = tableNameOf(statement);
  const parents = new Set<string>();
  for (const match of statement.matchAll(/REFERENCES\s+[`"]?(\w+)[`"]?/gi)) {
    if (match[1] !== undefined && match[1] !== name) {
      parents.add(match[1]);
    }
  }
  parentsOf.set(name, parents);
}
// Kahn 法: 親がすべて配置済みの表を毎周まとめて置く(1 周で 1 つも置けなければ循環)
const order: string[] = [];
let remaining = [...parentsOf.keys()];
while (remaining.length > 0) {
  const placed = new Set(order);
  const ready = remaining.filter((name) =>
    [...(parentsOf.get(name) ?? [])].every(
      (parent) => placed.has(parent) || !parentsOf.has(parent),
    ),
  );
  if (ready.length === 0) {
    throw new Error(`foreign-key cycle among: ${remaining.join(", ")}`);
  }
  order.push(...ready);
  remaining = remaining.filter((name) => !ready.includes(name));
}
const rank = new Map(order.map((name, index) => [name, index]));
function targetTableOf(statement: string): string {
  const match = /^(?:INSERT INTO|DELETE FROM)\s+[`"]?(\w+)[`"]?/i.exec(statement);
  return match?.[1] ?? "";
}
// 安定ソート: 同じ表の INSERT は元の順序(seq 順)を保つ
const insertsOrdered = inserts
  .map((statement, index) => ({ statement, index, rank: rank.get(targetTableOf(statement)) ?? -1 }))
  .toSorted((a, b) => a.rank - b.rank || a.index - b.index)
  .map((entry) => entry.statement);

await Bun.write(output, `${[...pragmas, ...tables, ...insertsOrdered, ...indexes].join("\n")}\n`);
console.log(
  `reordered ${String(statements.length)} statements: ${String(tables.length)} tables, ${String(inserts.length)} inserts, ${String(indexes.length)} indexes (dropped ${String(dropped.length)} BEGIN/COMMIT)`,
);
console.log(`insert order: ${[...new Set(insertsOrdered.map(targetTableOf))].join(" > ")}`);
