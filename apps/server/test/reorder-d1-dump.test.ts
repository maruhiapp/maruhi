// scripts/reorder-d1-dump.ts(D1 復元 runbook の道具 — hosted-ops.md §5-1 (3))の純関数部を
// 合成ダンプで固定する。2026-09-03 の演習で素の import が 2 回失敗した形(子表 → 親表の順・
// `PRAGMA defer_foreign_keys` が効かない)を最小の入力で再現する(PR #139 pullfrog 指摘)。
import { describe, expect, it } from "vitest";

import { reorderD1Dump, UnclassifiedStatementsError } from "../scripts/reorder-d1-dump.lib.ts";

const dump = `PRAGMA defer_foreign_keys=TRUE;
CREATE TABLE \`api_tokens\` (
\t\`id\` text PRIMARY KEY,
\t\`user_id\` text NOT NULL,
\tCONSTRAINT \`fk\` FOREIGN KEY (\`user_id\`) REFERENCES \`users\`(\`id\`)
);
INSERT INTO "api_tokens" ("id","user_id") VALUES('t1','u1');
CREATE TABLE \`memberships\` (
\t\`org_id\` text NOT NULL REFERENCES \`organizations\`(\`id\`),
\t\`user_id\` text NOT NULL REFERENCES \`users\`(\`id\`)
);
INSERT INTO "memberships" ("org_id","user_id") VALUES('o1','u1');
CREATE TABLE \`organizations\` (
\t\`id\` text PRIMARY KEY
);
INSERT INTO "organizations" ("id") VALUES('o1');
CREATE TABLE \`users\` (
\t\`id\` text PRIMARY KEY
);
INSERT INTO "users" ("id") VALUES('u1');
INSERT INTO "users" ("id") VALUES('u2');
DELETE FROM sqlite_sequence;
INSERT INTO "sqlite_sequence" ("name","seq") VALUES('x',1);
CREATE UNIQUE INDEX \`tok_user\` ON \`api_tokens\` (\`user_id\`);
`;

function kinds(sql: string): string[] {
  return sql
    .split("\n")
    .filter((line) => /^(?:PRAGMA|CREATE|INSERT|DELETE)/.test(line))
    .map((line) => line.replace(/\s*\(.*$/, "").replace(/ VALUES.*$/, ""));
}

describe("reorder-d1-dump", () => {
  it("puts CREATE TABLE first, then INSERTs parents-before-children, then indexes", () => {
    const { sql, summary } = reorderD1Dump(dump);
    expect(kinds(sql)).toEqual([
      "PRAGMA defer_foreign_keys=TRUE;",
      "CREATE TABLE `api_tokens`",
      "CREATE TABLE `memberships`",
      "CREATE TABLE `organizations`",
      "CREATE TABLE `users`",
      // CREATE の無い sqlite_sequence は先頭、その後 親(organizations / users)→ 子
      "DELETE FROM sqlite_sequence;",
      'INSERT INTO "sqlite_sequence"',
      'INSERT INTO "organizations"',
      'INSERT INTO "users"',
      'INSERT INTO "users"',
      'INSERT INTO "api_tokens"',
      'INSERT INTO "memberships"',
      "CREATE UNIQUE INDEX `tok_user` ON `api_tokens`",
    ]);
    expect(summary.insertOrder).toEqual([
      "sqlite_sequence",
      "organizations",
      "users",
      "api_tokens",
      "memberships",
    ]);
    expect(summary).toMatchObject({
      statements: 13,
      tables: 4,
      inserts: 7,
      indexes: 1,
      dropped: 0,
    });
  });

  it("keeps the original order of rows within one table (seq order)", () => {
    const { sql } = reorderD1Dump(dump);
    expect(sql.indexOf("VALUES('u1')")).toBeLessThan(sql.indexOf("VALUES('u2')"));
  });

  it("drops BEGIN / COMMIT (the import path executes statements one by one)", () => {
    const { sql, summary } = reorderD1Dump(`BEGIN TRANSACTION;\n${dump}COMMIT;\n`);
    expect(sql).not.toMatch(/^(?:BEGIN|COMMIT)/m);
    expect(summary.dropped).toBe(2);
  });

  it("refuses statements it cannot classify instead of guessing an order (fail-closed)", () => {
    expect(() =>
      reorderD1Dump(`${dump}CREATE TRIGGER t AFTER INSERT ON users BEGIN SELECT 1; END;\n`),
    ).toThrow(UnclassifiedStatementsError);
  });

  it("refuses a foreign-key cycle", () => {
    const cyclic = `CREATE TABLE \`a\` (\n\t\`b_id\` text REFERENCES \`b\`(\`id\`)\n);
CREATE TABLE \`b\` (\n\t\`a_id\` text REFERENCES \`a\`(\`id\`)\n);
`;
    expect(() => reorderD1Dump(cyclic)).toThrow(/foreign-key cycle/);
  });
});
