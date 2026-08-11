// プロジェクト DO のスキーママイグレーション機構(src/do-schema.ts)のテスト。
//
// workerd 実環境の SqlStorage で検証する: (a) 空 DB への全ステップ適用、
// (b) 途中版 DB への残ステップのみの適用、(c) 適用済み DB への再適用 no-op。
// 実 DO(ProjectChainDO)のコンストラクタは runInDurableObject のインスタンス化
// 時点でマイグレーションを適用してしまうため、「空 DB」「途中版 DB」は全テーブルの
// DROP + schema_meta の初期化で再現する。このファイルは専用の DO 名を使い、他の
// テストのプロジェクト DO と storage を共有しない。

import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import type { ProjectDoMigration } from "../src/do-schema.ts";
import {
  applyProjectDoMigrations,
  ensureProjectDoTables,
  PROJECT_DO_MIGRATIONS,
  PROJECT_DO_TABLES,
  readProjectDoSchemaVersion,
} from "../src/do-schema.ts";

/** このファイル専用 DO の SqlStorage 上で body を実行する。 */
async function withSql<T>(body: (sql: SqlStorage) => T): Promise<T> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName("do-schema-migrations-test"));
  return await runInDurableObject(stub, (_instance, state) => body(state.storage.sql));
}

/** 全ユーザーテーブル(_cf_ 内部テーブル以外)を DROP し、マイグレーション未適用の空 DB に戻す。 */
function dropAllUserTables(sql: SqlStorage): void {
  const names = sql
    .exec(
      `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '\\_cf\\_%' ESCAPE '\\' AND name NOT LIKE 'sqlite_%'`,
    )
    .toArray()
    .map((row) => String(row.name));
  for (const name of names) {
    sql.exec(`DROP TABLE ${name}`);
  }
}

function userTableNames(sql: SqlStorage): Set<string> {
  return new Set(
    sql
      .exec(
        `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '\\_cf\\_%' ESCAPE '\\' AND name NOT LIKE 'sqlite_%'`,
      )
      .toArray()
      .map((row) => String(row.name)),
  );
}

describe("project DO schema migrations", () => {
  it("空 DB への適用で全ステップが走り最新版になる", async () => {
    await withSql((sql) => {
      dropAllUserTables(sql);
      expect(readProjectDoSchemaVersion(sql)).toBe(0);

      ensureProjectDoTables(sql);

      expect(readProjectDoSchemaVersion(sql)).toBe(PROJECT_DO_MIGRATIONS.length);
      const tables = userTableNames(sql);
      for (const table of PROJECT_DO_TABLES) {
        expect(tables).toContain(table);
      }
      // tables 宣言(PROJECT_DO_TABLES の導出元)が実スキーマから乖離していないこと:
      // 実テーブル = 宣言テーブル + schema_meta
      expect(tables).toEqual(new Set([...PROJECT_DO_TABLES, "schema_meta"]));
    });
  });

  it("途中版 DB への適用は未適用ステップだけを順に走らせる", async () => {
    await withSql((sql) => {
      dropAllUserTables(sql);
      const applied: string[] = [];
      const stepOne: ProjectDoMigration = {
        tables: ["mig_test_a"],
        apply(s) {
          applied.push("one");
          s.exec(`CREATE TABLE mig_test_a (id INTEGER PRIMARY KEY)`);
        },
      };
      const stepTwo: ProjectDoMigration = {
        tables: ["mig_test_b"],
        apply(s) {
          applied.push("two");
          s.exec(`CREATE TABLE mig_test_b (id INTEGER PRIMARY KEY)`);
        },
      };

      // step 1 だけ適用された「旧版 DB」を作る
      applyProjectDoMigrations(sql, [stepOne]);
      expect(readProjectDoSchemaVersion(sql)).toBe(1);
      expect(applied).toEqual(["one"]);

      // ステップが増えた新コードでの起動に相当。step 1 は再実行されない
      // (stepOne の CREATE TABLE は IF NOT EXISTS なしのため、再実行されれば throw する)
      applyProjectDoMigrations(sql, [stepOne, stepTwo]);
      expect(readProjectDoSchemaVersion(sql)).toBe(2);
      expect(applied).toEqual(["one", "two"]);
      expect(userTableNames(sql)).toEqual(new Set(["schema_meta", "mig_test_a", "mig_test_b"]));

      // 後片付け: 実スキーマへ戻す(このファイル専用 DO だが、状態を残さない)
      dropAllUserTables(sql);
      ensureProjectDoTables(sql);
    });
  });

  it("適用済み DB への再適用は no-op", async () => {
    await withSql((sql) => {
      dropAllUserTables(sql);
      ensureProjectDoTables(sql);
      const before = readProjectDoSchemaVersion(sql);
      sql.exec(
        `INSERT INTO chain_entries (seq, entry_json, entry_hash_hex, canonical_bytes) VALUES (1, '{}', 'ab', 2)`,
      );

      ensureProjectDoTables(sql);

      // version もデータも変わらない(ステップは一切走らない)
      expect(readProjectDoSchemaVersion(sql)).toBe(before);
      expect(sql.exec(`SELECT COUNT(*) AS n FROM chain_entries`).toArray()[0]?.n).toBe(1);
      sql.exec(`DELETE FROM chain_entries`);
    });
  });
});
