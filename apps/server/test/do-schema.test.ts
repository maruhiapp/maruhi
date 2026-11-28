import { testEnvironmentId, testUserId } from "@maruhi/test-kit";
import { env, runInDurableObject } from "cloudflare:test";
import { Effect } from "effect";
import { describe, expect, it } from "vite-plus/test";

import { DataStore, dataStoreLayer } from "../src/data.package/index.ts";
import type { ProjectDoMigration, ProjectDoMigrationPlan } from "../src/do/do-schema.ts";
import {
  applyProjectDoMigrations,
  ensureProjectDoTables,
  PROJECT_DO_LATEST_SCHEMA_VERSION,
  PROJECT_DO_LOCAL_TABLES,
  PROJECT_DO_MIGRATIONS,
  PROJECT_DO_TABLES,
  readProjectDoSchemaVersion,
} from "../src/do/do-schema.ts";

async function withStorage<T>(body: (storage: DurableObjectStorage) => T): Promise<T> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName("do-schema-migrations-test"));
  return await runInDurableObject(stub, (_instance, state) => body(state.storage));
}

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
  it("applies the base to an empty DB and records version 9", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
      expect(readProjectDoSchemaVersion(sql)).toBe(0);

      ensureProjectDoTables(storage);

      expect(PROJECT_DO_LATEST_SCHEMA_VERSION).toBe(9);
      expect(readProjectDoSchemaVersion(sql)).toBe(PROJECT_DO_LATEST_SCHEMA_VERSION);
      const tables = userTableNames(sql);
      for (const table of PROJECT_DO_TABLES) {
        expect(tables).toContain(table);
      }
      expect(tables).toEqual(
        new Set([...PROJECT_DO_TABLES, ...PROJECT_DO_LOCAL_TABLES, "schema_meta"]),
      );
    });
  });

  it("refuses a stored version below the base as corrupt before running any DDL", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
      readProjectDoSchemaVersion(sql);
      sql.exec(
        `INSERT INTO schema_meta (id, version) VALUES (1, ?)`,
        PROJECT_DO_MIGRATIONS.baseVersion - 1,
      );
      expect(() => ensureProjectDoTables(storage)).toThrow(
        `project DO schema_meta.version is corrupt: ${PROJECT_DO_MIGRATIONS.baseVersion - 1}`,
      );
      expect(readProjectDoSchemaVersion(sql)).toBe(PROJECT_DO_MIGRATIONS.baseVersion - 1);
      expect(userTableNames(sql)).toEqual(new Set(["schema_meta"]));

      dropAllUserTables(sql);
      ensureProjectDoTables(storage);
    });
  });

  it("applying to a DB at the base version runs only the unapplied later steps in order", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
      const applied: string[] = [];
      const base: ProjectDoMigration = {
        tables: ["mig_test_a"],
        apply(s) {
          applied.push("base");
          s.exec(`CREATE TABLE mig_test_a (id INTEGER PRIMARY KEY)`);
        },
      };
      const laterStep: ProjectDoMigration = {
        tables: ["mig_test_b"],
        apply(s) {
          applied.push("later");
          s.exec(`CREATE TABLE mig_test_b (id INTEGER PRIMARY KEY)`);
        },
      };
      const plan = (steps: readonly ProjectDoMigration[]): ProjectDoMigrationPlan => ({
        baseVersion: 9,
        base,
        steps,
      });

      applyProjectDoMigrations(storage, plan([]));
      expect(readProjectDoSchemaVersion(sql)).toBe(9);
      expect(applied).toEqual(["base"]);

      applyProjectDoMigrations(storage, plan([laterStep]));
      expect(readProjectDoSchemaVersion(sql)).toBe(10);
      expect(applied).toEqual(["base", "later"]);
      expect(userTableNames(sql)).toEqual(new Set(["schema_meta", "mig_test_a", "mig_test_b"]));

      dropAllUserTables(sql);
      ensureProjectDoTables(storage);
    });
  });

  it("a later step that fails midway is rolled back wholesale and a rerun completes", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
      const base: ProjectDoMigration = {
        tables: ["mig_test_a"],
        apply(s) {
          s.exec(`CREATE TABLE mig_test_a (id INTEGER PRIMARY KEY)`);
        },
      };
      let failNext = true;
      const flaky: ProjectDoMigration = {
        tables: ["mig_test_c", "mig_test_d"],
        apply(s) {
          s.exec(`CREATE TABLE mig_test_c (id INTEGER PRIMARY KEY)`);
          if (failNext) {
            throw new Error("simulated mid-step failure");
          }
          s.exec(`CREATE TABLE mig_test_d (id INTEGER PRIMARY KEY)`);
        },
      };
      const plan: ProjectDoMigrationPlan = { baseVersion: 9, base, steps: [flaky] };

      expect(() => applyProjectDoMigrations(storage, plan)).toThrow("simulated mid-step failure");
      expect(readProjectDoSchemaVersion(sql)).toBe(9);
      expect(userTableNames(sql)).toEqual(new Set(["schema_meta", "mig_test_a"]));

      failNext = false;
      applyProjectDoMigrations(storage, plan);
      expect(readProjectDoSchemaVersion(sql)).toBe(10);
      expect(userTableNames(sql)).toEqual(
        new Set(["schema_meta", "mig_test_a", "mig_test_c", "mig_test_d"]),
      );

      dropAllUserTables(sql);
      ensureProjectDoTables(storage);
    });
  });

  it("rejects when the stored version is newer than the deployment's latest version (rollback defense)", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
      ensureProjectDoTables(storage);
      sql.exec(
        `UPDATE schema_meta SET version = ? WHERE id = 1`,
        PROJECT_DO_LATEST_SCHEMA_VERSION + 1,
      );

      expect(() => ensureProjectDoTables(storage)).toThrow(/newer than this deployment/);
      expect(readProjectDoSchemaVersion(sql)).toBe(PROJECT_DO_LATEST_SCHEMA_VERSION + 1);

      sql.exec(`UPDATE schema_meta SET version = ? WHERE id = 1`, PROJECT_DO_LATEST_SCHEMA_VERSION);
      ensureProjectDoTables(storage);
    });
  });

  it("a corrupt schema_meta.version fails explicitly instead of being treated as 0", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
      ensureProjectDoTables(storage);
      sql.exec(`UPDATE schema_meta SET version = 'garbage' WHERE id = 1`);

      expect(() => ensureProjectDoTables(storage)).toThrow(/schema_meta\.version is corrupt/);

      sql.exec(`UPDATE schema_meta SET version = ? WHERE id = 1`, PROJECT_DO_LATEST_SCHEMA_VERSION);
      ensureProjectDoTables(storage);
    });
  });

  it("re-applying to an already-migrated DB is a no-op", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
      ensureProjectDoTables(storage);
      const before = readProjectDoSchemaVersion(sql);
      sql.exec(
        `INSERT INTO chain_entries (seq, entry_json, entry_hash_hex, canonical_bytes) VALUES (1, '{}', 'ab', 2)`,
      );

      ensureProjectDoTables(storage);

      expect(readProjectDoSchemaVersion(sql)).toBe(before);
      expect(sql.exec(`SELECT COUNT(*) AS n FROM chain_entries`).toArray()[0]?.n).toBe(1);
      sql.exec(`DELETE FROM chain_entries`);
    });
  });

  it("has the recipient index dw_recipient on dek_wraps, and re-add cleanup uses it (EXPLAIN QUERY PLAN)", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
      ensureProjectDoTables(storage);
      const definition = sql
        .exec(`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'dw_recipient'`)
        .toArray()[0]?.["sql"];
      expect(String(definition)).toContain("dek_wraps (recipient_user_id, recipient_class)");

      const insertWrap = (userId: string, epoch: number, encPub: string, recipientClass: string) =>
        sql.exec(
          `INSERT INTO dek_wraps
             (environment_id, epoch, recipient_user_id, suite, recipient_enc_pub_hex, enc_hex,
              ciphertext_hex, signature_hex, signer_user_id, signer_key_fingerprint, created_at,
              recipient_class)
           VALUES ('env-dw', ?, ?, 's', ?, 'e', 'c', 'sig', 'signer', 'fp', 1, ?)`,
          epoch,
          userId,
          encPub,
          recipientClass,
        );
      insertWrap("user-a", 1, "old", "member");
      insertWrap("user-a", 2, "keep", "member");
      insertWrap("user-b", 1, "old", "member");
      insertWrap("user-a", 3, "old", "server");

      const captured: { query: string; bindings: unknown[] }[] = [];
      const wrapped = new Proxy(sql, {
        get(target, property) {
          if (property === "exec") {
            return (query: string, ...bindings: unknown[]) => {
              captured.push({ query, bindings });
              return target.exec(query, ...(bindings as (string | number | null)[]));
            };
          }
          return Reflect.get(target, property, target);
        },
      });
      const store = Effect.runSync(
        Effect.gen(function* () {
          return yield* DataStore;
        }).pipe(Effect.provide(dataStoreLayer(wrapped))),
      );
      const stale = store.write.deleteStaleMemberWraps(
        testUserId("user-a"),
        testEnvironmentId("keep"),
      );

      expect(stale).toEqual([{ environmentId: "env-dw", epoch: 1 }]);
      expect(
        sql
          .exec(`SELECT recipient_user_id, epoch FROM dek_wraps ORDER BY recipient_user_id, epoch`)
          .toArray()
          .map((row) => `${String(row["recipient_user_id"])}/${String(row["epoch"])}`),
      ).toEqual(["user-a/2", "user-a/3", "user-b/1"]);
      expect(captured).toHaveLength(2);
      for (const { query, bindings } of captured) {
        const plan = sql
          .exec(`EXPLAIN QUERY PLAN ${query}`, ...(bindings as (string | number)[]))
          .toArray()
          .map((row) => String(row["detail"]))
          .join("\n");
        expect(plan, query).toContain("USING INDEX dw_recipient");
      }
      sql.exec(`DELETE FROM dek_wraps`);
    });
  });
});
