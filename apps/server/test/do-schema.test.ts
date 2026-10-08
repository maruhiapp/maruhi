// Tests for the project DO's schema-migration machinery (src/do/do-schema.ts).
// Verifies on the real workerd SqlStorage: the base step on an empty DB
// (recorded as version 9), the fail-closed refusal of a stored version below
// the base, application/rollback/rerun of later steps on synthetic plans,
// and that re-applying to an already-migrated DB is a no-op.
//
// The real DO's (ProjectChainDO) constructor applies migrations at
// runInDurableObject instantiation time, so the "empty DB" / "mid-version
// DB" states are reproduced by dropping every table + initializing
// schema_meta. This file uses a dedicated DO name and does not share
// storage with other tests' project DOs.

import { env, runInDurableObject } from "cloudflare:test";
import { Effect } from "effect";
import { describe, expect, it } from "vitest";

import { DataStore, dataStoreLayer } from "../src/data/data-store.ts";
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
import { testEnvironmentId, testUserId } from "./support/data-crypto.ts";

/** Run body on the storage of this file's dedicated DO. */
async function withStorage<T>(body: (storage: DurableObjectStorage) => T): Promise<T> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName("do-schema-migrations-test"));
  return await runInDurableObject(stub, (_instance, state) => body(state.storage));
}

/** DROP every user table (except _cf_ internals), returning to an unmigrated empty DB. */
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

      // One step: the base records 9 directly (the latest version —
      // no later steps exist today)
      expect(PROJECT_DO_LATEST_SCHEMA_VERSION).toBe(9);
      expect(readProjectDoSchemaVersion(sql)).toBe(PROJECT_DO_LATEST_SCHEMA_VERSION);
      const tables = userTableNames(sql);
      for (const table of PROJECT_DO_TABLES) {
        expect(tables).toContain(table);
      }
      // The tables declaration (what PROJECT_DO_TABLES is derived from)
      // has not drifted from the real schema:
      // real tables = declared tables + the deployment-local tables + schema_meta
      expect(tables).toEqual(
        new Set([...PROJECT_DO_TABLES, ...PROJECT_DO_LOCAL_TABLES, "schema_meta"]),
      );
    });
  });

  it("refuses a stored version below the base as corrupt before running any DDL", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
      // No step records a version in 1..base-1: such a value is corrupt
      readProjectDoSchemaVersion(sql);
      sql.exec(
        `INSERT INTO schema_meta (id, version) VALUES (1, ?)`,
        PROJECT_DO_MIGRATIONS.baseVersion - 1,
      );
      expect(() => ensureProjectDoTables(storage)).toThrow(
        `project DO schema_meta.version is corrupt: ${PROJECT_DO_MIGRATIONS.baseVersion - 1}`,
      );
      // The refusal happens before any DDL: the version is not rewritten
      // and no table was created
      expect(readProjectDoSchemaVersion(sql)).toBe(PROJECT_DO_MIGRATIONS.baseVersion - 1);
      expect(userTableNames(sql)).toEqual(new Set(["schema_meta"]));

      // Cleanup: return to the real schema
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

      // Build an "old-version DB" with only the base applied
      applyProjectDoMigrations(storage, plan([]));
      expect(readProjectDoSchemaVersion(sql)).toBe(9);
      expect(applied).toEqual(["base"]);

      // Equivalent to booting with new code that gained a step. The base
      // is not re-run (its CREATE TABLE has no IF NOT EXISTS, so it would
      // throw if re-run); the later step records 10
      applyProjectDoMigrations(storage, plan([laterStep]));
      expect(readProjectDoSchemaVersion(sql)).toBe(10);
      expect(applied).toEqual(["base", "later"]);
      expect(userTableNames(sql)).toEqual(new Set(["schema_meta", "mig_test_a", "mig_test_b"]));

      // Cleanup: return to the real schema (a dedicated DO, but leave
      // no state behind)
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

      // The mid-step failure: the base's version stays committed, and the
      // failed step's first-half DDL (mig_test_c) leaves nothing behind
      expect(() => applyProjectDoMigrations(storage, plan)).toThrow("simulated mid-step failure");
      expect(readProjectDoSchemaVersion(sql)).toBe(9);
      expect(userTableNames(sql)).toEqual(new Set(["schema_meta", "mig_test_a"]));

      // The rerun, equivalent to the next boot, runs from the step's
      // head and completes (mig_test_c's CREATE TABLE has no
      // IF NOT EXISTS — it would throw if a partial application remained)
      failNext = false;
      applyProjectDoMigrations(storage, plan);
      expect(readProjectDoSchemaVersion(sql)).toBe(10);
      expect(userTableNames(sql)).toEqual(
        new Set(["schema_meta", "mig_test_a", "mig_test_c", "mig_test_d"]),
      );

      // Cleanup: return to the real schema
      dropAllUserTables(sql);
      ensureProjectDoTables(storage);
    });
  });

  it("rejects when the stored version is newer than the deployment's latest version (rollback defense)", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
      ensureProjectDoTables(storage);
      // Reproduce "old code was rollback-deployed onto a DB advanced 1
      // version by newer code"
      sql.exec(
        `UPDATE schema_meta SET version = ? WHERE id = 1`,
        PROJECT_DO_LATEST_SCHEMA_VERSION + 1,
      );

      expect(() => ensureProjectDoTables(storage)).toThrow(/newer than this deployment/);
      // The rejection happens before any step applies (version is not rewritten)
      expect(readProjectDoSchemaVersion(sql)).toBe(PROJECT_DO_LATEST_SCHEMA_VERSION + 1);

      // Cleanup: return to the real version
      sql.exec(`UPDATE schema_meta SET version = ? WHERE id = 1`, PROJECT_DO_LATEST_SCHEMA_VERSION);
      ensureProjectDoTables(storage);
    });
  });

  it("a corrupt schema_meta.version fails explicitly instead of being treated as 0", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
      ensureProjectDoTables(storage);
      // The CHECK constraint covers only id; version's type is not enforced (SQLite is dynamically typed)
      sql.exec(`UPDATE schema_meta SET version = 'garbage' WHERE id = 1`);

      // Pin that it does not fall into treating it as 0 and re-running
      // the base (its CREATEs have no IF NOT EXISTS and would collide
      // with the applied schema)
      expect(() => ensureProjectDoTables(storage)).toThrow(/schema_meta\.version is corrupt/);

      // Cleanup: return to the real version
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

      // Neither version nor data changes (no steps run at all)
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

      // Capture data-store's real queries and feed the same statements
      // to EXPLAIN (avoiding verifier drift from duplicating the
      // statements — the same technique as audit-index.test.ts)
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
      expect(captured).toHaveLength(2); // SELECT → DELETE
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
