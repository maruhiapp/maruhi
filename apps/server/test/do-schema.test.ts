// Tests for the project DO's schema-migration machinery (src/do-schema.ts).
// Verifies on the real workerd SqlStorage: applying to an empty DB and to
// a mid-version DB, rollback and rerun of a failed step, and that
// re-applying to an already-migrated DB is a no-op.
//
// The real DO's (ProjectChainDO) constructor applies migrations at
// runInDurableObject instantiation time, so the "empty DB" / "mid-version
// DB" states are reproduced by dropping every table + initializing
// schema_meta. This file uses a dedicated DO name and does not share
// storage with other tests' project DOs.

import { env, runInDurableObject } from "cloudflare:test";
import { Effect } from "effect";
import { describe, expect, it } from "vitest";

import { DataStore, dataStoreLayer } from "../src/data-store.ts";
import type { ProjectDoMigration } from "../src/do-schema.ts";
import {
  applyProjectDoMigrations,
  ensureProjectDoTables,
  PROJECT_DO_MIGRATIONS,
  PROJECT_DO_TABLES,
  readProjectDoSchemaVersion,
} from "../src/do-schema.ts";

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
  it("applies every step to an empty DB and reaches the latest version", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
      expect(readProjectDoSchemaVersion(sql)).toBe(0);

      ensureProjectDoTables(storage);

      expect(readProjectDoSchemaVersion(sql)).toBe(PROJECT_DO_MIGRATIONS.length);
      const tables = userTableNames(sql);
      for (const table of PROJECT_DO_TABLES) {
        expect(tables).toContain(table);
      }
      // The tables declaration (what PROJECT_DO_TABLES is derived from)
      // has not drifted from the real schema:
      // real tables = declared tables + schema_meta
      expect(tables).toEqual(new Set([...PROJECT_DO_TABLES, "schema_meta"]));
    });
  });

  it("applying to a mid-version DB runs only the unapplied steps in order", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
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

      // Build an "old-version DB" with only step 1 applied
      applyProjectDoMigrations(storage, [stepOne]);
      expect(readProjectDoSchemaVersion(sql)).toBe(1);
      expect(applied).toEqual(["one"]);

      // Equivalent to booting with new code that gained a step. Step 1
      // is not re-run (stepOne's CREATE TABLE has no IF NOT EXISTS, so
      // it would throw if re-run)
      applyProjectDoMigrations(storage, [stepOne, stepTwo]);
      expect(readProjectDoSchemaVersion(sql)).toBe(2);
      expect(applied).toEqual(["one", "two"]);
      expect(userTableNames(sql)).toEqual(new Set(["schema_meta", "mig_test_a", "mig_test_b"]));

      // Cleanup: return to the real schema (a dedicated DO, but leave
      // no state behind)
      dropAllUserTables(sql);
      ensureProjectDoTables(storage);
    });
  });

  it("a step that fails midway is rolled back wholesale and a rerun completes", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
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

      // The mid-step failure: version does not advance, and the step's
      // first-half DDL (mig_test_c) leaves nothing behind
      expect(() => applyProjectDoMigrations(storage, [flaky])).toThrow(
        "simulated mid-step failure",
      );
      expect(readProjectDoSchemaVersion(sql)).toBe(0);
      expect(userTableNames(sql)).toEqual(new Set(["schema_meta"]));

      // The rerun, equivalent to the next boot, runs from the step's
      // head and completes (mig_test_c's CREATE TABLE has no
      // IF NOT EXISTS — it would throw if a partial application remained)
      failNext = false;
      applyProjectDoMigrations(storage, [flaky]);
      expect(readProjectDoSchemaVersion(sql)).toBe(1);
      expect(userTableNames(sql)).toEqual(new Set(["schema_meta", "mig_test_c", "mig_test_d"]));

      // Cleanup: return to the real schema
      dropAllUserTables(sql);
      ensureProjectDoTables(storage);
    });
  });

  it("rejects when the stored version is newer than the deployment's step count (rollback defense)", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
      ensureProjectDoTables(storage);
      // Reproduce "old code was rollback-deployed onto a DB advanced 1
      // step by newer code"
      sql.exec(`UPDATE schema_meta SET version = ? WHERE id = 1`, PROJECT_DO_MIGRATIONS.length + 1);

      expect(() => ensureProjectDoTables(storage)).toThrow(/newer than this deployment/);
      // The rejection happens before any step applies (version is not rewritten)
      expect(readProjectDoSchemaVersion(sql)).toBe(PROJECT_DO_MIGRATIONS.length + 1);

      // Cleanup: return to the real version
      sql.exec(`UPDATE schema_meta SET version = ? WHERE id = 1`, PROJECT_DO_MIGRATIONS.length);
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
      // all steps (step 1's IF NOT EXISTS would pass, but a future
      // ALTER TABLE step is not idempotent)
      expect(() => ensureProjectDoTables(storage)).toThrow(/schema_meta\.version is corrupt/);

      // Cleanup: return to the real version
      sql.exec(`UPDATE schema_meta SET version = ? WHERE id = 1`, PROJECT_DO_MIGRATIONS.length);
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
      const stale = store.write.deleteStaleMemberWraps("user-a", "keep");

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
