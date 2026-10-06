// Tests for the project DO's schema-migration machinery (src/do/do-schema.ts).
// Verifies on the real workerd SqlStorage: the squashed base step on an
// empty DB (recorded as version 9, schema pinned against the dump the W4-Z3
// differential probe generated from the pre-squash steps 1-9), the refusal
// of a pre-squash version (1-8), application/rollback/rerun of later steps
// on synthetic plans, and that re-applying to an already-migrated DB is a
// no-op.
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
import { readMirrorState } from "../src/do/do-mirror.ts";
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
import expectedV9Schema from "./fixtures/do-schema-v9.json";

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

/** sqlite_master.sql normalized: quoting and whitespace differences are not schema differences. */
function canonSql(sql: unknown): string | null {
  if (sql === null || sql === undefined) {
    return null;
  }
  return String(sql).replaceAll('"', "").replace(/\s+/g, "");
}

interface SchemaObject {
  type: string;
  name: string;
  tblName: string;
  sql: string | null;
}

/** The schema objects in sqlite_master rowid order (creation order), the pinned shape. */
function schemaObjects(sql: SqlStorage): SchemaObject[] {
  return sql
    .exec(
      `SELECT type, name, tbl_name, sql FROM sqlite_master
       WHERE name NOT LIKE '\\_cf\\_%' ESCAPE '\\' AND name != 'sqlite_sequence'
       ORDER BY rowid`,
    )
    .toArray()
    .map((row) => ({
      type: String(row["type"]),
      name: String(row["name"]),
      tblName: String(row["tbl_name"]),
      sql: canonSql(row["sql"]),
    }));
}

/** The audit write trigger is derived schema: its text embeds READ_PATH_AUDIT_EVENTS and ensureAuditWriteTrigger rewrites it when the list changes — mask its sql so the v9 pin does not break on a routine list change (export.test.ts pins the text itself). */
const stripDerivedSql = (object: SchemaObject): SchemaObject =>
  object.name === "mutation_audit_events_write" ? { ...object, sql: "<derived>" } : object;

describe("project DO schema migrations", () => {
  it("applies the squashed base to an empty DB and records version 9", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
      expect(readProjectDoSchemaVersion(sql)).toBe(0);

      ensureProjectDoTables(storage);

      // One step: the squashed base records 9 directly (the latest version —
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

  it("builds the same schema as the pre-squash steps 1-9 produced (the pinned dump)", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
      // Apply only the base: the pin is the version-9 schema, and it stays a
      // v9 pin when a later step is appended above it
      applyProjectDoMigrations(storage, { ...PROJECT_DO_MIGRATIONS, steps: [] });

      // fixtures/do-schema-v9.json is the normalized dump the W4-Z3
      // differential probe generated from origin/main's steps 1-9 (the
      // mirror_state residue column the squash drops removed; regenerate by
      // re-running that probe against the pre-squash do-schema.ts). Every
      // object — table / index / trigger, in creation order — must match
      const fresh = schemaObjects(sql);
      expect(fresh.map(stripDerivedSql)).toEqual(
        (expectedV9Schema.objects as readonly SchemaObject[]).map(stripDerivedSql),
      );
      const auditTrigger = fresh.find((object) => object.name === "mutation_audit_events_write");
      expect(auditTrigger?.tblName).toBe("audit_events");
      expect(auditTrigger?.sql).toContain("AFTERINSERTONaudit_events");
      for (const [table, columns] of Object.entries(expectedV9Schema.tableXinfo)) {
        expect(sql.exec(`SELECT * FROM pragma_table_xinfo('${table}')`).toArray()).toEqual(columns);
      }
      for (const [table, indexes] of Object.entries(expectedV9Schema.indexList)) {
        expect(sql.exec(`SELECT * FROM pragma_index_list('${table}')`).toArray()).toEqual(indexes);
      }
      for (const [index, entries] of Object.entries(expectedV9Schema.indexXinfo)) {
        expect(sql.exec(`SELECT * FROM pragma_index_xinfo('${index}')`).toArray()).toEqual(entries);
      }
      for (const [table, keys] of Object.entries(expectedV9Schema.foreignKeys)) {
        expect(sql.exec(`SELECT * FROM pragma_foreign_key_list('${table}')`).toArray()).toEqual(
          keys,
        );
      }
    });
  });

  it("a DO already at version 9 with the pre-squash schema shape is a no-op (the residue column stays)", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
      ensureProjectDoTables(storage);
      // Reproduce a DO that reached 9 under the pre-squash steps: the
      // deployment-local mirror_state there carries the extra nullable
      // column the squash drops from the base
      sql.exec("ALTER TABLE mirror_state ADD COLUMN last_audit_head_hash_hex TEXT");
      sql.exec(
        `INSERT INTO mirror_state (id, source_origin, marked_at, expected_sequence, staging_table,
           last_synced_at, last_head_seq, last_head_hash_hex, last_audit_seq,
           last_attestation_mark, last_audit_head_hash_hex)
         VALUES (1, 'https://source.test', 1, 0, NULL, NULL, 0, '', 0, NULL, 'ab')`,
      );
      sql.exec(
        `INSERT INTO chain_entries (seq, entry_json, entry_hash_hex, canonical_bytes) VALUES (1, '{}', 'ab', 2)`,
      );
      const schemaBefore = schemaObjects(sql);

      ensureProjectDoTables(storage);

      // No step ran: the version, the schema (the residue column included)
      // and the rows are untouched
      expect(readProjectDoSchemaVersion(sql)).toBe(PROJECT_DO_LATEST_SCHEMA_VERSION);
      expect(schemaObjects(sql)).toEqual(schemaBefore);
      const mirrorRow = sql.exec("SELECT * FROM mirror_state WHERE id = 1").toArray()[0];
      expect(mirrorRow?.["last_audit_head_hash_hex"]).toBe("ab");
      expect(readMirrorState(sql)).toEqual({
        sourceOrigin: "https://source.test",
        markedAtMs: 1,
        expectedSequence: 0,
        stagingTable: null,
        lastSyncedAtMs: null,
        lastHeadSeq: 0,
        lastHeadHashHex: "",
        lastAuditSeq: 0,
        lastAttestationMark: null,
        lastMutationSeq: null,
      });
      expect(sql.exec(`SELECT COUNT(*) AS n FROM chain_entries`).toArray()[0]?.n).toBe(1);

      // Cleanup: return to the real schema (the ALTERed mirror_state is
      // dropped and recreated without the residue column)
      dropAllUserTables(sql);
      ensureProjectDoTables(storage);
    });
  });

  it("refuses a pre-squash stored version (1-8) before running any DDL", async () => {
    await withStorage((storage) => {
      const sql = storage.sql;
      dropAllUserTables(sql);
      // schema_meta exists (the version read creates it) but is empty —
      // write each pre-squash version into it
      readProjectDoSchemaVersion(sql);
      sql.exec(`INSERT INTO schema_meta (id, version) VALUES (1, 1)`);
      for (let version = 1; version <= 8; version++) {
        sql.exec(`UPDATE schema_meta SET version = ? WHERE id = 1`, version);
        expect(() => ensureProjectDoTables(storage)).toThrow(
          `project DO schema version ${version} predates the squashed schema ` +
            `(version 9, squashed 2026-10-06); this DO cannot be upgraded in place ` +
            `— recreate the project`,
        );
        // The refusal happens before any DDL: the version is not rewritten
        // and no table was created
        expect(readProjectDoSchemaVersion(sql)).toBe(version);
        expect(userTableNames(sql)).toEqual(new Set(["schema_meta"]));
      }

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
