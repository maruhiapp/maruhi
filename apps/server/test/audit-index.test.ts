// Tests for the partial indexing of audit_events' target / key-FP indexes
// (src/do-schema.ts — audit-log growth-density countermeasure ①).
//
// Three things are pinned on workerd's real SqlStorage:
// (a) the post-migration schema has `WHERE <column> IS NOT NULL` partial
//     indexes
// (b) the existing readers (Q1 / Q6 for rotation-needed detection and the
//     §7 target_user_id filter) choose the new indexes in EXPLAIN QUERY
//     PLAN — SQLite only uses a partial index when the WHERE clause
//     implies the index predicate, so we empirically pin that "an equality
//     condition implies IS NOT NULL" (a rewrite that stops implying it is
//     not fail-open, just a full scan — but the audit table can reach 10
//     GB, so we want to catch it as a performance regression)
// (c) the measured effect: the databaseSize difference between a plain
//     index and a partial index over 10,000 var.read rows (whose target
//     and key FP are all NULL)
//
// This file uses its own DO name and shares no storage with other tests'
// project DOs. The audit-store query text is captured by thinly wrapping
// SqlStorage, and the same text is fed to EXPLAIN (avoiding verifier drift
// from duplicating the statements).

import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import type { AuditEventInput } from "../src/audit-store.ts";
import { makeAuditStore } from "../src/audit-store.ts";

/** Run body on the storage of this file's dedicated DO. */
async function withSql<T>(body: (sql: SqlStorage) => T): Promise<T> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName("audit-partial-index-test"));
  return await runInDurableObject(stub, (_instance, state) => body(state.storage.sql));
}

const PARTIAL_INDEXES = {
  ae_target: "target_user_id",
  ae_target_fp: "target_key_fingerprint",
  ae_actor_fp: "actor_key_fingerprint",
} as const;

/** Index definitions in sqlite_master (name → CREATE statement). */
function indexDefinitions(sql: SqlStorage): ReadonlyMap<string, string> {
  return new Map(
    sql
      .exec(
        `SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'audit_events'`,
      )
      .toArray()
      .map((row) => [String(row["name"]), String(row["sql"])]),
  );
}

interface CapturedQuery {
  readonly query: string;
  readonly bindings: readonly unknown[];
}

/**
 * A SqlStorage wrapper that captures the SQL executed. Everything but
 * exec is delegated to the real object (native getters like databaseSize
 * are called with the real object as receiver).
 */
function capturing(sql: SqlStorage): {
  readonly sql: SqlStorage;
  readonly captured: CapturedQuery[];
} {
  const captured: CapturedQuery[] = [];
  const proxy = new Proxy(sql, {
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
  return { sql: proxy, captured };
}

/** Fold the EXPLAIN QUERY PLAN detail column into a single string. */
function planOf(sql: SqlStorage, captured: CapturedQuery): string {
  return sql
    .exec(`EXPLAIN QUERY PLAN ${captured.query}`, ...(captured.bindings as (string | number)[]))
    .toArray()
    .map((row) => String(row["detail"]))
    .join("\n");
}

/** One var.read row (target / key FP all NULL — the dominant row shape). */
function readEvent(index: number): AuditEventInput {
  return {
    serverTs: 1_700_000_000_000 + index,
    event: "var.read",
    actorType: "user",
    actorUserId: "user-reader-0001",
    environmentId: "env-density-0001",
    variableId: `var-density-${String(index % 100).padStart(4, "0")}`,
    epoch: 1,
    version: 1,
  };
}

describe("audit_events partial indexes (do-schema.ts — growth-density countermeasure ①)", () => {
  it("after migration, ae_target / ae_target_fp / ae_actor_fp are IS NOT NULL partial indexes", async () => {
    await withSql((sql) => {
      const definitions = indexDefinitions(sql);
      for (const [name, column] of Object.entries(PARTIAL_INDEXES)) {
        const definition = definitions.get(name);
        expect(definition, name).toBeDefined();
        expect(definition, name).toContain(`(${column}, seq)`);
        expect(definition, name).toContain(`WHERE ${column} IS NOT NULL`);
      }
      // The indexes var.read uses stay plain (no predicate)
      for (const name of ["ae_var", "ae_actor", "ae_event"]) {
        expect(definitions.get(name), name).not.toContain("WHERE");
      }
    });
  });

  it("existing readers choose the new partial indexes via equality conditions (EXPLAIN QUERY PLAN)", async () => {
    await withSql((sql) => {
      const { sql: wrapped, captured } = capturing(sql);
      const store = makeAuditStore(wrapped);
      const expectations: {
        readonly label: string;
        readonly index: string;
        readonly run: () => void;
      }[] = [
        {
          label: "Q1 membershipEventsFor (target_user_id = ?)",
          index: "ae_target",
          run: () => void store.readRotationSync.membershipEventsFor("user-x"),
        },
        {
          label: "Q3 variableReadsBy (actor_user_id = ? AND seq range)",
          index: "ae_actor",
          run: () =>
            void store.readRotationSync.variableReadsBy("user-x", { afterSeq: 10, beforeSeq: 20 }),
        },
        {
          label: "Q6 serverGrantEventsFor (target_key_fingerprint = ?)",
          index: "ae_target_fp",
          run: () => void store.readRotationSync.serverGrantEventsFor("ab".repeat(16)),
        },
        {
          label: "Q6 serverAccessEventsBy (actor_key_fingerprint = ?)",
          index: "ae_actor_fp",
          run: () => void store.readRotationSync.serverAccessEventsBy("ab".repeat(16)),
        },
        {
          label: "§7 targetUserId filter (admin visibility)",
          index: "ae_target",
          run: () =>
            void store.queryEventsSync({
              beforeRowId: null,
              limit: 50,
              event: null,
              eventPrefix: null,
              chainSeqPresent: false,
              actorUserId: null,
              targetUserId: "user-x",
              variableId: null,
              environmentId: null,
              visibility: { kind: "admin" },
            }),
        },
        {
          label: "§7 targetUserId filter (class1-or-self visibility)",
          index: "ae_target",
          run: () =>
            void store.queryEventsSync({
              beforeRowId: null,
              limit: 50,
              event: null,
              eventPrefix: null,
              chainSeqPresent: false,
              actorUserId: null,
              targetUserId: "user-x",
              variableId: null,
              environmentId: null,
              visibility: { kind: "class1-or-self", selfUserId: "user-self" },
            }),
        },
      ];
      for (const expectation of expectations) {
        captured.length = 0;
        expectation.run();
        const query = captured.at(-1);
        expect(query, expectation.label).toBeDefined();
        if (query === undefined) throw new Error("no query captured");
        expect(planOf(sql, query), expectation.label).toContain(`USING INDEX ${expectation.index}`);
      }
    });
  });

  it("Q3 variableReadsBy's seq range becomes an ae_actor range scan and returns no rows outside the open interval", async () => {
    await withSql((sql) => {
      sql.exec("DELETE FROM audit_events");
      const { sql: wrapped, captured } = capturing(sql);
      const store = makeAuditStore(wrapped);
      // var.read at seq 1..10 (all the same actor)
      store.appendManySync(Array.from({ length: 10 }, (_row, index) => readEvent(index)));
      captured.length = 0;
      const bounded = store.readRotationSync.variableReadsBy("user-reader-0001", {
        afterSeq: 3,
        beforeSeq: 7,
      });
      expect(bounded.map((row) => row.seq)).toEqual([4, 5, 6]);
      const query = captured.at(-1);
      if (query === undefined) throw new Error("no query captured");
      // The range is cut on the index's seq component (not reading all of the actor's rows then discarding)
      expect(planOf(sql, query)).toMatch(
        /USING INDEX ae_actor \(actor_user_id=\? AND seq>\? AND seq<\?\)/,
      );
      // Omitted / non-finite ends are unbounded (the traditional all-seq)
      expect(store.readRotationSync.variableReadsBy("user-reader-0001").length).toBe(10);
      expect(
        store.readRotationSync
          .variableReadsBy("user-reader-0001", {
            afterSeq: Number.NEGATIVE_INFINITY,
            beforeSeq: Number.POSITIVE_INFINITY,
          })
          .map((row) => row.seq),
      ).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
      sql.exec("DELETE FROM audit_events");
    });
  });

  it("with 10,000 var.read rows, the partial indexes are smaller than plain ones (measured via databaseSize)", async () => {
    const ROWS = 10_000;
    const measured = await withSql((sql) => {
      sql.exec("DELETE FROM audit_events");
      const store = makeAuditStore(sql);
      store.appendManySync(Array.from({ length: ROWS }, (_row, index) => readEvent(index)));
      const partial = sql.databaseSize;
      // Rebuild as plain indexes (no predicate) — index entries accumulate for NULL rows too
      for (const [name, column] of Object.entries(PARTIAL_INDEXES)) {
        sql.exec(`DROP INDEX ${name}`);
        sql.exec(`CREATE INDEX ${name} ON audit_events (${column}, seq)`);
      }
      const full = sql.databaseSize;
      // Restore the real schema (partial indexes) = the same DROP → CREATE
      // as the migration step. The elapsed time is proportional to the row
      // count (the source of the estimate for applying it to an existing DO)
      const startedAt = Date.now();
      for (const [name, column] of Object.entries(PARTIAL_INDEXES)) {
        sql.exec(`DROP INDEX ${name}`);
        sql.exec(
          `CREATE INDEX ${name} ON audit_events (${column}, seq) WHERE ${column} IS NOT NULL`,
        );
      }
      const rebuildMs = Date.now() - startedAt;
      // The measurement after the direction an existing DO actually takes
      // (plain index → partial index). Pins whether the freed pages return
      // to databaseSize (the metric the capacity guard reads)
      const rebuilt = sql.databaseSize;
      sql.exec("DELETE FROM audit_events");
      return { partial, full, rebuildMs, rebuilt };
    });
    // The partial indexes hold no NULL rows, so they are smaller by 3 indexes × 10,000 entries
    expect(measured.full).toBeGreaterThan(measured.partial);
    const perRow = (measured.full - measured.partial) / ROWS;
    console.log(
      `audit_events partial index: ${ROWS} var.read rows — full ${measured.full} B / partial ${measured.partial} B / delta ${measured.full - measured.partial} B (${perRow.toFixed(1)} B per row, ${(measured.partial / ROWS).toFixed(1)} B per row remaining); partial-index rebuild of ${ROWS} rows took ${measured.rebuildMs} ms and left databaseSize at ${measured.rebuilt} B`,
    );
    // The usage also returns in the migrate-in-place direction (DROP the
    // plain indexes → rebuild as partial): if the freed pages stayed on the
    // freelist it would equal full; if returned, it equals partial
    expect(measured.rebuilt).toBeLessThan(measured.full);
    expect(measured.rebuilt).toBeLessThanOrEqual(measured.partial);
    // The 3 indexes × (NULL key + seq) entries are at least tens of bytes per row
    expect(perRow).toBeGreaterThan(10);
  });
});
