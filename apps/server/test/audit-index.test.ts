import { auditReadPayload } from "@maruhi/core";
import { testEnvironmentId, testUserId, testVariableId } from "@maruhi/crypto/test-support";
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vite-plus/test";

import type { AuditEventInput } from "../src/audit-store.ts";
import { makeAuditStore } from "../src/audit-store.ts";
import { ensureProjectDoTables } from "../src/do/do-schema.ts";
import { deriveEffectiveFlags } from "../src/rotation-detect.ts";

async function withSql<T>(body: (sql: SqlStorage) => T): Promise<T> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName("audit-partial-index-test"));
  return await runInDurableObject(stub, (_instance, state) => {
    ensureProjectDoTables(state.storage);
    return body(state.storage.sql);
  });
}

const PARTIAL_INDEXES = {
  ae_target: "target_user_id",
  ae_target_fp: "target_key_fingerprint",
  ae_actor_fp: "actor_key_fingerprint",
} as const;

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

function planOf(sql: SqlStorage, captured: CapturedQuery): string {
  return sql
    .exec(`EXPLAIN QUERY PLAN ${captured.query}`, ...(captured.bindings as (string | number)[]))
    .toArray()
    .map((row) => String(row["detail"]))
    .join("\n");
}

function readEvent(index: number): AuditEventInput {
  return {
    serverTs: 1_700_000_000_000 + index,
    event: "var.read",
    actorType: "user",
    actorUserId: testUserId("user-reader-0001"),
    environmentId: "env-density-0001",
    payload: auditReadPayload([
      {
        variableId: testVariableId(`var-density-${String(index % 100).padStart(4, "0")}`),
        epoch: 1,
        version: 1,
      },
    ]),
  };
}

function pushEvent(environmentId: string, variableId: string, version: number): AuditEventInput {
  return {
    serverTs: 1_700_000_000_000 + version,
    event: "var.version_pushed",
    actorType: "user",
    actorUserId: testUserId("user-writer-0001"),
    environmentId,
    variableId,
    epoch: version,
    version,
  };
}

function recommendedEvent(environmentId: string, variableIds: readonly string[]): AuditEventInput {
  return {
    serverTs: 1_700_000_000_000,
    event: "rotation.recommended",
    actorType: "system",
    targetUserId: testUserId("user-removed-0001"),
    environmentId,
    epoch: 1,
    payload: {
      triggerChainSeq: 2,
      trigger: "remove_member",
      variables: variableIds.map((variableId) => ({ variableId, basis: "readable" as const })),
    },
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
          run: () => void store.readRotationSync.membershipEventsFor(testUserId("user-x")),
        },
        {
          label: "Q3 variableReadsBy (actor_user_id = ? AND seq range)",
          index: "ae_actor",
          run: () =>
            void store.readRotationSync.variableReadsBy(testUserId("user-x"), {
              afterSeq: 10,
              beforeSeq: 20,
            }),
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
              targetUserId: testUserId("user-x"),
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
              targetUserId: testUserId("user-x"),
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
      store.appendManySync(Array.from({ length: 10 }, (_row, index) => readEvent(index)));
      captured.length = 0;
      const bounded = store.readRotationSync.variableReadsBy(testUserId("user-reader-0001"), {
        afterSeq: 3,
        beforeSeq: 7,
      });
      expect(bounded.map((row) => row.seq)).toEqual([4, 5, 6]);
      const query = captured.at(-1);
      if (query === undefined) throw new Error("no query captured");
      expect(planOf(sql, query)).toMatch(
        /USING INDEX ae_actor \(actor_user_id=\? AND seq>\? AND seq<\?\)/,
      );
      expect(store.readRotationSync.variableReadsBy(testUserId("user-reader-0001")).length).toBe(
        10,
      );
      expect(
        store.readRotationSync
          .variableReadsBy(testUserId("user-reader-0001"), {
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
      for (const [name, column] of Object.entries(PARTIAL_INDEXES)) {
        sql.exec(`DROP INDEX ${name}`);
        sql.exec(`CREATE INDEX ${name} ON audit_events (${column}, seq)`);
      }
      const full = sql.databaseSize;
      const startedAt = Date.now();
      for (const [name, column] of Object.entries(PARTIAL_INDEXES)) {
        sql.exec(`DROP INDEX ${name}`);
        sql.exec(
          `CREATE INDEX ${name} ON audit_events (${column}, seq) WHERE ${column} IS NOT NULL`,
        );
      }
      const rebuildMs = Date.now() - startedAt;
      const rebuilt = sql.databaseSize;
      sql.exec("DELETE FROM audit_events");
      return { partial, full, rebuildMs, rebuilt };
    });
    expect(measured.full).toBeGreaterThan(measured.partial);
    const perRow = (measured.full - measured.partial) / ROWS;
    console.log(
      `audit_events partial index: ${ROWS} var.read rows — full ${measured.full} B / partial ${measured.partial} B / delta ${measured.full - measured.partial} B (${perRow.toFixed(1)} B per row, ${(measured.partial / ROWS).toFixed(1)} B per row remaining); partial-index rebuild of ${ROWS} rows took ${measured.rebuildMs} ms and left databaseSize at ${measured.rebuilt} B`,
    );
    expect(measured.rebuilt).toBeLessThan(measured.full);
    expect(measured.rebuilt).toBeLessThanOrEqual(measured.partial);
    expect(perRow).toBeGreaterThan(10);
  });
});

describe("rotation flag reads (Q5 — audit-store-rotation-read.ts)", () => {
  function seedFlagRows(store: ReturnType<typeof makeAuditStore>, sql: SqlStorage): void {
    store.appendManySync([
      { ...pushEvent("env-a", "var-a", 1), event: "var.created", payload: { name: "A" } },
      pushEvent("env-a", "var-a", 1),
      pushEvent("env-a", "var-b", 1),
      recommendedEvent("env-a", ["var-a"]),
      { ...pushEvent("env-a", "var-a", 1), event: "var.renamed", payload: { name: "B" } },
      pushEvent("env-b", "var-a", 1),
      recommendedEvent("env-b", ["var-a"]),
      readEvent(0),
      {
        serverTs: 1_700_000_000_000,
        event: "rotation.dismissed",
        actorType: "user",
        actorUserId: testUserId("user-admin-0001"),
        environmentId: "env-b",
        variableId: "var-a",
      },
      recommendedEvent("env-a", ["var-a"]),
      pushEvent("env-a", "var-b", 2),
      pushEvent("env-a", "var-a", 2),
    ]);
    sql.exec(
      "INSERT INTO audit_events (seq, row_id, server_ts, event, actor_type, epoch, payload) VALUES (13, lower(hex(randomblob(16))), ?, 'rotation.recommended', 'system', 1, ?)",
      1_700_000_000_000,
      JSON.stringify({ triggerChainSeq: 2, trigger: "remove_member", variables: "oops" }),
    );
  }

  it("rotationFlagEvents reads the aggregate recommended rows (ae_event) and each flagged pair's resolution rows (ae_var)", async () => {
    await withSql((sql) => {
      sql.exec("DELETE FROM audit_events");
      const { sql: wrapped, captured } = capturing(sql);
      const store = makeAuditStore(wrapped);
      seedFlagRows(store, sql);
      captured.length = 0;
      const rows = store.readRotationSync.rotationFlagEvents();
      expect(rows.map((row) => [row.seq, row.event, row.environmentId, row.variableId])).toEqual([
        [2, "var.version_pushed", "env-a", "var-a"],
        [4, "rotation.recommended", "env-a", "var-a"],
        [6, "var.version_pushed", "env-b", "var-a"],
        [7, "rotation.recommended", "env-b", "var-a"],
        [9, "rotation.dismissed", "env-b", "var-a"],
        [10, "rotation.recommended", "env-a", "var-a"],
        [12, "var.version_pushed", "env-a", "var-a"],
      ]);
      expect(deriveEffectiveFlags(rows)).toEqual([]);
      expect(deriveEffectiveFlags(rows.filter((row) => row.seq !== 12))).toMatchObject([
        { environmentId: "env-a", variableId: "var-a" },
        { environmentId: "env-a", variableId: "var-a" },
      ]);
      expect(captured).toHaveLength(2);
      const recommendedQuery = captured[0];
      const resolutionQuery = captured[1];
      if (recommendedQuery === undefined || resolutionQuery === undefined) {
        throw new Error("no query captured");
      }
      expect(planOf(sql, recommendedQuery)).toMatch(/USING INDEX ae_event \(event=\?\)/);
      const resolutionPlan = planOf(sql, resolutionQuery);
      expect(resolutionPlan).toMatch(
        /SEARCH a USING INDEX ae_var \(variable_id=\? AND environment_id=\?\)/,
      );
      expect(resolutionPlan).not.toMatch(/SCAN a\b/);
      sql.exec("DELETE FROM audit_events");
    });
  });

  it("rotationFlagEvents reads a resolution row with a malformed target_key_fingerprint as null instead of throwing", async () => {
    await withSql((sql) => {
      sql.exec("DELETE FROM audit_events");
      const store = makeAuditStore(sql);
      store.appendManySync([recommendedEvent("env-a", ["var-a"])]);
      sql.exec(
        "INSERT INTO audit_events (seq, row_id, server_ts, event, actor_type, environment_id, variable_id, target_key_fingerprint) VALUES (2, lower(hex(randomblob(16))), ?, 'rotation.dismissed', 'user', 'env-a', 'var-a', 'not-a-fingerprint')",
        1_700_000_000_000,
      );
      sql.exec(
        "INSERT INTO audit_events (seq, row_id, server_ts, event, actor_type, environment_id, variable_id, epoch, version, target_key_fingerprint) VALUES (3, lower(hex(randomblob(16))), ?, 'var.version_pushed', 'user', 'env-a', 'var-a', 1, 1, 'not-a-fingerprint')",
        1_700_000_000_000,
      );
      const rows = store.readRotationSync.rotationFlagEvents();
      expect(rows.map((row) => [row.seq, row.event, row.targetKeyFingerprintHex])).toEqual([
        [1, "rotation.recommended", null],
        [2, "rotation.dismissed", null],
        [3, "var.version_pushed", null],
      ]);
      sql.exec("DELETE FROM audit_events");
    });
  });

  it("rotationFlagEventsFor reads the given pairs only (recommended via ae_event, resolution via ae_var)", async () => {
    await withSql((sql) => {
      sql.exec("DELETE FROM audit_events");
      const { sql: wrapped, captured } = capturing(sql);
      const store = makeAuditStore(wrapped);
      seedFlagRows(store, sql);
      captured.length = 0;
      const envB = testEnvironmentId("env-b");
      const rows = store.readRotationSync.rotationFlagEventsFor([
        { environmentId: envB, variableId: testVariableId("var-a") },
        { environmentId: envB, variableId: testVariableId("var-a") },
        { environmentId: testEnvironmentId("env-a"), variableId: testVariableId("var-b") },
        { environmentId: testEnvironmentId("env-a"), variableId: testVariableId("var-a") },
      ]);
      expect(rows.map((row) => [row.seq, row.event, row.environmentId, row.variableId])).toEqual([
        [2, "var.version_pushed", "env-a", "var-a"],
        [3, "var.version_pushed", "env-a", "var-b"],
        [4, "rotation.recommended", "env-a", "var-a"],
        [6, "var.version_pushed", "env-b", "var-a"],
        [7, "rotation.recommended", "env-b", "var-a"],
        [9, "rotation.dismissed", "env-b", "var-a"],
        [10, "rotation.recommended", "env-a", "var-a"],
        [11, "var.version_pushed", "env-a", "var-b"],
        [12, "var.version_pushed", "env-a", "var-a"],
      ]);
      expect(captured).toHaveLength(2);
      const recommendedQuery = captured[0];
      const resolutionQuery = captured[1];
      if (recommendedQuery === undefined || resolutionQuery === undefined) {
        throw new Error("no query captured");
      }
      expect(planOf(sql, recommendedQuery)).toMatch(/USING INDEX ae_event \(event=\?\)/);
      const resolutionPlan = planOf(sql, resolutionQuery);
      expect(resolutionPlan).toMatch(
        /SEARCH a USING INDEX ae_var \(variable_id=\? AND environment_id=\?\)/,
      );
      expect(resolutionPlan).not.toMatch(/SCAN a\b/);
      sql.exec("DELETE FROM audit_events");
    });
  });

  it("rotationFlagEventsFor expands a multi-variable aggregate row to the requested pair only (restrict)", async () => {
    await withSql((sql) => {
      sql.exec("DELETE FROM audit_events");
      const store = makeAuditStore(sql);
      store.appendManySync([
        recommendedEvent("env-a", ["var-a", "var-b"]),
        pushEvent("env-a", "var-a", 1),
        pushEvent("env-a", "var-b", 1),
      ]);
      const rows = store.readRotationSync.rotationFlagEventsFor([
        { environmentId: testEnvironmentId("env-a"), variableId: testVariableId("var-b") },
      ]);
      expect(rows.map((row) => [row.seq, row.event, row.variableId])).toEqual([
        [1, "rotation.recommended", "var-b"],
        [3, "var.version_pushed", "var-b"],
      ]);
      expect(rows.some((row) => row.variableId === "var-a")).toBe(false);
      sql.exec("DELETE FROM audit_events");
    });
  });

  it("the §7 variable filter's rotation.recommended aggregate query uses ae_event, never ae_var over var.read", async () => {
    await withSql((sql) => {
      sql.exec("DELETE FROM audit_events");
      const { sql: wrapped, captured } = capturing(sql);
      const store = makeAuditStore(wrapped);
      store.appendManySync([
        { ...pushEvent("env-a", "var-a", 1), event: "var.created", payload: { name: "A" } },
        recommendedEvent("env-a", ["var-a"]),
        readEvent(0),
      ]);
      captured.length = 0;
      store.queryEventsSync({
        beforeRowId: null,
        limit: 50,
        event: null,
        eventPrefix: null,
        chainSeqPresent: false,
        actorUserId: null,
        targetUserId: null,
        variableId: testVariableId("var-a"),
        environmentId: null,
        visibility: { kind: "admin" },
      });
      const recommendedQuery = captured.find((query) =>
        query.query.includes("+variable_id IS NULL"),
      );
      if (recommendedQuery === undefined) {
        throw new Error("no rotation.recommended aggregate query captured");
      }
      const plan = planOf(sql, recommendedQuery);
      expect(plan).toMatch(/USING INDEX ae_event \(event=\?\)/);
      expect(plan).not.toMatch(/USING INDEX ae_var/);
      sql.exec("DELETE FROM audit_events");
    });
  });
});
