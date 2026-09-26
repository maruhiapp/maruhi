// Tests for the aggregated form of `var.read` (AUDIT_SPEC §3.3 —
// audit-log growth-density countermeasure ②). @cloudflare/vitest-plugin
// (real workerd environment).
//
// What is pinned:
// - Recorded shape: one bulk pull with values = one row per environment.
//   The variable_id / epoch / version columns are NULL, and payload =
//   { variables: [{ variableId, epoch, version }, …] } (variableId
//   ascending). A pull that returned zero variables writes no row
// - Density: one pull of a 100-variable environment → 1 audit row. The
//   byte count of rows + indexes is measured (the source of the numbers
//   in the §3.3 / AUTH_SPEC §12-8 headroom accounting)
// - Equivalence of rotation-needed detection (§4.1 step 3 (a)): the
//   detectMemberRemoval basis agrees across the three shapes — legacy
//   only / aggregated only / mixed (aggregation must not lose detection
//   inputs — the ruling CZ line). Reads outside the interval are not
//   counted by either shape
// - The §7 variable_id filter (Q4): the union of the legacy column match
//   and the aggregated payload match. Paging (cursor / limit) stays
//   seq-descending with no duplicates across the 2-query union

import { auditReadPayload, auditReadVariablesOf } from "@maruhi/core";
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import type { AuditEventInput } from "../src/audit-store.ts";
import { makeAuditStore } from "../src/audit-store.ts";
import { detectMemberRemoval } from "../src/rotation-detect.ts";
import { fetchEvents, type WireAuditEvent } from "./support/audit-read-scenario.ts";
import {
  createEnvironmentOk,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  deleteVariableRequest,
  ENV,
  fixture,
  registerDataScenario,
  token,
  VAR,
} from "./support/data-scenario.ts";
import { readAuditEvents } from "./support/project-do.ts";

registerDataScenario();

async function pullAs(userId: string, environmentId: string = ENV): Promise<void> {
  const response = await requestJson("GET", `/environments/${environmentId}/pull`, token(userId));
  expect(response.status).toBe(200);
}

function varReadRows(events: readonly Record<string, unknown>[]): Record<string, unknown>[] {
  return events.filter((event) => event["event"] === "var.read");
}

describe("recording the aggregated form (§3.3)", () => {
  it("a pull with values is one row per environment — variable-grained columns are NULL, payload carries an ascending enumeration", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    // Create in the reverse of ascending order to verify the enumeration is pinned to variableId ascending
    await createVariableOk(dek, "var-zeta", "ZETA", "z");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await createVariableOk(dek, "var-alpha", "ALPHA", "a");
    await pullAs(READER);

    const reads = varReadRows(await readAuditEvents(projectId));
    expect(reads).toHaveLength(1);
    const read = reads[0];
    if (read === undefined) throw new Error("missing var.read row");
    expect(read["actor_type"]).toBe("user");
    expect(read["actor_user_id"]).toBe(READER);
    expect(read["environment_id"]).toBe(ENV);
    expect(read["variable_id"]).toBeNull();
    expect(read["epoch"]).toBeNull();
    expect(read["version"]).toBeNull();
    expect(read["target_user_id"]).toBeNull();
    expect(read["actor_key_fingerprint"]).toBeNull();
    // Pinned down to the stored bytes (the input of row_digest): key order is variableId → epoch → version
    expect(String(read["payload"])).toBe(
      JSON.stringify({
        variables: [
          { variableId: "var-alpha", epoch: 1, version: 1 },
          { variableId: VAR, epoch: 1, version: 1 },
          { variableId: "var-zeta", epoch: 1, version: 1 },
        ],
      }),
    );
    // Round-trip through the shared helper (the server's writer and the CLI's reader are the same implementation)
    expect(auditReadVariablesOf(JSON.parse(String(read["payload"])))).toEqual([
      { variableId: "var-alpha", epoch: 1, version: 1 },
      { variableId: VAR, epoch: 1, version: 1 },
      { variableId: "var-zeta", epoch: 1, version: 1 },
    ]);
  });

  it("a pull that returned zero variables writes no row (the recording condition = distribution of ciphertext)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await pullAs(READER);
    expect(varReadRows(await readAuditEvents(projectId))).toHaveLength(0);
  });

  it("one pull of a 100-variable environment → 1 audit row. The enumeration has 100 entries", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    for (let index = 0; index < 100; index += 1) {
      await createVariableOk(
        dek,
        `var-dense-${String(index).padStart(3, "0")}`,
        `DENSE_${index}`,
        `dense-${index}`,
      );
    }
    const before = (await readAuditEvents(projectId)).length;
    await pullAs(READER);
    const events = await readAuditEvents(projectId);
    expect(events.length).toBe(before + 1);
    const reads = varReadRows(events);
    expect(reads).toHaveLength(1);
    const listed = auditReadVariablesOf(JSON.parse(String(reads[0]?.["payload"])));
    expect(listed).toHaveLength(100);
    expect(listed?.map((variable) => variable.variableId)).toEqual(
      Array.from({ length: 100 }, (_v, index) => `var-dense-${String(index).padStart(3, "0")}`),
    );
  });
});

/** Seed aggregated / legacy rows directly (for detection equivalence and density measurement). */
function aggregatedRead(
  actorUserId: string,
  environmentId: string,
  variableIds: readonly string[],
): AuditEventInput {
  return {
    serverTs: 1_700_000_000_000,
    event: "var.read",
    actorType: "user",
    actorUserId,
    environmentId,
    payload: auditReadPayload(
      variableIds.map((variableId) => ({ variableId, epoch: 1, version: 1 })),
    ),
  };
}

function legacyRead(
  actorUserId: string,
  environmentId: string,
  variableId: string,
): AuditEventInput {
  return {
    serverTs: 1_700_000_000_000,
    event: "var.read",
    actorType: "user",
    actorUserId,
    environmentId,
    variableId,
    epoch: 1,
    version: 1,
  };
}

describe("measured density (row + index bytes — the §3.3 / AUTH_SPEC §12-8 accounting)", () => {
  it("the aggregated form is 1 row per pull, and even at 100 variables it is smaller than the legacy 100 rows", async () => {
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName("audit-read-density-test"));
    const measured = await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql;
      const store = makeAuditStore(sql);
      // Identifiers match the CLI's real issuance shape (`v` + 24 hex = 25 chars — meta-statement.ts)
      const variables = Array.from(
        { length: 100 },
        (_v, i) => `v${i.toString(16).padStart(24, "0")}`,
      );
      const measure = (rows: readonly AuditEventInput[]): number => {
        sql.exec("DELETE FROM audit_events");
        const base = sql.databaseSize;
        store.appendManySync(rows);
        return sql.databaseSize - base;
      };
      const LEGACY_ROWS = 20_000;
      const legacy = measure(
        Array.from({ length: LEGACY_ROWS }, (_r, i) =>
          legacyRead("user-reader", "env-0001", variables[i % 100] as string),
        ),
      );
      const AGG_ROWS = 200;
      const aggregated100 = measure(
        Array.from({ length: AGG_ROWS }, () =>
          aggregatedRead("user-reader", "env-0001", variables),
        ),
      );
      const aggregated1 = measure(
        Array.from({ length: 2_000 }, () =>
          aggregatedRead("user-reader", "env-0001", [variables[0] as string]),
        ),
      );
      sql.exec("DELETE FROM audit_events");
      return {
        legacyPerRow: legacy / LEGACY_ROWS,
        aggregated100PerRow: aggregated100 / AGG_ROWS,
        aggregated1PerRow: aggregated1 / 2_000,
      };
    });
    const perVariable = (measured.aggregated100PerRow - measured.aggregated1PerRow) / 99;
    const base = measured.aggregated1PerRow - perVariable;
    console.log(
      `var.read density — legacy ${measured.legacyPerRow.toFixed(1)} B/row; aggregated ${base.toFixed(1)} B/row + ${perVariable.toFixed(1)} B/variable (1 var ${measured.aggregated1PerRow.toFixed(1)} B, 100 vars ${measured.aggregated100PerRow.toFixed(1)} B)`,
    );
    // A pull of 100 variables: legacy 100 rows vs aggregated 1 row — smaller in bytes too
    expect(measured.aggregated100PerRow).toBeLessThan(measured.legacyPerRow * 100);
    expect(perVariable).toBeGreaterThan(0);
  });
});

describe("equivalence of rotation-needed detection (§4.1 step 3 (a) — legacy / aggregated / mixed)", () => {
  const TARGET = "user-target-0001";
  const E = "env-equiv-0001";

  /** A column sharing the membership interval (genesis through member_removed), the existence of variables V1–V3, and out-of-interval reads. */
  function scenario(readsInside: readonly AuditEventInput[]): readonly AuditEventInput[] {
    const ts = 1_700_000_000_000;
    return [
      {
        serverTs: ts,
        event: "chain.genesis",
        actorType: "user",
        actorUserId: OWNER,
        targetUserId: OWNER,
        chainSeq: 1,
      },
      {
        serverTs: ts,
        event: "var.created",
        actorType: "user",
        actorUserId: OWNER,
        environmentId: E,
        variableId: "v1",
      },
      {
        serverTs: ts,
        event: "var.created",
        actorType: "user",
        actorUserId: OWNER,
        environmentId: E,
        variableId: "v2",
      },
      {
        serverTs: ts,
        event: "var.created",
        actorType: "user",
        actorUserId: OWNER,
        environmentId: E,
        variableId: "v3",
      },
      // Reads before the membership interval (not counted — by either shape)
      aggregatedRead(TARGET, E, ["v3"]),
      legacyRead(TARGET, E, "v3"),
      {
        serverTs: ts,
        event: "chain.member_added",
        actorType: "user",
        actorUserId: OWNER,
        targetUserId: TARGET,
        chainSeq: 2,
        payload: { role: "member" },
      },
      ...readsInside,
      {
        serverTs: ts,
        event: "chain.member_removed",
        actorType: "user",
        actorUserId: OWNER,
        targetUserId: TARGET,
        chainSeq: 3,
      },
    ];
  }

  async function basisOf(rows: readonly AuditEventInput[]): Promise<Record<string, string>> {
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName("audit-read-equivalence-test"));
    return await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql;
      sql.exec("DELETE FROM audit_events");
      const store = makeAuditStore(sql);
      store.appendManySync(rows);
      const recommended = detectMemberRemoval({
        read: store.readRotationSync,
        targetUserId: TARGET,
        triggerChainSeq: 3,
        nowMs: 1_700_000_000_500,
      });
      sql.exec("DELETE FROM audit_events");
      return Object.fromEntries(
        recommended.map((event) => [
          `${event.environmentId}/${event.variableId}`,
          String(event.payload?.["basis"]),
        ]),
      );
    });
  }

  it("the basis agrees across legacy-only, aggregated-only, and mixed (v1 / v2 = read, v3 = readable)", async () => {
    const expected = { [`${E}/v1`]: "read", [`${E}/v2`]: "read", [`${E}/v3`]: "readable" };
    const legacyOnly = await basisOf(
      scenario([legacyRead(TARGET, E, "v1"), legacyRead(TARGET, E, "v2")]),
    );
    const aggregatedOnly = await basisOf(scenario([aggregatedRead(TARGET, E, ["v1", "v2"])]));
    const mixed = await basisOf(
      scenario([legacyRead(TARGET, E, "v1"), aggregatedRead(TARGET, E, ["v2"])]),
    );
    expect(legacyOnly).toEqual(expected);
    expect(aggregatedOnly).toEqual(expected);
    expect(mixed).toEqual(expected);
  });

  it("other people's aggregated rows are not counted (matched on the actor column — the same column as visibility / self-detection)", async () => {
    const basis = await basisOf(scenario([aggregatedRead(MEMBER, E, ["v1", "v2"])]));
    expect(basis).toEqual({
      [`${E}/v1`]: "readable",
      [`${E}/v2`]: "readable",
      [`${E}/v3`]: "readable",
    });
  });
});

describe("the §7 variable_id filter (Q4 — legacy column match + aggregated payload match)", () => {
  it("an aggregated row matches only when its enumeration contains that variable, and a pull after deletion is not included", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await createVariableOk(dek, "var-second", "SECOND", "two");
    await pullAs(READER);
    await pullAs(MEMBER);
    expect((await deleteVariableRequest(VAR, OWNER)).status).toBe(204);
    // The pull after deletion enumerates only var-second
    await pullAs(READER);

    const forVar = await fetchEvents(token(OWNER), { variableId: VAR, limit: "200" });
    expect(forVar.status).toBe(200);
    const readsForVar = forVar.events.filter((event) => event.event === "var.read");
    expect(readsForVar).toHaveLength(2);
    for (const event of readsForVar) {
      expect(event.variableId).toBeUndefined();
      expect(auditReadVariablesOf(event.payload)?.map((v) => v.variableId)).toContain(VAR);
    }
    expect(forVar.events.map((event) => event.event)).toEqual(
      expect.arrayContaining(["var.created", "var.version_pushed", "var.deleted", "var.read"]),
    );
    // The column-match rows are only that variable's rows
    for (const event of forVar.events.filter((e) => e.event !== "var.read")) {
      expect(event.variableId).toBe(VAR);
    }

    const forSecond = await fetchEvents(token(OWNER), { variableId: "var-second", limit: "200" });
    expect(forSecond.events.filter((event) => event.event === "var.read")).toHaveLength(3);

    const forAbsent = await fetchEvents(token(OWNER), { variableId: "var-absent", limit: "200" });
    expect(forAbsent.events).toHaveLength(0);
  });

  it("paging stays seq-descending with no duplicates across the 2-query union, reaching all rows", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await createVariableOk(dek, "var-second", "SECOND", "two");
    for (let i = 0; i < 3; i += 1) {
      await pullAs(READER);
    }
    const all = await fetchEvents(token(OWNER), { variableId: VAR, limit: "200" });
    expect(all.events.length).toBeGreaterThanOrEqual(5);
    const paged: WireAuditEvent[] = [];
    let before: string | undefined;
    for (let page = 0; page < 20; page += 1) {
      const query: Record<string, string> = { variableId: VAR, limit: "2" };
      if (before !== undefined) query["before"] = before;
      const result = await fetchEvents(token(OWNER), query);
      if (result.events.length === 0) break;
      paged.push(...result.events);
      before = result.events[result.events.length - 1]?.id;
    }
    expect(paged.map((event) => event.id)).toEqual(all.events.map((event) => event.id));
    const seqs = paged.map((event) => event.seq ?? -1);
    expect(seqs).toEqual([...seqs].toSorted((a, b) => b - a));
    expect(new Set(seqs).size).toBe(seqs.length);
  });

  it("below admin (class1-or-self), only one's own aggregated rows appear in the filter", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await pullAs(READER);
    await pullAs(MEMBER);
    const own = await fetchEvents(token(READER), { variableId: VAR, limit: "200" });
    const reads = own.events.filter((event) => event.event === "var.read");
    expect(reads).toHaveLength(1);
    expect(reads[0]?.actor.userId).toBe(READER);
    expect(reads[0]?.seq).toBeUndefined();
  });
});

/** A SqlStorage wrapper that captures the SQL executed (for pinning EXPLAIN / query shape). */
function capturing(sql: SqlStorage): { readonly sql: SqlStorage; readonly queries: string[] } {
  const queries: string[] = [];
  const proxy = new Proxy(sql, {
    get(target, property) {
      if (property === "exec") {
        return (query: string, ...bindings: (string | number | null)[]) => {
          queries.push(query);
          return target.exec(query, ...bindings);
        };
      }
      return Reflect.get(target, property, target);
    },
  });
  return { sql: proxy, queries };
}

/** Rewrite a row's environment ID (for seeding the shape where multiple environments hold the same variable ID). */
function inEnv(row: AuditEventInput, environmentId: string): AuditEventInput {
  return { ...row, environmentId };
}

/** The environment-ID column of var.read rows (still seq-descending). */
function readEnvironments(
  rows: readonly { event: string; environmentId: string | null }[],
): readonly (string | null)[] {
  return rows.filter((row) => row.event === "var.read").map((row) => row.environmentId);
}

describe("scan range of the variable_id filter (bounding the shared resource consumed before judging)", () => {
  const E = "env-scan-0001";
  const ts = 1_700_000_000_000;

  const baseQuery = {
    beforeRowId: null,
    limit: 50,
    event: null,
    eventPrefix: null,
    chainSeqPresent: false,
    actorUserId: null,
    targetUserId: null,
    environmentId: null,
  } as const;

  async function withScanDo<T>(
    rows: readonly AuditEventInput[],
    body: (store: ReturnType<typeof makeAuditStore>, queries: string[]) => T,
  ): Promise<T> {
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName("audit-read-scan-test"));
    return await runInDurableObject(stub, (_instance, state) => {
      const raw = state.storage.sql;
      raw.exec("DELETE FROM audit_events");
      makeAuditStore(raw).appendManySync(rows);
      const { sql, queries } = capturing(raw);
      const result = body(makeAuditStore(sql), queries);
      raw.exec("DELETE FROM audit_events");
      return result;
    });
  }

  const created = (variableId: string): AuditEventInput => ({
    serverTs: ts,
    event: "var.created",
    actorType: "user",
    actorUserId: OWNER,
    environmentId: E,
    variableId,
  });
  const pushed = (variableId: string): AuditEventInput => ({
    serverTs: ts,
    event: "var.version_pushed",
    actorType: "user",
    actorUserId: OWNER,
    environmentId: E,
    variableId,
    epoch: 1,
    version: 1,
  });

  it("a variable that never held a value (declared only) does not run the aggregated-side payload check", async () => {
    const result = await withScanDo(
      [
        created("v-declared"),
        created("v-active"),
        pushed("v-active"),
        aggregatedRead(READER, E, ["v-active"]),
      ],
      (store, queries) => {
        const declared = store.queryEventsSync({
          ...baseQuery,
          variableId: "v-declared",
          visibility: { kind: "admin" },
        });
        const declaredScans = queries.filter((query) => query.includes("json_each")).length;
        queries.length = 0;
        const active = store.queryEventsSync({
          ...baseQuery,
          variableId: "v-active",
          visibility: { kind: "admin" },
        });
        const activeScans = queries.filter((query) => query.includes("json_each")).length;
        return {
          declaredEvents: declared.map((row) => row.event),
          declaredScans,
          activeEvents: active.map((row) => row.event),
          activeScans,
        };
      },
    );
    expect(result.declaredEvents).toEqual(["var.created"]);
    expect(result.declaredScans).toBe(0);
    expect(result.activeEvents).toEqual(["var.read", "var.version_pushed", "var.created"]);
    expect(result.activeScans).toBe(1);
  });

  it("the existence interval is a per-environment union — even when deleted in environment A, environment B's aggregated rows are not missed", async () => {
    const B = "env-scan-0002";
    const result = await withScanDo(
      [
        created("v-shared"),
        pushed("v-shared"),
        inEnv(created("v-shared"), B),
        inEnv(pushed("v-shared"), B),
        aggregatedRead(READER, E, ["v-shared"]),
        {
          serverTs: ts,
          event: "var.deleted",
          actorType: "user",
          actorUserId: OWNER,
          environmentId: E,
          variableId: "v-shared",
        },
        // B's pull after A's deletion — a row that would be dropped if a per-variable MAX(deleted) were used as the upper bound
        aggregatedRead(READER, B, ["v-shared"]),
      ],
      (store) => {
        const all = store.queryEventsSync({
          ...baseQuery,
          variableId: "v-shared",
          visibility: { kind: "admin" },
        });
        const onlyA = store.queryEventsSync({
          ...baseQuery,
          environmentId: E,
          variableId: "v-shared",
          visibility: { kind: "admin" },
        });
        const onlyB = store.queryEventsSync({
          ...baseQuery,
          environmentId: B,
          variableId: "v-shared",
          visibility: { kind: "admin" },
        });
        return {
          all: readEnvironments(all),
          onlyA: readEnvironments(onlyA),
          onlyB: readEnvironments(onlyB),
        };
      },
    );
    expect(result.all).toEqual([B, E]);
    expect(result.onlyA).toEqual([E]);
    expect(result.onlyB).toEqual([B]);
  });

  it("a below-admin aggregated-side query is bound to one's own actor rows (it does not scan other people's pull history)", async () => {
    const result = await withScanDo(
      [
        created("v-active"),
        pushed("v-active"),
        aggregatedRead(MEMBER, E, ["v-active"]),
        aggregatedRead(READER, E, ["v-active"]),
      ],
      (store, queries) => {
        const rows = store.queryEventsSync({
          ...baseQuery,
          variableId: "v-active",
          visibility: { kind: "class1-or-self", selfUserId: READER },
        });
        const scan = queries.find((query) => query.includes("json_each")) ?? "";
        return {
          actors: rows.filter((row) => row.event === "var.read").map((row) => row.actorUserId),
          boundToSelf: scan.includes("actor_user_id = ?"),
        };
      },
    );
    expect(result.actors).toEqual([READER]);
    expect(result.boundToSelf).toBe(true);
  });
});
