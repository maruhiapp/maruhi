// `var.read` の集約形(AUDIT_SPEC §3.3 — 2026-09-02 監査ログの成長密度対策 ②)の
// テスト。vitest-pool-workers(workerd 実環境)。
//
// 固定するもの:
// - 記録形: 値付き一括 pull 1 回 = 環境単位 1 行。variable_id / epoch / version
//   列は NULL、payload = { variables: [{ variableId, epoch, version }, …] }
//   (variableId 昇順)。返した変数が 0 の pull は行を書かない
// - 密度: 100 変数の環境を 1 回 pull → 監査行 1 行(旧: 100 行)。行 + 索引の
//   バイト数の実測(仕様 §3.3 / AUTH_SPEC §12-8 余裕の会計の数値の出所)
// - 要ローテーション検出の同値性(§4.1 手順 3 の (a)): 旧形のみ / 集約形のみ /
//   混在の 3 形で detectMemberRemoval の basis が一致する(集約は検出の入力を
//   欠損させない — 裁定 CZ の線引き)。区間外の読み取りは両形とも数えない
// - §7 の variable_id フィルタ(Q4): 旧形の列一致と集約形の payload 一致の
//   和集合。ページング(カーソル・limit)が 2 クエリ合流でも seq 降順・重複なし

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

describe("集約形の記録(§3.3)", () => {
  it("値付き pull は環境単位 1 行 — 変数粒度の列は NULL、payload に昇順の列挙", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    // 作成順を昇順と逆にして、列挙が variableId 昇順に固定されることを見る
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
    // 保存バイト列(row_digest の入力)まで固定: キー順 variableId → epoch → version
    expect(String(read["payload"])).toBe(
      JSON.stringify({
        variables: [
          { variableId: "var-alpha", epoch: 1, version: 1 },
          { variableId: VAR, epoch: 1, version: 1 },
          { variableId: "var-zeta", epoch: 1, version: 1 },
        ],
      }),
    );
    // 共有ヘルパの往復(サーバーの書き手と CLI の読み手が同一実装)
    expect(auditReadVariablesOf(JSON.parse(String(read["payload"])))).toEqual([
      { variableId: "var-alpha", epoch: 1, version: 1 },
      { variableId: VAR, epoch: 1, version: 1 },
      { variableId: "var-zeta", epoch: 1, version: 1 },
    ]);
  });

  it("返した変数が 0 の pull は行を書かない(記録条件 = 暗号文の配布)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await pullAs(READER);
    expect(varReadRows(await readAuditEvents(projectId))).toHaveLength(0);
  });

  it("100 変数の環境を 1 回 pull → 監査行 1 行(旧: 100 行)。列挙は 100 件", async () => {
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

/** 集約形 / 旧形の行を直接シードする(検出の同値性・密度の実測用)。 */
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

describe("密度の実測(行 + 索引のバイト数 — §3.3 / AUTH_SPEC §12-8 の会計)", () => {
  it("集約形は 1 pull 1 行で、100 変数でも旧形 100 行より小さい", async () => {
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName("audit-read-density-test"));
    const measured = await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql;
      const store = makeAuditStore(sql);
      // 識別子は CLI の実発行形(`v` + 24 hex = 25 文字 — meta-statement.ts)に揃える
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
    // 100 変数の pull: 旧形 100 行 vs 集約形 1 行 — バイトでも小さい
    expect(measured.aggregated100PerRow).toBeLessThan(measured.legacyPerRow * 100);
    expect(perVariable).toBeGreaterThan(0);
  });
});

describe("要ローテーション検出の同値性(§4.1 手順 3 (a) — 旧形 / 集約形 / 混在)", () => {
  const TARGET = "user-target-0001";
  const E = "env-equiv-0001";

  /** 在籍区間(genesis 〜 member_removed)と変数 V1〜V3 の存在、区間外の読み取りを共通に持つ列。 */
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
      // 在籍区間の前の読み取り(数えない — 両形とも)
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

  it("旧形のみ・集約形のみ・混在で basis が一致する(v1 / v2 = read, v3 = readable)", async () => {
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

  it("他人の集約行は数えない(actor 列で照合 — 可視性・本人判定と同じ列)", async () => {
    const basis = await basisOf(scenario([aggregatedRead(MEMBER, E, ["v1", "v2"])]));
    expect(basis).toEqual({
      [`${E}/v1`]: "readable",
      [`${E}/v2`]: "readable",
      [`${E}/v3`]: "readable",
    });
  });
});

describe("§7 の variable_id フィルタ(Q4 — 旧形の列一致 + 集約形の payload 一致)", () => {
  it("集約行は列挙が当該変数を含むときだけ一致し、削除後の pull は含まない", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await createVariableOk(dek, "var-second", "SECOND", "two");
    await pullAs(READER);
    await pullAs(MEMBER);
    expect((await deleteVariableRequest(VAR, OWNER)).status).toBe(204);
    // 削除後の pull は var-second だけを列挙する
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
    // 列一致の行は当該変数の行だけ
    for (const event of forVar.events.filter((e) => e.event !== "var.read")) {
      expect(event.variableId).toBe(VAR);
    }

    const forSecond = await fetchEvents(token(OWNER), { variableId: "var-second", limit: "200" });
    expect(forSecond.events.filter((event) => event.event === "var.read")).toHaveLength(3);

    const forAbsent = await fetchEvents(token(OWNER), { variableId: "var-absent", limit: "200" });
    expect(forAbsent.events).toHaveLength(0);
  });

  it("ページングは 2 クエリ合流でも seq 降順・重複なし・全件到達", async () => {
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

  it("admin 未満(class1-or-self)では本人の集約行だけがフィルタに現れる", async () => {
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

/** 実行された SQL を捕捉する SqlStorage の包み(EXPLAIN・クエリ形の固定用)。 */
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

/** 行の環境 ID を差し替える(複数環境に同じ変数 ID がある形のシード用)。 */
function inEnv(row: AuditEventInput, environmentId: string): AuditEventInput {
  return { ...row, environmentId };
}

/** var.read 行の環境 ID 列(seq 降順のまま)。 */
function readEnvironments(
  rows: readonly { event: string; environmentId: string | null }[],
): readonly (string | null)[] {
  return rows.filter((row) => row.event === "var.read").map((row) => row.environmentId);
}

describe("variable_id フィルタの走査範囲(第 2 次探索 — 判定前に消費する共有資源の有界化)", () => {
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

  it("値を一度も持たない(declared のみの)変数は集約側の payload 検査を走らせない", async () => {
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

  it("存在区間は環境ごとの和 — 環境 A で削除済みでも環境 B の集約行を取りこぼさない", async () => {
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
        // A の削除後の B の pull — 変数単位の MAX(deleted) を上限にすると落ちる行
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

  it("admin 未満の集約側クエリは本人の actor 行に束縛される(他人の pull 履歴を走査しない)", async () => {
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
