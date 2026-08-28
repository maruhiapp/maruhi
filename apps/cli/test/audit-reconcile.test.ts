// `maruhi audit reconcile`(AUDIT_SPEC §6 — admin の監査突合)の統合テスト。
//
// 固定する性質:
//  1. 正例: 公証 2 個の前進(所属 (a)・非後退 (b)・位置下限 (c) と申告ヘッドの
//     所属がすべて成立)で exit 0
//  2. 所属違反 (a) = 行改竄の証拠として報告(Row-tampering evidence)
//  3. 位置違反 (b)(c) = 受理ポリシー不執行のサーバーの証拠として報告
//     (Acceptance-policy violation — 陳腐化リプレイ可能状態)
//  4. seq 欠番 = 削除の痕跡として報告し、以後の派生誤報を出さずに打ち切る
//  5. GET /audit-head の申告値も再計算列への所属を検査する(裁定 AK)
//  6. AuditHeadNotReady(503)は有界再試行で吸収する
//  7. 実効 admin 未満(write スコープ)は行取得より前に明確なエラー
//
// 監査行はテストが構成する「サーバー申告」であり、公証ヘッドは実際の
// computeAuditRowDigest / computeAuditHeadHash(audit-head.json が固定する
// 正規実装)で計算する — 突合の合否が本物のハッシュ連鎖に依存することを固定する。

import type { AuditHeadRow, ChainEntry, ChainOperation } from "@maruhi/crypto";
import { computeAuditHeadHash, computeAuditRowDigest, SUITE_ID } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  buildChain,
  type BuiltChain,
  genesisOp,
  makeTestUser,
  type TestUser,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, type MockResponse, onRequest } from "./support/server.ts";

const BASE_TS = 1_756_000_000_000;

let owner: TestUser;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

/** 決定的な 32 桁 hex 行 id(テスト用 — 実サーバーはランダム採番)。 */
function idOf(seq: number): string {
  return seq.toString(16).padStart(32, "0");
}

/**
 * モックの並び順の内部キー(seq を落とした negative でも id から復元できる —
 * idOf は seq の 16 進)。
 */
function orderOf(row: Record<string, unknown>): number {
  return typeof row["seq"] === "number" ? row["seq"] : Number.parseInt(String(row["id"]), 16);
}

/** テストが構成する監査行(ワイヤ形と計算入力形の共通材料)。 */
interface SeedRow {
  readonly seq: number;
  readonly event: string;
  readonly chainSeq?: number;
  readonly payload?: Readonly<Record<string, unknown>>;
}

/** ワイヤの監査行(admin 可視 — seq を運ぶ)。 */
function wireRowOf(row: SeedRow): Record<string, unknown> {
  return {
    id: idOf(row.seq),
    seq: row.seq,
    serverTs: BASE_TS + row.seq,
    event: row.event,
    actor: { type: "user", userId: owner.userId },
    ...(row.chainSeq === undefined ? {} : { chainSeq: row.chainSeq }),
    ...(row.payload === undefined ? {} : { payload: row.payload }),
  };
}

/** 計算入力形(CLI の再計算と同じ写像 — §5.1 の 17 列)。 */
function headRowOf(row: SeedRow): AuditHeadRow {
  return {
    seq: row.seq,
    rowId: idOf(row.seq),
    serverTs: BASE_TS + row.seq,
    clientTs: null,
    event: row.event,
    actorType: "user",
    actorUserId: owner.userId,
    actorKeyFingerprintHex: null,
    actorApiTokenId: null,
    targetUserId: null,
    targetKeyFingerprintHex: null,
    environmentId: null,
    variableId: null,
    epoch: null,
    version: null,
    chainSeq: row.chainSeq ?? null,
    payloadText: row.payload === undefined ? null : JSON.stringify(row.payload),
  };
}

/** 累積ハッシュ列 h_1..h_N を正規実装で計算する(index 0 = h_1)。 */
async function headsOf(rows: readonly SeedRow[]): Promise<readonly string[]> {
  const heads: string[] = [];
  let head = "";
  for (const row of rows) {
    const digest = await computeAuditRowDigest(headRowOf(row));
    if (!digest.ok) {
      throw new Error(`digest failed at seq ${row.seq}`);
    }
    const next = await computeAuditHeadHash(SUITE_ID, head, row.seq, digest.value);
    if (!next.ok) {
      throw new Error(`head failed at seq ${row.seq}`);
    }
    head = next.value;
    heads.push(head);
  }
  return heads;
}

function checkpointOp(auditHeadHashHex: string): ChainOperation {
  return { op: "checkpoint", payload: { environments: [], auditHeadHashHex } };
}

interface ReconcileServerInput {
  readonly built: BuiltChain;
  /** 配布する監査行(ワイヤ形)。既定 = rows の全件。 */
  readonly served: readonly Record<string, unknown>[];
  readonly declaredHeadHex: string;
  readonly tokenScopes?: readonly unknown[];
  /** audit-head 呼び出しごとの差し込み(undefined = 200 で申告を返す)。 */
  readonly onAuditHead?: (call: number) => MockResponse | undefined;
}

interface ReconcileServerState {
  readonly handlers: readonly MockHandler[];
  readonly eventCalls: () => number;
  readonly auditHeadCalls: () => number;
}

/** reconcile が要る全エンドポイント(chain / auth/me / audit-head / audit/events)。 */
function makeReconcileServer(input: ReconcileServerInput): ReconcileServerState {
  const projectId = input.built.projectId;
  let eventCalls = 0;
  let auditHeadCalls = 0;
  const handlers: MockHandler[] = [
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: {
        projectId,
        entries: input.built.entries as readonly ChainEntry[],
        headSeq: input.built.entries.length,
        headHashHex: input.built.hashes[input.built.hashes.length - 1],
      },
    })),
    onRequest("GET", "/auth/me", () => ({
      status: 200,
      json: {
        userId: owner.userId,
        orgs: [],
        ...(input.tokenScopes === undefined ? {} : { tokenScopes: input.tokenScopes }),
      },
    })),
    onRequest("GET", `/projects/${projectId}/audit-head`, () => {
      const injected = input.onAuditHead?.(auditHeadCalls);
      auditHeadCalls += 1;
      if (injected !== undefined) {
        return injected;
      }
      return { status: 200, json: { auditHeadHashHex: input.declaredHeadHex } };
    }),
    (request) => {
      if (request.method !== "GET" || request.path !== `/projects/${projectId}/audit/events`) {
        return null;
      }
      eventCalls += 1;
      const before = request.query["before"];
      const limit = Number(request.query["limit"] ?? "50");
      let cursorSeq = Number.POSITIVE_INFINITY;
      if (before !== undefined) {
        const cursor = input.served.find((row) => row["id"] === before);
        if (cursor === undefined) {
          return { status: 200, json: { events: [] } };
        }
        cursorSeq = orderOf(cursor);
      }
      const page = [...input.served]
        .filter((row) => orderOf(row) < cursorSeq)
        .toSorted((a, b) => orderOf(b) - orderOf(a))
        .slice(0, limit);
      return { status: 200, json: { events: page } };
    },
  ];
  return { handlers, eventCalls: () => eventCalls, auditHeadCalls: () => auditHeadCalls };
}

async function seededEnv(server: MockServer, projectId: string): Promise<TestEnv> {
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, { server: server.origin, defaultProject: projectId });
  return env;
}

/**
 * 標準フィクスチャ: チェーン = genesis(1) → checkpoint(2) → checkpoint(3)。
 * 監査行 = ミラー的な行 1..3 + 追加行 4(㊙ payload — 非 ASCII の round-trip
 * まで実計算で通す)。checkpoint 2 は h_1(初回 — (c) は空虚に真)、
 * checkpoint 3 は h_2(floor = checkpoint 2 のミラー行 seq2 ≥、(b) 非後退)を
 * 公証する = 正例。head* の上書きで各違反を構成する。
 */
async function makeFixture(overrides?: {
  /** 公証ヘッドの上書き(引数 = 再計算列 h_1..h_4 — 違反ケースの構成用)。 */
  readonly headAtChain2?: (heads: readonly string[]) => string;
  readonly headAtChain3?: (heads: readonly string[]) => string;
}): Promise<{ rows: readonly SeedRow[]; heads: readonly string[]; built: BuiltChain }> {
  const rows: readonly SeedRow[] = [
    { seq: 1, event: "chain.genesis", chainSeq: 1 },
    { seq: 2, event: "chain.checkpointed", chainSeq: 2 },
    { seq: 3, event: "chain.checkpointed", chainSeq: 3 },
    { seq: 4, event: "var.read", payload: { note: "㊙ / まる ひ", nested: { list: [1, 2] } } },
  ];
  const heads = await headsOf(rows);
  const built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: checkpointOp(overrides?.headAtChain2?.(heads) ?? heads[0]!) },
    { actor: owner, operation: checkpointOp(overrides?.headAtChain3?.(heads) ?? heads[1]!) },
  ]);
  return { rows, heads, built };
}

describe("maruhi audit reconcile(AUDIT_SPEC §6 の admin 突合)", () => {
  it("正例: 公証 2 個の前進 — 所属 (a)・位置 (b)(c)・申告所属がすべて成立して exit 0", async () => {
    const { rows, heads, built } = await makeFixture();
    const state = makeReconcileServer({
      built,
      served: rows.map(wireRowOf),
      declaredHeadHex: heads[3]!,
      tokenScopes: [{ project: built.projectId, permission: "admin" }],
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain("Audit reconciliation OK");
    expect(output).toContain("4 audit rows recomputed, 2 notarized checkpoints checked");
  });

  it("所属違反 (a): 公証ヘッドが再計算列に無い = 行改竄の証拠として報告する", async () => {
    const { rows, heads, built } = await makeFixture({ headAtChain3: () => "ab".repeat(32) });
    const state = makeReconcileServer({
      built,
      served: rows.map(wireRowOf),
      declaredHeadHex: heads[3]!,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(1);
    const output = env.errors.join("\n");
    expect(output).toContain("[Row-tampering evidence]");
    expect(output).toContain(
      "checkpoint at chain seq 3 notarizes an audit head that does not appear",
    );
    expect(output).toContain("membership check (a)");
    // 2 区分の総括文言(§6): 所属違反 = 公証後の行の改変・削除
    expect(output).toContain("rows in the notarized prefix were altered or deleted");
  });

  it("位置違反 (c): 非前進ヘッドの連続公証 = 受理ポリシー不執行の証拠として報告する", async () => {
    // checkpoint 3 が checkpoint 2 と同じ h_1 を公証する(実在する古いヘッドの
    // 返し続け)。(b) は等号を許すため通り、(c) の位置下限(直前 checkpoint の
    // ミラー行 seq2)が落とす — 受理検査と同一述語
    const { rows, heads, built } = await makeFixture({ headAtChain3: (h) => h[0]! });
    const state = makeReconcileServer({
      built,
      served: rows.map(wireRowOf),
      declaredHeadHex: heads[3]!,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(1);
    const output = env.errors.join("\n");
    expect(output).toContain("[Acceptance-policy violation (stale-replay risk)]");
    expect(output).toContain("position-floor check (c)");
    expect(output).toContain("the server accepted attestations it must reject");
    // 所属違反ではない(h_1 は実在する)— 区分の混同がないこと
    expect(output).not.toContain("[Row-tampering evidence]");
  });

  it("位置違反 (b): 公証位置の後退も受理ポリシー不執行として報告する", async () => {
    const { rows, heads, built } = await makeFixture({
      headAtChain2: (h) => h[2]!,
      headAtChain3: (h) => h[0]!,
    });
    const state = makeReconcileServer({
      built,
      served: rows.map(wireRowOf),
      declaredHeadHex: heads[3]!,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(1);
    const output = env.errors.join("\n");
    expect(output).toContain("non-regression check (b)");
    expect(output).toContain("[Acceptance-policy violation (stale-replay risk)]");
  });

  it("seq 欠番 = 削除の痕跡として報告し、派生の誤報を出さずに打ち切る", async () => {
    const { rows, heads, built } = await makeFixture();
    const state = makeReconcileServer({
      built,
      // seq 3(checkpoint 3 のミラー行)を落とす = 削除の痕跡
      served: rows.filter((row) => row.seq !== 3).map(wireRowOf),
      declaredHeadHex: heads[3]!,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(1);
    const output = env.errors.join("\n");
    expect(output).toContain("audit seq 3 is missing");
    expect(output).toContain("trace of deleted rows");
    // 欠番以降の連鎖は全て食い違うため、所属検査には進まない(誤帰属の量産をしない)
    expect(output).not.toContain("membership check (a)");
  });

  it("GET /audit-head の申告値も再計算列への所属を検査する(裁定 AK)", async () => {
    const { rows, built } = await makeFixture();
    const state = makeReconcileServer({
      built,
      served: rows.map(wireRowOf),
      declaredHeadHex: "12".repeat(32),
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(1);
    const output = env.errors.join("\n");
    expect(output).toContain("declared by GET /audit-head does not appear");
    expect(output).toContain("[Row-tampering evidence]");
  });

  it("AuditHeadNotReady(503)は有界再試行で吸収する", async () => {
    const { rows, heads, built } = await makeFixture();
    const state = makeReconcileServer({
      built,
      served: rows.map(wireRowOf),
      declaredHeadHex: heads[3]!,
      onAuditHead: (call) =>
        call === 0 ? { status: 503, json: { _tag: "AuditHeadNotReady" } } : undefined,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(0);
    expect(state.auditHeadCalls()).toBe(2);
    expect(env.logs.join("\n")).toContain("Audit reconciliation OK");
  });

  it("実効 admin 未満(write スコープ)は行取得より前に明確なエラー", async () => {
    const { rows, heads, built } = await makeFixture();
    const state = makeReconcileServer({
      built,
      served: rows.map(wireRowOf),
      declaredHeadHex: heads[3]!,
      tokenScopes: [{ project: built.projectId, permission: "write" }],
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("requires effective admin permission");
    // 突合を始めない(監査行の取得も申告取得も 0 回)
    expect(state.eventCalls()).toBe(0);
    expect(state.auditHeadCalls()).toBe(0);
  });

  it("seq の無い行(admin ビューでない応答)は自己矛盾として中止する", async () => {
    const { rows, heads, built } = await makeFixture();
    const noSeq = rows.map(wireRowOf).map((row) => {
      const { seq: _seq, ...rest } = row;
      return rest;
    });
    const state = makeReconcileServer({ built, served: noSeq, declaredHeadHex: heads[3]! });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("carries no seq");
  });
});
