// `maruhi audit`(AUDIT_SPEC §6 / §7 — C1)の統合テスト。
//
// 固定する性質:
//  1. list は監査行を表示し、変数の表示名は検証済みステートメントからのみ解決
//     する。payload の名前スナップショット(サーバー申告)は「記録」として
//     区別表示され、表示名の位置に昇格しない(TCB 規律 — AUDIT_SPEC §7)
//  2. chain.* ミラー行は検証済みチェーンと突合され(共有写像 chainMirrorEvent)、
//     一致は 突合=OK、不一致は警告 + 終了コード 1。chain.* 外で chain_seq を
//     名乗る行も無ラベル表示せず整合性違反にする(改竄の証拠 — §6 / S1)
//  3. verify はミラーの全単射検証(§1-5): 欠落(削除の隠蔽)・改変・重複の
//     いずれも検出して終了コード 1
//  4. invites / self は D1 側の行を表示し、self は要監視イベント
//     (auth.recovery_blob_fetched — §3.1)の含意を添える
//  5. 引数の書き方の誤り(self への --project・limit の範囲外・不明な操作)は
//     通信より前に usage エラー(2)

import { chainMirrorEvent } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  statementFor,
  type TestUser,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "env-audit-1";
const BASE_TS = 1_755_000_000_000;

let owner: TestUser;
let member: TestUser;
let dek1: Uint8Array;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  member = await makeTestUser("user-member-2222");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** ベースチェーン(genesis → 環境作成 → メンバー追加。未収束義務なし)。 */
async function baseChain(): Promise<BuiltChain> {
  return buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: addMemberOp(member, "member") },
  ]);
}

type WireRow = Record<string, unknown>;

/** 決定的な 32 桁 hex 行 id(テスト用 — 実サーバーはランダム採番)。 */
function idOf(seq: number): string {
  return seq.toString(16).padStart(32, "0");
}

/** undefined の項目を落として割り当てる(ワイヤの optionalKey と同型)。 */
function assignPresent(target: Record<string, unknown>, source: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(source)) {
    if (value !== undefined) {
      target[key] = value;
    }
  }
}

/** 検証済みエントリ → ワイヤのミラー行(サーバーと同じ共有写像から構成)。 */
function wireMirrorRow(entry: ChainEntry, seq: number): WireRow {
  const record = chainMirrorEvent(entry, BASE_TS + seq);
  const actor: Record<string, unknown> = { type: record.actorType };
  assignPresent(actor, {
    userId: record.actorUserId,
    keyFingerprintHex: record.actorKeyFingerprintHex,
  });
  const row: WireRow = {
    id: idOf(seq),
    seq,
    serverTs: record.serverTs,
    event: record.event,
    actor,
  };
  assignPresent(row, {
    clientTs: record.clientTs,
    targetUserId: record.targetUserId,
    targetKeyFingerprintHex: record.targetKeyFingerprintHex,
    environmentId: record.environmentId,
    epoch: record.epoch,
    chainSeq: record.chainSeq,
    payload: record.payload,
  });
  return row;
}

/** チェーン全エントリのミラー行(監査 seq = chain seq に揃える)。 */
function mirrorRowsOf(built: BuiltChain): WireRow[] {
  return built.entries.map((entry) => wireMirrorRow(entry, entry.seq));
}

/**
 * 監査イベントエンドポイントのモック: event / eventPrefix / before / limit を
 * サーバーと同じ意味論(seq 降順・row id カーソルの解決、不明な id は空ページ)で
 * 適用する。eventPrefix は前置一致(AUDIT_SPEC §7 — deepsec R1)。
 */
function auditEventsHandler(projectId: string, rows: () => readonly WireRow[]): MockHandler {
  return (request) => {
    if (request.method !== "GET" || request.path !== `/projects/${projectId}/audit/events`) {
      return null;
    }
    const eventFilter = request.query["event"];
    const prefixFilter = request.query["eventPrefix"];
    const chainSeqPresent = request.query["chainSeqPresent"];
    const before = request.query["before"];
    const limit = Number(request.query["limit"] ?? "50");
    let cursorSeq = Number.POSITIVE_INFINITY;
    if (before !== undefined) {
      const cursor = rows().find((row) => row["id"] === before);
      if (cursor === undefined) {
        return { status: 200, json: { events: [] } };
      }
      cursorSeq = cursor["seq"] as number;
    }
    const filtered = rows()
      .filter((row) => (eventFilter === undefined ? true : row["event"] === eventFilter))
      .filter((row) =>
        prefixFilter === undefined ? true : String(row["event"]).startsWith(prefixFilter),
      )
      .filter((row) => (chainSeqPresent === undefined ? true : row["chainSeq"] !== undefined))
      .filter((row) => (row["seq"] as number) < cursorSeq)
      .toSorted((a, b) => (b["seq"] as number) - (a["seq"] as number))
      .slice(0, limit);
    return { status: 200, json: { events: filtered } };
  };
}

interface AuditServerInput {
  readonly built: BuiltChain;
  readonly rows: readonly WireRow[];
  /** メタデータ pull の可否(false = 404 — 名前解決の劣化経路)。 */
  readonly metadataAvailable?: boolean;
}

async function makeAuditServer(input: AuditServerInput): Promise<readonly MockHandler[]> {
  const projectId = input.built.projectId;
  const envStatement = await environmentStatementFor({
    projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: headOf(input.built, 2),
  });
  const activeStatement = await statementFor({
    projectId,
    environmentId: ENV_ID,
    variableId: "va",
    name: "ALPHA",
    author: owner,
    head: headOf(input.built, 2),
  });
  const manifest = await manifestFor({
    projectId,
    environmentId: ENV_ID,
    epoch: 1,
    issuer: owner,
    head: headOf(input.built, input.built.entries.length),
    envStatement,
    statements: [activeStatement],
  });
  return [
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: {
        projectId,
        entries: input.built.entries as readonly ChainEntry[],
        headSeq: input.built.entries.length,
        headHashHex: input.built.hashes[input.built.hashes.length - 1],
      },
    })),
    onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull/metadata`, () =>
      input.metadataAvailable === false
        ? { status: 404, json: { _tag: "EnvironmentNotFound", environmentId: ENV_ID } }
        : {
            status: 200,
            json: {
              environmentId: ENV_ID,
              currentEpoch: 1,
              statement: envStatement,
              variables: [activeStatement],
              deletedVariables: [],
              manifest,
            },
          },
    ),
    auditEventsHandler(projectId, () => input.rows),
  ];
}

async function startEnv(handlers: readonly MockHandler[], projectId?: string): Promise<TestEnv> {
  const server = await MockServer.start([...handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    ...(projectId === undefined ? {} : { defaultProject: projectId }),
  });
  return env;
}

/** var.version_pushed の行(名前解決・payload 表示の検査用)。 */
function pushRow(seq: number, payload?: Record<string, unknown>): WireRow {
  return {
    id: idOf(seq),
    seq,
    serverTs: BASE_TS + seq,
    event: "var.version_pushed",
    actor: { type: "user", userId: member.userId },
    environmentId: ENV_ID,
    variableId: "va",
    epoch: 1,
    version: 2,
    ...(payload === undefined ? {} : { payload }),
  };
}

/** 集約形 var.read の行(AUDIT_SPEC §3.3 — 値付き pull ごとに環境単位 1 行)。 */
function aggregatedReadRow(seq: number, extraPayload: Record<string, unknown> = {}): WireRow {
  return {
    id: idOf(seq),
    seq,
    serverTs: BASE_TS + seq,
    event: "var.read",
    actor: { type: "user", userId: member.userId, apiTokenId: "tok-1" },
    environmentId: ENV_ID,
    payload: {
      variables: [
        { variableId: "va", epoch: 1, version: 2 },
        { variableId: "vb", epoch: 1, version: 1 },
      ],
      ...extraPayload,
    },
  };
}

describe("maruhi audit(list)", () => {
  it("集約形 var.read は件数の要約で出し、--expand-reads で 1 変数 1 行に展開する", async () => {
    const built = await baseChain();
    // seq=5 は変数の列挙以外の payload(authMethod — 旧形なら recorded= に出ていた)を持つ
    const rows = [
      ...mirrorRowsOf(built),
      aggregatedReadRow(4),
      aggregatedReadRow(5, { authMethod: "github_oauth" }),
    ];
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);

    expect(await runCli(["audit"], env.layer)).toBe(0);
    const summary = env.logs.join("\n");
    const readLine = env.logs.find((line) => line.startsWith("seq=4\t"));
    expect(readLine).toContain("read=2 variables");
    // 列挙(payload)は recorded= として 1 行に流し込まない・展開もしない
    expect(readLine).not.toContain("recorded=");
    // 列挙以外の payload は引き続き recorded= に出る(列挙は除く)
    const withMethod = env.logs.find((line) => line.startsWith("seq=5\t"));
    expect(withMethod).toContain('recorded={"authMethod":"github_oauth"}');
    expect(withMethod).not.toContain('"variables"');
    expect(summary).not.toContain("var=ALPHA");
    // 集約形の案内は Note(stderr)— 一覧(stdout)には混ぜない
    expect(env.errors.join("\n")).toContain("--expand-reads");

    const expanded = await makeTestEnv();
    seedSession(expanded, servers[servers.length - 1]?.origin ?? "", owner);
    await seedConfig(expanded, {
      server: servers[servers.length - 1]?.origin ?? "",
      defaultProject: built.projectId,
    });
    expect(await runCli(["audit", "--expand-reads"], expanded.layer)).toBe(0);
    const logs = expanded.logs.join("\n");
    expect(logs).toContain("read=2 variables");
    // 展開行: 表示名は検証済みステートメント由来(va = ALPHA)、無い変数は id のみ
    expect(logs).toContain("- var=ALPHA (va)\tepoch=1\tversion=2");
    expect(logs).toContain("- var=vb\tepoch=1\tversion=1");
    expect(expanded.errors.join("\n")).not.toContain("--expand-reads");

    // --var 指定時は一致した変数の項目を行内に添える(展開はしない)
    const filtered = await makeTestEnv();
    seedSession(filtered, servers[servers.length - 1]?.origin ?? "", owner);
    await seedConfig(filtered, {
      server: servers[servers.length - 1]?.origin ?? "",
      defaultProject: built.projectId,
    });
    expect(await runCli(["audit", "--var", "va"], filtered.layer)).toBe(0);
    const matchedLine = filtered.logs.find((line) => line.startsWith("seq=4\t"));
    expect(matchedLine).toContain("read=2 variables\tmatched=var=ALPHA (va)\tepoch=1\tversion=2");
    expect(filtered.logs.join("\n")).not.toContain("- var=vb");
  });

  it("行を表示し、名前は検証済みステートメントから解決、ミラー行は突合 OK", async () => {
    const built = await baseChain();
    // payload の名前スナップショットはサーバー申告 — 表示名の位置に昇格しない
    const rows = [...mirrorRowsOf(built), pushRow(4, { name: "EVIL_NAME" })];
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);

    expect(await runCli(["audit"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    // 新しい順(seq 降順)
    const positions = [4, 3, 2, 1].map((seq) => logs.indexOf(`seq=${seq}\t`));
    expect(positions.every((index) => index >= 0)).toBe(true);
    expect(positions).toEqual([...positions].toSorted((a, b) => a - b));
    // ミラー行の突合(共有写像どおりの行は OK)
    expect(logs).toContain("chain.genesis");
    expect(logs).toContain("chain.member_added");
    expect(logs).toContain("mirror=OK");
    // 表示名は検証済みステートメント由来のみ。payload のスナップショットは
    // 「記録=」の中にだけ現れる
    expect(logs).toContain("var=ALPHA (va)");
    expect(logs).not.toContain("var=EVIL_NAME");
    expect(logs).toContain("EVIL_NAME");
    expect(env.errors.join("\n")).not.toContain("does not match the verified chain");
  });

  it("メタデータを取得できない環境は識別子表示へ劣化する(一覧は止めない)", async () => {
    const built = await baseChain();
    const rows = [...mirrorRowsOf(built), pushRow(4)];
    const env = await startEnv(
      await makeAuditServer({ built, rows, metadataAvailable: false }),
      built.projectId,
    );
    expect(await runCli(["audit"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("var=va");
    expect(env.logs.join("\n")).not.toContain("ALPHA");
    expect(env.errors.join("\n")).toContain("could not fetch verified metadata");
  });

  it("改竄されたミラー行(actor の差し替え)は警告 + 終了コード 1", async () => {
    const built = await baseChain();
    const rows = mirrorRowsOf(built);
    const tampered = rows[2];
    if (tampered === undefined) {
      throw new Error("fixture is missing the add_member mirror row");
    }
    rows[2] = { ...tampered, actor: { type: "user", userId: "user-evil-9999" } };
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit"], env.layer)).toBe(1);
    expect(env.logs.join("\n")).toContain("mirror=mismatch");
    const errors = env.errors.join("\n");
    expect(errors).toContain("does not match the verified chain");
    expect(errors).toContain("actor.user_id");
  });

  it("chain.* 外で chain_seq を名乗る行は明示的な不信ラベル + 終了コード 1(S1)", async () => {
    const built = await baseChain();
    const forged = {
      ...pushRow(4),
      event: "member.add",
      chainSeq: 2,
    };
    const env = await startEnv(
      await makeAuditServer({ built, rows: [...mirrorRowsOf(built), forged] }),
      built.projectId,
    );

    expect(await runCli(["audit"], env.layer)).toBe(1);
    const logs = env.logs.join("\n");
    expect(logs).toContain("member.add");
    expect(logs).toContain("chain_seq=2");
    expect(logs).toContain(
      "mirror=unverified (chain_seq is invalid outside the chain.* namespace)",
    );
    const errors = env.errors.join("\n");
    expect(errors).toContain("only chain.* mirror rows may carry chain provenance");
  });

  it("--event と --before / --limit をそのままクエリへ写す", async () => {
    const built = await baseChain();
    // seq=9 の行を置き、そこから前(seq < 9)を row id カーソルで要求する
    const rows = [...mirrorRowsOf(built), pushRow(4), pushRow(9)];
    const handlers = await makeAuditServer({ built, rows });
    const server = await MockServer.start([...handlers]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(
      await runCli(
        ["audit", "--event", "var.version_pushed", "--limit", "10", "--before", idOf(9)],
        env.layer,
      ),
    ).toBe(0);
    const audit = server.requests.find((request) => request.path.endsWith("/audit/events"));
    expect(audit?.query).toMatchObject({
      event: "var.version_pushed",
      limit: "10",
      before: idOf(9),
    });
    const logs = env.logs.join("\n");
    // カーソル行(seq=9)自身は含まれず、seq=4 の行だけが返る
    expect(logs).toContain("seq=4\t");
    expect(logs).not.toContain("seq=9\t");
    expect(logs).toContain("var.version_pushed");
    expect(logs).not.toContain("chain.genesis");
  });
});

describe("maruhi audit verify(ミラー全単射検証 — §1-5 / §6)", () => {
  it("全単射 + 全フィールド一致なら OK(終了コード 0)", async () => {
    const built = await baseChain();
    const env = await startEnv(
      await makeAuditServer({ built, rows: mirrorRowsOf(built) }),
      built.projectId,
    );
    expect(await runCli(["audit", "verify"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("Mirror bijection verification OK");
  });

  it("ミラー行の欠落(削除の隠蔽)を検出する", async () => {
    const built = await baseChain();
    // seq=3(add_member)のミラーを落とす — per-row 突合では原理的に見えない欠落
    const rows = mirrorRowsOf(built).filter((row) => row["seq"] !== 3);
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("no corresponding mirror row");
    expect(errors).toContain("chain_seq=3");
  });

  it("ミラー行の改変(鍵 FP の差し替え)を検出する", async () => {
    const built = await baseChain();
    const rows = mirrorRowsOf(built);
    const genesis = rows[0];
    if (genesis === undefined) {
      throw new Error("fixture is missing the genesis mirror row");
    }
    rows[0] = {
      ...genesis,
      actor: {
        ...(genesis["actor"] as Record<string, unknown>),
        keyFingerprintHex: "ab".repeat(16),
      },
    };
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("actor.key_fingerprint");
  });

  it("同一 chain_seq への重複ミラー行を検出する", async () => {
    const built = await baseChain();
    const rows = mirrorRowsOf(built);
    const duplicated = rows[2];
    if (duplicated === undefined) {
      throw new Error("fixture is missing the add_member mirror row");
    }
    rows.push({ ...duplicated, id: idOf(9), seq: 9 });
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("duplicates");
  });

  it("偽のトークン経由表示(actor.api_token_id の付与)を検出する", async () => {
    const built = await baseChain();
    const rows = mirrorRowsOf(built);
    const tampered = rows[2];
    if (tampered === undefined) {
      throw new Error("fixture is missing the add_member mirror row");
    }
    rows[2] = {
      ...tampered,
      actor: { ...(tampered["actor"] as Record<string, unknown>), apiTokenId: "tok-evil" },
    };
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("actor.api_token_id");
  });

  it("到達し得ない chain_seq を名乗る偽造行は連続性違反として検出する(恒久すり抜けの遮断)", async () => {
    const built = await baseChain();
    const rows = mirrorRowsOf(built);
    const template = rows[2];
    if (template === undefined) {
      throw new Error("fixture is missing the add_member mirror row");
    }
    // head(3)の遠く先を名乗る偽造行 — 旧実装では「未検証」に数えられるだけで
    // exit 0 +「検証 OK」になっていた(pullfrog 指摘)
    rows.push({ ...template, id: idOf(50), seq: 50, chainSeq: 50000 });
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("not contiguous");
    expect(env.logs.join("\n")).not.toContain("Mirror bijection verification OK");
  });

  it("写像に無い chain.* 名を名乗る偽造行を検出する(deepsec R1)", async () => {
    const built = await baseChain();
    const rows = mirrorRowsOf(built);
    const template = rows[2];
    if (template === undefined) {
      throw new Error("fixture is missing the add_member mirror row");
    }
    // 既知のミラー名を 1 つずつ完全一致で引く旧実装では、この行はそもそも
    // 取得されず(欠落も重複も起きない)、exit 0 +「検証 OK」になっていた
    rows.push({ ...template, id: idOf(9), seq: 9, event: "chain.role_granted" });
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("unknown chain op");
    expect(errors).toContain("chain.role_granted");
    expect(env.logs.join("\n")).not.toContain("Mirror bijection verification OK");
  });

  it("chain.* 外で chain_seq を名乗る偽造行も presence filter で取得して検出する(S1)", async () => {
    const built = await baseChain();
    const rows = mirrorRowsOf(built);
    const forged = {
      ...pushRow(9),
      event: "chainx.grant",
      chainSeq: 2,
    };
    const handlers = await makeAuditServer({ built, rows: [...rows, forged] });
    const server = await MockServer.start([...handlers]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("outside the chain.* namespace");
    expect(errors).toContain("chainx.grant");
    expect(env.logs.join("\n")).not.toContain("Mirror bijection verification OK");
    expect(
      server.requests.some(
        (request) =>
          request.path.endsWith("/audit/events") && request.query["chainSeqPresent"] === "true",
      ),
    ).toBe(true);
  });

  it("head 直後から連続する新しい行は偽造断定しないが、OK とも言わない(exit 1 + 再実行案内)", async () => {
    const built = await baseChain();
    const rows = mirrorRowsOf(built);
    const template = rows[2];
    if (template === undefined) {
      throw new Error("fixture is missing the add_member mirror row");
    }
    // 同期直後にチェーンが 1 エントリ伸びた形(chain_seq = head + 1)
    rows.push({ ...template, id: idOf(4), seq: 4, chainSeq: 4 });
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Mirror verification incomplete");
    expect(errors).not.toContain("not contiguous");
    expect(env.logs.join("\n")).not.toContain("Mirror bijection verification OK");
  });
});

describe("maruhi audit invites / self", () => {
  it("invites は D1 側の invite.* 行を表示する", async () => {
    const built = await baseChain();
    const handlers = [
      ...(await makeAuditServer({ built, rows: mirrorRowsOf(built) })),
      onRequest("GET", `/projects/${built.projectId}/audit/invites`, () => ({
        status: 200,
        json: {
          // D1 応答は seq を運ばない(AUDIT_SPEC §7 — グローバル連番の非開示)
          events: [
            {
              id: idOf(12),
              serverTs: BASE_TS,
              event: "invite.created",
              actor: { type: "user", userId: owner.userId },
              projectId: built.projectId,
              payload: { inviteId: "inv-0001", role: "member" },
            },
          ],
        },
      })),
    ];
    const env = await startEnv(handlers, built.projectId);
    expect(await runCli(["audit", "invites"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("invite.created");
    expect(logs).toContain("inv-0001");
  });

  it("D1 経路の chain_seq も無ラベル表示せず整合性違反にする(S1)", async () => {
    const built = await baseChain();
    const handlers = [
      ...(await makeAuditServer({ built, rows: mirrorRowsOf(built) })),
      onRequest("GET", `/projects/${built.projectId}/audit/invites`, () => ({
        status: 200,
        json: {
          events: [
            {
              id: idOf(13),
              serverTs: BASE_TS,
              event: "invite.created",
              actor: { type: "user", userId: owner.userId },
              projectId: built.projectId,
              chainSeq: 2,
            },
          ],
        },
      })),
    ];
    const env = await startEnv(handlers, built.projectId);
    expect(await runCli(["audit", "invites"], env.layer)).toBe(1);
    expect(env.logs.join("\n")).toContain(
      "chain_seq=2 (mirror=unverified (chain_seq is invalid on this audit endpoint))",
    );
    expect(env.errors.join("\n")).toContain("this endpoint does not store chain provenance");
  });

  it("self はアカウント系イベントを表示し、要監視イベントの含意を添える", async () => {
    const handlers = [
      onRequest("GET", "/auth/audit/events", () => ({
        status: 200,
        json: {
          // D1 応答は seq を運ばない(AUDIT_SPEC §7)
          events: [
            {
              id: idOf(2),
              serverTs: BASE_TS + 2,
              event: "auth.recovery_blob_fetched",
              actor: { type: "user", userId: owner.userId },
            },
            {
              id: idOf(1),
              serverTs: BASE_TS + 1,
              event: "auth.token_created",
              actor: { type: "user", userId: owner.userId },
              payload: { name: "cli:host" },
            },
          ],
        },
      })),
    ];
    const env = await startEnv(handlers);
    expect(await runCli(["audit", "self"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("auth.recovery_blob_fetched");
    expect(logs).toContain("auth.token_created");
    // 要監視イベントの含意は Note(stderr)
    expect(env.errors.join("\n")).toContain("reissue your recovery code");
  });
});

describe("引数の書き方の検査(通信より前)", () => {
  it("audit self への --project は操作専用オプションとして拒否する(exit 2)", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["audit", "self", "--project", "x"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Unknown flag");
  });

  it("limit の範囲外・不明な操作は usage エラー(exit 2)", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["audit", "--limit", "0"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--limit must be an integer between 1 and 200");
    const env2 = await makeTestEnv();
    expect(await runCli(["audit", "bogus"], env2.layer)).toBe(2);
    expect(env2.errors.join("\n")).toContain("Unknown subcommand");
  });
});
