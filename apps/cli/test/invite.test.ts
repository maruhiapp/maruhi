// `maruhi invite create|accept|list|revoke`(AUTH_SPEC §15 / CRYPTO_SPEC §6.5 —
// Wave 2 B1b)の統合テスト。
//
// 固定する性質:
//  1. リンクの組み立て・解釈(§15-3): パラメータ順・r 省略可・壊れたリンクの
//     生トークン降格禁止
//  2. create: 発行 + 発行ピン(token_hash / role)の保存 + role=admin は owner のみ
//  3. accept: アンカーのピン留め(§6.3 (a))→ 儀式(最終語再入力 /
//     --inviter-fingerprint / エージェント拒否)→ 鍵ガード(生成 3 ガード)→
//     受諾署名(検証可能)→ 応答突合(p 一致・r 警告)
//  4. list: 受諾ブロックの §6.5 独立検証・発行ピン突合(不一致 = exit 1)
//  5. revoke: 失効と 410 の文言

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

import {
  decodeHex,
  fingerprintToWords,
  signInviteAccept,
  SUITE_ID,
  verifyInviteAcceptSignature,
} from "@maruhi/crypto";
import { Effect } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { buildInviteLink, parseInviteAcceptInput } from "../src/invite-link.ts";
import { tokenHashHexOf } from "../src/invite.ts";
import { tokenEntryName, type StoredToken } from "../src/keychain.ts";
import { buildChain, genesisOp, makeTestUser, type TestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const TOKEN = "maruhi_inv_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9xY01";
const INVITE_ID = "inv-0001";

let inviter: TestUser;
let acceptor: TestUser;
let inviterWords: readonly string[];
let tokenHashHex: string;

const servers: MockServer[] = [];

beforeAll(async () => {
  inviter = await makeTestUser("user-inviter-11");
  acceptor = await makeTestUser("user-acceptor-22");
  const bytes = decodeHex(inviter.fingerprintHex);
  if (bytes === null) throw new Error("inviter fp");
  const words = await fingerprintToWords(bytes);
  if (!words.ok) throw new Error("inviter fp words");
  inviterWords = words.value;
  tokenHashHex = await Effect.runPromise(tokenHashHexOf(TOKEN));
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function start(handlers: readonly MockHandler[]): Promise<MockServer> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  return server;
}

function chainHandler(built: {
  readonly projectId: string;
  readonly entries: readonly unknown[];
  readonly hashes: readonly string[];
}): MockHandler {
  return onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
    status: 200,
    json: {
      projectId: built.projectId,
      entries: built.entries,
      headSeq: built.entries.length,
      headHashHex: built.hashes[built.hashes.length - 1],
    },
  }));
}

/** ログイン済み(master 鍵なし)の状態をシードする — 鍵生成経路のテスト用。 */
function seedTokenOnly(env: TestEnv, origin: string, user: TestUser): void {
  const token: StoredToken = {
    token: "maruhi_pat_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9x123",
    userId: user.userId,
    tokenId: "tok_0001",
  };
  env.keychain.set(tokenEntryName(origin), JSON.stringify(token));
}

/** 受諾者側の pins ファイル(アンカー)を読み出す。 */
async function readPins(env: TestEnv, projectId: string): Promise<Record<string, unknown>> {
  const json = await readFile(join(env.pinsDir, `${projectId}.json`), "utf8");
  return JSON.parse(json) as Record<string, unknown>;
}

describe("invite link(§15-3)", () => {
  const PROJECT_ID = "ab".repeat(32);

  function sampleLink(): string {
    return buildInviteLink({
      origin: "https://maruhi.example",
      token: TOKEN,
      projectId: PROJECT_ID,
      headHashHex: "cd".repeat(32),
      headSeq: 7,
      inviterUserId: "user-inviter-11",
      inviterKeyFingerprintHex: "ef".repeat(16),
      role: "member",
    });
  }

  it("組み立て → 解釈がラウンドトリップする(パラメータ順は仕様の記載順)", () => {
    const link = sampleLink();
    expect(link).toBe(
      `https://maruhi.example/invite#v=1&t=${TOKEN}&p=${PROJECT_ID}&h=${"cd".repeat(32)}&s=7&iu=user-inviter-11&if=${"ef".repeat(16)}&r=member`,
    );
    const parsed = parseInviteAcceptInput(link);
    if (parsed.kind !== "link") throw new Error(`expected link, got ${parsed.kind}`);
    expect(parsed.link).toEqual({
      token: TOKEN,
      projectId: PROJECT_ID,
      headHashHex: "cd".repeat(32),
      headSeq: 7,
      inviterUserId: "user-inviter-11",
      inviterKeyFingerprintHex: "ef".repeat(16),
      role: "member",
    });
  });

  it("r なしのリンク(追補前の発行分)も有効として解釈する(role = null)", () => {
    const link = sampleLink().replace("&r=member", "");
    const parsed = parseInviteAcceptInput(link);
    if (parsed.kind !== "link") throw new Error("expected link");
    expect(parsed.link.role).toBeNull();
  });

  it("生トークンはトークンとして解釈し、それ以外の文字列は拒否する", () => {
    expect(parseInviteAcceptInput(TOKEN)).toEqual({ kind: "token", token: TOKEN });
    expect(parseInviteAcceptInput("maruhi_inv_short")).toEqual({
      kind: "rejected",
      reason: "not-a-link-or-token",
    });
  });

  it("必須パラメータの欠落・不正な r は生トークン扱いへ降格せずエラーにする", () => {
    for (const broken of [
      sampleLink().replace(`&h=${"cd".repeat(32)}`, ""),
      sampleLink().replace("&s=7", "&s=0"),
      sampleLink().replace("&r=member", "&r=superuser"),
      sampleLink().replace(`&if=${"ef".repeat(16)}`, "&if=zz"),
    ]) {
      expect(parseInviteAcceptInput(broken)).toEqual({
        kind: "rejected",
        reason: "missing-or-invalid-fragment-params",
      });
    }
    expect(parseInviteAcceptInput(sampleLink().replace("#v=1", "#v=2"))).toEqual({
      kind: "rejected",
      reason: "unsupported-version",
    });
  });
});

describe("maruhi invite create", () => {
  it("発行してリンク(検証済みヘッドのアンカー + 自 FP + r)を表示し、発行ピンを保存する", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const issued: unknown[] = [];
    const server = await start([
      chainHandler(built),
      onRequest("POST", `/projects/${built.projectId}/invites`, (request) => {
        issued.push(request.body);
        return {
          status: 200,
          json: { id: INVITE_ID, token: TOKEN, role: "member", expiresAtMs: 1755993600000 },
        };
      }),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["invite", "create", "--role", "member"], env.layer)).toBe(0);
    expect(issued).toEqual([{ role: "member" }]);
    const expectedLink = buildInviteLink({
      origin: server.origin,
      token: TOKEN,
      projectId: built.projectId,
      headHashHex: built.hashes[0] ?? "",
      headSeq: 1,
      inviterUserId: inviter.userId,
      inviterKeyFingerprintHex: inviter.fingerprintHex,
      role: "member",
    });
    expect(env.logs).toContain(expectedLink);
    // 発行ピン(§6.5 の招待者側対応物): token_hash と role を非機密ローカルへ
    const pins = await readPins(env, built.projectId);
    expect(pins["issued"]).toEqual({
      [INVITE_ID]: { tokenHashHex, role: "member", expiresAtMs: 1755993600000 },
    });
  });

  it("role=admin の発行は owner のみ(admin の実行は通信前に拒否する)", async () => {
    const admin2 = await makeTestUser("user-admin2-333");
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      {
        actor: inviter,
        operation: {
          op: "add_member",
          payload: {
            targetUserId: admin2.userId,
            encPubHex: admin2.encPubHex,
            sigPubHex: admin2.sigPubHex,
            role: "admin",
          },
        },
      },
    ]);
    const issueCalls: unknown[] = [];
    const server = await start([
      chainHandler(built),
      onRequest("POST", `/projects/${built.projectId}/invites`, (request) => {
        issueCalls.push(request.body);
        return { status: 500, json: {} };
      }),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, admin2);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["invite", "create", "--role", "admin"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("role = admin の招待の発行は owner のみ");
    expect(issueCalls).toHaveLength(0);
  });

  it("エージェント環境では発行そのものを拒否する(トークン生値がトランスクリプトへ残る)", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const issueCalls: unknown[] = [];
    const server = await start([
      chainHandler(built),
      onRequest("POST", `/projects/${built.projectId}/invites`, (request) => {
        issueCalls.push(request.body);
        return {
          status: 200,
          json: { id: INVITE_ID, token: TOKEN, role: "member", expiresAtMs: 1755993600000 },
        };
      }),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    env.setAgent({ isAgent: true, name: "test-agent" });

    expect(await runCli(["invite", "create", "--role", "member"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("招待の発行を拒否しました");
    // 発行 POST の前に拒否する(サーバー側に pending を作らない)
    expect(issueCalls).toHaveLength(0);
  });

  it("発行ピンの保存失敗(破損ピンファイル)でも発行は成立し、リンクを表示して警告する", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const server = await start([
      chainHandler(built),
      onRequest("POST", `/projects/${built.projectId}/invites`, () => ({
        status: 200,
        json: { id: INVITE_ID, token: TOKEN, role: "member", expiresAtMs: 1755993600000 },
      })),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    // 破損ピンファイル(merge は上書きを拒否する — pins.ts の規律)
    await mkdir(env.pinsDir, { recursive: true });
    await writeFile(join(env.pinsDir, `${built.projectId}.json`), "{ broken");

    // リンクは一度しか表示されない: ピン保存の失敗で成立済みの発行を落とさない
    expect(await runCli(["invite", "create", "--role", "member"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain(`#v=1&t=${TOKEN}&`);
    expect(env.errors.join("\n")).toContain("発行ピンを保存できませんでした");
    // 破損ファイルは上書きされない(検出可能性を保存)
    expect(await readFile(join(env.pinsDir, `${built.projectId}.json`), "utf8")).toBe("{ broken");
  });

  it("429 の 2 種(pending 上限 / レート制限)を区別して表示する", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    for (const [json, fragment] of [
      [{ _tag: "InvitePendingLimit", limit: 100 }, "上限(100)"],
      [{ _tag: "InviteRateLimited", retryAfterSeconds: 1800 }, "約 1800 秒後"],
    ] as const) {
      const server = await start([
        chainHandler(built),
        onRequest("POST", `/projects/${built.projectId}/invites`, () => ({ status: 429, json })),
      ]);
      const env = await makeTestEnv();
      seedSession(env, server.origin, inviter);
      await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
      expect(await runCli(["invite", "create", "--role", "reader"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain(fragment);
    }
  });
});

describe("maruhi invite accept", () => {
  const PROJECT_ID = "ab".repeat(32);

  function linkFor(role: "reader" | "member" | "admin" | null = "member"): string {
    const link = buildInviteLink({
      origin: "https://maruhi.example",
      token: TOKEN,
      projectId: PROJECT_ID,
      headHashHex: "cd".repeat(32),
      headSeq: 3,
      inviterUserId: inviter.userId,
      inviterKeyFingerprintHex: inviter.fingerprintHex,
      role: role ?? "member",
    });
    return role === null ? link.replace("&r=member", "") : link;
  }

  function acceptHandler(record: (body: unknown) => void, role = "member"): MockHandler {
    return onRequest("POST", "/invites/accept", (request) => {
      record(request.body);
      return { status: 200, json: { id: INVITE_ID, projectId: PROJECT_ID, role } };
    });
  }

  it("儀式(最終語再入力)→ 受諾署名 → 受諾。アンカーをピン留めし、自 FP ワードを表示する", async () => {
    const bodies: unknown[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);

    expect(await runCli(["invite", "accept", linkFor()], env.layer)).toBe(0);

    // 受諾署名は §6.5 のとおり検証可能(project / token hash / 主体 / 宣言鍵に束縛)
    expect(bodies).toHaveLength(1);
    const body = bodies[0] as {
      token: string;
      encPubHex: string;
      sigPubHex: string;
      signatureHex: string;
    };
    expect(body.token).toBe(TOKEN);
    expect(body.encPubHex).toBe(acceptor.encPubHex);
    expect(body.sigPubHex).toBe(acceptor.sigPubHex);
    const verified = await verifyInviteAcceptSignature({
      context: {
        suite: SUITE_ID,
        projectId: PROJECT_ID,
        inviteTokenHashHex: tokenHashHex,
        inviteeUserId: acceptor.userId,
        inviteeEncPubHex: acceptor.encPubHex,
        inviteeSigPubHex: acceptor.sigPubHex,
      },
      signatureHex: body.signatureHex,
    });
    expect(verified.ok).toBe(true);

    // アンカー(§6.3 (a))のピン留め(未照合 = verifiedAtSeq null)
    const pins = await readPins(env, PROJECT_ID);
    expect(pins["anchor"]).toEqual({
      headSeq: 3,
      headHashHex: "cd".repeat(32),
      inviterUserId: inviter.userId,
      inviterKeyFingerprintHex: inviter.fingerprintHex,
      verifiedAtSeq: null,
    });

    const logs = env.logs.join("\n");
    expect(logs).toContain("招待を受諾しました");
    expect(logs).toContain("この 12 語を帯域外(通話等)で招待者本人に読み上げてください");
    expect(logs).toContain("初回同期で、リンクアンカー");
  });

  it("儀式の再入力が 3 回一致しなければ受諾しない", async () => {
    const bodies: unknown[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setPromptResponses(["wrong1", "wrong2", "wrong3"]);

    expect(await runCli(["invite", "accept", linkFor()], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("招待者 FP の確認に失敗しました");
    expect(bodies).toHaveLength(0);
  });

  it("--inviter-fingerprint はリンク if= と照合し、一致すれば対話なし・不一致なら受諾前に拒否する", async () => {
    const bodies: unknown[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });

    expect(
      await runCli(
        ["invite", "accept", linkFor(), "--inviter-fingerprint", inviter.fingerprintHex],
        env.layer,
      ),
    ).toBe(0);
    expect(env.prompts).toHaveLength(0);
    expect(bodies).toHaveLength(1);

    const env2 = await makeTestEnv();
    seedSession(env2, server.origin, acceptor);
    await seedConfig(env2, { server: server.origin });
    expect(
      await runCli(
        ["invite", "accept", linkFor(), "--inviter-fingerprint", "0".repeat(32)],
        env2.layer,
      ),
    ).toBe(1);
    expect(env2.errors.join("\n")).toContain("リンクが改竄されている可能性");
    expect(bodies).toHaveLength(1);
  });

  it("エージェント環境では --inviter-fingerprint なしの儀式代行を拒否する", async () => {
    const bodies: unknown[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setAgent({ isAgent: true, name: "test-agent" });

    expect(await runCli(["invite", "accept", linkFor()], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("儀式を実行できません");
    expect(bodies).toHaveLength(0);

    // フラグの明示があれば受諾できる(儀式の帯域外照合を代行しない、の線引き)
    env.errors.length = 0;
    expect(
      await runCli(
        ["invite", "accept", linkFor(), "--inviter-fingerprint", inviter.fingerprintHex],
        env.layer,
      ),
    ).toBe(0);
    expect(bodies).toHaveLength(1);
  });

  it("鍵未生成: 対話確認 → 生成 → リカバリー儀式 → 生成鍵で受諾(§15-3 の連結)", async () => {
    const bodies: unknown[] = [];
    const server = await start([
      acceptHandler((body) => bodies.push(body)),
      onRequest("GET", "/auth/recovery/status", () => ({
        status: 200,
        json: { registered: false, updatedAtMs: null },
      })),
      onRequest("PUT", "/auth/recovery", () => ({ status: 204 })),
    ]);
    const env = await makeTestEnv();
    seedTokenOnly(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setPromptResponses([
      inviterWords[inviterWords.length - 1] ?? "",
      "yes",
      // リカバリーコードの保存確認(表示済み stderr から最終グループを読む)
      () => {
        const line = env.errors.find((item) => /^ {4}[A-Z2-7]{4}(-[A-Z2-7]{4})+$/.test(item));
        const groups = (line ?? "").trim().split("-");
        return groups[groups.length - 1] ?? "";
      },
    ]);

    expect(await runCli(["invite", "accept", linkFor()], env.layer)).toBe(0);
    expect(bodies).toHaveLength(1);
    const body = bodies[0] as { encPubHex: string; sigPubHex: string; signatureHex: string };
    // 生成された鍵での自己束縛署名が検証に通る(宣言鍵 = 検証鍵)
    const verified = await verifyInviteAcceptSignature({
      context: {
        suite: SUITE_ID,
        projectId: PROJECT_ID,
        inviteTokenHashHex: tokenHashHex,
        inviteeUserId: acceptor.userId,
        inviteeEncPubHex: body.encPubHex,
        inviteeSigPubHex: body.sigPubHex,
      },
      signatureHex: body.signatureHex,
    });
    expect(verified.ok).toBe(true);
    expect(env.logs.join("\n")).toContain("master keypair を生成し");
  });

  it("鍵未生成ガード: リカバリー登録済みなら生成せず key recover へ誘導する", async () => {
    const bodies: unknown[] = [];
    const server = await start([
      acceptHandler((body) => bodies.push(body)),
      onRequest("GET", "/auth/recovery/status", () => ({
        status: 200,
        json: { registered: true, updatedAtMs: 1754006400000 },
      })),
    ]);
    const env = await makeTestEnv();
    seedTokenOnly(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);

    expect(await runCli(["invite", "accept", linkFor()], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("`maruhi key recover` でこの端末へ復元してから");
    expect(bodies).toHaveLength(0);
    // 鍵は生成されていない(キーチェーンは token エントリのみ)
    expect(env.keychain.size).toBe(1);
  });

  it("鍵未生成ガード: エージェント環境では生成しない(受諾自体を拒否して案内)", async () => {
    const bodies: unknown[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedTokenOnly(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setAgent({ isAgent: true, name: "test-agent" });

    expect(
      await runCli(
        ["invite", "accept", linkFor(), "--inviter-fingerprint", inviter.fingerprintHex],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("鍵の新規生成を行いません");
    expect(bodies).toHaveLength(0);
    expect(env.keychain.size).toBe(1);
  });

  it("生トークン受諾は --project 必須・対話の了解つき。エージェント環境では拒否する", async () => {
    const bodies: unknown[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });

    // --project なし = usage エラー(§6.5 の署名対象に project_id が要る)
    expect(await runCli(["invite", "accept", TOKEN], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--project <プロジェクト ID> が必須");

    // --project あり + 了解 yes → 受諾(警告つき)
    env.setPromptResponses(["yes"]);
    expect(await runCli(["invite", "accept", TOKEN, "--project", PROJECT_ID], env.layer)).toBe(0);
    expect(bodies).toHaveLength(1);
    expect(env.errors.join("\n")).toContain("警告: 生トークンでの受諾は");

    // エージェント環境では照合材料がないため拒否
    const env2 = await makeTestEnv();
    seedSession(env2, server.origin, acceptor);
    await seedConfig(env2, { server: server.origin });
    env2.setAgent({ isAgent: true });
    expect(await runCli(["invite", "accept", TOKEN, "--project", PROJECT_ID], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain("生トークンでの受諾を拒否しました");
  });

  it("410 の理由を運用手順に翻訳する(先着受諾 = 横取りの顕在化)", async () => {
    for (const [reason, fragment] of [
      ["accepted", "リンクの横取りの可能性"],
      ["expired", "期限切れ"],
    ] as const) {
      const server = await start([
        onRequest("POST", "/invites/accept", () => ({
          status: 410,
          json: { _tag: "InviteGone", reason },
        })),
      ]);
      const env = await makeTestEnv();
      seedSession(env, server.origin, acceptor);
      await seedConfig(env, { server: server.origin });
      env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
      expect(await runCli(["invite", "accept", linkFor()], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain(fragment);
    }
  });

  it("受諾が成立しなければアンカーをピン留めしない(410 でピンファイルを作らない)", async () => {
    // 受諾前にピン留めすると、失敗する受諾(失効・偽トークン)を含む細工リンクの
    // 投入だけで既存アンカーを差し替えられる(自己 DoS / 置換)— §15-3 追補の回帰
    const server = await start([
      onRequest("POST", "/invites/accept", () => ({
        status: 410,
        json: { _tag: "InviteGone", reason: "expired" },
      })),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);

    expect(await runCli(["invite", "accept", linkFor()], env.layer)).toBe(1);
    await expect(readPins(env, PROJECT_ID)).rejects.toThrow(); // ピンファイル不在
  });

  it("機械照合済みアンカーは再受諾でも上書きせず、未照合アンカーは最新の受諾で置き換える", async () => {
    const verifiedAnchor = {
      headSeq: 9,
      headHashHex: "12".repeat(32),
      inviterUserId: "user-original-77",
      inviterKeyFingerprintHex: "34".repeat(16),
      verifiedAtSeq: 9,
    };
    const server = await start([acceptHandler(() => undefined)]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    await mkdir(env.pinsDir, { recursive: true });
    await writeFile(
      join(env.pinsDir, `${PROJECT_ID}.json`),
      JSON.stringify({ v: 1, anchor: verifiedAnchor, issued: {} }),
    );
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);

    expect(await runCli(["invite", "accept", linkFor()], env.layer)).toBe(0);
    expect((await readPins(env, PROJECT_ID))["anchor"]).toEqual(verifiedAnchor);
    expect(env.logs.join("\n")).toContain("既存のアンカーを維持します");

    // 未照合(verifiedAtSeq: null)のアンカーは最後の正規受諾が勝つ
    const env2 = await makeTestEnv();
    seedSession(env2, server.origin, acceptor);
    await seedConfig(env2, { server: server.origin });
    await mkdir(env2.pinsDir, { recursive: true });
    await writeFile(
      join(env2.pinsDir, `${PROJECT_ID}.json`),
      JSON.stringify({ v: 1, anchor: { ...verifiedAnchor, verifiedAtSeq: null }, issued: {} }),
    );
    env2.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);

    expect(await runCli(["invite", "accept", linkFor()], env2.layer)).toBe(0);
    expect((await readPins(env2, PROJECT_ID))["anchor"]).toEqual({
      headSeq: 3,
      headHashHex: "cd".repeat(32),
      inviterUserId: inviter.userId,
      inviterKeyFingerprintHex: inviter.fingerprintHex,
      verifiedAtSeq: null,
    });
  });

  it("ピンファイル破損時は受諾を成立させたまま警告し、破損ファイルを上書きしない", async () => {
    // 受諾はサーバー側で成立済み(トークン消費済み)— ピン留め失敗で失敗扱いに
    // すると「再実行」の導線が 410(accepted)へ誘導する誤案内になる
    const server = await start([acceptHandler(() => undefined)]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    await mkdir(env.pinsDir, { recursive: true });
    await writeFile(join(env.pinsDir, `${PROJECT_ID}.json`), "{ broken");
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);

    expect(await runCli(["invite", "accept", linkFor()], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("アンカーをピン留めできませんでした");
    expect(await readFile(join(env.pinsDir, `${PROJECT_ID}.json`), "utf8")).toBe("{ broken");
  });

  it("リンク申告 r と応答 role の不一致は警告し、応答 projectId の不一致は拒否する", async () => {
    // r=admin と申告するリンク、実際の role は member → 警告(受諾は成立)
    const server = await start([acceptHandler(() => undefined, "member")]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
    expect(await runCli(["invite", "accept", linkFor("admin")], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain(
      "リンク申告の role(admin)と実際の role(member)が一致しません",
    );

    // 応答の projectId が署名対象と異なる = サーバー自己矛盾 → 拒否
    const server2 = await start([
      onRequest("POST", "/invites/accept", () => ({
        status: 200,
        json: { id: INVITE_ID, projectId: "ff".repeat(32), role: "member" },
      })),
    ]);
    const env2 = await makeTestEnv();
    seedSession(env2, server2.origin, acceptor);
    await seedConfig(env2, { server: server2.origin });
    env2.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
    expect(await runCli(["invite", "accept", linkFor()], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain("サーバー応答の矛盾");
  });
});

describe("maruhi invite list / revoke", () => {
  async function acceptanceBlockFor(projectId: string): Promise<{
    inviteeUserId: string;
    inviteeEncPubHex: string;
    inviteeSigPubHex: string;
    signatureHex: string;
    acceptedAtMs: number;
  }> {
    const signature = await signInviteAccept({
      context: {
        suite: SUITE_ID,
        projectId,
        inviteTokenHashHex: tokenHashHex,
        inviteeUserId: acceptor.userId,
        inviteeEncPubHex: acceptor.encPubHex,
        inviteeSigPubHex: acceptor.sigPubHex,
      },
      signingKey: acceptor.sigKeyPair.privateKey,
    });
    if (!signature.ok) throw new Error("acceptance signature failed");
    return {
      inviteeUserId: acceptor.userId,
      inviteeEncPubHex: acceptor.encPubHex,
      inviteeSigPubHex: acceptor.sigPubHex,
      signatureHex: signature.value,
      acceptedAtMs: 1755300000000,
    };
  }

  function listRow(projectId: string, acceptance: unknown, role = "member"): unknown {
    return {
      id: INVITE_ID,
      projectId,
      role,
      status: acceptance === null ? "pending" : "accepted",
      inviterUserId: inviter.userId,
      tokenHashHex,
      createdAtMs: 1755200000000,
      expiresAtMs: 1755993600000,
      acceptance,
    };
  }

  it("受諾ブロックを §6.5 独立検証し、受諾鍵の FP ワードを表示する", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const acceptance = await acceptanceBlockFor(built.projectId);
    const server = await start([
      chainHandler(built),
      onRequest("GET", `/projects/${built.projectId}/invites`, () => ({
        status: 200,
        json: { invitations: [listRow(built.projectId, acceptance)] },
      })),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["invite", "list"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(`受諾: ${acceptor.userId}(署名検証 OK)`);
    expect(logs).toContain(`fp:   ${acceptor.fingerprintHex}`);
  });

  it("改竄された受諾署名は検証失敗として警告し、exit 1 にする", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const acceptance = await acceptanceBlockFor(built.projectId);
    const tampered = {
      ...acceptance,
      // 別 user_id へ付け替え(署名対象の invitee_user_id 束縛が破れる)
      inviteeUserId: "user-attacker-99",
    };
    const server = await start([
      chainHandler(built),
      onRequest("GET", `/projects/${built.projectId}/invites`, () => ({
        status: 200,
        json: { invitations: [listRow(built.projectId, tampered)] },
      })),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["invite", "list"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("受諾署名が検証に失敗しました");
  });

  it("発行ピンとサーバー申告(role)の不一致を警告し、exit 1 にする", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const acceptance = await acceptanceBlockFor(built.projectId);
    const server = await start([
      chainHandler(built),
      onRequest("GET", `/projects/${built.projectId}/invites`, () => ({
        status: 200,
        // サーバーが role を admin と偽って申告する
        json: { invitations: [listRow(built.projectId, acceptance, "admin")] },
      })),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    // 発行時ピン(role=member)をローカルへ用意
    await mkdir(env.pinsDir, { recursive: true });
    await writeFile(
      join(env.pinsDir, `${built.projectId}.json`),
      JSON.stringify({
        v: 1,
        anchor: null,
        issued: { [INVITE_ID]: { tokenHashHex, role: "member", expiresAtMs: 1755993600000 } },
      }),
    );

    expect(await runCli(["invite", "list"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("発行時のローカル記録と一致しません");
  });

  it("revoke: 失効の成功と、completed への 410 は member remove を案内する", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const server = await start([
      chainHandler(built),
      onRequest("DELETE", `/projects/${built.projectId}/invites/${INVITE_ID}`, () => ({
        status: 204,
      })),
      onRequest("DELETE", `/projects/${built.projectId}/invites/inv-0002`, () => ({
        status: 410,
        json: { _tag: "InviteGone", reason: "completed" },
      })),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["invite", "revoke", INVITE_ID], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("招待を失効させました");

    expect(await runCli(["invite", "revoke", "inv-0002"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("maruhi member remove を実行してください");
  });
});
