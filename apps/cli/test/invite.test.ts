// `maruhi invite create|accept|list|revoke`(AUTH_SPEC §15 / CRYPTO_SPEC §6.5 —
// 2026-09-13 IV 改訂・v2 リンク)の統合テスト。
//
// 固定する性質:
//  1. リンクの組み立て・解釈(§15-3): パラメータ順・il 省略可・壊れたリンク /
//     旧版(v=1)/ 生トークンはすべて拒否(互換経路なし)
//  2. create: クライアント採番 id + 発行署名(自分のチェーン sig 鍵)+ 発行ピン
//     (link_pub / role)の保存 + role=admin は owner のみ + 鍵不一致の拒否
//  3. accept: 発行署名の検証(機械)→ 儀式(最終語再入力 / --inviter-fingerprint /
//     エージェント拒否)→ 鍵ガード → 共同署名(検証可能)→ 応答突合(p / r は
//     署名済みなので不一致 = 拒否)→ アンカーのピン留め(受諾成立後のみ)
//  4. list: 発行署名・受諾ブロックの §6.5 独立検証・発行ピン突合(不一致 = exit 1)
//  5. revoke: 失効と 410 の文言

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

import {
  decodeHex,
  fingerprintToWords,
  SUITE_ID,
  verifyInviteAcceptSignature,
  verifyInviteIssueSignature,
  verifyInviteLinkSignature,
} from "@maruhi/crypto";
import { Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { buildInviteLink, parseInviteAcceptInput } from "../src/invite-link.ts";
import { serializeStoredToken, tokenEntryName, type StoredToken } from "../src/keychain.ts";
import { buildChain, genesisOp, makeTestUser, type TestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import {
  acceptanceFixture,
  flipHex,
  githubSigningKeysHandler,
  INVITE_ID,
  inviteLinkText,
  issueInviteFixture,
  type IssuedInviteFixture,
  LINK_SEED_HEX,
  sshLineOf,
} from "./support/invite.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let inviter: TestUser;
let acceptor: TestUser;
let inviterWords: readonly string[];

const servers: MockServer[] = [];

beforeAll(async () => {
  inviter = await makeTestUser("user-inviter-11");
  acceptor = await makeTestUser("user-acceptor-22");
  const bytes = decodeHex(inviter.fingerprintHex);
  if (bytes === null) throw new Error("inviter fp");
  const words = await fingerprintToWords(bytes);
  if (!words.ok) throw new Error("inviter fp words");
  inviterWords = words.value;
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
    token: Redacted.make("maruhi_pat_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9x123"),
    userId: user.userId,
    tokenId: "tok_0001",
  };
  env.keychain.set(tokenEntryName(origin), serializeStoredToken(token));
}

/** 受諾者側の pins ファイル(アンカー)を読み出す。 */
async function readPins(env: TestEnv, projectId: string): Promise<Record<string, unknown>> {
  const json = await readFile(join(env.pinsDir, `${projectId}.json`), "utf8");
  return JSON.parse(json) as Record<string, unknown>;
}

/** 発行 POST の本文(ワイヤ形)。 */
interface IssueBody {
  readonly id: string;
  readonly role: string;
  readonly linkPubHex: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly issueSignatureHex: string;
}

/** 受諾 POST の本文(ワイヤ形)。 */
interface AcceptBody {
  readonly linkPubHex: string;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly acceptSignatureHex: string;
  readonly linkSignatureHex: string;
}

describe("invite link(§15-3 v2)", () => {
  const PROJECT_ID = "ab".repeat(32);
  let issued: IssuedInviteFixture;

  beforeAll(async () => {
    issued = await issueInviteFixture({
      inviter,
      projectId: PROJECT_ID,
      headHashHex: "cd".repeat(32),
      headSeq: 7,
      inviterLogin: "octocat",
    });
  });

  it("組み立て → 解釈がラウンドトリップする(パラメータ順は仕様の記載順)", () => {
    const link = inviteLinkText("https://maruhi.example", issued);
    expect(link).toBe(
      `https://maruhi.example/invite#v=2&i=${INVITE_ID}&k=${LINK_SEED_HEX}&p=${PROJECT_ID}&h=${"cd".repeat(32)}&s=7&iu=${inviter.userId}&ie=${inviter.encPubHex}&is=${inviter.sigPubHex}&r=member&il=octocat&sig=${issued.link.issueSignatureHex}`,
    );
    const parsed = parseInviteAcceptInput(Redacted.make(link));
    if (parsed.kind !== "link") throw new Error(`expected link, got ${parsed.kind}`);
    // 種は剥がして突合する: toEqual は Redacted の中身を見ないため(own
    // プロパティが無く、値の違う 2 つが等価判定される)、包んだまま比較すると
    // 「どんな種でも通る」空の表明になる
    expect(Redacted.value(parsed.link.linkSeedHex)).toBe(LINK_SEED_HEX);
    expect({ ...parsed.link, linkSeedHex: undefined }).toEqual({
      ...issued.link,
      linkSeedHex: undefined,
    });
  });

  it("il なしのリンクも有効として解釈する(inviterLogin = null)", () => {
    const link = inviteLinkText("https://maruhi.example", issued).replace("&il=octocat", "");
    const parsed = parseInviteAcceptInput(Redacted.make(link));
    if (parsed.kind !== "link") throw new Error("expected link");
    expect(parsed.link.inviterLogin).toBeNull();
    expect(
      Redacted.value(buildInviteLink({ origin: "https://maruhi.example", link: parsed.link })),
    ).toBe(link);
  });

  it("生トークン・旧版(v=1)・v なしはすべて拒否する(互換経路なし)", () => {
    expect(
      parseInviteAcceptInput(
        Redacted.make("maruhi_inv_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9xY01"),
      ),
    ).toEqual({ kind: "rejected", reason: "not-a-link" });
    expect(
      parseInviteAcceptInput(
        Redacted.make(
          `https://maruhi.example/invite#v=1&t=maruhi_inv_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9xY01&p=${PROJECT_ID}`,
        ),
      ),
    ).toEqual({ kind: "rejected", reason: "unsupported-version" });
    expect(
      parseInviteAcceptInput(Redacted.make(`https://maruhi.example/invite#p=${PROJECT_ID}`)),
    ).toEqual({ kind: "rejected", reason: "missing-or-invalid-fragment-params" });
  });

  it("必須パラメータの欠落・形式不正はエラーにする(壊れたリンクを受諾へ滑り込ませない)", () => {
    const link = inviteLinkText("https://maruhi.example", issued);
    for (const broken of [
      link.replace(`&i=${INVITE_ID}`, ""),
      link.replace(`&k=${LINK_SEED_HEX}`, `&k=${"zz".repeat(32)}`),
      link.replace(`&h=${"cd".repeat(32)}`, ""),
      link.replace("&s=7", "&s=0"),
      link.replace("&r=member", "&r=superuser"),
      link.replace(`&is=${inviter.sigPubHex}`, "&is=zz"),
      link.replace("&il=octocat", "&il=-bad-"),
      link.replace(`&sig=${issued.link.issueSignatureHex}`, "&sig=00"),
    ]) {
      expect(parseInviteAcceptInput(Redacted.make(broken))).toEqual({
        kind: "rejected",
        reason: "missing-or-invalid-fragment-params",
      });
    }
  });
});

describe("maruhi invite create", () => {
  function issueHandler(
    projectId: string,
    record: (body: IssueBody) => void,
    status = 200,
  ): MockHandler {
    return onRequest("POST", `/projects/${projectId}/invites`, (request) => {
      record(request.body as IssueBody);
      return status === 200
        ? { status, json: { expiresAtMs: 1755993600000 } }
        : { status, json: {} };
    });
  }

  it("id を採番し、発行署名つきの発行文を送り、リンク(種 + 発行文)を表示して発行ピンを保存する", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const issued: IssueBody[] = [];
    const server = await start([
      chainHandler(built),
      issueHandler(built.projectId, (b) => issued.push(b)),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["invite", "create", "--role", "member"], env.layer)).toBe(0);
    expect(issued).toHaveLength(1);
    const body = issued[0];
    if (body === undefined) throw new Error("no issue body");
    expect(body.role).toBe("member");
    expect(body.headSeq).toBe(1);
    expect(body.headHashHex).toBe(built.hashes[0]);
    // 発行署名は招待者のチェーン鍵で検証できる(CRYPTO_SPEC §6.5)
    const verified = await verifyInviteIssueSignature({
      context: {
        suite: SUITE_ID,
        inviteId: body.id,
        projectId: built.projectId,
        linkPubHex: body.linkPubHex,
        headHashHex: body.headHashHex,
        headSeq: body.headSeq,
        role: "member",
        inviterUserId: inviter.userId,
        inviterEncPubHex: inviter.encPubHex,
        inviterSigPubHex: inviter.sigPubHex,
      },
      signatureHex: body.issueSignatureHex,
    });
    expect(verified.ok).toBe(true);
    // サーバーへは種を送らない(公開鍵と発行文だけ)
    expect(JSON.stringify(body)).not.toContain("k=");
    expect(Object.keys(body).toSorted()).toEqual([
      "headHashHex",
      "headSeq",
      "id",
      "issueSignatureHex",
      "linkPubHex",
      "role",
    ]);

    // 表示したリンクは解釈でき、発行文と一致する(種から導出した公開鍵 = 送った link_pub)
    const shown = env.logs.find((line) => line.startsWith(`${server.origin}/invite#v=2&`));
    if (shown === undefined) throw new Error("link not shown");
    const parsed = parseInviteAcceptInput(Redacted.make(shown));
    if (parsed.kind !== "link") throw new Error("link did not parse");
    expect(parsed.link.inviteId).toBe(body.id);
    expect(parsed.link.issueSignatureHex).toBe(body.issueSignatureHex);
    expect(parsed.link.inviterSigPubHex).toBe(inviter.sigPubHex);
    expect(parsed.link.inviterLogin).toBeNull();
    const reissued = await issueInviteFixture({
      inviter,
      projectId: built.projectId,
      headHashHex: body.headHashHex,
      headSeq: body.headSeq,
      inviteId: body.id,
      seedHex: Redacted.value(parsed.link.linkSeedHex),
    });
    expect(reissued.linkPubHex).toBe(body.linkPubHex);

    // 発行ピン(§6.5 の招待者側対応物 — SHOULD): link_pub と role を非機密ローカルへ
    const pins = await readPins(env, built.projectId);
    expect(pins["issued"]).toEqual({
      [body.id]: {
        linkPubHex: body.linkPubHex,
        role: "member",
        expiresAtMs: 1755993600000,
        expectedGithubLogin: null,
      },
    });
    expect(env.errors.join("\n")).toContain("This link is shown only once");
  });

  it("--github は宛先 login を発行ピンに保持し、il= は /auth/me の自 login から組む(IV2)", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const server = await start([
      chainHandler(built),
      issueHandler(built.projectId, () => undefined),
      onRequest("GET", "/auth/me", () => ({
        status: 200,
        json: { userId: inviter.userId, orgs: [], providerLogin: "alice" },
      })),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(
      await runCli(["invite", "create", "--role", "member", "--github", "bob"], env.layer),
    ).toBe(0);
    const shown = env.logs.find((line) => line.startsWith(`${server.origin}/invite#v=2&`));
    const parsed = parseInviteAcceptInput(Redacted.make(shown ?? ""));
    if (parsed.kind !== "link") throw new Error("link did not parse");
    expect(parsed.link.inviterLogin).toBe("alice");
    const pins = await readPins(env, built.projectId);
    const issued = pins["issued"] as Record<string, { expectedGithubLogin: string | null }>;
    expect(issued[parsed.link.inviteId]?.expectedGithubLogin).toBe("bob");
    // 宛先 login はサーバーへ送らない(発行ピンにのみ)— 案内文は GitHub 照合を言う
    expect(env.errors.join("\n")).toContain("github.com/bob's signing keys");

    // login の形が不正なら発行前に落ちる(usage)
    expect(
      await runCli(["invite", "create", "--role", "member", "--github", "bad--login"], env.layer),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("--github must be a GitHub login");

    // identityBacking = none では il を組まない(裏付け元を使わない環境)
    const env2 = await makeTestEnv();
    seedSession(env2, server.origin, inviter);
    await seedConfig(env2, {
      server: server.origin,
      defaultProject: built.projectId,
      identityBacking: "none",
    });
    expect(await runCli(["invite", "create", "--role", "member"], env2.layer)).toBe(0);
    const shown2 = env2.logs.find((line) => line.startsWith(`${server.origin}/invite#v=2&`));
    expect(shown2).not.toContain("&il=");
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
    const issueCalls: IssueBody[] = [];
    const server = await start([
      chainHandler(built),
      issueHandler(built.projectId, (b) => issueCalls.push(b), 500),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, admin2);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["invite", "create", "--role", "admin"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Only an owner can issue a role=admin invite");
    expect(issueCalls).toHaveLength(0);
  });

  it("手元の master 鍵がチェーン上の自分の鍵と違えば発行しない(検証不能な発行文を作らない)", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    // 同じ user_id で別の鍵(別デバイスで生成し直した形)
    const otherKeys = await makeTestUser(inviter.userId);
    const issueCalls: IssueBody[] = [];
    const server = await start([
      chainHandler(built),
      issueHandler(built.projectId, (b) => issueCalls.push(b)),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, otherKeys);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["invite", "create", "--role", "member"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Your master key on this machine does not match your key on the project chain",
    );
    expect(issueCalls).toHaveLength(0);
  });

  it("エージェント環境では発行そのものを拒否する(種がトランスクリプトへ残る)", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const issueCalls: IssueBody[] = [];
    const server = await start([
      chainHandler(built),
      issueHandler(built.projectId, (b) => issueCalls.push(b)),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    env.setAgent({ isAgent: true, name: "test-agent" });

    expect(await runCli(["invite", "create", "--role", "member"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("the invite was not issued");
    // 発行 POST の前に拒否する(サーバー側に pending を作らない)
    expect(issueCalls).toHaveLength(0);
  });

  it("stdin / stdout / stderr のどれかが非TTYなら発行前に拒否する", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    for (const terminal of [
      { stdin: false, stdout: true, stderr: true },
      { stdin: true, stdout: false, stderr: true },
      { stdin: true, stdout: true, stderr: false },
    ]) {
      const issueCalls: IssueBody[] = [];
      const server = await start([
        chainHandler(built),
        issueHandler(built.projectId, (b) => issueCalls.push(b)),
      ]);
      const env = await makeTestEnv();
      seedSession(env, server.origin, inviter);
      await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
      env.setTerminal(terminal);

      expect(await runCli(["invite", "create", "--role", "member"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain("stdin, stdout, and stderr must all be terminals");
      expect(issueCalls).toHaveLength(0);
      expect(env.logs.some((line) => line.includes("#v=2&"))).toBe(false);
    }
  });

  it("発行ピンの保存失敗(破損ピンファイル)でも発行は成立し、リンクを表示して警告する", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const server = await start([
      chainHandler(built),
      issueHandler(built.projectId, () => undefined),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    // 破損ピンファイル(merge は上書きを拒否する — pins.ts の規律)
    await mkdir(env.pinsDir, { recursive: true });
    await writeFile(join(env.pinsDir, `${built.projectId}.json`), "{ broken");

    // リンクは一度しか表示されない: ピン保存の失敗で成立済みの発行を落とさない
    expect(await runCli(["invite", "create", "--role", "member"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("/invite#v=2&i=");
    expect(env.errors.join("\n")).toContain("could not save the issuance pin");
    // 破損ファイルは上書きされない(検出可能性を保存)
    expect(await readFile(join(env.pinsDir, `${built.projectId}.json`), "utf8")).toBe("{ broken");
  });

  it("409(id / link_pub 衝突)と 429 の 2 種(pending 上限 / レート制限)を区別して表示する", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    for (const [status, json, fragment] of [
      [
        409,
        { _tag: "InviteConflict", field: "linkPub" },
        "already has an invite with the same id or link key",
      ],
      [429, { _tag: "InvitePendingLimit", limit: 100 }, "reached the limit (100)"],
      [429, { _tag: "InviteRateLimited", retryAfterSeconds: 1800 }, "about 1800 seconds"],
    ] as const) {
      const server = await start([
        chainHandler(built),
        onRequest("POST", `/projects/${built.projectId}/invites`, () => ({ status, json })),
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
  const HEAD_HASH = "cd".repeat(32);

  async function issuedFor(
    role: "reader" | "member" | "admin" = "member",
  ): Promise<IssuedInviteFixture> {
    return issueInviteFixture({
      inviter,
      projectId: PROJECT_ID,
      headHashHex: HEAD_HASH,
      headSeq: 3,
      role,
    });
  }

  async function linkFor(role: "reader" | "member" | "admin" = "member"): Promise<string> {
    return inviteLinkText("https://maruhi.example", await issuedFor(role));
  }

  function acceptHandler(record: (body: AcceptBody) => void, role = "member"): MockHandler {
    return onRequest("POST", "/invites/accept", (request) => {
      record(request.body as AcceptBody);
      return { status: 200, json: { id: INVITE_ID, projectId: PROJECT_ID, role } };
    });
  }

  /** 受諾 POST 本文の両署名を §6.5 のとおり独立検証する。 */
  async function verifyBody(body: AcceptBody, linkPubHex: string): Promise<void> {
    const context = {
      suite: SUITE_ID,
      projectId: PROJECT_ID,
      linkPubHex,
      inviteeUserId: acceptor.userId,
      inviteeEncPubHex: body.encPubHex,
      inviteeSigPubHex: body.sigPubHex,
    };
    expect(body.linkPubHex).toBe(linkPubHex);
    const accept = await verifyInviteAcceptSignature({
      context,
      signatureHex: body.acceptSignatureHex,
    });
    const link = await verifyInviteLinkSignature({
      context,
      linkSignatureHex: body.linkSignatureHex,
    });
    expect(accept.ok).toBe(true);
    expect(link.ok).toBe(true);
  }

  it("発行署名の検証 → 儀式(最終語再入力)→ 共同署名 → 受諾。アンカーをピン留めし、自 FP ワードを表示する", async () => {
    const issued = await issuedFor();
    const bodies: AcceptBody[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);

    expect(
      await runCli(["invite", "accept", inviteLinkText(server.origin, issued)], env.layer),
    ).toBe(0);

    // 受諾署名・リンク署名は §6.5 のとおり検証可能(project / link_pub / 主体 / 宣言鍵に束縛)。
    // 種はサーバーへ送らない
    expect(bodies).toHaveLength(1);
    const body = bodies[0];
    if (body === undefined) throw new Error("no accept body");
    expect(body.encPubHex).toBe(acceptor.encPubHex);
    expect(body.sigPubHex).toBe(acceptor.sigPubHex);
    expect(JSON.stringify(body)).not.toContain(LINK_SEED_HEX);
    await verifyBody(body, issued.linkPubHex);

    // アンカー(§6.3 (a))のピン留め(未照合 = verifiedAtSeq null。招待者の sig 鍵も保持)
    const pins = await readPins(env, PROJECT_ID);
    expect(pins["anchor"]).toEqual({
      headSeq: 3,
      headHashHex: HEAD_HASH,
      inviterUserId: inviter.userId,
      inviterKeyFingerprintHex: inviter.fingerprintHex,
      inviterSigPubHex: inviter.sigPubHex,
      verifiedAtSeq: null,
    });

    const logs = env.logs.join("\n");
    expect(logs).toContain("Accepted the invite");
    expect(logs).toContain(`  hex:  ${inviter.fingerprintHex}`);
    expect(logs).toContain("read these 12 words to them out of band");
    expect(logs).toContain(
      "the link anchor (genesis, head, inviter key) is machine-checked automatically",
    );
  });

  it("発行署名が検証できないリンクは儀式の前に拒否する(改竄・ゴースト招待者)", async () => {
    const issued = await issuedFor();
    const bodies: AcceptBody[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    for (const tampered of [
      // 署名そのものの改竄
      inviteLinkText(server.origin, {
        ...issued,
        link: { ...issued.link, issueSignatureHex: flipHex(issued.link.issueSignatureHex) },
      }),
      // 署名対象(role)の改竄
      inviteLinkText(server.origin, { ...issued, link: { ...issued.link, role: "admin" } }),
      // 種のすり替え(link_pub が発行文と一致しない)
      inviteLinkText(server.origin, {
        ...issued,
        link: { ...issued.link, linkSeedHex: Redacted.make("d8".repeat(32)) },
      }),
    ]) {
      const env = await makeTestEnv();
      seedSession(env, server.origin, acceptor);
      await seedConfig(env, { server: server.origin });
      env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
      expect(await runCli(["invite", "accept", tampered], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain(
        "issue signature does not verify under the inviter key it names",
      );
      expect(env.prompts).toHaveLength(0);
    }
    expect(bodies).toHaveLength(0);
  });

  it("儀式の再入力が 3 回一致しなければ受諾しない", async () => {
    const bodies: AcceptBody[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setPromptResponses(["wrong1", "wrong2", "wrong3"]);

    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Inviter fingerprint confirmation failed");
    expect(bodies).toHaveLength(0);
  });

  it("--inviter-fingerprint はリンクの ie/is から導出した FP と照合し、一致すれば対話なし・不一致なら受諾前に拒否する", async () => {
    const bodies: AcceptBody[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });

    expect(
      await runCli(
        ["invite", "accept", await linkFor(), "--inviter-fingerprint", inviter.fingerprintHex],
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
        ["invite", "accept", await linkFor(), "--inviter-fingerprint", "0".repeat(32)],
        env2.layer,
      ),
    ).toBe(1);
    expect(env2.errors.join("\n")).toContain(
      "--inviter-fingerprint does not match the inviter fingerprint derived from the link (ie= / is=)",
    );
    expect(bodies).toHaveLength(1);
  });

  it("エージェント環境では --inviter-fingerprint なしの儀式代行を拒否する", async () => {
    const bodies: AcceptBody[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setAgent({ isAgent: true, name: "test-agent" });

    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Refused to run the inviter-fingerprint confirmation ceremony",
    );
    expect(bodies).toHaveLength(0);

    // フラグの明示があれば受諾できる(儀式の帯域外照合を代行しない、の線引き)
    env.errors.length = 0;
    expect(
      await runCli(
        ["invite", "accept", await linkFor(), "--inviter-fingerprint", inviter.fingerprintHex],
        env.layer,
      ),
    ).toBe(0);
    expect(bodies).toHaveLength(1);
  });

  it("検証済み指紋帳: 儀式の成功が招待者の指紋を記録し、同じ招待者の次の受諾は yes 確認のみで通る(KF)", async () => {
    const bodies: AcceptBody[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });

    // 1 回目: 儀式(最終語再入力)→ 成功が帳へ記録される
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(1);
    const json = await readFile(env.fingerprintBookPath, "utf8");
    const stored = JSON.parse(json) as {
      known: Record<string, Record<string, { fingerprintHex: string }>>;
    };
    expect(stored.known[server.origin]?.[inviter.userId]?.fingerprintHex).toBe(
      inviter.fingerprintHex,
    );
    expect(env.errors.join("\n")).toContain("recorded the verified fingerprint");

    // 2 回目(同じ招待者からの別招待に相当): 帳のヒットで 12 語の読み上げ
    // 再実施は免除されるが、受諾そのものの明示確認(yes)は残る。読み上げ
    // 照合の指示 2 行はヒット時は出さない(指示直後に免除を言わない)
    const logsBeforeSecondRun = env.logs.length;
    env.setPromptResponses(["yes"]);
    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(2);
    expect(env.prompts[1]).toContain("Type yes to accept this invite attributed to");
    const secondRunLogs = env.logs.slice(logsBeforeSecondRun).join("\n");
    expect(secondRunLogs).toContain("not required again");
    expect(secondRunLogs).not.toContain("reads to you out of band");
    expect(bodies).toHaveLength(2);

    // 3 回目(エージェント環境): 帳のヒットがあっても代行は拒否(フラグ必須 —
    // member add 側と対称の固定)
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(1);
    expect(env.prompts).toHaveLength(2);
    expect(env.errors.join("\n")).toContain(
      "Refused to run the inviter-fingerprint confirmation ceremony",
    );
    expect(bodies).toHaveLength(2);

    // 4 回目(非対話 — stdin がパイプ): 帳のヒットがあっても yes 確認へは
    // 進めず、完全な儀式(最終語再入力)へ戻る(盲目的な `printf yes |` で
    // 通らない — 一次境界は端末)
    env.setAgent({ isAgent: false });
    env.setTerminal({ stdin: false });
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(3);
    expect(env.prompts[2]).toContain("type the last of the 12 words");
    expect(env.errors.join("\n")).toContain("stdin is not an interactive terminal");
    expect(bodies).toHaveLength(3);
  });

  it("鍵未生成: 対話確認 → 生成 → リカバリー儀式 → 生成鍵で受諾(§15-3 の連結)", async () => {
    const issued = await issuedFor();
    const bodies: AcceptBody[] = [];
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

    expect(
      await runCli(["invite", "accept", inviteLinkText(server.origin, issued)], env.layer),
    ).toBe(0);
    expect(bodies).toHaveLength(1);
    const body = bodies[0];
    if (body === undefined) throw new Error("no accept body");
    // 生成された鍵での自己束縛署名が検証に通る(宣言鍵 = 検証鍵)
    await verifyBody(body, issued.linkPubHex);
    expect(env.logs.join("\n")).toContain("Generated your master key");
  });

  it("鍵未生成ガード: リカバリー登録済みなら生成せず key recover へ誘導する", async () => {
    const bodies: AcceptBody[] = [];
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

    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "restore it onto this machine with `maruhi key recover` and re-run",
    );
    expect(bodies).toHaveLength(0);
    // 鍵は生成されていない(キーチェーンは token エントリのみ)
    expect(env.keychain.size).toBe(1);
  });

  it("鍵未生成ガード: エージェント環境では生成しない(受諾自体を拒否して案内)", async () => {
    const bodies: AcceptBody[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedTokenOnly(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setAgent({ isAgent: true, name: "test-agent" });

    expect(
      await runCli(
        ["invite", "accept", await linkFor(), "--inviter-fingerprint", inviter.fingerprintHex],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Key generation is not performed in AI agent environments",
    );
    expect(bodies).toHaveLength(0);
    expect(env.keychain.size).toBe(1);
  });

  it("生トークン・旧版(v=1)リンクは usage エラー(2)で再発行を案内する(互換経路なし)", async () => {
    const bodies: AcceptBody[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });

    expect(
      await runCli(
        ["invite", "accept", "maruhi_inv_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9xY01"],
        env.layer,
      ),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify an invite link (…/invite#v=2&…)");

    env.errors.length = 0;
    expect(
      await runCli(
        ["invite", "accept", `${server.origin}/invite#v=1&t=maruhi_inv_x&p=${PROJECT_ID}`],
        env.layer,
      ),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("Ask the inviter to issue a new link");
    expect(bodies).toHaveLength(0);
    expect(env.prompts).toHaveLength(0);
  });

  describe("裏付け元(IV2 — 充足形 4)", () => {
    async function backedLink(origin: string): Promise<string> {
      const issued = await issueInviteFixture({
        inviter,
        projectId: PROJECT_ID,
        headHashHex: HEAD_HASH,
        headSeq: 3,
        inviterLogin: "alice",
      });
      return inviteLinkText(origin, issued);
    }

    async function backedEnv(
      registeredKeys: readonly string[],
      status = 200,
    ): Promise<{ env: TestEnv; bodies: AcceptBody[]; origin: string }> {
      const bodies: AcceptBody[] = [];
      const server = await start([
        acceptHandler((body) => bodies.push(body)),
        githubSigningKeysHandler("alice", registeredKeys, status),
      ]);
      const env = await makeTestEnv();
      seedSession(env, server.origin, acceptor);
      await seedConfig(env, { server: server.origin });
      env.setVendorOrigin("api.github.com", server.origin);
      return { env, bodies, origin: server.origin };
    }

    it("is= が il= の署名鍵に登録済みなら --from の一致で対話なしに受諾し、完了表示は登録を案内する", async () => {
      const { env, bodies, origin } = await backedEnv([sshLineOf(inviter)]);
      expect(
        await runCli(["invite", "accept", await backedLink(origin), "--from", "alice"], env.layer),
      ).toBe(0);
      expect(env.prompts).toHaveLength(0);
      expect(bodies).toHaveLength(1);
      const logs = env.logs.join("\n");
      expect(logs).toContain("Inviter key verified");
      expect(logs).toContain("--from matches the link's inviter login");
      expect(logs).not.toContain("reads to you out of band");
      expect(logs).toContain(
        "Register this key on GitHub as a signing key with `maruhi key publish`",
      );
    });

    it("対話では login を名指しする yes だけで受諾する(12 語の読み上げは不要)", async () => {
      const { env, bodies, origin } = await backedEnv([sshLineOf(inviter)]);
      env.setPromptResponses(["yes"]);
      expect(await runCli(["invite", "accept", await backedLink(origin)], env.layer)).toBe(0);
      expect(env.prompts).toHaveLength(1);
      expect(env.prompts[0]).toContain("Type yes to accept this invite from github.com/alice");
      expect(bodies).toHaveLength(1);

      // yes 以外は受諾しない
      const second = await backedEnv([sshLineOf(inviter)]);
      second.env.setPromptResponses(["no"]);
      expect(
        await runCli(["invite", "accept", await backedLink(second.origin)], second.env.layer),
      ).toBe(1);
      expect(second.env.errors.join("\n")).toContain("The acceptance was cancelled");
      expect(second.bodies).toHaveLength(0);
    });

    it("--from と il= の不一致は拒否する(差し替えられた有効な別人のリンク)", async () => {
      const { env, bodies, origin } = await backedEnv([sshLineOf(inviter)]);
      expect(
        await runCli(
          ["invite", "accept", await backedLink(origin), "--from", "mallory"],
          env.layer,
        ),
      ).toBe(1);
      expect(env.errors.join("\n")).toContain("The link may have been swapped");
      expect(bodies).toHaveLength(0);
    });

    it("未登録・取得不能は儀式へ戻る(note つき)。エージェント環境は --from なしを拒否し、あれば通す", async () => {
      // 未登録(別の鍵だけが載っている)
      const { env, bodies, origin } = await backedEnv([sshLineOf(acceptor)]);
      env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
      expect(await runCli(["invite", "accept", await backedLink(origin)], env.layer)).toBe(0);
      expect(env.errors.join("\n")).toContain(
        "not registered as a signing key on github.com/alice — falling back to the inviter fingerprint confirmation",
      );
      expect(env.prompts[0]).toContain("type the last of the 12 words");
      expect(bodies).toHaveLength(1);

      // 取得不能(上限)
      const limited = await backedEnv([], 403);
      limited.env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
      expect(
        await runCli(["invite", "accept", await backedLink(limited.origin)], limited.env.layer),
      ).toBe(0);
      expect(limited.env.errors.join("\n")).toContain("could not be fetched");
      expect(limited.bodies).toHaveLength(1);

      // エージェント環境: 登録済みでも yes の代行はしない — --from の明示だけが経路
      const agent = await backedEnv([sshLineOf(inviter)]);
      agent.env.setAgent({ isAgent: true, name: "test-agent" });
      expect(
        await runCli(["invite", "accept", await backedLink(agent.origin)], agent.env.layer),
      ).toBe(1);
      expect(agent.env.errors.join("\n")).toContain("Re-run with --from alice");
      expect(agent.bodies).toHaveLength(0);
      expect(
        await runCli(
          ["invite", "accept", await backedLink(agent.origin), "--from", "alice"],
          agent.env.layer,
        ),
      ).toBe(0);
      expect(agent.bodies).toHaveLength(1);
    });

    it("identityBacking = none では --from を照合せず、儀式へ戻る", async () => {
      const { env, bodies, origin } = await backedEnv([sshLineOf(inviter)]);
      await seedConfig(env, { server: origin, identityBacking: "none" });
      env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
      expect(
        await runCli(["invite", "accept", await backedLink(origin), "--from", "alice"], env.layer),
      ).toBe(0);
      expect(env.errors.join("\n")).toContain(
        "identityBacking is none, so --from cannot be checked",
      );
      expect(bodies).toHaveLength(1);
    });
  });

  it("404 / 410 / 422 の理由を運用手順に翻訳する(先着受諾 = 横取りの顕在化、旧行 = 再発行)", async () => {
    for (const [status, json, fragment] of [
      [404, { _tag: "InviteNotFound" }, "does not know this invite link's key"],
      [410, { _tag: "InviteGone", reason: "accepted" }, "the link may have been intercepted"],
      [410, { _tag: "InviteGone", reason: "expired" }, "This invite has expired"],
      [
        410,
        { _tag: "InviteGone", reason: "unbound" },
        "issued before the link-bound invite format",
      ],
      [422, { _tag: "InviteSignatureInvalid", which: "link" }, "The link signature was rejected"],
      [
        422,
        { _tag: "InviteSignatureInvalid", which: "accept" },
        "The acceptance signature was rejected",
      ],
    ] as const) {
      const server = await start([onRequest("POST", "/invites/accept", () => ({ status, json }))]);
      const env = await makeTestEnv();
      seedSession(env, server.origin, acceptor);
      await seedConfig(env, { server: server.origin });
      env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
      expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain(fragment);
    }
  });

  it("受諾が成立しなければアンカーをピン留めしない(410 でピンファイルを作らない)", async () => {
    // 受諾前にピン留めすると、失敗する受諾(失効・偽リンク)を含む細工リンクの
    // 投入だけで既存アンカーを差し替えられる(自己 DoS / 置換)
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

    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(1);
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

    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(0);
    expect((await readPins(env, PROJECT_ID))["anchor"]).toEqual(verifiedAnchor);
    expect(env.logs.join("\n")).toContain("keeping the existing anchor");

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

    expect(await runCli(["invite", "accept", await linkFor()], env2.layer)).toBe(0);
    expect((await readPins(env2, PROJECT_ID))["anchor"]).toEqual({
      headSeq: 3,
      headHashHex: HEAD_HASH,
      inviterUserId: inviter.userId,
      inviterKeyFingerprintHex: inviter.fingerprintHex,
      inviterSigPubHex: inviter.sigPubHex,
      verifiedAtSeq: null,
    });
    // 置換は痕跡を残す(偽リンクによる差し替え = DoS 経路の監査可能性)
    expect(env2.logs.join("\n")).toContain(
      "Replacing the unverified existing anchor with this acceptance's link anchor",
    );
  });

  it("ピンファイル破損時は受諾を成立させたまま警告し、破損ファイルを上書きしない", async () => {
    // 受諾はサーバー側で成立済み(リンク消費済み)— ピン留め失敗で失敗扱いに
    // すると「再実行」の導線が 410(accepted)へ誘導する誤案内になる
    const server = await start([acceptHandler(() => undefined)]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    await mkdir(env.pinsDir, { recursive: true });
    await writeFile(join(env.pinsDir, `${PROJECT_ID}.json`), "{ broken");
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);

    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("could not pin the invite link anchor");
    expect(await readFile(join(env.pinsDir, `${PROJECT_ID}.json`), "utf8")).toBe("{ broken");
    // 完了報告が警告と矛盾しない: 機械照合の約束を出さず、劣化を案内する
    const logs = env.logs.join("\n");
    expect(logs).not.toContain(
      "the link anchor (genesis, head, inviter key) is machine-checked automatically",
    );
    expect(logs).toContain("the first-sync machine check will not run");
  });

  it("署名済みリンクの r / p と応答の不一致は拒否する(サーバーの自己矛盾・行のすり替え)", async () => {
    // r=admin と署名されたリンク、応答の role は member → 拒否(発行署名と矛盾)
    const server = await start([acceptHandler(() => undefined, "member")]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
    expect(await runCli(["invite", "accept", await linkFor("admin")], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The role declared in the signed link (admin) does not match the role the server reports (member)",
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
    expect(await runCli(["invite", "accept", await linkFor()], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain("the server's response contradicts itself");
  });
});

describe("maruhi invite list / revoke", () => {
  async function issuedFor(
    built: { readonly projectId: string; readonly hashes: readonly string[] },
    role: "reader" | "member" | "admin" = "member",
  ): Promise<IssuedInviteFixture> {
    return issueInviteFixture({
      inviter,
      projectId: built.projectId,
      headHashHex: built.hashes[built.hashes.length - 1] ?? "",
      headSeq: built.hashes.length,
      role,
    });
  }

  function listRow(
    projectId: string,
    issued: IssuedInviteFixture | null,
    acceptance: unknown,
    role = "member",
  ): unknown {
    return {
      id: INVITE_ID,
      projectId,
      role,
      status: acceptance === null ? "pending" : "accepted",
      inviterUserId: inviter.userId,
      issuance: issued === null ? null : issued.issuance,
      createdAtMs: 1755200000000,
      expiresAtMs: 1755993600000,
      acceptance,
    };
  }

  it("発行文と受諾ブロックを §6.5 独立検証し、受諾鍵の FP ワードを表示する", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const issued = await issuedFor(built);
    const acceptance = await acceptanceFixture({
      projectId: built.projectId,
      issued,
      invitee: acceptor,
    });
    const server = await start([
      chainHandler(built),
      onRequest("GET", `/projects/${built.projectId}/invites`, () => ({
        status: 200,
        json: { invitations: [listRow(built.projectId, issued, acceptance)] },
      })),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["invite", "list"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("issuance: signature verified against the inviter's chain key");
    expect(logs).toContain(
      `accepted: ${acceptor.userId} (acceptance and link signatures verified)`,
    );
    expect(logs).toContain(`fp:   ${acceptor.fingerprintHex}`);
  });

  it("IV 改訂前の行(発行文なし)は受諾不能として案内し、失敗には数えない", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const server = await start([
      chainHandler(built),
      onRequest("GET", `/projects/${built.projectId}/invites`, () => ({
        status: 200,
        json: { invitations: [listRow(built.projectId, null, null)] },
      })),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["invite", "list"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("issued before the link-bound invite format");
  });

  it("改竄された発行署名・受諾署名・リンク署名は検証失敗として警告し、exit 1 にする", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const issued = await issuedFor(built);
    const acceptance = await acceptanceFixture({
      projectId: built.projectId,
      issued,
      invitee: acceptor,
    });
    for (const [row, fragment] of [
      // 発行文の role 改竄(発行署名が覆う)
      [
        listRow(built.projectId, issued, acceptance, "admin"),
        "issue signature that does not verify",
      ],
      // 別 user_id へ付け替え(両署名の invitee_user_id 束縛が破れる — リンク署名を先に報告)
      [
        listRow(built.projectId, issued, { ...acceptance, inviteeUserId: "user-attacker-99" }),
        "the link signature failed verification",
      ],
      // 受諾署名だけの改竄
      [
        listRow(built.projectId, issued, {
          ...acceptance,
          signatureHex: flipHex(acceptance.signatureHex),
        }),
        "the acceptance signature failed verification",
      ],
    ] as const) {
      const server = await start([
        chainHandler(built),
        onRequest("GET", `/projects/${built.projectId}/invites`, () => ({
          status: 200,
          json: { invitations: [row] },
        })),
      ]);
      const env = await makeTestEnv();
      seedSession(env, server.origin, inviter);
      await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

      expect(await runCli(["invite", "list"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain(fragment);
    }
  });

  it("発行ピンとサーバー申告(link_pub)の不一致を警告し、exit 1 にする", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const issued = await issuedFor(built);
    const server = await start([
      chainHandler(built),
      onRequest("GET", `/projects/${built.projectId}/invites`, () => ({
        status: 200,
        json: { invitations: [listRow(built.projectId, issued, null)] },
      })),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    // 発行時ピン(別のリンク鍵)をローカルへ用意 — サーバーの行がすり替えられた形
    await mkdir(env.pinsDir, { recursive: true });
    await writeFile(
      join(env.pinsDir, `${built.projectId}.json`),
      JSON.stringify({
        v: 1,
        anchor: null,
        issued: {
          [INVITE_ID]: {
            linkPubHex: "ee".repeat(32),
            role: "member",
            expiresAtMs: 1755993600000,
            expectedGithubLogin: null,
          },
        },
      }),
    );

    expect(await runCli(["invite", "list"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not match the local record from issuance");
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
    expect(env.logs.join("\n")).toContain("Revoked the invite");

    expect(await runCli(["invite", "revoke", "inv-0002"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("run `maruhi member remove`");
  });
});
