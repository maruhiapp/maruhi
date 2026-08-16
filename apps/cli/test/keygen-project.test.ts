// key generate / show と project init(genesis)/ verify のテスト。

import { computeChainEntryHash, verifyChain, type ChainEntry } from "@maruhi/crypto";
import { Redacted } from "effect";
import { afterEach, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { masterKeyEntryName, parseStoredMasterKey, tokenEntryName } from "../src/keychain.ts";
import { addMemberOp, buildChain, genesisOp, makeTestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function start(handlers: readonly MockHandler[]): Promise<MockServer> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  return server;
}

async function loggedInEnv(origin: string, userId: string): Promise<TestEnv> {
  const env = await makeTestEnv();
  await seedConfig(env, { server: origin });
  env.keychain.set(
    tokenEntryName(origin),
    JSON.stringify({ token: "maruhi_pat_stored", userId, tokenId: "tok_1" }),
  );
  return env;
}

/** リカバリー登録状態の応答(key show / generate の後段が呼ぶ)。 */
function recoveryStatusHandler(registered: boolean): MockHandler {
  return onRequest("GET", "/auth/recovery/status", () => ({
    status: 200,
    json: { registered, updatedAtMs: registered ? 1754006400000 : null },
  }));
}

/** リカバリーラップ登録の受理(generate / recovery の PUT)。 */
function recoveryPutHandler(): MockHandler {
  return onRequest("PUT", "/auth/recovery", () => ({ status: 204 }));
}

/**
 * リカバリーコード行(4 文字 × 13 グループ)を stderr 出力から取り出す。
 * コードは鍵素材なので stdout(リダイレクトされうる)には出ない。
 */
function displayedRecoveryCode(env: TestEnv): string {
  const line = env.errors.find((entry) => /^ {4}[A-Z2-7]{4}(-[A-Z2-7]{4}){12}$/.test(entry));
  if (line === undefined) {
    throw new Error("recovery code line not found in stderr output");
  }
  return line.trim();
}

/** 保存確認プロンプトへの正答(コードの最終グループ)を遅延評価でキューする。 */
function queueSaveConfirmation(env: TestEnv): void {
  env.setPromptResponses([
    () => {
      const groups = displayedRecoveryCode(env).split("-");
      return groups[groups.length - 1] ?? "";
    },
  ]);
}

describe("maruhi key", () => {
  it("generate は鍵をキーチェーンに保存し、FP を表示する(秘密鍵は表示しない)", async () => {
    const maruhi = await start([recoveryStatusHandler(false), recoveryPutHandler()]);
    const env = await loggedInEnv(maruhi.origin, "user-0001");
    queueSaveConfirmation(env);
    expect(await runCli(["key", "generate"], env.layer)).toBe(0);
    const stored = env.keychain.get(masterKeyEntryName(maruhi.origin, "user-0001"));
    expect(stored).toBeDefined();
    const record = parseStoredMasterKey(stored ?? "");
    expect(record).not.toBeNull();
    if (record === null) throw new Error("expected a parsed master-key record");
    expect(record.suite).toBe("maruhi/v1");
    // 秘密側は Redacted。生値の検査(長さ・出力への非混入)は剥がして行う
    const encSkHex = Redacted.value(record.encSkHex);
    const sigSkSeedHex = Redacted.value(record.sigSkSeedHex);
    expect(encSkHex).toHaveLength(64);
    // 伏字が保存されていない = 鍵を復元できるレコードが書かれている
    expect(stored).toContain(encSkHex);
    // 出力に秘密鍵素材が漏れない
    const output = env.logs.join("\n");
    expect(output).toContain("key fingerprint:");
    expect(output).not.toContain(encSkHex);
    expect(output).not.toContain(sigSkSeedHex);
  });

  it("既存鍵の上書きを拒否する", async () => {
    const maruhi = await start([recoveryStatusHandler(false), recoveryPutHandler()]);
    const env = await loggedInEnv(maruhi.origin, "user-0001");
    queueSaveConfirmation(env);
    expect(await runCli(["key", "generate"], env.layer)).toBe(0);
    expect(await runCli(["key", "generate"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("既に存在します");
  });

  it("未知スイートの master 鍵レコードを拒否する", async () => {
    const user = await makeTestUser("user-0001");
    const maruhi = await start([]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    env.keychain.set(
      masterKeyEntryName(maruhi.origin, user.userId),
      JSON.stringify({
        suite: "maruhi/v2",
        encPubHex: user.encPubHex,
        encSkHex: user.encSkHex,
        sigPubHex: user.sigPubHex,
        sigSkSeedHex: user.sigSkSeedHex,
      }),
    );
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    const message = env.errors.join("\n");
    // 原因(どのスイートか)は名指しする
    expect(message).toContain("maruhi/v2");
    // 破損と違い**消してはいけない**: 将来版が書いた鍵を消させると恒久喪失に
    // なる。上書き防止ガード(ensureNoStoredMasterKey)側と同じ案内を出す
    expect(message).toContain("このレコードは残してください");
    // 逃げ道は条件付きでのみ示す(リカバリーコードがあるときだけ消してよい)
    expect(message).toContain("リカバリーコードを持っている場合に限り");
  });

  it("show は公開鍵と FP のみ表示し、リカバリー登録状態を出す", async () => {
    const user = await makeTestUser("user-0001");
    const maruhi = await start([recoveryStatusHandler(true)]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    expect(await runCli(["key", "show"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain(user.encPubHex);
    expect(output).toContain(user.fingerprintHex);
    expect(output).toContain("recovery:        登録済み");
    expect(output).not.toContain(user.encSkHex);
    expect(output).not.toContain(user.sigSkSeedHex);
  });

  it("show はリカバリー状態を取得できなくても失敗しない(オフラインで使える)", async () => {
    const user = await makeTestUser("user-0001");
    // recovery/status ハンドラなし = サーバー側が応答しない状況
    const maruhi = await start([]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    expect(await runCli(["key", "show"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain(user.fingerprintHex);
    expect(env.logs.join("\n")).toContain("recovery:        確認できませんでした");
    expect(env.errors.join("\n")).toContain("リカバリー登録状態を確認できません");
  });

  it("show はリカバリー未登録なら発行を促す(保管リマインダ)", async () => {
    const user = await makeTestUser("user-0001");
    const maruhi = await start([recoveryStatusHandler(false)]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    expect(await runCli(["key", "show"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("recovery:        未登録");
    expect(env.errors.join("\n")).toContain("`maruhi key recovery` で発行してください");
  });

  it("show は制御文字を含む userId をサニタイズする", async () => {
    const user = await makeTestUser("user\u001b[31m-0001");
    const maruhi = await start([recoveryStatusHandler(true)]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    expect(await runCli(["key", "show"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).not.toContain("\u001b");
    expect(output).toContain("user\uFFFD[31m-0001");
  });
});

function meHandler(userId: string, orgs: readonly { orgId: string; slug: string }[]): MockHandler {
  return onRequest("GET", "/auth/me", () => ({
    status: 200,
    json: {
      userId,
      orgs: orgs.map((org) => ({ ...org, name: org.slug, role: "owner" })),
    },
  }));
}

/** genesis を受理し、実サーバーと同じく entry ハッシュを ID として返す。 */
function initHandler(record: (body: { orgId: string; entry: ChainEntry }) => void): MockHandler {
  return async (request) => {
    if (request.method !== "POST" || request.path !== "/projects") {
      return null;
    }
    const body = request.body as { orgId: string; entry: ChainEntry };
    record(body);
    const hash = await computeChainEntryHash(body.entry);
    return { status: 200, json: { projectId: hash, headSeq: 1, headHashHex: hash } };
  };
}

describe("maruhi project init", () => {
  it("genesis を署名して送信し、予見したプロジェクト ID と応答を突合する", async () => {
    const user = await makeTestUser("user-0001");
    let submitted: { orgId: string; entry: ChainEntry } | null = null;
    const maruhi = await start([
      meHandler(user.userId, [{ orgId: "org_personal", slug: "me" }]),
      initHandler((body) => {
        submitted = body;
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    seedSession(env, maruhi.origin, user);

    expect(await runCli(["project", "init"], env.layer)).toBe(0);
    // パーソナル org が自動選択され(表示層で org を出さない — §9-1)、
    // 送信された genesis はそれ自体で検証可能
    const body = submitted as { orgId: string; entry: ChainEntry } | null;
    expect(body?.orgId).toBe("org_personal");
    const verified = await verifyChain([body?.entry as ChainEntry]);
    expect(verified.ok).toBe(true);
    const hash = await computeChainEntryHash(body?.entry as ChainEntry);
    expect(env.logs.join("\n")).toContain(`プロジェクトを作成しました: ${hash}`);
  });

  it("サーバーが genesis ハッシュと異なる ID を返したら失敗する", async () => {
    const user = await makeTestUser("user-0001");
    const bogus = "ab".repeat(32);
    const maruhi = await start([
      meHandler(user.userId, [{ orgId: "org_personal", slug: "me" }]),
      onRequest("POST", "/projects", () => ({
        status: 200,
        json: { projectId: bogus, headSeq: 1, headHashHex: bogus },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    seedSession(env, maruhi.origin, user);
    expect(await runCli(["project", "init"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("genesis ハッシュと一致しません");
  });

  it("org が空の場合は状態異常として正確に報告する(「複数所属」と言わない)", async () => {
    const user = await makeTestUser("user-0001");
    const maruhi = await start([meHandler(user.userId, [])]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    seedSession(env, maruhi.origin, user);
    expect(await runCli(["project", "init"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("所属する org がありません");
    expect(errors).not.toContain("複数の org");
  });

  it("複数 org は --org 必須。slug 指定で作成できる", async () => {
    const user = await makeTestUser("user-0001");
    let submittedOrgId = "";
    const maruhi = await start([
      meHandler(user.userId, [
        { orgId: "org_personal", slug: "me" },
        { orgId: "org_team", slug: "team" },
      ]),
      initHandler((body) => {
        submittedOrgId = body.orgId;
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    seedSession(env, maruhi.origin, user);

    expect(await runCli(["project", "init"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("--org");

    expect(await runCli(["project", "init", "--org", "team"], env.layer)).toBe(0);
    expect(submittedOrgId).toBe("org_team");
  });
});

describe("maruhi project verify", () => {
  it("チェーンを検証してメンバーとエポックを表示する", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const member = await makeTestUser("user-member-2222");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "reader") },
    ]);
    const maruhi = await start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
        },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    seedSession(env, maruhi.origin, owner);
    expect(await runCli(["project", "verify", "--project", built.projectId], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain("チェーン検証 OK");
    expect(output).toContain(owner.userId);
    expect(output).toContain(member.userId);
    expect(output).toContain(`fp=${member.fingerprintHex}`);
  });
});
