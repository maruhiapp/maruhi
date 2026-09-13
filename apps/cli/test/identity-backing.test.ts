// 裏付け元 `github-signing-keys`(CRYPTO_SPEC §6.5 — IV2)の単体・コマンドテスト。
//
// 固定する性質:
//  1. checkSigningKeyBacking: 送るのは login だけ・ホスト固定・fail-closed(失敗も
//     不能も型で返し、CliError にしない)・ssh-ed25519 以外は読み飛ばす
//  2. `key publish`: OpenSSH 行の印字(stdout は鍵行のみ)と `--gh` の gh 呼び出し
//     (stdin = 鍵行・GH_ENV)、gh の失敗は手動手順つきのエラー
//  3. 登録の導線(裁定 G ⑥): `key generate` 直後の yes で登録、非対話・no・
//     エージェント・`identityBacking = none` では聞かない / 案内のみ
//  4. `config set identityBacking` の受理検査

import { Effect, Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { checkSigningKeyBacking } from "../src/github-signing-keys.ts";
import { masterKeyEntryName, serializeStoredToken, tokenEntryName } from "../src/keychain.ts";
import { GH_ENV } from "../src/sync-exec.ts";
import { makeTestUser, type TestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { githubSigningKeysHandler, sshLineOf } from "./support/invite.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let alice: TestUser;
let bob: TestUser;

const servers: MockServer[] = [];

beforeAll(async () => {
  alice = await makeTestUser("user-alice-11");
  bob = await makeTestUser("user-bob-22");
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function start(handlers: readonly MockHandler[]): Promise<MockServer> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  return server;
}

async function verdictOf(env: TestEnv, login: string, sigPubHex: string) {
  return Effect.runPromise(
    checkSigningKeyBacking({ login, sigPubHex }).pipe(Effect.provide(env.layer)),
  );
}

function loggedIn(env: TestEnv, origin: string, user: TestUser): void {
  env.keychain.set(
    tokenEntryName(origin),
    serializeStoredToken({
      token: Redacted.make("maruhi_pat_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9x123"),
      userId: user.userId,
      tokenId: "tok_1",
    }),
  );
}

/** リカバリーコードの保存確認への正答(表示済み stderr から最終グループ)。 */
function saveConfirmation(env: TestEnv): () => string {
  return () => {
    const line = env.errors.find((item) => /^ {4}[A-Z2-7]{4}(-[A-Z2-7]{4})+$/.test(item));
    const groups = (line ?? "").trim().split("-");
    return groups[groups.length - 1] ?? "";
  };
}

function recoveryHandlers(): MockHandler[] {
  return [
    onRequest("GET", "/auth/recovery/status", () => ({
      status: 200,
      json: { registered: false, updatedAtMs: null },
    })),
    onRequest("PUT", "/auth/recovery", () => ({ status: 204 })),
  ];
}

describe("checkSigningKeyBacking(裏付け元の問い合わせ)", () => {
  it("名指しした login の署名鍵一覧に対象の鍵がバイト一致で含まれれば match", async () => {
    const requests: string[] = [];
    const github = await start([
      (request) => {
        requests.push(`${request.method} ${request.path}`);
        return null;
      },
      githubSigningKeysHandler("bob", [
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0 bob@laptop",
        `${sshLineOf(bob)} maruhi ${bob.fingerprintHex}`,
      ]),
    ]);
    const env = await makeTestEnv();
    env.setVendorOrigin("api.github.com", github.origin);
    expect(await verdictOf(env, "bob", bob.sigPubHex)).toEqual({ kind: "match" });
    // 送るのは login だけ(クエリ・本文なし)
    expect(requests).toEqual(["GET /users/bob/ssh_signing_keys"]);
  });

  it("鍵が無い / login が無い / 取得不能 / 形が違う を型で区別し、決して失敗させない", async () => {
    const github = await start([
      githubSigningKeysHandler("bob", [sshLineOf(alice)]),
      githubSigningKeysHandler("ghost", [], 404),
      githubSigningKeysHandler("limited", [], 403),
      onRequest("GET", "/users/odd/ssh_signing_keys", () => ({
        status: 200,
        json: { not: "an array" },
      })),
    ]);
    const env = await makeTestEnv();
    env.setVendorOrigin("api.github.com", github.origin);
    expect(await verdictOf(env, "bob", bob.sigPubHex)).toEqual({ kind: "not-registered" });
    expect(await verdictOf(env, "ghost", bob.sigPubHex)).toEqual({ kind: "no-user" });
    expect((await verdictOf(env, "limited", bob.sigPubHex)).kind).toBe("unavailable");
    expect((await verdictOf(env, "odd", bob.sigPubHex)).kind).toBe("unavailable");
    // login の形が不正なら問い合わせ自体をしない(不能扱い)
    expect((await verdictOf(env, "-bad-", bob.sigPubHex)).kind).toBe("unavailable");
  });
});

describe("maruhi key publish", () => {
  it("OpenSSH 行を stdout に 1 行だけ出し、手順を stderr に出す", async () => {
    const maruhi = await start([]);
    const env = await makeTestEnv();
    seedSession(env, maruhi.origin, bob);
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["key", "publish"], env.layer)).toBe(0);
    expect(env.logs).toEqual([sshLineOf(bob)]);
    expect(env.errors.join("\n")).toContain("https://github.com/settings/ssh/new");
    expect(env.errors.join("\n")).toContain("`maruhi key publish --gh`");
    expect(env.execCalls).toHaveLength(0);
  });

  it("--gh は gh ssh-key add を stdin = 鍵行で呼び、失敗は手動手順つきで報告する", async () => {
    const maruhi = await start([]);
    const env = await makeTestEnv();
    seedSession(env, maruhi.origin, bob);
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["key", "publish", "--gh"], env.layer)).toBe(0);
    expect(env.execCalls).toHaveLength(1);
    const call = env.execCalls[0];
    if (call === undefined) throw new Error("no exec call");
    expect(call.command).toEqual([
      "gh",
      "ssh-key",
      "add",
      "-",
      "--type",
      "signing",
      "--title",
      `maruhi ${bob.fingerprintHex}`,
    ]);
    expect(new TextDecoder().decode(call.stdin)).toBe(`${sshLineOf(bob)}\n`);
    expect(call.extraEnv).toEqual(GH_ENV);
    expect(env.logs.join("\n")).toContain("Registered your signing key on GitHub");

    const env2 = await makeTestEnv();
    seedSession(env2, maruhi.origin, bob);
    await seedConfig(env2, { server: maruhi.origin });
    env2.setExecHandler(() => ({
      exitCode: 4,
      output: "To get started with GitHub CLI, please run: gh auth login\n",
    }));
    expect(await runCli(["key", "publish", "--gh"], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain("gh could not add the signing key (exit 4");
    expect(env2.errors.join("\n")).toContain("https://github.com/settings/ssh/new");
  });
});

describe("鍵生成直後の登録の導線(裁定 G ⑥)", () => {
  it("yes で gh 経由の登録まで済ませ、no / EOF は案内だけ出す(生成は成立したまま)", async () => {
    const maruhi = await start(recoveryHandlers());
    const env = await makeTestEnv();
    loggedIn(env, maruhi.origin, bob);
    await seedConfig(env, { server: maruhi.origin });
    env.setPromptResponses([saveConfirmation(env), "yes"]);
    expect(await runCli(["key", "generate"], env.layer)).toBe(0);
    expect(env.prompts[1]).toContain("Type yes to register it now through the gh CLI");
    expect(env.execCalls).toHaveLength(1);
    expect(env.execCalls[0]?.command.slice(0, 3)).toEqual(["gh", "ssh-key", "add"]);
    expect(env.logs.join("\n")).toContain("Registered your signing key on GitHub");

    const env2 = await makeTestEnv();
    loggedIn(env2, maruhi.origin, bob);
    await seedConfig(env2, { server: maruhi.origin });
    env2.setPromptResponses([saveConfirmation(env2), "no"]);
    expect(await runCli(["key", "generate"], env2.layer)).toBe(0);
    expect(env2.execCalls).toHaveLength(0);
    expect(env2.errors.join("\n")).toContain("register it later with `maruhi key publish`");
    expect(env2.keychain.get(masterKeyEntryName(maruhi.origin, bob.userId))).toBeDefined();

    // EOF(応答の枯渇)も「登録しない」
    const env3 = await makeTestEnv();
    loggedIn(env3, maruhi.origin, bob);
    await seedConfig(env3, { server: maruhi.origin });
    env3.setPromptResponses([saveConfirmation(env3)]);
    expect(await runCli(["key", "generate"], env3.layer)).toBe(0);
    expect(env3.execCalls).toHaveLength(0);
    expect(env3.errors.join("\n")).toContain("register it later with `maruhi key publish`");
  });

  it("非対話端末では案内だけ、identityBacking = none では何も出さない", async () => {
    const maruhi = await start(recoveryHandlers());
    const env = await makeTestEnv();
    loggedIn(env, maruhi.origin, bob);
    await seedConfig(env, { server: maruhi.origin });
    // エージェント環境: リカバリーコードの発行も登録の問いかけも代行しない(案内のみ)
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["key", "generate"], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(0);
    expect(env.execCalls).toHaveLength(0);
    expect(env.errors.join("\n")).toContain(
      "register this key on GitHub as a signing key with `maruhi key publish`",
    );

    const env2 = await makeTestEnv();
    loggedIn(env2, maruhi.origin, bob);
    await seedConfig(env2, { server: maruhi.origin, identityBacking: "none" });
    env2.setPromptResponses([saveConfirmation(env2)]);
    expect(await runCli(["key", "generate"], env2.layer)).toBe(0);
    expect(env2.prompts).toHaveLength(1);
    expect(env2.errors.join("\n")).not.toContain("maruhi key publish");
  });
});

describe("config identityBacking", () => {
  it("閉集合の値だけを受理し、get は設定値を返す", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["config", "set", "identityBacking", "none"], env.layer)).toBe(0);
    expect(await runCli(["config", "get", "identityBacking"], env.layer)).toBe(0);
    expect(env.logs).toContain("none");
    expect(await runCli(["config", "set", "identityBacking", "ldap"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain(
      "identityBacking must be one of: github-signing-keys | none",
    );
  });
});
