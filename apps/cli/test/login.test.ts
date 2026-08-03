// login(GitHub device flow → /auth/device/exchange → キーチェーン)と
// logout(自トークン失効 + キーチェーン削除)のテスト。
// GitHub・maruhi サーバーともローカル HTTP モック(実 device-flow 実装を検証)。

import { afterEach, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { tokenEntryName } from "../src/keychain.ts";
import { makeTestEnv, seedConfig } from "./support/env.ts";
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

/** device flow の GitHub 側(開始 + ポーリング n 回 pending → トークン)。 */
function fakeGitHub(input: {
  readonly pendingPolls: number;
  readonly accessToken: string;
  readonly finalError?: string;
}): { handlers: MockHandler[]; polls: () => number } {
  let polls = 0;
  const handlers: MockHandler[] = [
    onRequest("POST", "/login/device/code", () => ({
      status: 200,
      json: {
        device_code: "dev-code-0001",
        user_code: "ABCD-1234",
        verification_uri: "https://github.example/login/device",
        interval: 0,
        expires_in: 900,
      },
    })),
    onRequest("POST", "/login/oauth/access_token", (request) => {
      const body = request.body as Record<string, string>;
      expect(body["device_code"]).toBe("dev-code-0001");
      polls += 1;
      if (polls <= input.pendingPolls) {
        return { status: 200, json: { error: "authorization_pending" } };
      }
      if (input.finalError !== undefined) {
        return { status: 200, json: { error: input.finalError } };
      }
      return { status: 200, json: { access_token: input.accessToken } };
    }),
  ];
  return { handlers, polls: () => polls };
}

describe("maruhi login", () => {
  it("device flow → 交換 → maruhi トークンのみキーチェーンへ保存する", async () => {
    const github = fakeGitHub({ pendingPolls: 2, accessToken: "gho_github-token-value" });
    const githubServer = await start(github.handlers);
    let receivedGithubToken = "";
    let receivedTokenName = "";
    const maruhi = await start([
      onRequest("POST", "/auth/device/exchange", (request) => {
        const body = request.body as Record<string, unknown>;
        receivedGithubToken = String(body["githubAccessToken"]);
        receivedTokenName = String(body["tokenName"]);
        return {
          status: 200,
          json: { token: "maruhi_pat_issued", tokenId: "tok_1", userId: "user-0001" },
        };
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.testclient" });

    const code = await runCli(
      [
        "login",
        "--token-name",
        "cli-test",
        "--github-base-url",
        githubServer.origin,
        "--github-poll-interval",
        "0",
      ],
      env.layer,
    );
    expect(code).toBe(0);
    expect(github.polls()).toBe(3);
    // ユーザーコードと検証 URL が表示される
    expect(env.logs.join("\n")).toContain("ABCD-1234");
    expect(env.logs.join("\n")).toContain("https://github.example/login/device");
    // GitHub トークンはサーバーへ渡され、キーチェーンには保存されない(§4-5)
    expect(receivedGithubToken).toBe("gho_github-token-value");
    expect(receivedTokenName).toBe("cli-test");
    const stored = env.keychain.get(tokenEntryName(maruhi.origin));
    expect(stored).toBeDefined();
    expect(JSON.parse(stored ?? "{}")).toEqual({
      token: "maruhi_pat_issued",
      userId: "user-0001",
      tokenId: "tok_1",
    });
    expect(stored).not.toContain("gho_github-token-value");
    // トークン生値は端末出力にも出ない
    expect(env.logs.join("\n")).not.toContain("maruhi_pat_issued");
  });

  it("ブラウザ側の拒否(access_denied)はエラーで終了する", async () => {
    const github = fakeGitHub({
      pendingPolls: 0,
      accessToken: "unused",
      finalError: "access_denied",
    });
    const githubServer = await start(github.handlers);
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.testclient" });
    const code = await runCli(
      ["login", "--github-base-url", githubServer.origin, "--github-poll-interval", "0"],
      env.layer,
    );
    expect(code).toBe(1);
    expect(env.errors.join("\n")).toContain("認可が拒否");
    expect(env.keychain.size).toBe(0);
  });

  it("キーチェーン保存に失敗したら発行済みトークンを失効させてから失敗する(孤児化防止)", async () => {
    const github = fakeGitHub({ pendingPolls: 0, accessToken: "gho_x" });
    const githubServer = await start(github.handlers);
    let revoked = 0;
    const maruhi = await start([
      onRequest("POST", "/auth/device/exchange", () => ({
        status: 200,
        json: { token: "maruhi_pat_issued", tokenId: "tok_1", userId: "user-0001" },
      })),
      onRequest("POST", "/auth/token/revoke", (request) => {
        expect(request.headers["authorization"]).toBe("Bearer maruhi_pat_issued");
        revoked += 1;
        return { status: 204 };
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.testclient" });
    env.failKeychainWrites();
    expect(
      await runCli(
        ["login", "--github-base-url", githubServer.origin, "--github-poll-interval", "0"],
        env.layer,
      ),
    ).toBe(1);
    expect(revoked).toBe(1);
    expect(env.keychain.size).toBe(0);
    expect(env.errors.join("\n")).toContain("キーチェーン");
  });

  it("キーチェーン保存失敗 + 失効も失敗した場合は「失効させた」と主張しない", async () => {
    const github = fakeGitHub({ pendingPolls: 0, accessToken: "gho_x" });
    const githubServer = await start(github.handlers);
    const maruhi = await start([
      onRequest("POST", "/auth/device/exchange", () => ({
        status: 200,
        json: { token: "maruhi_pat_issued", tokenId: "tok_1", userId: "user-0001" },
      })),
      onRequest("POST", "/auth/token/revoke", () => ({ status: 500, bodyText: "boom" })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.testclient" });
    env.failKeychainWrites();
    expect(
      await runCli(
        [
          "login",
          "--github-base-url",
          githubServer.origin,
          "--token-name",
          "cli-test",
          "--github-poll-interval",
          "0",
        ],
        env.layer,
      ),
    ).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("失効にも失敗しました");
    expect(errors).not.toContain("失効させました)");
    // 同名再ログインによるローテーション失効の案内がある
    expect(errors).toContain("cli-test");
  });

  it("--github-base-url の非 loopback http は拒否する(平文経路の遮断)", async () => {
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.testclient" });
    expect(await runCli(["login", "--github-base-url", "http://evil.example"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("loopback");
  });

  it("client_id 未設定は設定手順を案内して失敗する", async () => {
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    const code = await runCli(["login"], env.layer);
    expect(code).toBe(1);
    expect(env.errors.join("\n")).toContain("githubClientId");
  });
});

describe("maruhi logout", () => {
  it("自トークンを失効させ、キーチェーンから削除する", async () => {
    let revoked = 0;
    const maruhi = await start([
      onRequest("POST", "/auth/token/revoke", (request) => {
        expect(request.headers["authorization"]).toBe("Bearer maruhi_pat_stored");
        revoked += 1;
        return { status: 204 };
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: "user-0001", tokenId: "tok_1" }),
    );
    expect(await runCli(["logout"], env.layer)).toBe(0);
    expect(revoked).toBe(1);
    expect(env.keychain.size).toBe(0);
  });

  it("失効 API の失敗(5xx)時はキーチェーンを先に削除する(無効トークンを残さない)", async () => {
    const maruhi = await start([
      onRequest("POST", "/auth/token/revoke", () => ({ status: 500, bodyText: "boom" })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: "user-0001", tokenId: "tok_1" }),
    );
    // 削除を失効より先に行う: 失効成功後に削除が失敗すると無効トークンが
    // キーチェーンに残り以後の全コマンドが 401 になるため。失効失敗は exit 1
    // だが、キーチェーンからは既に削除済み(再ログインで回収可能)
    expect(await runCli(["logout"], env.layer)).toBe(1);
    expect(env.keychain.size).toBe(0);
  });

  it("既に失効済み(401)の場合もキーチェーンを削除して成功する", async () => {
    const maruhi = await start([
      onRequest("POST", "/auth/token/revoke", () => ({
        status: 401,
        json: { _tag: "Unauthorized" },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: "user-0001", tokenId: "tok_1" }),
    );
    expect(await runCli(["logout"], env.layer)).toBe(0);
    expect(env.keychain.size).toBe(0);
  });

  it("MARUHI_TOKEN が残っている場合は「引き続き認証される」ことを警告する", async () => {
    const maruhi = await start([onRequest("POST", "/auth/token/revoke", () => ({ status: 204 }))]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: "user-0001", tokenId: "tok_1" }),
    );
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    expect(await runCli(["logout"], env.layer)).toBe(0);
    expect(env.keychain.size).toBe(0);
    expect(env.logs.join("\n")).toContain("MARUHI_TOKEN が設定されているため");
  });

  it("トークン未保存はエラーメッセージで案内する", async () => {
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    expect(await runCli(["logout"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("キーチェーンにありません");
  });
});
