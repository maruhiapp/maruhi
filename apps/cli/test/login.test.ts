// login(GitHub device flow → /auth/device/exchange → キーチェーン)と
// logout(自トークン失効 + キーチェーン削除)のテスト。
// GitHub・maruhi サーバーともローカル HTTP モック(実 device-flow 実装を検証)。

import { afterEach, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { masterKeyEntryName, tokenEntryName } from "../src/keychain.ts";
import { makeTestEnv, seedConfig } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let servers: MockServer[] = [];

/** 交換応答の有効期限フィクスチャ(AUTH_SPEC §6 — W3a: 2099-01-01T00:00:00Z)。 */
const EXPIRES_AT_MS = Date.UTC(2099, 0, 1);

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
  it("長すぎる --token-name は device flow より前に落とす(ブラウザ承認を無駄にしない)", async () => {
    // 上限(api-schema の MAX_TOKEN_NAME_LENGTH)を引数層で見ないと、長すぎる
    // 名前は **ブラウザでの承認を完走した後**にリクエストの encode 失敗として
    // 現れる。しかも Schema のエラーは応答側と同じ型なので、診断が
    // 「サーバー側の異常」に見えてしまう(--github-base-url と同じ規律)
    const github = fakeGitHub({ pendingPolls: 0, accessToken: "gho_github_token_value" });
    const githubServer = await start(github.handlers);
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.testclient" });

    const code = await runCli(
      [
        "login",
        "--token-name",
        "n".repeat(129),
        "--github-base-url",
        githubServer.origin,
        "--github-poll-interval",
        "0",
      ],
      env.layer,
    );
    // 書き方の誤りは usage エラー(2)
    expect(code).toBe(2);
    expect(env.errors.join("\n")).toContain("--token-name must be at most 128 characters");
    // device flow は開始すらしない(ブラウザ承認を求めない)
    expect(github.polls()).toBe(0);
    expect(env.logs.join("\n")).not.toContain("Waiting for approval");
    expect(maruhi.requests).toHaveLength(0);
  });

  it("client_id が config に無くても、長すぎる --token-name は /auth/config より前に落とす", async () => {
    // client_id がフラグにも config にも無いと resolveClientId は
    // `/auth/config` を引く。検査がそれより後ろだと (a) 無駄な往復が先に起き、
    // (b) その取得が失敗したとき書き方の誤りが「接続に失敗しました」に化ける。
    // 検査は**どの通信よりも前**であることをこのケースで固定する
    const github = fakeGitHub({ pendingPolls: 0, accessToken: "gho_github_token_value" });
    const githubServer = await start(github.handlers);
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    const code = await runCli(
      [
        "login",
        "--token-name",
        "n".repeat(129),
        "--github-base-url",
        githubServer.origin,
        "--github-poll-interval",
        "0",
      ],
      env.layer,
    );
    expect(code).toBe(2);
    expect(env.errors.join("\n")).toContain("--token-name must be at most 128 characters");
    // /auth/config も device flow も起こさない
    expect(maruhi.requests).toHaveLength(0);
    expect(github.polls()).toBe(0);
  });

  it("範囲外の --token-ttl-days はどの通信よりも前に落とす(AUTH_SPEC §6 — W3a)", async () => {
    // 上限は api-schema の MAX_TOKEN_TTL_DAYS と共有(--token-name と同じ規律:
    // 書き方の誤りをブラウザ承認の完走後に出さない)
    const github = fakeGitHub({ pendingPolls: 0, accessToken: "gho_github_token_value" });
    const githubServer = await start(github.handlers);
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.testclient" });

    for (const value of ["0", "366"]) {
      const code = await runCli(
        [
          "login",
          "--token-ttl-days",
          value,
          "--github-base-url",
          githubServer.origin,
          "--github-poll-interval",
          "0",
        ],
        env.layer,
      );
      expect(code).toBe(2);
    }
    expect(env.errors.join("\n")).toContain("--token-ttl-days must be between 1 and 365");
    expect(github.polls()).toBe(0);
    expect(maruhi.requests).toHaveLength(0);
  });

  it("--token-ttl-days は expiresInDays として交換 payload に載り、省略時は載らない", async () => {
    const github = fakeGitHub({ pendingPolls: 0, accessToken: "gho_github_token_value" });
    const githubServer = await start(github.handlers);
    const bodies: Record<string, unknown>[] = [];
    const maruhi = await start([
      onRequest("POST", "/auth/device/exchange", (request) => {
        bodies.push(request.body as Record<string, unknown>);
        return {
          status: 200,
          json: {
            token: "maruhi_pat_issued",
            tokenId: "tok_1",
            userId: "user-0001",
            expiresAtMs: EXPIRES_AT_MS,
          },
        };
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.testclient" });

    const flags = ["--github-base-url", githubServer.origin, "--github-poll-interval", "0"];
    expect(await runCli(["login", "--token-ttl-days", "365", ...flags], env.layer)).toBe(0);
    expect(await runCli(["login", ...flags], env.layer)).toBe(0);
    expect(bodies[0]?.["expiresInDays"]).toBe(365);
    // 省略時はサーバー既定(90 日)に委ねる — キー自体を送らない
    expect(Object.hasOwn(bodies[1] ?? {}, "expiresInDays")).toBe(false);
    // 有効期限は発行時に固定され、いつ再ログインが要るかを表示する
    expect(env.logs.join("\n")).toContain("The token expires on 2099-01-01 (UTC)");
  });

  it("expiresAtMs を返さない旧サーバーでもログインは成功し、期限未申告を注記する(PR #108 pullfrog 指摘)", async () => {
    // maruhi login は fail-closed な期限切れからの唯一の回復コマンド —
    // W3a より古いサーバー相手に応答 decode で落とすと、発行済みトークンを
    // サーバー側に孤児化させたまま復旧手段がなくなる
    const github = fakeGitHub({ pendingPolls: 0, accessToken: "gho_github_token_value" });
    const githubServer = await start(github.handlers);
    const maruhi = await start([
      onRequest("POST", "/auth/device/exchange", () => ({
        status: 200,
        json: { token: "maruhi_pat_issued", tokenId: "tok_1", userId: "user-0001" },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.testclient" });

    const code = await runCli(
      ["login", "--github-base-url", githubServer.origin, "--github-poll-interval", "0"],
      env.layer,
    );
    expect(code).toBe(0);
    expect(env.keychain.get(tokenEntryName(maruhi.origin))).toBeDefined();
    const logs = env.logs.join("\n");
    expect(logs).not.toContain("The token expires on");
    expect(logs).toContain("did not report a token expiry");
  });

  it("範囲外の expiresAtMs でもクラッシュせず明示劣化する(display.ts の total 表示)", async () => {
    // ワイヤの expiresAtMs は無制限 number — Date 範囲(±8.64e15)外を
    // toISOString へ渡すと RangeError の defect になる(deepsec B1/B4/B5 の
    // display.ts 規律。PR #108 pullfrog 指摘の変異検証)
    const github = fakeGitHub({ pendingPolls: 0, accessToken: "gho_github_token_value" });
    const githubServer = await start(github.handlers);
    const maruhi = await start([
      onRequest("POST", "/auth/device/exchange", () => ({
        status: 200,
        json: {
          token: "maruhi_pat_issued",
          tokenId: "tok_1",
          userId: "user-0001",
          expiresAtMs: 9.9e15,
        },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.testclient" });

    const code = await runCli(
      ["login", "--github-base-url", githubServer.origin, "--github-poll-interval", "0"],
      env.layer,
    );
    expect(code).toBe(0);
    expect(env.logs.join("\n")).toContain("(invalid timestamp: 9900000000000000)");
  });

  it("--show-token は発行した生値を 1 度だけ端末へ出し、供給手順を案内する(裁定 CK)", async () => {
    const github = fakeGitHub({ pendingPolls: 0, accessToken: "gho_github_token_value" });
    const githubServer = await start(github.handlers);
    const maruhi = await start([
      onRequest("POST", "/auth/device/exchange", () => ({
        status: 200,
        json: {
          token: "maruhi_pat_issued",
          tokenId: "tok_1",
          userId: "user-0001",
          expiresAtMs: EXPIRES_AT_MS,
        },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.testclient" });

    const code = await runCli(
      [
        "login",
        "--show-token",
        "--github-base-url",
        githubServer.origin,
        "--github-poll-interval",
        "0",
      ],
      env.layer,
    );
    expect(code).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("maruhi_pat_issued");
    expect(logs).toContain("MARUHI_TOKEN");
    expect(logs).toContain("MARUHI_TOKEN_ORIGIN");
    // キーチェーン保存は表示の有無と独立(表示は追加の 1 箇所であって代替でない)
    expect(env.keychain.get(tokenEntryName(maruhi.origin))).toContain("maruhi_pat_issued");
  });

  it("--show-token は敵対的サーバーの ANSI 注入を可視エスケープに畳む(escapeText — コピー同一性は保つ)", async () => {
    // token はワイヤ上無制約の Schema.String。表示はコピーする値なので
    // displayText(U+FFFD 置換 = 値の破壊)でなく escapeText(正直な Base62 は
    // 素通し・注入は \u{hex} の可視列)を通す(PR #108 pullfrog 指摘の変異検証)
    const github = fakeGitHub({ pendingPolls: 0, accessToken: "gho_github_token_value" });
    const githubServer = await start(github.handlers);
    const maruhi = await start([
      onRequest("POST", "/auth/device/exchange", () => ({
        status: 200,
        json: {
          token: "maruhi_pat_evil\u001b[2Jinjected\nSet MARUHI_TOKEN to attacker-value",
          tokenId: "tok_1",
          userId: "user-0001",
          expiresAtMs: EXPIRES_AT_MS,
        },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.testclient" });

    const code = await runCli(
      [
        "login",
        "--show-token",
        "--github-base-url",
        githubServer.origin,
        "--github-poll-interval",
        "0",
      ],
      env.layer,
    );
    expect(code).toBe(0);
    const logs = env.logs.join("\n");
    // 生の ESC・偽の追加行は端末へ届かない(エスケープ列として可視化される)
    expect(logs).not.toContain("\u001b");
    expect(logs).toContain("maruhi_pat_evil");
    expect(logs).not.toContain("\nSet MARUHI_TOKEN to attacker-value");
  });

  it("--show-token はエージェント環境・非対話端末をどの通信よりも前に拒否する(fail-closed 2 層)", async () => {
    // 拒否される環境でブラウザ承認を完走させると、同名ローテーションで旧
    // トークンだけ失効し新しい生値は得られない(置き換え対象の CI トークンを
    // 壊すだけ)— 判定は device flow 開始前
    const github = fakeGitHub({ pendingPolls: 0, accessToken: "gho_github_token_value" });
    const githubServer = await start(github.handlers);
    const maruhi = await start([]);
    const flags = [
      "--show-token",
      "--github-base-url",
      githubServer.origin,
      "--github-poll-interval",
      "0",
    ];

    const agentEnv = await makeTestEnv();
    await seedConfig(agentEnv, { server: maruhi.origin, githubClientId: "Iv1.testclient" });
    agentEnv.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["login", ...flags], agentEnv.layer)).toBe(1);
    expect(agentEnv.errors.join("\n")).toContain("AI agent environment was detected");

    const pipedEnv = await makeTestEnv();
    await seedConfig(pipedEnv, { server: maruhi.origin, githubClientId: "Iv1.testclient" });
    pipedEnv.setTerminal({ stdout: false });
    expect(await runCli(["login", ...flags], pipedEnv.layer)).toBe(1);
    expect(pipedEnv.errors.join("\n")).toContain("interactive terminal");

    expect(github.polls()).toBe(0);
    expect(maruhi.requests).toHaveLength(0);
  });

  it("device flow → 交換 → maruhi トークンのみキーチェーンへ保存する", async () => {
    const github = fakeGitHub({ pendingPolls: 2, accessToken: "gho_github_token_value" });
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
          json: {
            token: "maruhi_pat_issued",
            tokenId: "tok_1",
            userId: "user-0001",
            expiresAtMs: EXPIRES_AT_MS,
          },
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
    expect(receivedGithubToken).toBe("gho_github_token_value");
    expect(receivedTokenName).toBe("cli-test");
    const stored = env.keychain.get(tokenEntryName(maruhi.origin));
    expect(stored).toBeDefined();
    expect(JSON.parse(stored ?? "{}")).toEqual({
      token: "maruhi_pat_issued",
      userId: "user-0001",
      tokenId: "tok_1",
      // 期限接近警告(裁定 CL)のローカル判定材料もレコードへ載る
      expiresAtMs: EXPIRES_AT_MS,
    });
    expect(stored).not.toContain("gho_github_token_value");
    // トークン生値は端末出力にも出ない
    expect(env.logs.join("\n")).not.toContain("maruhi_pat_issued");
  });

  it("ログイン後、鍵なし + リカバリー登録済みなら `key recover` を案内する", async () => {
    const github = fakeGitHub({ pendingPolls: 0, accessToken: "gho_x" });
    const githubServer = await start(github.handlers);
    const maruhi = await start([
      onRequest("POST", "/auth/device/exchange", () => ({
        status: 200,
        json: {
          token: "maruhi_pat_issued",
          tokenId: "tok_1",
          userId: "user-0001",
          expiresAtMs: EXPIRES_AT_MS,
        },
      })),
      onRequest("GET", "/auth/recovery/status", () => ({
        status: 200,
        json: { registered: true, updatedAtMs: 1754006400000 },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.testclient" });
    const code = await runCli(
      ["login", "--github-base-url", githubServer.origin, "--github-poll-interval", "0"],
      env.layer,
    );
    expect(code).toBe(0);
    expect(env.logs.join("\n")).toContain("`maruhi key recover`");
  });

  it("ログイン後、鍵あり + リカバリー未登録なら発行を促す(保管リマインダ)", async () => {
    const github = fakeGitHub({ pendingPolls: 0, accessToken: "gho_x" });
    const githubServer = await start(github.handlers);
    const maruhi = await start([
      onRequest("POST", "/auth/device/exchange", () => ({
        status: 200,
        json: {
          token: "maruhi_pat_issued",
          tokenId: "tok_1",
          userId: "user-0001",
          expiresAtMs: EXPIRES_AT_MS,
        },
      })),
      onRequest("GET", "/auth/recovery/status", () => ({
        status: 200,
        json: { registered: false, updatedAtMs: null },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.testclient" });
    // 事前にこの (origin, user) の master 鍵レコードを置いておく
    env.keychain.set(
      masterKeyEntryName(maruhi.origin, "user-0001"),
      JSON.stringify({
        suite: "maruhi/v1",
        encPubHex: "00".repeat(32),
        encSkHex: "00".repeat(32),
        sigPubHex: "00".repeat(32),
        sigSkSeedHex: "00".repeat(32),
      }),
    );
    const code = await runCli(
      ["login", "--github-base-url", githubServer.origin, "--github-poll-interval", "0"],
      env.layer,
    );
    expect(code).toBe(0);
    expect(env.errors.join("\n")).toContain("issue one with `maruhi key recovery`");
  });

  it("ログイン後の案内は状態確認に失敗してもログインを失敗させず、スキップを明示する", async () => {
    const github = fakeGitHub({ pendingPolls: 0, accessToken: "gho_x" });
    const githubServer = await start(github.handlers);
    // recovery/status ハンドラなし = 状態確認が失敗する状況
    const maruhi = await start([
      onRequest("POST", "/auth/device/exchange", () => ({
        status: 200,
        json: {
          token: "maruhi_pat_issued",
          tokenId: "tok_1",
          userId: "user-0001",
          expiresAtMs: EXPIRES_AT_MS,
        },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.testclient" });
    const code = await runCli(
      ["login", "--github-base-url", githubServer.origin, "--github-poll-interval", "0"],
      env.layer,
    );
    expect(code).toBe(0);
    // 無言のスキップにしない(CLAUDE.md: catch で無言に飲まない)
    expect(env.errors.join("\n")).toContain("skipped the next-step hint");
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
    expect(env.errors.join("\n")).toContain("authorization was denied");
    expect(env.keychain.size).toBe(0);
  });

  it("キーチェーン保存に失敗したら発行済みトークンを失効させてから失敗する(孤児化防止)", async () => {
    const github = fakeGitHub({ pendingPolls: 0, accessToken: "gho_x" });
    const githubServer = await start(github.handlers);
    let revoked = 0;
    const maruhi = await start([
      onRequest("POST", "/auth/device/exchange", () => ({
        status: 200,
        json: {
          token: "maruhi_pat_issued",
          tokenId: "tok_1",
          userId: "user-0001",
          expiresAtMs: EXPIRES_AT_MS,
        },
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
        json: {
          token: "maruhi_pat_issued",
          tokenId: "tok_1",
          userId: "user-0001",
          expiresAtMs: EXPIRES_AT_MS,
        },
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
    expect(errors).toContain("revoking the issued token also failed");
    expect(errors).not.toContain("has been revoked on the server");
    // 同名再ログインによるローテーション失効の案内がある
    expect(errors).toContain("cli-test");
  });

  it("--github-base-url の非 loopback http は拒否する(平文経路の遮断)", async () => {
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.testclient" });
    // 書き方の誤りは usage エラー(2)。URL そのものは返さない
    // (`http://user:token@host` の形で認証情報が書かれうる)
    expect(await runCli(["login", "--github-base-url", "http://evil.example"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("loopback");
    expect(env.errors.join("\n")).not.toContain("evil.example");
  });

  it("--github-base-url の形式検査は通信より前に走る(接続失敗として報告しない)", async () => {
    // client_id を config に置かない = 通信で取りに行く経路。形式の検査を
    // 後ろに置くと、書き方の誤りが「Failed to connect to the server」になる
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    expect(await runCli(["login", "--github-base-url", "ftp://x.example"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("must be http(s)");
    expect(env.errors.join("\n")).not.toContain("Failed to connect");
  });

  it("config の server が不正な場合は、直す先を示して 1 で落ちる", async () => {
    // コマンドラインに何も書いていないので「書き方の誤り(2)」ではない
    const env = await makeTestEnv();
    await seedConfig(env, { server: "ftp://bad.example" });
    expect(await runCli(["logout"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("fix server in your config");
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
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", maruhi.origin);
    expect(await runCli(["logout"], env.layer)).toBe(0);
    expect(env.keychain.size).toBe(0);
    expect(env.logs.join("\n")).toContain("MARUHI_TOKEN is set");
  });

  it("MARUHI_TOKEN が伏字・MARUHI_TOKEN_ORIGIN 未設定なら原因ごとに案内する", async () => {
    // どちらも次のコマンドが失敗する状態だが、直し方が違う(貼り直す / 足す)
    for (const [token, origin, expected] of [
      ["<redacted:maruhi-token>", "https://x.example", "redaction placeholder"],
      ["maruhi_pat_env", undefined, "MARUHI_TOKEN_ORIGIN is not set"],
      // 形が使えない理由は解決側の文言をそのまま出す(言い換えない)
      ["maruhi_pat_env", "not-a-url", "Cannot parse"],
      ["maruhi_pat_env", "http://remote.example", "loopback"],
    ] as const) {
      const maruhi = await start([
        onRequest("POST", "/auth/token/revoke", () => ({ status: 204 })),
      ]);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });
      env.keychain.set(
        tokenEntryName(maruhi.origin),
        JSON.stringify({ token: "maruhi_pat_stored", userId: "user-0001", tokenId: "tok_1" }),
      );
      env.setEnvVar("MARUHI_TOKEN", token);
      if (origin !== undefined) {
        env.setEnvVar("MARUHI_TOKEN_ORIGIN", origin);
      }
      expect(await runCli(["logout"], env.layer)).toBe(0);
      const logs = env.logs.join("\n");
      expect(logs).toContain(expected);
      expect(logs).not.toContain("stays authenticated with that token");
    }
  });

  it("MARUHI_TOKEN_ORIGIN が一致しない場合は「使われない」と案内する", async () => {
    // resolveSession は origin 束縛を要求し、一致しなければ**キーチェーンへ
    // 落ちずに失敗する**。ここで「引き続き認証されます」と言うと、次の
    // コマンドが失敗する理由と食い違う
    const maruhi = await start([onRequest("POST", "/auth/token/revoke", () => ({ status: 204 }))]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: "user-0001", tokenId: "tok_1" }),
    );
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", "https://other.example");
    expect(await runCli(["logout"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("not used for authentication");
    expect(logs).not.toContain("stays authenticated with that token");
  });

  it("空白だけの MARUHI_TOKEN では警告しない(セッション解決と同じ判定)", async () => {
    // resolveSession は trim 後に空なら未設定として扱う。ここだけ生値で見ると
    // 「引き続き認証されます」と言った直後に「Not logged in」で落ちる
    const maruhi = await start([onRequest("POST", "/auth/token/revoke", () => ({ status: 204 }))]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: "user-0001", tokenId: "tok_1" }),
    );
    env.setEnvVar("MARUHI_TOKEN", " \n");
    expect(await runCli(["logout"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).not.toContain("MARUHI_TOKEN is set");
  });

  it("トークン未保存はエラーメッセージで案内する", async () => {
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    expect(await runCli(["logout"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("No token for this server in the keychain");
  });
});

describe("client_id の自動解決(AUTH_SPEC §4 = GET /auth/config)", () => {
  it("config に githubClientId がなければサーバーから自動解決してログインする", async () => {
    const github = fakeGitHub({ pendingPolls: 0, accessToken: "gho_x" });
    const githubServer = await start(github.handlers);
    let configCalls = 0;
    const maruhi = await start([
      onRequest("GET", "/auth/config", () => {
        configCalls += 1;
        return { status: 200, json: { githubClientId: "Iv1.fromserver" } };
      }),
      onRequest("POST", "/auth/device/exchange", () => ({
        status: 200,
        json: {
          token: "maruhi_pat_issued",
          tokenId: "tok_1",
          userId: "user-0001",
          expiresAtMs: EXPIRES_AT_MS,
        },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    const code = await runCli(
      ["login", "--github-base-url", githubServer.origin, "--github-poll-interval", "0"],
      env.layer,
    );
    expect(code).toBe(0);
    expect(configCalls).toBe(1);
    expect(env.keychain.get(tokenEntryName(maruhi.origin))).toBeDefined();
  });

  it("config の githubClientId があればサーバーへ問い合わせない(上書き手段 — 裁定 (iii))", async () => {
    const github = fakeGitHub({ pendingPolls: 0, accessToken: "gho_x" });
    const githubServer = await start(github.handlers);
    let configCalls = 0;
    const maruhi = await start([
      onRequest("GET", "/auth/config", () => {
        configCalls += 1;
        return { status: 200, json: { githubClientId: "Iv1.fromserver" } };
      }),
      onRequest("POST", "/auth/device/exchange", () => ({
        status: 200,
        json: {
          token: "maruhi_pat_issued",
          tokenId: "tok_1",
          userId: "user-0001",
          expiresAtMs: EXPIRES_AT_MS,
        },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.configured" });

    const code = await runCli(
      ["login", "--github-base-url", githubServer.origin, "--github-poll-interval", "0"],
      env.layer,
    );
    expect(code).toBe(0);
    expect(configCalls).toBe(0);
  });

  it("未設定サーバー(503 SetupIncomplete)はセットアップガイドを案内して失敗する", async () => {
    const maruhi = await start([
      onRequest("GET", "/auth/config", () => ({
        status: 503,
        json: { _tag: "SetupIncomplete", reason: "github-oauth-unconfigured" },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    const code = await runCli(["login"], env.layer);
    expect(code).toBe(1);
    expect(env.errors.join("\n")).toContain("self-hosting setup is incomplete");
    expect(env.errors.join("\n")).toContain("SELF_HOSTING");
  });

  it("自動取得に失敗したら手動設定(config set githubClientId)の逃げ道を案内する", async () => {
    // /auth/config を持たない旧サーバー相当(404)
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    const code = await runCli(["login"], env.layer);
    expect(code).toBe(1);
    expect(env.errors.join("\n")).toContain("maruhi config set githubClientId");
  });
});
