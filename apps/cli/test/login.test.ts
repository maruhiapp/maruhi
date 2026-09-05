// login(サーバー仲介 web-flow ハンドオフ — AUTH_SPEC §4: start → ブラウザ承認
// → poll → キーチェーン)と logout(自トークン失効 + キーチェーン削除)のテスト。
// maruhi サーバーはローカル HTTP モック。CLI はアイデンティティプロバイダと
// 直接通信しない(§4 の原則)ので、GitHub 側のモックは存在しない。

import { afterEach, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { masterKeyEntryName, tokenEntryName } from "../src/keychain.ts";
import { makeTestEnv, seedConfig } from "./support/env.ts";
import {
  type MockHandler,
  type MockRequest,
  type MockResponse,
  MockServer,
  onRequest,
} from "./support/server.ts";

let servers: MockServer[] = [];

/** 交換応答の有効期限フィクスチャ(AUTH_SPEC §6 — W3a: 2099-01-01T00:00:00Z)。 */
const EXPIRES_AT_MS = Date.UTC(2099, 0, 1);

/** 公開相関子(128-bit hex — api-schema の CliFlowIdSchema に一致)。 */
const FLOW_ID = "0123456789abcdef0123456789abcdef";

/** CLI 専用 bearer 資格情報のフィクスチャ(§4-1 (1) — CLI には不透明)。 */
const FLOW_TOKEN = "v1.dGVzdC1mbG93.fixture-mac-value";

const USER_CODE = "ABCD-1234";
const VERIFICATION_URL = `https://maruhi.example/auth/cli/verify?flow=${FLOW_ID}&vsig=feedface`;

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function start(handlers: readonly MockHandler[]): Promise<MockServer> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  return server;
}

/** poll の approved 応答(§4-1 (5) — 生値 token はこの一度だけワイヤに現れる)。 */
function approvedResponse(input?: {
  readonly token?: string;
  readonly expiresAtMs?: number;
}): MockResponse {
  return {
    status: 200,
    json: {
      status: "approved",
      token: input?.token ?? "maruhi_pat_issued",
      tokenId: "tok_1",
      userId: "user-0001",
      expiresAtMs: input?.expiresAtMs ?? EXPIRES_AT_MS,
    },
  };
}

/**
 * ハンドオフの maruhi 側(start + ポーリング n 回 pending → 最終応答)。
 * start 応答の pollIntervalSeconds は 0(テストは `--poll-interval 0` で下限も
 * 0 に落とし、実時間の sleep をしない)。
 */
function fakeHandoff(
  input: {
    readonly pendingPolls?: number;
    /** 最終 poll 応答(既定: approved)。 */
    readonly finalPoll?: MockResponse;
    /** start 応答の上書き(期限・間隔の境界ケース用)。 */
    readonly startOverrides?: Readonly<Record<string, unknown>>;
    readonly token?: string;
    readonly expiresAtMs?: number;
  } = {},
): {
  handlers: MockHandler[];
  polls: () => number;
  startBodies: Record<string, unknown>[];
  pollBodies: Record<string, unknown>[];
} {
  const startBodies: Record<string, unknown>[] = [];
  const pollBodies: Record<string, unknown>[] = [];
  let polls = 0;
  const pendingPolls = input.pendingPolls ?? 0;
  const handlers: MockHandler[] = [
    onRequest("POST", "/auth/cli/start", (request: MockRequest) => {
      startBodies.push(request.body as Record<string, unknown>);
      return {
        status: 200,
        json: {
          flowId: FLOW_ID,
          flowToken: FLOW_TOKEN,
          userCode: USER_CODE,
          verificationUrl: VERIFICATION_URL,
          expiresInSeconds: 900,
          pollIntervalSeconds: 0,
          ...input.startOverrides,
        },
      };
    }),
    onRequest("POST", "/auth/cli/poll", (request: MockRequest) => {
      pollBodies.push(request.body as Record<string, unknown>);
      polls += 1;
      if (polls <= pendingPolls) {
        return { status: 200, json: { status: "pending" } };
      }
      return (
        input.finalPoll ??
        approvedResponse({
          ...(input.token === undefined ? {} : { token: input.token }),
          ...(input.expiresAtMs === undefined ? {} : { expiresAtMs: input.expiresAtMs }),
        })
      );
    }),
  ];
  return { handlers, polls: () => polls, startBodies, pollBodies };
}

/** 全テスト共通のフラグ(実時間の sleep をしない)。 */
const FAST_POLL = ["--poll-interval", "0"] as const;

describe("maruhi login", () => {
  it("長すぎる --token-name はどの通信よりも前に落とす(ブラウザ承認を無駄にしない)", async () => {
    // 上限(api-schema の MAX_TOKEN_NAME_LENGTH)を引数層で見ないと、長すぎる
    // 名前は **ブラウザでの承認を完走した後**にリクエストの encode 失敗として
    // 現れる。しかも Schema のエラーは応答側と同じ型なので、診断が
    // 「サーバー側の異常」に見えてしまう
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    const code = await runCli(["login", "--token-name", "n".repeat(129), ...FAST_POLL], env.layer);
    // 書き方の誤りは usage エラー(2)
    expect(code).toBe(2);
    expect(env.errors.join("\n")).toContain("--token-name must be at most 128 characters");
    // start すら呼ばない(ブラウザ承認を求めない)
    expect(maruhi.requests).toHaveLength(0);
    expect(env.errors.join("\n")).not.toContain("Waiting for approval");
  });

  it("範囲外の --token-ttl-days はどの通信よりも前に落とす(AUTH_SPEC §6 — W3a)", async () => {
    // 上限は api-schema の MAX_TOKEN_TTL_DAYS と共有(--token-name と同じ規律:
    // 書き方の誤りをブラウザ承認の完走後に出さない)
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    for (const value of ["0", "366"]) {
      const code = await runCli(["login", "--token-ttl-days", value, ...FAST_POLL], env.layer);
      expect(code).toBe(2);
    }
    expect(env.errors.join("\n")).toContain("--token-ttl-days must be between 1 and 365");
    expect(maruhi.requests).toHaveLength(0);
  });

  it("--token-ttl-days は expiresInDays として start payload に載り、省略時は載らない", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", "--token-ttl-days", "365", ...FAST_POLL], env.layer)).toBe(0);
    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    expect(handoff.startBodies[0]?.["expiresInDays"]).toBe(365);
    // 省略時はサーバー既定(90 日)に委ねる — キー自体を送らない
    expect(Object.hasOwn(handoff.startBodies[1] ?? {}, "expiresInDays")).toBe(false);
    // 有効期限は発行時に固定され、いつ再ログインが要るかを表示する
    expect(env.logs.join("\n")).toContain("The token expires on 2099-01-01 (UTC)");
  });

  it("start → 承認待ち → poll → maruhi トークンのみキーチェーンへ保存する", async () => {
    const handoff = fakeHandoff({ pendingPolls: 2 });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    const code = await runCli(["login", "--token-name", "cli-test", ...FAST_POLL], env.layer);
    expect(code).toBe(0);
    expect(handoff.polls()).toBe(3);
    // 発行パラメータは start に載る(§4-1 (1) — 発行時ではなく開始時に確定)
    expect(handoff.startBodies[0]?.["tokenName"]).toBe("cli-test");
    // poll はフロー資格の 2 識別子のみを運ぶ(§4-1 (5))
    expect(handoff.pollBodies[0]).toEqual({ flowId: FLOW_ID, flowToken: FLOW_TOKEN });
    const logs = env.logs.join("\n");
    // 検証 URL とユーザーコードは対話の案内(stderr — 裁定 D-2)に出る
    // (フィッシング照合の材料 — §4-1 (2))。有効期間はサーバー応答から導く
    const guidance = env.errors.join("\n");
    expect(guidance).toContain(VERIFICATION_URL);
    expect(guidance).toContain(`Confirmation code: ${USER_CODE}`);
    expect(guidance).toContain("This request expires in 15 minutes");
    expect(guidance).toContain("Waiting for approval");
    // 結果(stdout)は成功の 1 行 + 期限
    expect(logs).toContain("Signed in as user-0001");
    // flowToken は資格情報 — ブラウザチャネルにも端末出力にも出ない(§4-1 (1))
    expect(logs).not.toContain(FLOW_TOKEN);
    expect(env.errors.join("\n")).not.toContain(FLOW_TOKEN);
    const stored = env.keychain.get(tokenEntryName(maruhi.origin));
    expect(stored).toBeDefined();
    expect(JSON.parse(stored ?? "{}")).toEqual({
      token: "maruhi_pat_issued",
      userId: "user-0001",
      tokenId: "tok_1",
      // 期限接近警告(裁定 CL)のローカル判定材料もレコードへ載る
      expiresAtMs: EXPIRES_AT_MS,
    });
    expect(stored).not.toContain(FLOW_TOKEN);
    // トークン生値は端末出力に出ない(--show-token なし)
    expect(logs).not.toContain("maruhi_pat_issued");
  });

  describe("signupPolicy の事前 fail-fast(AUTH_SPEC §3 / hosted-design §2-2 (i)(ii))", () => {
    /** /auth/config が signupPolicy を申告するハンドオフ一式。 */
    function handoffWithConfig(config: Record<string, unknown>): {
      handlers: MockHandler[];
      polls: () => number;
    } {
      const handoff = fakeHandoff();
      return {
        handlers: [
          onRequest("GET", "/auth/config", () => ({
            status: 200,
            json: { githubClientId: "dummy", ...config },
          })),
          ...handoff.handlers,
        ],
        polls: handoff.polls,
      };
    }

    it("invite 制: 対話端末では既存アカウント保持を確認し、yes なら進む", async () => {
      const handoff = handoffWithConfig({ signupPolicy: "invite" });
      const maruhi = await start(handoff.handlers);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });
      env.setPromptResponses(["y"]);

      expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
      expect(env.prompts.join("\n")).toContain("Do you already have a maruhi account");
      expect(env.errors.join("\n")).toContain("invite-only");
      // 確認を通過したら通常どおり start → poll へ進む
      expect(handoff.polls()).toBeGreaterThan(0);
    });

    it("invite 制: no(既定)なら start を呼ぶ前に案内を出して終了する", async () => {
      const handoff = handoffWithConfig({ signupPolicy: "invite" });
      const maruhi = await start(handoff.handlers);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });
      env.setPromptResponses([""]);

      expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
      // 誤操作ガード(認可ではない): 無駄なブラウザ往復を始めない
      expect(maruhi.requests.map((request) => request.path)).toEqual(["/auth/config"]);
      const output = [...env.logs, ...env.errors].join("\n");
      expect(output).toContain("sign up in your browser first");
      expect(output).toContain("Sign up in the browser first, then run `maruhi login` again");
      expect(env.keychain.size).toBe(0);
    });

    it("closed: 対話端末では確認を挟み、no なら終了する", async () => {
      const handoff = handoffWithConfig({ signupPolicy: "closed" });
      const maruhi = await start(handoff.handlers);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });
      env.setPromptResponses(["n"]);

      expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain("not accepting new sign-ups");
      expect(maruhi.requests.map((request) => request.path)).toEqual(["/auth/config"]);
    });

    it("非対話環境(エージェント・パイプ)では案内だけ出して進む(プロンプトで吊るさない)", async () => {
      for (const shape of ["agent", "piped"] as const) {
        const handoff = handoffWithConfig({ signupPolicy: "invite" });
        const maruhi = await start(handoff.handlers);
        const env = await makeTestEnv();
        await seedConfig(env, { server: maruhi.origin });
        if (shape === "agent") {
          env.setAgent({ isAgent: true, name: "test-agent" });
        } else {
          env.setTerminal({ stdin: false });
        }
        expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
        expect(env.prompts).toHaveLength(0);
        expect(env.errors.join("\n")).toContain("invite-only");
        expect(env.keychain.get(tokenEntryName(maruhi.origin))).toBeDefined();
      }
    });

    it("open では確認も案内も挟まない", async () => {
      const handoff = handoffWithConfig({ signupPolicy: "open" });
      const maruhi = await start(handoff.handlers);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });

      expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
      expect(env.prompts).toHaveLength(0);
      expect(env.errors.join("\n")).not.toContain("invite-only");
    });

    it("signupPolicy 未申告(旧サーバー)・/auth/config 不在でも従来どおり進む(advisory の欠落で login を壊さない)", async () => {
      // 未申告: フィールドなしの 200
      const withoutField = handoffWithConfig({});
      const oldServer = await start(withoutField.handlers);
      const env1 = await makeTestEnv();
      await seedConfig(env1, { server: oldServer.origin });
      expect(await runCli(["login", ...FAST_POLL], env1.layer)).toBe(0);
      expect(env1.prompts).toHaveLength(0);
      // 不在: /auth/config ハンドラなし(404)— fakeHandoff 素のまま
      const bare = fakeHandoff();
      const bareServer = await start(bare.handlers);
      const env2 = await makeTestEnv();
      await seedConfig(env2, { server: bareServer.origin });
      expect(await runCli(["login", ...FAST_POLL], env2.layer)).toBe(0);
      expect(env2.prompts).toHaveLength(0);
    });
  });

  it("対話端末 × 非エージェントではブラウザ自動起動を試みる(§4-1 (2) の UX 分岐)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    // 既定の TestEnv = 対話端末 × 非エージェント

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    expect(env.browserOpens).toEqual([VERIFICATION_URL]);
    expect(env.errors.join("\n")).toContain("Opened your browser");
  });

  it("エージェント環境・非対話端末ではブラウザを開かないが、表示 + ポーリングで完走する", async () => {
    // 縮退経路は 1 本(表示 + ポーリング)で全環境を覆う — 新しいセキュリティ
    // ゲートではないので、非対象環境でもログインは成功する
    for (const shape of ["agent", "piped"] as const) {
      const handoff = fakeHandoff();
      const maruhi = await start(handoff.handlers);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });
      if (shape === "agent") {
        env.setAgent({ isAgent: true, name: "test-agent" });
      } else {
        env.setTerminal({ stdout: false });
      }
      expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
      expect(env.browserOpens).toHaveLength(0);
      const guidance = env.errors.join("\n");
      expect(guidance).toContain(VERIFICATION_URL);
      expect(guidance).toContain(USER_CODE);
      // 自動起動を試みていないので「開けなかった」とも言わない
      expect(guidance).not.toContain("Could not open a browser");
      expect(env.keychain.get(tokenEntryName(maruhi.origin))).toBeDefined();
    }
  });

  it("ブラウザ起動に失敗しても完走する(起動は best-effort)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.setBrowserOpenSucceeds(false);

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    expect(env.browserOpens).toEqual([VERIFICATION_URL]);
    // 失敗した起動を「開いた」と主張しない(URL の手動オープン案内は常に出ている)
    expect(env.errors.join("\n")).not.toContain("Opened your browser");
    expect(env.errors.join("\n")).toContain("Could not open a browser automatically");
  });

  it("http(s) 以外・パース不能な verificationUrl は OS opener に渡さない(fail-closed)", async () => {
    // OS の URL ハンドラは任意スキームをディスパッチする。verificationUrl は
    // サーバー応答由来の untrusted 入力なので、opener に渡す前に検証し、不合格は
    // ブラウザ自動起動をスキップして手動オープン案内(表示)+ ポーリングで完走する
    for (const url of ["file:///etc/passwd", "javascript:alert(1)", "not a url"]) {
      const handoff = fakeHandoff({ startOverrides: { verificationUrl: url } });
      const maruhi = await start(handoff.handlers);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });
      // 既定の TestEnv = 対話端末 × 非エージェント(自動起動の対象環境)
      expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
      expect(env.browserOpens).toHaveLength(0);
      expect(env.keychain.get(tokenEntryName(maruhi.origin))).toBeDefined();
    }
  });

  it("サーバー由来の verificationUrl / userCode の制御文字は中和して表示する", async () => {
    // 敵対的・侵害済みサーバーの ANSI 注入を端末へ生で流さない(displayText)
    const handoff = fakeHandoff({
      startOverrides: {
        verificationUrl: "https://evil.example/\u001b[2Jverify",
        userCode: "AB\u001bCD",
      },
    });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    expect(env.logs.join("\n")).not.toContain("\u001b");
    expect(env.errors.join("\n")).not.toContain("\u001b");
    expect(env.errors.join("\n")).toContain("Confirmation code: AB\uFFFDCD");
  });

  it("ブラウザ側の拒否(denied)はエラーで終了する(§4-1 (4) の拒否操作)", async () => {
    const handoff = fakeHandoff({ finalPoll: { status: 200, json: { status: "denied" } } });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("denied in the browser");
    expect(env.keychain.size).toBe(0);
  });

  it("期限切れ(410 CliFlowExpired)はポーリングをやめて再ログインを案内する(§4-2)", async () => {
    const handoff = fakeHandoff({
      finalPoll: { status: 410, json: { _tag: "CliFlowExpired" } },
    });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("The sign-in request expired");
    expect(handoff.polls()).toBe(1);
    expect(env.keychain.size).toBe(0);
  });

  it("一様拒否(400 CliFlowRejected)は理由を出し分けず再ログインを案内する(§4-2)", async () => {
    // 資格不一致・消費済みフローの再 poll 等はすべて同一応答(サーバーがフロー
    // 状態のオラクルを作らない)— CLI 側も理由を捏造しない
    const handoff = fakeHandoff({
      finalPoll: { status: 400, json: { _tag: "CliFlowRejected" } },
    });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("rejected by the server");
    expect(env.keychain.size).toBe(0);
  });

  it("poll の 429 は失敗ではなく退避して続行する(§4-1 (5))", async () => {
    let polls = 0;
    const maruhi = await start([
      onRequest("POST", "/auth/cli/start", () => ({
        status: 200,
        json: {
          flowId: FLOW_ID,
          flowToken: FLOW_TOKEN,
          userCode: USER_CODE,
          verificationUrl: VERIFICATION_URL,
          expiresInSeconds: 900,
          pollIntervalSeconds: 0,
        },
      })),
      onRequest("POST", "/auth/cli/poll", () => {
        polls += 1;
        if (polls === 1) {
          return { status: 429, json: { _tag: "AuthRateLimited", retryAfterSeconds: 0 } };
        }
        return approvedResponse();
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    expect(polls).toBe(2);
    expect(env.keychain.get(tokenEntryName(maruhi.origin))).toBeDefined();
  });

  it("次のポーリングが申告期限を越えるならローカルで期限切れにする(deadline は sleep の前)", async () => {
    // サーバー申告の残余期限 1ms × 間隔 10 秒 — 待っている間にフローは失効する
    // ので、無駄な sleep もリクエストもせずに終了する
    const handoff = fakeHandoff({
      startOverrides: { expiresInSeconds: 0.001, pollIntervalSeconds: 10 },
    });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("The sign-in request expired");
    expect(handoff.polls()).toBe(0);
  });

  it("有効期間の案内と期限切れの文面はサーバー応答の expiresInSeconds から導く(裁定 D-1)", async () => {
    // 分単位で切り捨て、1 分未満だけ秒で言う。定数は CLI に無い(サーバーの
    // TTL を変えても案内が食い違わない)。期限切れの文面にも同じ期間を添える
    for (const [seconds, window] of [
      [600, "10 minutes"],
      [61, "1 minute"],
      [45, "45 seconds"],
    ] as const) {
      const handoff = fakeHandoff({
        startOverrides: { expiresInSeconds: seconds },
        finalPoll: { status: 410, json: { _tag: "CliFlowExpired" } },
      });
      const maruhi = await start(handoff.handlers);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });
      expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
      const guidance = env.errors.join("\n");
      expect(guidance).toContain(`This request expires in ${window}`);
      expect(guidance).toContain(`The sign-in request expired (it was valid for ${window})`);
    }
    // 非数・非正は既定(サーバーの起草値と同じ 15 分)へ丸めて案内する
    const handoff = fakeHandoff({ startOverrides: { expiresInSeconds: -1 } });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("This request expires in 15 minutes");
  });

  it("対話の案内は stderr、結果は stdout(`maruhi login > file` でも案内が見える)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    expect(await runCli(["login", "--token-name", "cli-test", ...FAST_POLL], env.layer)).toBe(0);
    // stdout は結果だけ(URL・コード・待機表示を混ぜない)
    expect(env.logs).toEqual([
      "Signed in as user-0001. The token is stored in the OS keychain",
      "The token expires on 2099-01-01 (UTC). Signing in again with the same token name (cli-test) rotates it and revokes the old one",
    ]);
    expect(env.logs.join("\n")).not.toContain(VERIFICATION_URL);
  });

  it("未設定サーバー(503 SetupIncomplete)はセットアップガイドを案内して失敗する", async () => {
    const maruhi = await start([
      onRequest("POST", "/auth/cli/start", () => ({
        status: 503,
        json: { _tag: "SetupIncomplete", reason: "github-oauth-unconfigured" },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("self-hosting setup is incomplete");
    expect(env.errors.join("\n")).toContain("SELF_HOSTING");
  });

  it("範囲外の expiresAtMs でもクラッシュせず明示劣化する(display.ts の total 表示)", async () => {
    // ワイヤの expiresAtMs は無制限 number — Date 範囲(±8.64e15)外を
    // toISOString へ渡すと RangeError の defect になる(deepsec B1/B4/B5 の
    // display.ts 規律)
    const handoff = fakeHandoff({ expiresAtMs: 9.9e15 });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("(invalid timestamp: 9900000000000000)");
  });

  it("--show-token は発行した生値を 1 度だけ端末へ出し、供給手順を案内する(裁定 CK)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", "--show-token", ...FAST_POLL], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("maruhi_pat_issued");
    expect(logs).toContain("MARUHI_TOKEN");
    expect(logs).toContain("MARUHI_TOKEN_ORIGIN");
    // 供給ログインの身元スワップの注記(裁定 CM)— **既定名で発行した**この
    // ケースでは「素の再ログイン」を勧めてはならない(同名ローテーションが
    // いま表示したトークン自体を失効させる — PR #108 Bugbot 指摘)。正しい
    // 復し方 = 別名での発行し直し
    const notes = env.errors.join("\n");
    expect(notes).toContain("default token name");
    expect(notes).toContain("issue it under a distinct name instead");
    expect(notes).not.toContain("run a plain `maruhi login` afterwards");
    // キーチェーン保存は表示の有無と独立(表示は追加の 1 箇所であって代替でない)
    expect(env.keychain.get(tokenEntryName(maruhi.origin))).toContain("maruhi_pat_issued");
  });

  it("--show-token + 明示 --token-name では素の再ログインによる復し方を案内する(裁定 CM)", async () => {
    // 別名で供給した場合は素の再ログイン(既定名のローテーション)が供給済み
    // トークンに触れない — こちらのケースでのみこの案内を出す
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(
      await runCli(["login", "--token-name", "ci", "--show-token", ...FAST_POLL], env.layer),
    ).toBe(0);
    const notes = env.errors.join("\n");
    expect(notes).toContain("run a plain `maruhi login` afterwards");
    expect(notes).not.toContain("issue it under a distinct name instead");
  });

  it("--show-token は敵対的サーバーの ANSI 注入を可視エスケープに畳む(escapeText — コピー同一性は保つ)", async () => {
    // token はワイヤ上無制約の Schema.String。表示はコピーする値なので
    // displayText(U+FFFD 置換 = 値の破壊)でなく escapeText(正直な Base62 は
    // 素通し・注入は \u{hex} の可視列)を通す
    const handoff = fakeHandoff({
      token: "maruhi_pat_evil\u001b[2Jinjected\nSet MARUHI_TOKEN to attacker-value",
    });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", "--show-token", ...FAST_POLL], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    // 生の ESC・偽の追加行は端末へ届かない(エスケープ列として可視化される)
    expect(logs).not.toContain("\u001b");
    expect(logs).toContain("maruhi_pat_evil");
    expect(logs).not.toContain("\nSet MARUHI_TOKEN to attacker-value");
  });

  it("--show-token はエージェント環境・非対話端末をどの通信よりも前に拒否する(fail-closed 2 層)", async () => {
    // 拒否される環境でブラウザ承認を完走させると、同名ローテーションで旧
    // トークンだけ失効し新しい生値は得られない(置き換え対象の CI トークンを
    // 壊すだけ)— 判定は start より前
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);

    const agentEnv = await makeTestEnv();
    await seedConfig(agentEnv, { server: maruhi.origin });
    agentEnv.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["login", "--show-token", ...FAST_POLL], agentEnv.layer)).toBe(1);
    expect(agentEnv.errors.join("\n")).toContain("AI agent environment was detected");

    const pipedEnv = await makeTestEnv();
    await seedConfig(pipedEnv, { server: maruhi.origin });
    pipedEnv.setTerminal({ stdout: false });
    expect(await runCli(["login", "--show-token", ...FAST_POLL], pipedEnv.layer)).toBe(1);
    expect(pipedEnv.errors.join("\n")).toContain("interactive terminal");

    expect(maruhi.requests).toHaveLength(0);
  });

  it("ログイン後、鍵なし + リカバリー登録済みなら `key recover` を案内する", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start([
      ...handoff.handlers,
      onRequest("GET", "/auth/recovery/status", () => ({
        status: 200,
        json: { registered: true, updatedAtMs: 1754006400000 },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("`maruhi key recover`");
  });

  it("ログイン後、鍵あり + リカバリー未登録なら発行を促す(保管リマインダ)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start([
      ...handoff.handlers,
      onRequest("GET", "/auth/recovery/status", () => ({
        status: 200,
        json: { registered: false, updatedAtMs: null },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
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

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("issue one with `maruhi key recovery`");
  });

  it("ログイン後の案内は状態確認に失敗してもログインを失敗させず、スキップを明示する", async () => {
    // recovery/status ハンドラなし = 状態確認が失敗する状況
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    // 無言のスキップにしない(CLAUDE.md: catch で無言に飲まない)
    expect(env.errors.join("\n")).toContain("skipped the next-step hint");
  });

  it("キーチェーン保存に失敗したら発行済みトークンを失効させてから失敗する(孤児化防止)", async () => {
    let revoked = 0;
    const handoff = fakeHandoff();
    const maruhi = await start([
      ...handoff.handlers,
      onRequest("POST", "/auth/token/revoke", (request) => {
        expect(request.headers["authorization"]).toBe("Bearer maruhi_pat_issued");
        revoked += 1;
        return { status: 204 };
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.failKeychainWrites();

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
    expect(revoked).toBe(1);
    expect(env.keychain.size).toBe(0);
    expect(env.errors.join("\n")).toContain("キーチェーン");
  });

  it("キーチェーン保存失敗 + 失効も失敗した場合は「失効させた」と主張しない", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start([
      ...handoff.handlers,
      onRequest("POST", "/auth/token/revoke", () => ({ status: 500, bodyText: "boom" })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.failKeychainWrites();

    expect(await runCli(["login", "--token-name", "cli-test", ...FAST_POLL], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("revoking the issued token also failed");
    expect(errors).not.toContain("has been revoked on the server");
    // 同名再ログインによるローテーション失効の案内がある
    expect(errors).toContain("cli-test");
  });

  it("config の server が不正な場合は、直す先を示して 1 で落ちる", async () => {
    // コマンドラインに何も書いていないので「書き方の誤り(2)」ではない
    const env = await makeTestEnv();
    await seedConfig(env, { server: "ftp://bad.example" });
    expect(await runCli(["logout"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("fix server in your config");
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
    expect(env.errors.join("\n")).toContain("MARUHI_TOKEN is set");
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
      const notes = env.errors.join("\n");
      expect(notes).toContain(expected);
      expect(notes).not.toContain("stays authenticated with that token");
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
    const notes = env.errors.join("\n");
    expect(notes).toContain("not used for authentication");
    expect(notes).not.toContain("stays authenticated with that token");
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
    expect(env.errors.join("\n")).not.toContain("MARUHI_TOKEN is set");
  });

  it("トークン未保存はエラーメッセージで案内する", async () => {
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    expect(await runCli(["logout"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("No token for this server in the keychain");
  });
});
