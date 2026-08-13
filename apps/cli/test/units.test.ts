// 細部のユニットテスト: device flow のポーリング規則(RFC 8628 §3.5)、
// キーチェーンレコードの codec、run の注入検証、stdin 正規化、
// MARUHI_TOKEN 環境変数経路、サーバー URL 解決。

import { ProjectNotFoundError } from "@maruhi/api-schema";
import { Effect, Exit, Layer } from "effect";
import { afterEach, describe, expect, it } from "vitest";

import { normalizeStdinValue, runCli } from "../src/cli.ts";
import { pollDeviceFlow, startDeviceFlow } from "../src/device-flow.ts";
import { decodeValueText } from "../src/display.ts";
import { toCliError } from "../src/failure.ts";
import {
  masterKeyEntryName,
  parseStoredMasterKey,
  parseStoredToken,
  tokenEntryName,
} from "../src/keychain.ts";
import type { DecryptedVariable } from "../src/pull.ts";
import { buildInjectionEnv, ProcessRunner, runOp } from "../src/run.ts";
import { resolveServerOrigin } from "../src/session.ts";
import { makeTestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig } from "./support/env.ts";
import { MockServer, onRequest } from "./support/server.ts";

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

describe("pollDeviceFlow", () => {
  it("slow_down は待ち時間を増やして続行する", async () => {
    let polls = 0;
    const server = await MockServer.start([
      onRequest("POST", "/login/oauth/access_token", () => {
        polls += 1;
        if (polls === 1) {
          return { status: 200, json: { error: "slow_down" } };
        }
        return { status: 200, json: { access_token: "gho_x" } };
      }),
    ]);
    servers.push(server);
    const token = await Effect.runPromise(
      pollDeviceFlow({
        clientId: "c",
        githubBaseUrl: server.origin,
        slowDownExtraSeconds: 0.01,
        authorization: {
          deviceCode: "d",
          userCode: "u",
          verificationUri: "v",
          intervalSeconds: 0,
          expiresInSeconds: 60,
        },
      }),
    );
    expect(token).toBe("gho_x");
    expect(polls).toBe(2);
  });

  it("expired_token(サーバー申告)で中断する。RFC 準拠の 400 + error ボディも分類できる", async () => {
    const server = await MockServer.start([
      onRequest("POST", "/login/oauth/access_token", () => ({
        // RFC 8628 準拠実装の形(GitHub 実サーバーは 200 + error)
        status: 400,
        json: { error: "expired_token" },
      })),
    ]);
    servers.push(server);
    const exit = await Effect.runPromiseExit(
      pollDeviceFlow({
        clientId: "c",
        githubBaseUrl: server.origin,
        authorization: {
          deviceCode: "d",
          userCode: "u",
          verificationUri: "v",
          intervalSeconds: 0,
          expiresInSeconds: 60,
        },
      }),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("有効期限");
  });

  it("device flow 開始応答の欠損(device_code なし)を検出する", async () => {
    const server = await MockServer.start([
      onRequest("POST", "/login/device/code", () => ({ status: 200, json: { interval: 5 } })),
    ]);
    servers.push(server);
    const exit = await Effect.runPromiseExit(
      startDeviceFlow({ clientId: "c", githubBaseUrl: server.origin }),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("device flow");
  });

  it("サーバーが interval 0 を返しても下限(既定 5 秒)に丸める(ビジースピン防止)", async () => {
    const server = await MockServer.start([
      onRequest("POST", "/login/device/code", () => ({
        status: 200,
        json: {
          device_code: "d",
          user_code: "U",
          verification_uri: "https://github.example/device",
          interval: 0,
          expires_in: 900,
        },
      })),
    ]);
    servers.push(server);
    const auth = await Effect.runPromise(
      startDeviceFlow({ clientId: "c", githubBaseUrl: server.origin }),
    );
    expect(auth.intervalSeconds).toBe(5);
  });

  it("minIntervalSeconds を渡すと下限を上書きできる(テスト用)", async () => {
    const server = await MockServer.start([
      onRequest("POST", "/login/device/code", () => ({
        status: 200,
        json: {
          device_code: "d",
          user_code: "U",
          verification_uri: "https://github.example/device",
          interval: 0,
          expires_in: 900,
        },
      })),
    ]);
    servers.push(server);
    const auth = await Effect.runPromise(
      startDeviceFlow({ clientId: "c", githubBaseUrl: server.origin, minIntervalSeconds: 0 }),
    );
    expect(auth.intervalSeconds).toBe(0);
  });

  it("期限切れ(deadline 超過)で中断する", async () => {
    const server = await MockServer.start([
      onRequest("POST", "/login/oauth/access_token", () => ({
        status: 200,
        json: { error: "authorization_pending" },
      })),
    ]);
    servers.push(server);
    const exit = await Effect.runPromiseExit(
      pollDeviceFlow({
        clientId: "c",
        githubBaseUrl: server.origin,
        authorization: {
          deviceCode: "d",
          userCode: "u",
          verificationUri: "v",
          intervalSeconds: 0.01,
          expiresInSeconds: 0.02,
        },
      }),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("有効期限");
  });
});

describe("keychain record codecs", () => {
  it("トークン・master 鍵レコードの往復と破損検出", () => {
    const token = { token: "maruhi_pat_x", userId: "u1", tokenId: "t1" };
    expect(parseStoredToken(JSON.stringify(token))).toEqual(token);
    expect(parseStoredToken("not json")).toBeNull();
    expect(parseStoredToken(JSON.stringify({ token: "x" }))).toBeNull();
    expect(parseStoredMasterKey(JSON.stringify({ suite: "maruhi/v1" }))).toBeNull();
  });

  it("キーチェーン名はサーバー origin(と userId)でスコープされる", () => {
    expect(tokenEntryName("https://a.example")).not.toBe(tokenEntryName("https://b.example"));
    expect(masterKeyEntryName("https://a.example", "u1")).not.toBe(
      masterKeyEntryName("https://a.example", "u2"),
    );
  });
});

describe("resolveServerOrigin", () => {
  it("フラグ → config の順に解決し、origin へ正規化する", async () => {
    const origin = await Effect.runPromise(
      resolveServerOrigin("https://maruhi.example/some/path", {}),
    );
    expect(origin).toBe("https://maruhi.example");
    const fromConfig = await Effect.runPromise(
      resolveServerOrigin(undefined, { server: "http://localhost:8787" }),
    );
    expect(fromConfig).toBe("http://localhost:8787");
  });

  it("未設定・不正 URL はエラー", async () => {
    const missing = await Effect.runPromiseExit(resolveServerOrigin(undefined, {}));
    expect(Exit.isFailure(missing)).toBe(true);
    const invalid = await Effect.runPromiseExit(resolveServerOrigin("not-a-url", {}));
    expect(Exit.isFailure(invalid)).toBe(true);
  });

  it("http: は loopback のみ許可する(平文送信の遮断)", async () => {
    const loopback = await Effect.runPromise(resolveServerOrigin("http://localhost:8787", {}));
    expect(loopback).toBe("http://localhost:8787");
    const remote = await Effect.runPromiseExit(resolveServerOrigin("http://maruhi.example", {}));
    expect(Exit.isFailure(remote)).toBe(true);
    expect(JSON.stringify(remote)).toContain("loopback");
  });
});

function variable(name: string, value: string | Uint8Array): DecryptedVariable {
  return {
    variableId: "v1",
    name,
    version: 1,
    epoch: 1,
    value: typeof value === "string" ? new TextEncoder().encode(value) : value,
  };
}

describe("runOp", () => {
  /** 子プロセスを起動しないランナー(起動まで到達したら分かるようにする)。 */
  const spawnedNothing = Layer.succeed(ProcessRunner, {
    run: () => Effect.succeed(0),
  });

  it("実行対象が空文字列だけなら子プロセスを起動しない", async () => {
    // 入口の引数検査(cli.ts)と同じ判定をここでも持つ(直接呼び出し向けの
    // 防衛線)。`[""]` は「1 要素あるが実行できない」形
    const exit = await Effect.runPromiseExit(
      runOp({ command: [""], variables: [] }).pipe(Effect.provide(spawnedNothing)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("`--` の後に指定");
    // 書き方の誤りは入口と同じ usage エラー(終了コード 2)として立てる
    expect(JSON.stringify(exit)).toContain('"usage":true');
  });
});

describe("buildInjectionEnv", () => {
  it("名前・値を検証して env map を作る", async () => {
    const env = await Effect.runPromise(
      buildInjectionEnv([variable("A", "1"), variable("B_2", "two")]),
    );
    expect(env).toEqual({ A: "1", B_2: "two" });
  });

  it("`=` を含む名前・NUL を含む値・不正 UTF-8 を拒否する(値はエラーに出さない)", async () => {
    const badName = await Effect.runPromiseExit(buildInjectionEnv([variable("A=B", "x")]));
    expect(Exit.isFailure(badName)).toBe(true);
    const nulName = await Effect.runPromiseExit(buildInjectionEnv([variable("A\0B", "x")]));
    expect(Exit.isFailure(nulName)).toBe(true);
    const withNul = await Effect.runPromiseExit(buildInjectionEnv([variable("SECRET_A", "a\0b")]));
    expect(Exit.isFailure(withNul)).toBe(true);
    expect(JSON.stringify(withNul)).not.toContain("a\\u0000b");
    const invalidUtf8 = await Effect.runPromiseExit(
      buildInjectionEnv([variable("SECRET_B", new Uint8Array([0xff, 0xfe]))]),
    );
    expect(Exit.isFailure(invalidUtf8)).toBe(true);
  });

  it("bash 関数インポート名(BASH_FUNC_x%% / x())を拒否する(shellshock 系)", async () => {
    for (const name of ["BASH_FUNC_ls%%", "evil()", "a b", "my-secret", "1abc"]) {
      const exit = await Effect.runPromiseExit(buildInjectionEnv([variable(name, "x")]));
      expect(Exit.isFailure(exit)).toBe(true);
      expect(JSON.stringify(exit)).toContain("英数字と _ のみ");
    }
  });

  it("大文字小文字の違いだけの名前の衝突を拒否する(Windows の非区別対策)", async () => {
    const exit = await Effect.runPromiseExit(
      buildInjectionEnv([variable("Secret_A", "x"), variable("SECRET_A", "y")]),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("大文字小文字の違い");
  });

  it("実行制御系の環境変数名(PATH / LD_* / NODE_OPTIONS 等)への注入を拒否する", async () => {
    // "Path" は Windows の大文字小文字非区別への防衛(大文字化して比較)
    for (const name of [
      "PATH",
      "Path",
      "LD_PRELOAD",
      "DYLD_INSERT_LIBRARIES",
      "NODE_OPTIONS",
      "NODE_TLS_REJECT_UNAUTHORIZED",
      "SSLKEYLOGFILE",
      "BUN_OPTIONS",
    ]) {
      const exit = await Effect.runPromiseExit(buildInjectionEnv([variable(name, "x")]));
      expect(Exit.isFailure(exit)).toBe(true);
      expect(JSON.stringify(exit)).toContain("実行制御系");
    }
  });
});

const decode = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

describe("decodeValueText(値デコード方針の一本化)", () => {
  it("有効な UTF-8(改行・タブ込み)はそのまま返し、不正 UTF-8 は null を返す", () => {
    expect(decodeValueText(new TextEncoder().encode("multi\nline\tvalue"))).toBe(
      "multi\nline\tvalue",
    );
    // --show / run 共通の fatal 方針: 置換文字で偽装せず、呼び出し側が明示エラーにする
    expect(decodeValueText(new Uint8Array([0xff, 0xfe]))).toBeNull();
  });
});

describe("toCliError(サーバー由来文字列の端末中和)", () => {
  it("エラー Schema の自由文字列 ID と未知エラーの message を中和する", () => {
    // ワイヤ上無制約の Schema.String 列(悪意あるサーバーが ANSI/改行を埋められる)
    const notFound = toCliError(
      new ProjectNotFoundError({ projectId: "x\u001b[31mred\u001b[0m\nfake" }),
    );
    expect(notFound.message).not.toContain("\u001b");
    expect(notFound.message).not.toContain("\n");
    expect(notFound.message).toContain("x\uFFFD[31mred\uFFFD[0m\uFFFDfake");
    // 未知エラー fallback(応答本文の断片を含みうる)も無条件に中和する
    const unknown = toCliError(new Error("boom\u001b]0;pwned\u0007"));
    expect(unknown.message).not.toContain("\u001b");
    expect(unknown.message).not.toContain("\u0007");
  });
});

describe("normalizeStdinValue", () => {
  it("末尾の改行 1 つ(LF / CRLF)のみ除去する", () => {
    expect(decode(normalizeStdinValue(new TextEncoder().encode("v\n")))).toBe("v");
    expect(decode(normalizeStdinValue(new TextEncoder().encode("v\r\n")))).toBe("v");
    expect(decode(normalizeStdinValue(new TextEncoder().encode("v\n\n")))).toBe("v\n");
    expect(decode(normalizeStdinValue(new TextEncoder().encode("v")))).toBe("v");
  });
});

describe("MARUHI_TOKEN 環境変数経路", () => {
  it("キーチェーンなしでも /auth/me で userId を解決して動く", async () => {
    const user = await makeTestUser("user-env-0001");
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", (request) => {
        expect(request.headers["authorization"]).toBe("Bearer maruhi_pat_env");
        return { status: 200, json: { userId: user.userId, orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    // key show は session 解決 + master 鍵を要求する。master 鍵がないため
    // エラーになるが、セッション解決(/auth/me)自体は通ることを検証する
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("master 鍵がありません");
  });

  it("環境変数がキーチェーンより優先される", async () => {
    const user = await makeTestUser("user-env-0001");
    let presented = "";
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", (request) => {
        presented = String(request.headers["authorization"]);
        return { status: 200, json: { userId: user.userId, orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({ token: "maruhi_pat_keychain", userId: user.userId, tokenId: "tok_1" }),
    );
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    await runCli(["key", "show"], env.layer);
    expect(presented).toBe("Bearer maruhi_pat_env");
  });

  it("/auth/me が 401 なら案内メッセージで失敗する", async () => {
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => ({ status: 401, json: { _tag: "Unauthorized" } })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("MARUHI_TOKEN での認証に失敗");
  });

  it("MARUHI_TOKEN_ORIGIN 未指定なら MARUHI_TOKEN を使わず案内する", async () => {
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => ({ status: 200, json: { userId: "u", orgs: [] } })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("MARUHI_TOKEN_ORIGIN で対象サーバー origin を指定");
  });

  it("MARUHI_TOKEN_ORIGIN が接続先と一致しなければトークンを送らない", async () => {
    let hit = false;
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => {
        hit = true;
        return { status: 200, json: { userId: "u", orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", "https://other.example");
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("一致しません");
    // トークンは接続先へ送信されない
    expect(hit).toBe(false);
  });
});

describe("入力検証と defect の扱い", () => {
  it("不正なプロジェクト ID / 環境 ID は早期にエラーになる", async () => {
    const env = await makeTestEnv();
    await seedConfig(env, { server: "https://maruhi.example", defaultEnvironment: "dev" });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    // 書き方の誤りは usage エラー(2)。指定値そのものは返さない
    expect(await runCli(["pull", "--project", "not-hex"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("プロジェクト ID の形式が正しくありません");
    expect(env.errors.join("\n")).not.toContain("not-hex");
    const env2 = await makeTestEnv();
    await seedConfig(env2, {
      server: "https://maruhi.example",
      defaultProject: "ab".repeat(32),
    });
    env2.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    // 環境 ID の形式検証はネットワークアクセス(セッション解決)より先に走る
    expect(await runCli(["pull", "--env", "!bad"], env2.layer)).toBe(2);
    expect(env2.errors.join("\n")).toContain("環境 ID の形式が正しくありません");
    expect(env2.errors.join("\n")).not.toContain("!bad");
  });

  it("defect(バグ由来の throw)は usage エラー(2)でなく 1 で報告される", async () => {
    const env = await makeTestEnv();
    env.breakConfigLoadWithDefect();
    expect(await runCli(["config", "get", "server"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("内部エラー");
  });
});
