// 細部のユニットテスト: device flow のポーリング規則(RFC 8628 §3.5)、
// キーチェーンレコードの codec、run の注入検証、stdin 正規化、
// MARUHI_TOKEN 環境変数経路、サーバー URL 解決。

import { Effect, Exit } from "effect";
import { afterEach, describe, expect, it } from "vitest";

import { normalizeStdinValue, runCli } from "../src/cli.ts";
import { pollDeviceFlow } from "../src/device-flow.ts";
import {
  masterKeyEntryName,
  parseStoredMasterKey,
  parseStoredToken,
  tokenEntryName,
} from "../src/keychain.ts";
import type { DecryptedVariable } from "../src/pull.ts";
import { buildInjectionEnv } from "../src/run.ts";
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
    const withNul = await Effect.runPromiseExit(buildInjectionEnv([variable("SECRET_A", "a\0b")]));
    expect(Exit.isFailure(withNul)).toBe(true);
    expect(JSON.stringify(withNul)).not.toContain("a\\u0000b");
    const invalidUtf8 = await Effect.runPromiseExit(
      buildInjectionEnv([variable("SECRET_B", new Uint8Array([0xff, 0xfe]))]),
    );
    expect(Exit.isFailure(invalidUtf8)).toBe(true);
  });
});

const decode = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

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
    // key show は session 解決 + master 鍵を要求する。master 鍵がないため
    // エラーになるが、セッション解決(/auth/me)自体は通ることを検証する
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("master 鍵がありません");
  });
});
