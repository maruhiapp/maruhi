// `maruhi token list` / `maruhi token revoke`(AUTH_SPEC §6 — W3a)のワイヤレベルテスト。
//
// 固定するもの:
// - list: createdAtMs 昇順の整列、スコープの `project:permission` 連結、
//   null の lastUsed / expires は "never"、空一覧の文言(exit 0)
// - list: 403 は admin トークン / ブラウザセッションへの案内(exit 1)
// - revoke: DELETE /auth/tokens/:tokenId を送り、成功を 1 行で報告
// - revoke: 404(一様 — 存在秘匿)は `maruhi token list` への案内、403 は資格の案内
// - どちらも想定外のサーバーエラーは型付きエラーで exit 1

import { afterEach, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { makeTestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

const PROJECT_A = "a".repeat(64);

/** 2026-01-02T03:04:05Z 起点のフィクスチャ時刻。 */
const T0 = Date.UTC(2026, 0, 2, 3, 4, 5);
const HOUR = 60 * 60 * 1000;

async function startEnv(handlers: readonly MockHandler[]): Promise<{
  server: MockServer;
  env: TestEnv;
}> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const owner = await makeTestUser("user-owner-1111");
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, { server: server.origin });
  return { server, env };
}

describe("maruhi token list", () => {
  it("createdAtMs 昇順に並べ、スコープを連結し、null の時刻は never と表示する", async () => {
    const { env } = await startEnv([
      onRequest("GET", "/auth/tokens", () => ({
        status: 200,
        json: {
          // サーバー応答順は作成順と逆(CLI 側で整列することを確かめる)
          tokens: [
            {
              id: "tok_newer",
              name: "ci",
              tokenPrefix: "maruhi_pat_Zz",
              scopes: [
                { project: PROJECT_A, permission: "read" },
                { project: "*", permission: "write" },
              ],
              createdAtMs: T0 + 2 * HOUR,
              lastUsedAtMs: T0 + 3 * HOUR,
              expiresAtMs: T0 + 24 * HOUR,
            },
            {
              id: "tok_older",
              name: "cli:laptop",
              tokenPrefix: "maruhi_pat_Ab",
              scopes: [{ project: "*", permission: "admin" }],
              createdAtMs: T0,
              lastUsedAtMs: null,
              expiresAtMs: null,
            },
          ],
        },
      })),
    ]);

    expect(await runCli(["token", "list"], env.layer)).toBe(0);
    expect(env.logs).toEqual([
      "id\tname\tprefix\tscopes\tcreated\tlast used\texpires",
      "tok_older\tcli:laptop\tmaruhi_pat_Ab\t*:admin\t2026-01-02 03:04 UTC\tnever\tnever",
      `tok_newer\tci\tmaruhi_pat_Zz\t${PROJECT_A}:read,*:write\t2026-01-02 05:04 UTC\t2026-01-02 06:04 UTC\t2026-01-03 03:04 UTC`,
    ]);
  });

  it("トークンが無ければ No API tokens(exit 0)", async () => {
    const { env } = await startEnv([
      onRequest("GET", "/auth/tokens", () => ({ status: 200, json: { tokens: [] } })),
    ]);

    expect(await runCli(["token", "list"], env.layer)).toBe(0);
    expect(env.logs).toEqual(["No API tokens"]);
  });

  it("403 は admin トークン / ブラウザセッションが要る旨を案内して exit 1", async () => {
    const { env } = await startEnv([
      onRequest("GET", "/auth/tokens", () => ({
        status: 403,
        json: { _tag: "Forbidden", reason: "insufficient-scope" },
      })),
    ]);

    expect(await runCli(["token", "list"], env.layer)).toBe(1);
    expect(env.logs).toEqual([]);
    const stderr = env.errors.join("\n");
    expect(stderr).toContain("Listing tokens needs an admin token");
    expect(stderr).toContain("browser session");
  });

  it("想定外のサーバーエラーは exit 1(一覧を出さない)", async () => {
    const { env } = await startEnv([
      onRequest("GET", "/auth/tokens", () => ({ status: 500, json: { _tag: "Internal" } })),
    ]);

    expect(await runCli(["token", "list"], env.layer)).toBe(1);
    expect(env.logs).toEqual([]);
    expect(env.errors.join("\n")).not.toContain("Listing tokens needs an admin token");
  });
});

describe("maruhi token revoke", () => {
  it("DELETE /auth/tokens/:tokenId を送り、失効を報告する", async () => {
    const { server, env } = await startEnv([
      onRequest("DELETE", "/auth/tokens/tok_target", () => ({ status: 204 })),
    ]);

    expect(await runCli(["token", "revoke", "tok_target"], env.layer)).toBe(0);
    expect(env.logs).toEqual(["Revoked token tok_target"]);
    expect(
      server.requests.filter((request) => request.method === "DELETE").map((r) => r.path),
    ).toEqual(["/auth/tokens/tok_target"]);
  });

  it("404(一様 — 存在秘匿)は token list への案内で exit 1", async () => {
    const { env } = await startEnv([
      onRequest("DELETE", "/auth/tokens/tok_missing", () => ({
        status: 404,
        json: { _tag: "TokenNotFound" },
      })),
    ]);

    expect(await runCli(["token", "revoke", "tok_missing"], env.layer)).toBe(1);
    expect(env.logs).toEqual([]);
    const stderr = env.errors.join("\n");
    expect(stderr).toContain("No token with id tok_missing belongs to you");
    expect(stderr).toContain("maruhi token list");
  });

  it("403 は admin トークン / ブラウザセッションが要る旨を案内して exit 1", async () => {
    const { env } = await startEnv([
      onRequest("DELETE", "/auth/tokens/tok_target", () => ({
        status: 403,
        json: { _tag: "Forbidden", reason: "insufficient-scope" },
      })),
    ]);

    expect(await runCli(["token", "revoke", "tok_target"], env.layer)).toBe(1);
    expect(env.logs).toEqual([]);
    expect(env.errors.join("\n")).toContain(
      "Revoking a token by id needs an admin token (all projects × admin) or a browser session",
    );
  });

  it("想定外のサーバーエラーは exit 1(失効を報告しない)", async () => {
    const { env } = await startEnv([
      onRequest("DELETE", "/auth/tokens/tok_target", () => ({
        status: 500,
        json: { _tag: "Internal" },
      })),
    ]);

    expect(await runCli(["token", "revoke", "tok_target"], env.layer)).toBe(1);
    expect(env.logs).toEqual([]);
    const stderr = env.errors.join("\n");
    expect(stderr).not.toContain("No token with id");
    expect(stderr).not.toContain("Revoking a token by id needs");
  });
});
