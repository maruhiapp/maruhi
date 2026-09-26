// Wire-level tests for `maruhi token list` / `maruhi token revoke`
// (AUTH_SPEC §6 — W3a).
//
// What they pin down:
// - list: ascending createdAtMs ordering, scopes joined as
//   `project:permission`, null lastUsed / expires rendered "never", and
//   the empty-list wording (exit 0)
// - list: a 403 guides toward an admin token / browser session (exit 1)
// - revoke: sends DELETE /auth/tokens/:tokenId and reports success in one
//   line
// - revoke: a 404 (uniform — hides existence) guides toward `maruhi token
//   list`; a 403 is the credential guidance
// - both: an unexpected server error is a typed error with exit 1

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

/** Fixture times starting from 2026-01-02T03:04:05Z. */
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
  it("orders ascending by createdAtMs, joins scopes, and renders null times as never", async () => {
    const { env } = await startEnv([
      onRequest("GET", "/auth/tokens", () => ({
        status: 200,
        json: {
          // The server's response order is the reverse of creation order
          // (confirming the CLI sorts)
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

  it("no tokens says No API tokens (exit 0)", async () => {
    const { env } = await startEnv([
      onRequest("GET", "/auth/tokens", () => ({ status: 200, json: { tokens: [] } })),
    ]);

    expect(await runCli(["token", "list"], env.layer)).toBe(0);
    expect(env.logs).toEqual(["No API tokens"]);
  });

  it("a 403 guides that an admin token / browser session is needed, exit 1", async () => {
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

  it("an unexpected server error is exit 1 (no list emitted)", async () => {
    const { env } = await startEnv([
      onRequest("GET", "/auth/tokens", () => ({ status: 500, json: { _tag: "Internal" } })),
    ]);

    expect(await runCli(["token", "list"], env.layer)).toBe(1);
    expect(env.logs).toEqual([]);
    expect(env.errors.join("\n")).not.toContain("Listing tokens needs an admin token");
  });
});

describe("maruhi token revoke", () => {
  it("sends DELETE /auth/tokens/:tokenId and reports the revocation", async () => {
    const { server, env } = await startEnv([
      onRequest("DELETE", "/auth/tokens/tok_target", () => ({ status: 204 })),
    ]);

    expect(await runCli(["token", "revoke", "tok_target"], env.layer)).toBe(0);
    expect(env.logs).toEqual(["Revoked token tok_target"]);
    expect(
      server.requests.filter((request) => request.method === "DELETE").map((r) => r.path),
    ).toEqual(["/auth/tokens/tok_target"]);
  });

  it("a 404 (uniform — hides existence) guides toward token list, exit 1", async () => {
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

  it("a 403 guides that an admin token / browser session is needed, exit 1", async () => {
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

  it("an unexpected server error is exit 1 (no revocation reported)", async () => {
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
