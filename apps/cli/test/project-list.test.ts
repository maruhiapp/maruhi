// Wire-level tests for `maruhi project list` (AUTH_SPEC §11-5).
//
// What it pins down:
// - Page tracking: passes nextAfter as the exclusive cursor to the next
//   page and collects until exhausted
// - Display: stdout is data lines only (projectId + role); the note (a
//   disclaimer that it's the server's report) goes to stderr (the data
//   discipline — same as other list commands)
// - The empty-list wording and exit 0
// - A runaway server (nextAfter never exhausts) is bounded and cut off at
//   the page cap (exit 1)

import { afterEach, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { makeTestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { MockServer, onRequest } from "./support/server.ts";

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

const PROJECT_A = "a".repeat(64);
const PROJECT_B = "b".repeat(64);

async function startEnv(server: MockServer): Promise<TestEnv> {
  const owner = await makeTestUser("user-owner-1111");
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, { server: server.origin });
  return env;
}

describe("maruhi project list", () => {
  it("follows nextAfter to gather every page and displays one project per line", async () => {
    const server = await MockServer.start([
      onRequest("GET", "/projects", (request) =>
        request.query["after"] === undefined
          ? {
              status: 200,
              json: {
                projects: [{ projectId: PROJECT_A, role: "owner" }],
                nextAfter: PROJECT_A,
              },
            }
          : {
              status: 200,
              json: { projects: [{ projectId: PROJECT_B, role: "reader" }] },
            },
      ),
    ]);
    servers.push(server);
    const env = await startEnv(server);

    expect(await runCli(["project", "list"], env.layer)).toBe(0);
    // stdout is data lines only (ascending project_id = server response
    // order preserved)
    expect(env.logs).toEqual([`${PROJECT_A}\trole=owner`, `${PROJECT_B}\trole=reader`]);
    // The note (the server-report disclaimer + the path to verify) goes
    // to stderr
    expect(env.errors.join("\n")).toContain("2 projects as reported by the server");
    // Page 2 was passed the exclusive cursor
    const listRequests = server.requests.filter((request) => request.path === "/projects");
    expect(listRequests).toHaveLength(2);
    expect(listRequests[1]?.query["after"]).toBe(PROJECT_A);
  });

  it("zero memberships says No projects (exit 0)", async () => {
    const server = await MockServer.start([
      onRequest("GET", "/projects", () => ({ status: 200, json: { projects: [] } })),
    ]);
    servers.push(server);
    const env = await startEnv(server);

    expect(await runCli(["project", "list"], env.layer)).toBe(0);
    expect(env.logs).toEqual(["No projects"]);
  });

  it("a server whose nextAfter never exhausts is cut off at the page cap with exit 1 (bounded)", async () => {
    const server = await MockServer.start([
      onRequest("GET", "/projects", () => ({
        status: 200,
        json: { projects: [{ projectId: PROJECT_A, role: "owner" }], nextAfter: PROJECT_A },
      })),
    ]);
    servers.push(server);
    const env = await startEnv(server);

    expect(await runCli(["project", "list"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("page bound");
    // It doesn't keep hitting past the page cap
    expect(server.requests.length).toBeLessThanOrEqual(100);
  });
});
