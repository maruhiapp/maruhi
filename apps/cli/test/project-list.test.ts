import { generateIdentity } from "@maruhi/test-kit";
import { afterEach, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { MockServer, onEndpoint } from "./support/server.ts";

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

const PROJECT_A = "a".repeat(64);
const PROJECT_B = "b".repeat(64);

async function startEnv(server: MockServer): Promise<TestEnv> {
  const owner = await generateIdentity("user-owner-1111");
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, { server: server.origin });
  return env;
}

describe("maruhi project list", () => {
  it("follows nextAfter to gather every page and displays one project per line", async () => {
    const server = await MockServer.start([
      onEndpoint("membership.list", (request) =>
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
    expect(env.logs).toEqual([`${PROJECT_A}\trole=owner`, `${PROJECT_B}\trole=reader`]);
    expect(env.errors.join("\n")).toContain("2 projects as reported by the server");
    const listRequests = server.requests.filter((request) => request.path === "/projects");
    expect(listRequests).toHaveLength(2);
    expect(listRequests[1]?.query["after"]).toBe(PROJECT_A);
  });

  it("zero memberships says No projects (exit 0)", async () => {
    const server = await MockServer.start([
      onEndpoint("membership.list", () => ({ status: 200, json: { projects: [] } })),
    ]);
    servers.push(server);
    const env = await startEnv(server);

    expect(await runCli(["project", "list"], env.layer)).toBe(0);
    expect(env.logs).toEqual(["No projects"]);
  });

  it("a server whose nextAfter never exhausts is cut off at the page cap with exit 1 (bounded)", async () => {
    const server = await MockServer.start([
      onEndpoint("membership.list", () => ({
        status: 200,
        json: { projects: [{ projectId: PROJECT_A, role: "owner" }], nextAfter: PROJECT_A },
      })),
    ]);
    servers.push(server);
    const env = await startEnv(server);

    expect(await runCli(["project", "list"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("page bound");
    expect(server.requests.length).toBeLessThanOrEqual(100);
  });
});
