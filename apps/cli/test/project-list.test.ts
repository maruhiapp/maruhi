// `maruhi project list`(AUTH_SPEC §11-5 — W2a)のワイヤレベルテスト。
//
// 固定するもの:
// - ページ追跡: nextAfter を排他カーソルとして次ページへ渡し、尽きるまで集める
// - 表示: stdout はデータ行(projectId + role)のみ、注記(サーバー申告の断り)は
//   stderr(データの規律 — 他の list 系と同じ)
// - 空一覧の文言と exit 0
// - 暴走サーバー(nextAfter が尽きない)のページ上限での有界打ち切り(exit 1)

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
  it("nextAfter を辿って全ページを集め、1 行 1 プロジェクトで表示する", async () => {
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
    // stdout はデータ行のみ(project_id 昇順 = サーバー応答順を保つ)
    expect(env.logs).toEqual([`${PROJECT_A}\trole=owner`, `${PROJECT_B}\trole=reader`]);
    // 注記(サーバー申告の断り + verify への導線)は stderr
    expect(env.errors.join("\n")).toContain("2 projects as reported by the server");
    // 2 ページ目は排他カーソルを渡している
    const listRequests = server.requests.filter((request) => request.path === "/projects");
    expect(listRequests).toHaveLength(2);
    expect(listRequests[1]?.query["after"]).toBe(PROJECT_A);
  });

  it("membership ゼロは No projects(exit 0)", async () => {
    const server = await MockServer.start([
      onRequest("GET", "/projects", () => ({ status: 200, json: { projects: [] } })),
    ]);
    servers.push(server);
    const env = await startEnv(server);

    expect(await runCli(["project", "list"], env.layer)).toBe(0);
    expect(env.logs).toEqual(["No projects"]);
  });

  it("nextAfter が尽きないサーバーはページ上限で打ち切り exit 1(有界化)", async () => {
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
    // 上限ページ数を超えて叩き続けない
    expect(server.requests.length).toBeLessThanOrEqual(100);
  });
});
