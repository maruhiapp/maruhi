import { afterEach, expect, vi } from "vite-plus/test";

import { makeTestUser } from "./crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./env.ts";
import { MockServer } from "./server.ts";

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
  vi.restoreAllMocks();
});

export async function startEnv(): Promise<{ env: TestEnv; server: MockServer }> {
  const owner = await makeTestUser("user-owner-1111");
  const server = await MockServer.start([]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: "1111111111111111111111111111111111111111111111111111111111111111",
    defaultEnvironment: "prod",
  });
  return { env, server };
}

export function expectNoLeak(env: TestEnv, secrets: readonly string[]): void {
  const output = [...env.logs, ...env.errors].join("\n");
  for (const secret of secrets) {
    expect(output).not.toContain(secret);
  }
}
