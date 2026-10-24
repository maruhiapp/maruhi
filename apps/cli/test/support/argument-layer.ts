// The shared setup of the argument-layer tests (effect-cli.test.ts and the
// command groups' files its header names): a logged-in environment whose
// server records every request and answers each with 404, and the check
// that no typed value reaches the output. After each test, the servers it
// started are closed and its mocks restored.

import { afterEach, expect, vi } from "vitest";

import { makeTestUser } from "./crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./env.ts";
import { MockServer } from "./server.ts";

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
  vi.restoreAllMocks();
});

/**
 * An environment that is logged in with the default project / environment.
 * The server **never responds** (every request is 404), but it does record —
 * to confirm via "zero requests" that the rejection happened before the
 * command body ran.
 */
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

/** The shared check that no plaintext is mixed into a diagnostic (a typed value never becomes vocabulary). */
export function expectNoLeak(env: TestEnv, secrets: readonly string[]): void {
  const output = [...env.logs, ...env.errors].join("\n");
  for (const secret of secrets) {
    expect(output).not.toContain(secret);
  }
}
