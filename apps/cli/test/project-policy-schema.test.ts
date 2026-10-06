// Wire-level tests for `maruhi project policy schema` (AUTH_SPEC §12-11).
//
// What it pins down:
// - Bare = show (one GET, no PUT); `--set <tier>` = GET + PUT, and the
//   PUT is sent even when the tier is already set (the server's same-value
//   PUT is a no-op without an audit row)
// - `--set` is a closed set (enabled | locked): anything else, the removed
//   `disabled` included, is a usage error before any request
// - A 403 for the role names what it needs; the command runs under an
//   agent (it displays no value)
// - The 422 the policy produces (schema-required) renders with the next
//   step and counts as a settled server rejection

import { SchemaPolicyRejectedError } from "@maruhi/api-schema";
import { afterEach, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { isServerRejection, toCliError } from "../src/failure.ts";
import { makeTestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

const PROJECT = "a".repeat(64);
const POLICY_PATH = `/projects/${PROJECT}/schema-policy`;

/** A server holding one policy value: GET reads it, PUT replaces it. */
function policyHandlers(initial: "enabled" | "locked"): MockHandler[] {
  let current = initial;
  return [
    onRequest("GET", POLICY_PATH, () => ({ status: 200, json: { schemaPolicy: current } })),
    onRequest("PUT", POLICY_PATH, (request) => {
      current = (request.body as { schemaPolicy: "enabled" | "locked" }).schemaPolicy;
      return { status: 204 };
    }),
  ];
}

async function startEnv(handlers: MockHandler[]): Promise<{ env: TestEnv; server: MockServer }> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const owner = await makeTestUser("user-owner-1111");
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, { server: server.origin, defaultProject: PROJECT });
  return { env, server };
}

const puts = (server: MockServer) =>
  server.requests.filter((request) => request.method === "PUT" && request.path === POLICY_PATH);

describe("maruhi project policy schema", () => {
  it("no flag shows the policy and changes nothing", async () => {
    const { env, server } = await startEnv(policyHandlers("enabled"));
    expect(await runCli(["project", "policy", "schema"], env.layer)).toBe(0);
    expect(env.logs).toEqual([
      "Schema policy: enabled — creating a variable without a declared type is allowed",
    ]);
    expect(puts(server)).toHaveLength(0);
  });

  it("--set locked sends the PUT and reports the transition", async () => {
    const { env, server } = await startEnv(policyHandlers("enabled"));
    expect(await runCli(["project", "policy", "schema", "--set", "locked"], env.layer)).toBe(0);
    expect(puts(server).map((request) => request.body)).toEqual([{ schemaPolicy: "locked" }]);
    expect(env.logs.join("\n")).toContain("Schema policy: enabled → locked");
    expect(env.logs.join("\n")).toContain("creating a variable requires a declared type");
  });

  it("--set to the current tier still sends the PUT and says it is unchanged", async () => {
    const { env, server } = await startEnv(policyHandlers("locked"));
    expect(await runCli(["project", "policy", "schema", "--set", "locked"], env.layer)).toBe(0);
    expect(puts(server)).toHaveLength(1);
    expect(env.logs.join("\n")).toContain("Schema policy is already locked");
  });

  it("a tier outside enabled | locked (disabled included) is a usage error before any request", async () => {
    for (const tier of ["disabled", "Locked"]) {
      const { env, server } = await startEnv(policyHandlers("enabled"));
      expect(await runCli(["project", "policy", "schema", "--set", tier], env.layer), tier).toBe(2);
      expect(env.errors.join("\n")).toContain("--set must be one of enabled | locked");
      expect(server.requests).toHaveLength(0);
    }
  });

  it("a 403 for the role names the admin role it needs (exit 1)", async () => {
    const { env } = await startEnv([
      onRequest("GET", POLICY_PATH, () => ({ status: 200, json: { schemaPolicy: "enabled" } })),
      onRequest("PUT", POLICY_PATH, () => ({
        status: 403,
        json: { _tag: "Forbidden", reason: "insufficient-role" },
      })),
    ]);
    expect(await runCli(["project", "policy", "schema", "--set", "locked"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "changing the schema policy needs the admin role on this project",
    );
  });

  it("runs under an agent (the policy is not a value)", async () => {
    const { env } = await startEnv(policyHandlers("locked"));
    env.setAgent({ isAgent: true, name: "test-agent" });
    env.setTerminal({ stdin: false, stdout: false, stderr: false });
    expect(await runCli(["project", "policy", "schema"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("Schema policy: locked");
  });
});

describe("the schema-required rejection (422)", () => {
  it("renders with the next step and is a settled server rejection", () => {
    const error = new SchemaPolicyRejectedError({ reason: "schema-required" });
    expect(toCliError(error).message).toContain("maruhi schema set NAME --type");
    expect(isServerRejection(error)).toBe(true);
  });
});
