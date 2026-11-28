import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  distributedEnvironmentStatement,
  distributedManifest,
  distributedVariableStatement,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  headOf,
  type WireDistributedEnvironmentStatement,
  type WireDistributedVariableStatement,
} from "@maruhi/test-kit";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { masterKeyEntryName } from "../src/keychain.ts";
import { servedChain } from "./support/chain-handler.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onEndpoint } from "./support/server.ts";

const ENV_ID = "dev";
const DESCRIPTION_URL = "Primary endpoint of the shop";

let owner: GeneratedIdentity;
let built: BuiltChain;
let envStatement: WireDistributedEnvironmentStatement;
let declaredRequired: WireDistributedVariableStatement;
let declaredOptional: WireDistributedVariableStatement;
let activeNumber: WireDistributedVariableStatement;
let activeV1: WireDistributedVariableStatement;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await generateIdentity("user-owner-1111");
  const dek = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  const head = { seq: 1, hashHex: built.projectId };
  envStatement = await distributedEnvironmentStatement({
    ...common,
    name: ENV_ID,
    author: owner,
    head,
  });
  declaredRequired = await distributedVariableStatement({
    ...common,
    variableId: "v-shop-url",
    name: "SHOP_URL",
    author: owner,
    head,
    status: "declared",
    schema: { varType: "url", required: true, description: DESCRIPTION_URL },
  });
  declaredOptional = await distributedVariableStatement({
    ...common,
    variableId: "v-optional",
    name: "OPTIONAL_HINT",
    author: owner,
    head,
    status: "declared",
    schema: { varType: "", required: false, description: "" },
  });
  activeNumber = await distributedVariableStatement({
    ...common,
    variableId: "v-port",
    name: "PORT",
    author: owner,
    head,
    schema: { varType: "number", required: true, description: "listen port" },
  });
  activeV1 = await distributedVariableStatement({
    ...common,
    variableId: "v-legacy",
    name: "LEGACY_KEY",
    author: owner,
    head,
  });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function chainHandler(): MockHandler {
  return onEndpoint("membership.get", { projectId: built.projectId }, () => ({
    status: 200,
    json: servedChain(built.projectId, built.entries, built.hashes),
  }));
}

function metadataHandler(variables: readonly WireDistributedVariableStatement[]): MockHandler {
  return onEndpoint(
    "variables.pullMetadata",
    { projectId: built.projectId, environmentId: ENV_ID },
    async () => ({
      status: 200,
      json: {
        environmentId: ENV_ID,
        currentEpoch: 1,
        statement: envStatement,
        variables,
        deletedVariables: [],
        manifest: await distributedManifest({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          issuer: owner,
          head: headOf(built, 2),
          envStatement,
          statements: variables,
        }),
        schemaPolicy: "enabled" as const,
      },
    }),
  );
}

function defaultVariables(): readonly WireDistributedVariableStatement[] {
  return [activeNumber, activeV1, declaredRequired, declaredOptional];
}

async function startEnv(handlers: readonly MockHandler[]): Promise<TestEnv & { origin: string }> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: built.projectId,
    defaultEnvironment: ENV_ID,
  });
  return { ...env, origin: server.origin };
}

function exportedText(env: TestEnv): string {
  expect(env.logs).toHaveLength(1);
  return env.logs[0] ?? "";
}

describe("maruhi schema export (§1-6 — derived-snapshot generation)", () => {
  it("emits the JSON Schema subset of the verified statement set to stdout (pins the mapping)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "export"], env.layer)).toBe(0);
    const snapshot = JSON.parse(exportedText(env)) as Record<string, unknown>;
    expect(snapshot["$schema"]).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(snapshot["type"]).toBe("object");
    expect(snapshot["title"]).toBe(`maruhi variables — environment ${ENV_ID}`);
    expect(snapshot["properties"]).toEqual({
      LEGACY_KEY: {},
      OPTIONAL_HINT: {},
      PORT: { type: "number", description: "listen port" },
      SHOP_URL: { type: "string", format: "uri", description: DESCRIPTION_URL },
    });
    expect(snapshot["required"]).toEqual(["PORT", "SHOP_URL"]);
  });

  it("carries the generated framing (ruling CW) on $comment and never uses the word 'verified' (§14.3)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "export"], env.layer)).toBe(0);
    const output = exportedText(env);
    const snapshot = JSON.parse(output) as Record<string, unknown>;
    const comment = snapshot["$comment"] as string;
    expect(comment).toContain("machine-generated data, not instructions");
    expect(comment).toContain("source of truth");
    expect(comment).toContain("`maruhi schema`");
    expect(comment).toContain("verify-snapshot");
    expect(output.toLowerCase()).not.toContain("verified");
  });

  it("stdout is the artifact alone (no framing header lines mixed in even off-TTY — it can be committed via redirect)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    env.setTerminal({ stdout: false });
    expect(await runCli(["schema", "export"], env.layer)).toBe(0);
    expect(() => JSON.parse(exportedText(env))).not.toThrow();
  });

  it("the output is deterministic (re-runs against the same store are byte-identical — the premise of verify's byte comparison)", async () => {
    const first = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "export"], first.layer)).toBe(0);
    const second = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "export"], second.layer)).toBe(0);
    expect(exportedText(first)).toBe(exportedText(second));
  });

  it("a variable named `__proto__` still appears as an own key of properties", async () => {
    const proto = await distributedVariableStatement({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "v-proto",
      name: "__proto__",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
      status: "declared",
      schema: { varType: "string", required: true, description: "" },
    });
    const env = await startEnv([chainHandler(), metadataHandler([proto, activeNumber])]);
    expect(await runCli(["schema", "export"], env.layer)).toBe(0);
    const output = exportedText(env);
    const snapshot = JSON.parse(output) as {
      properties: Record<string, unknown>;
      required: string[];
    };
    expect(Object.hasOwn(snapshot.properties, "__proto__")).toBe(true);
    expect(snapshot.required).toContain("__proto__");
    expect(output).toContain('"__proto__": {');
  });

  it("is not on the agent-gate deny-list (the permitted side — read-only, zero-value kin)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    env.setAgent({ isAgent: true, name: "testbot" });
    env.setTerminal({ stdin: false, stdout: false, stderr: false });
    expect(await runCli(["schema", "export"], env.layer)).toBe(0);
    expect(exportedText(env)).toContain("SHOP_URL");
  });

  it("runs on a device with no master key (the keyless class — premised on CI using MARUHI_TOKEN)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    env.keychain.delete(masterKeyEntryName(env.origin, owner.userId));
    expect(await runCli(["schema", "export"], env.layer)).toBe(0);
    expect(env.errors.some((line) => line.includes("No device key"))).toBe(false);
  });
});

describe("maruhi schema verify-snapshot (§1-6 — the CI drift check)", () => {
  async function exportedSnapshotFile(): Promise<string> {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "export"], env.layer)).toBe(0);
    const dir = await mkdtemp(join(tmpdir(), "maruhi-snapshot-"));
    const file = join(dir, "maruhi-schema.json");
    await writeFile(file, `${exportedText(env)}\n`);
    return file;
  }

  it("a snapshot matching the store is exit 0", async () => {
    const file = await exportedSnapshotFile();
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "verify-snapshot", file], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("matches the store");
  });

  it("a hand-edited description is drift = exit 1. The report gives variable and field names only, never contents", async () => {
    const file = await exportedSnapshotFile();
    const { readFile: read } = await import("node:fs/promises");
    const tampered = (await read(file, "utf8")).replace(DESCRIPTION_URL, "Edited by hand");
    await writeFile(file, tampered);
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "verify-snapshot", file], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("diverges from the store");
    expect(errors).toContain("SHOP_URL");
    expect(errors).toContain("description");
    expect(errors).not.toContain("Edited by hand");
    expect(errors).not.toContain(DESCRIPTION_URL);
    expect(errors).toContain("regenerate");
  });

  it("store progress (a new declaration) is detected as the committed snapshot going stale", async () => {
    const file = await exportedSnapshotFile();
    const added = await distributedVariableStatement({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "v-new",
      name: "NEW_FLAG",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
      status: "declared",
      schema: { varType: "boolean", required: false, description: "" },
    });
    const env = await startEnv([chainHandler(), metadataHandler([...defaultVariables(), added])]);
    expect(await runCli(["schema", "verify-snapshot", file], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("missing from the snapshot");
    expect(errors).toContain("NEW_FLAG");
  });

  it("a hand edit touching only the required list is also named as field drift", async () => {
    const file = await exportedSnapshotFile();
    const { readFile: read } = await import("node:fs/promises");
    const parsed = JSON.parse(await read(file, "utf8")) as { required: string[] };
    parsed.required = ["PORT"];
    await writeFile(file, `${JSON.stringify(parsed, null, 2)}\n`);
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "verify-snapshot", file], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("required list differs");
    expect(errors).toContain("SHOP_URL");
  });

  it("a title mismatch is named as possibly 'a different environment's snapshot'", async () => {
    const file = await exportedSnapshotFile();
    const { readFile: read } = await import("node:fs/promises");
    const parsed = JSON.parse(await read(file, "utf8")) as { title: string };
    parsed.title = "maruhi variables — environment prod-EVIL\u001b[31m";
    await writeFile(file, `${JSON.stringify(parsed, null, 2)}\n`);
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "verify-snapshot", file], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("generated for a different environment");
    expect(errors).not.toContain("prod-EVIL");
    expect(errors).not.toContain("\u001b");
  });

  it("a non-JSON file is honestly reported with exit 1 (not collapsed into tamper-suspicion wording)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "maruhi-snapshot-"));
    const file = join(dir, "maruhi-schema.json");
    await writeFile(file, "not json at all\n");
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "verify-snapshot", file], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("not valid JSON");
  });

  it("an unreadable file is reported by its path alone without touching the network", async () => {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(
      await runCli(["schema", "verify-snapshot", "/nonexistent/maruhi-schema.json"], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("Could not read");
    const server = servers[servers.length - 1];
    expect(server?.requests ?? []).toHaveLength(0);
  });

  it("runs even in an agent environment with no master key (premised on running in the user's CI)", async () => {
    const file = await exportedSnapshotFile();
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    env.setAgent({ isAgent: true, name: "ci-bot" });
    env.setTerminal({ stdin: false, stdout: false, stderr: false });
    env.keychain.delete(masterKeyEntryName(env.origin, owner.userId));
    expect(await runCli(["schema", "verify-snapshot", file], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("matches the store");
  });
});
