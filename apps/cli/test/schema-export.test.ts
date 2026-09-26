// Tests for the valueless schema (design doc §1-6): `maruhi schema
// export` (derived-snapshot generation — the JSON Schema subset mapping,
// generated-marker framing, determinism) and `maruhi schema
// verify-snapshot` (CI drift check — fail-loud, names/field-names-only
// reporting, no descriptions in output). Both commands are pinned as the
// read-only, zero-value keyless class (no agent gate, no master key
// needed).

import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { masterKeyEntryName } from "../src/keychain.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedVariableStatement,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "dev";
const DESCRIPTION_URL = "Primary endpoint of the shop";

let owner: TestUser;
let built: BuiltChain;
let envStatement: WireDistributedEnvironmentStatement;
/** declared (required, url type, with a description). */
let declaredRequired: WireDistributedVariableStatement;
/** declared (required = false, no type, no description). */
let declaredOptional: WireDistributedVariableStatement;
/** active (number type, required). */
let activeNumber: WireDistributedVariableStatement;
/** active (v1 — no schema fields). */
let activeV1: WireDistributedVariableStatement;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  const dek = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  const head = { seq: 1, hashHex: built.projectId };
  envStatement = await environmentStatementFor({ ...common, name: ENV_ID, author: owner, head });
  declaredRequired = await statementFor({
    ...common,
    variableId: "v-shop-url",
    name: "SHOP_URL",
    author: owner,
    head,
    status: "declared",
    schema: { varType: "url", required: true, description: DESCRIPTION_URL },
  });
  declaredOptional = await statementFor({
    ...common,
    variableId: "v-optional",
    name: "OPTIONAL_HINT",
    author: owner,
    head,
    status: "declared",
    schema: { varType: "", required: false, description: "" },
  });
  activeNumber = await statementFor({
    ...common,
    variableId: "v-port",
    name: "PORT",
    author: owner,
    head,
    schema: { varType: "number", required: true, description: "listen port" },
  });
  activeV1 = await statementFor({
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
  return onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
    status: 200,
    json: {
      projectId: built.projectId,
      entries: built.entries,
      headSeq: built.entries.length,
      headHashHex: built.hashes[built.hashes.length - 1],
    },
  }));
}

/** A metadata-only pull response (declared variables live inside `variables` — §12-7). */
function metadataHandler(variables: readonly WireDistributedVariableStatement[]): MockHandler {
  return onRequest(
    "GET",
    `/projects/${built.projectId}/environments/${ENV_ID}/pull/metadata`,
    async () => ({
      status: 200,
      json: {
        environmentId: ENV_ID,
        currentEpoch: 1,
        statement: envStatement,
        variables,
        deletedVariables: [],
        manifest: await manifestFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          issuer: owner,
          head: headOf(built, 2),
          envStatement,
          statements: variables,
        }),
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

/** Extracts export's stdout (one line = the whole artifact). */
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
      // Names in UTF-16 ascending order (determinism). v1 = an empty
      // schema (no fabricated constraints), a "" type = no type keyword,
      // url = string + format uri, an empty description = omitted
      LEGACY_KEY: {},
      OPTIONAL_HINT: {},
      PORT: { type: "number", description: "listen port" },
      SHOP_URL: { type: "string", format: "uri", description: DESCRIPTION_URL },
    });
    // required = only statements with required = true (v1 doesn't get
    // in — required is never invented; optional doesn't either)
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
    // Positive guidance toward agents that have maruhi (§1-6)
    expect(comment).toContain("`maruhi schema`");
    expect(comment).toContain("verify-snapshot");
    // Types are treated as declarations — the artifact never uses the
    // word "verified" either (§14.3)
    expect(output.toLowerCase()).not.toContain("verified");
  });

  it("stdout is the artifact alone (no framing header lines mixed in even off-TTY — it can be committed via redirect)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    env.setTerminal({ stdout: false });
    expect(await runCli(["schema", "export"], env.layer)).toBe(0);
    // All of stdout is valid JSON as-is (the framing is the in-JSON
    // $comment's job)
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
    // The name is a free string from a signed statement — plain object
    // assignment gets eaten by the setter and the variable silently
    // vanishes from properties while surviving in required, a
    // self-contradictory artifact (undetectable even by byte comparison
    // since export and verify share the generator)
    const proto = await statementFor({
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
    // It also appears as an own key in the generated text itself
    // (JSON.parse creates an own key, but had the generator dropped it,
    // the string wouldn't contain it either)
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
  /** The state of export's output written verbatim to a file (the committed snapshot). */
  async function exportedSnapshotFile(): Promise<string> {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "export"], env.layer)).toBe(0);
    const dir = await mkdtemp(join(tmpdir(), "maruhi-snapshot-"));
    const file = join(dir, "maruhi-schema.json");
    // The same shape as a shell redirect (export > file) = generated
    // line + trailing newline
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
    // The description's contents (file-side or store-side) never reach
    // the terminal report (§2)
    expect(errors).not.toContain("Edited by hand");
    expect(errors).not.toContain(DESCRIPTION_URL);
    expect(errors).toContain("regenerate");
  });

  it("store progress (a new declaration) is detected as the committed snapshot going stale", async () => {
    const file = await exportedSnapshotFile();
    const added = await statementFor({
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
    // A different environment's file whose variable set happens to match
    // must not be collapsed into generic formatting-drift wording. The
    // file-side title contents (attacker-writable) stay out of the report
    const file = await exportedSnapshotFile();
    const { readFile: read } = await import("node:fs/promises");
    const parsed = JSON.parse(await read(file, "utf8")) as { title: string };
    parsed.title = "maruhi variables — environment prod-EVIL\u001b[31m";
    await writeFile(file, `${JSON.stringify(parsed, null, 2)}\n`);
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "verify-snapshot", file], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("generated for a different environment");
    // The file-side title contents are never carried to the terminal
    // report
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
