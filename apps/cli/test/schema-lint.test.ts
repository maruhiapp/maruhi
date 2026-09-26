// Tests for the valueless-schema lint (design doc §1-7): `maruhi schema
// lint` — static scanning of env references in source, cross-checked
// against the store-side schema. Pins its best-effort positioning
// (always-on caveat output), name-only reports (no descriptions), the
// exit-code asymmetry (undeclared = exit 1 / unread only = exit 0), and
// the keyless class.

import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { masterKeyEntryName } from "../src/keychain.ts";
import { scanEnvReferences } from "../src/schema-lint.ts";
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
const SECRET_DESCRIPTION = "Endpoint description that must never reach the lint report";

let owner: TestUser;
let built: BuiltChain;
let envStatement: WireDistributedEnvironmentStatement;
/** declared (url type, with a description) — the side the code reads. */
let declaredShopUrl: WireDistributedVariableStatement;
/** active (v1 — no schema fields) — the name exists in the store. */
let activeV1: WireDistributedVariableStatement;
/** declared — the side no code reads. */
let declaredUnread: WireDistributedVariableStatement;
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
  declaredShopUrl = await statementFor({
    ...common,
    variableId: "v-shop-url",
    name: "SHOP_URL",
    author: owner,
    head,
    status: "declared",
    schema: { varType: "url", required: true, description: SECRET_DESCRIPTION },
  });
  activeV1 = await statementFor({
    ...common,
    variableId: "v-legacy",
    name: "LEGACY_KEY",
    author: owner,
    head,
  });
  declaredUnread = await statementFor({
    ...common,
    variableId: "v-unread",
    name: "UNREAD_FLAG",
    author: owner,
    head,
    status: "declared",
    schema: { varType: "boolean", required: false, description: "" },
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
  return [declaredShopUrl, activeV1, declaredUnread];
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

/** Writes a source tree (path → contents) under a temp directory. Returns the root path. */
async function sourceTree(files: Readonly<Record<string, string>>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "maruhi-lint-"));
  for (const [path, content] of Object.entries(files)) {
    const target = join(root, path);
    await mkdir(join(target, ".."), { recursive: true });
    await writeFile(target, content);
  }
  return root;
}

describe("scanEnvReferences (the scanner — the verbatim shape of the implementation rulings)", () => {
  it("picks up the major runtimes' static verbatim env references", () => {
    const found = scanEnvReferences(
      [
        "const a = process.env.SHOP_URL;",
        'const b = process.env["BRACKET_VAR"];',
        "const c = import.meta.env.VITE_FLAG;",
        "const d = Bun.env.BUN_VAR;",
        'const e = Deno.env.get("DENO_VAR");',
        'x = os.environ["PY_BRACKET"]',
        'y = os.environ.get("PY_GET", "default")',
        'z = os.getenv("PY_GETENV")',
        'v, ok := os.LookupEnv("GO_LOOKUP")',
        'w := os.Getenv("GO_VAR")',
        'r = ENV["RUBY_VAR"]',
        's = ENV.fetch("RUBY_FETCH")',
        'let t = std::env::var("RUST_VAR")?;',
        'let u = env::var_os("RUST_OS_VAR");',
      ].join("\n"),
    );
    expect([...found].toSorted()).toEqual([
      "BRACKET_VAR",
      "BUN_VAR",
      "DENO_VAR",
      "GO_LOOKUP",
      "GO_VAR",
      "PY_BRACKET",
      "PY_GET",
      "PY_GETENV",
      "RUBY_FETCH",
      "RUBY_VAR",
      "RUST_OS_VAR",
      "RUST_VAR",
      "SHOP_URL",
      "VITE_FLAG",
    ]);
  });

  it("picks up destructuring of the env object and optional chaining", () => {
    const found = scanEnvReferences(
      [
        "const { FOO, BAR: renamed, BAZ = 'fallback' } = process.env;",
        "const {",
        "  MULTI_LINE_VAR,",
        '  "QUOTED_VAR": q,',
        "} = process.env;",
        "const { BUN_DESTRUCTURED } = Bun.env;",
        "const { VITE_DESTRUCTURED } = import.meta.env;",
        "const opt = process.env?.OPT_CHAINED;",
        "const optMeta = import.meta.env?.OPT_META;",
      ].join("\n"),
    );
    expect([...found].toSorted()).toEqual([
      "BAR",
      "BAZ",
      "BUN_DESTRUCTURED",
      "FOO",
      "MULTI_LINE_VAR",
      "OPT_CHAINED",
      "OPT_META",
      "QUOTED_VAR",
      "VITE_DESTRUCTURED",
    ]);
  });

  it("skips destructuring rest, non-env right sides, and non-identifier keys", () => {
    const found = scanEnvReferences(
      [
        "const { ...rest } = process.env;",
        "const { a, b } = notprocess.env;",
        "const { c } = someObject;",
        "const { d } = MY_ENV;",
      ].join("\n"),
    );
    // rest doesn't fit the identifier shape; a non-env right side fails
    // the left-boundary + right-side pinning
    expect(found.size).toBe(0);
  });

  it("doesn't pick up references whose identifier tail happens to match the shape (the left boundary)", () => {
    const found = scanEnvReferences(
      [
        'const a = MY_ENV["FOO"];',
        'const b = TEST_ENV.fetch("BAR");',
        "const c = myprocess.env.BAZ;",
        'x = chaos.getenv("QUX")',
      ].join("\n"),
    );
    expect(found.size).toBe(0);
    // The bare shape keeps being picked up (the boundary addition must
    // not drop the positive case)
    expect([...scanEnvReferences('ENV["RUBY_VAR"]')]).toEqual(["RUBY_VAR"]);
  });

  it("dynamic access is not picked up (the best-effort line — don't pretend it's detectable)", () => {
    const found = scanEnvReferences(
      ["const name = 'DYNAMIC';", "const v = process.env[name];", "const w = os.environ[key]"].join(
        "\n",
      ),
    );
    expect(found.size).toBe(0);
  });
});

describe("maruhi schema lint (§1-7 — the code-contract cross-check)", () => {
  it("detects names the code reads but the store doesn't declare, exit 1 (fail-loud)", async () => {
    const root = await sourceTree({
      "src/config.ts":
        "export const url = process.env.SHOP_URL;\nconst k = process.env.MISSING_VAR;\n",
    });
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", root], env.layer)).toBe(1);
    const output = env.logs.join("\n");
    expect(output).toContain(
      `Read by the scanned code but not declared in environment ${ENV_ID}: 1`,
    );
    expect(output).toContain("MISSING_VAR");
    // Declared references don't appear under undeclared (a v1 variable's
    // name still exists in the store)
    expect(output).not.toContain("  SHOP_URL");
    const errors = env.errors.join("\n");
    expect(errors).toContain("not declared in environment");
    expect(errors).toContain("--ignore");
  });

  it("declared-but-unread names are reported but stay exit 0 (dynamic access / another repo may consume them)", async () => {
    const root = await sourceTree({
      "src/config.ts":
        "export const url = process.env.SHOP_URL;\nconst legacy = process.env.LEGACY_KEY;\n",
    });
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", root], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain(
      `Declared in environment ${ENV_ID} but not read by the scanned code: 1`,
    );
    expect(output).toContain("UNREAD_FLAG");
  });

  it("the report is variable names only — no description on any line (§1-7 / §2)", async () => {
    const root = await sourceTree({
      "src/config.ts": "export const url = process.env.SHOP_URL;\n",
    });
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", root], env.layer)).toBe(0);
    const all = [...env.logs, ...env.errors].join("\n");
    expect(all).not.toContain(SECRET_DESCRIPTION);
    // Types are declarations — the report never uses the word
    // "verified" (§14.3)
    expect(all.toLowerCase()).not.toContain("verified");
  });

  it("always prints the best-effort caveat to stderr regardless of outcome (a check gap ≠ a guarantee gap)", async () => {
    const clean = await sourceTree({
      "src/config.ts": "export const url = process.env.SHOP_URL;\n",
    });
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", clean], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("best-effort static scan");
    expect(env.errors.join("\n")).toContain("not a guarantee");
  });

  it("--ignore excludes names from the undeclared check (runtime variables outside maruhi's management)", async () => {
    const root = await sourceTree({
      "src/config.ts": "const mode = process.env.NODE_ENV;\nconst u = process.env.SHOP_URL;\n",
    });
    const failing = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", root], failing.layer)).toBe(1);
    const passing = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", root, "--ignore", "NODE_ENV"], passing.layer)).toBe(0);
    expect(passing.logs.join("\n")).not.toContain("NODE_ENV");
  });

  it("doesn't scan dependency/generated directories like node_modules and .git", async () => {
    const root = await sourceTree({
      "src/app.ts": "const u = process.env.SHOP_URL;\n",
      "node_modules/pkg/index.js": "const x = process.env.DEP_ONLY_VAR;\n",
      ".git/hooks/sample.py": 'x = os.getenv("GIT_HOOK_VAR")\n',
    });
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", root], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).not.toContain("DEP_ONLY_VAR");
    expect(output).not.toContain("GIT_HOOK_VAR");
  });

  it("always prints the count line even at zero (the output shape doesn't vary per run)", async () => {
    const root = await sourceTree({
      "src/app.ts":
        "const a = process.env.SHOP_URL;\nconst b = process.env.LEGACY_KEY;\nconst c = process.env.UNREAD_FLAG;\n",
    });
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", root], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain(
      `Read by the scanned code but not declared in environment ${ENV_ID}: 0`,
    );
    expect(output).toContain(
      `Declared in environment ${ENV_ID} but not read by the scanned code: 0`,
    );
  });

  it("a nonexistent path reports a scan error before any networking", async () => {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", "/nonexistent/source-dir"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Could not scan");
    // The scan failure precedes any server round-trip (not a single
    // request is made)
    const server = servers[servers.length - 1];
    expect(server?.requests ?? []).toHaveLength(0);
  });

  it("runs even in an agent environment with no master key (pins agent-gate non-application — CI premise)", async () => {
    const root = await sourceTree({
      "src/app.ts": "const u = process.env.SHOP_URL;\n",
    });
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    env.setAgent({ isAgent: true, name: "ci-bot" });
    env.setTerminal({ stdin: false, stdout: false, stderr: false });
    env.keychain.delete(masterKeyEntryName(env.origin, owner.userId));
    expect(await runCli(["schema", "lint", root], env.layer)).toBe(0);
  });
});
