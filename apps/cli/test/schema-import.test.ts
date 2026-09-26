// Tests for `maruhi schema import` (design doc §1-3).
//
// Invariants pinned down:
//  1. **Ceremony-class deny (the ADR-0016 decision-7 pattern)**: known
//     agent detection and a non-interactive terminal are refused with a
//     typed error, and no blanket --yes exists. The gate runs before
//     any file read or communication
//  2. **Values are never sent**: values are used only for type
//     inference (observing the shape); no plaintext appears in sends,
//     displays, or logs. The single exception is the value push of an
//     activation the user explicitly chose per variable (E2EE —
//     plaintext never hits the wire)
//  3. Per-variable interactive approval (editable), the default skip
//     of existing names, and skipping rows that fail the name
//     acceptance constraint with a reason
//  4. The entropy warning (ruling CW) is a check on the description
//     candidate, and approving it as-is needs its own explicit
//     confirmation. The warning text never carries the detected value
//  5. Registration is serial per-variable compounds × manifest CAS
//     (O(N) round trips — finding F′)
//  6. The completion-time deletion offer defaults to no (only an
//     explicit y deletes)

import { existsSync } from "node:fs";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { observeValue, parseEnvFile } from "../src/env-file.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  makeTestUser,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { makeMetaEnvironmentServer, type MetaEnvironmentState } from "./support/meta-server.ts";
import { MockServer } from "./support/server.ts";

const ENV_ID = "dev";

let owner: TestUser;
let built: BuiltChain;
let dek1: Uint8Array;
let wrap1: WireRecipientDek;
let envStatement: WireDistributedEnvironmentStatement;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
  ]);
  wrap1 = await wrapDekFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    epoch: 1,
    dek: dek1,
    recipient: owner,
    signer: owner,
  });
  envStatement = await environmentStatementFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
  });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function startImportEnv(options?: {
  readonly initialVariables?: Parameters<typeof makeMetaEnvironmentServer>[0]["initialVariables"];
  readonly schemaPolicy?: "disabled" | "enabled" | "locked";
}): Promise<{ env: TestEnv; state: MetaEnvironmentState }> {
  const { state, handlers } = makeMetaEnvironmentServer({
    chain: built,
    owner,
    environmentId: ENV_ID,
    envStatement,
    initialVariables: options?.initialVariables ?? [],
    wrap: wrap1,
    ...(options?.schemaPolicy === undefined ? {} : { schemaPolicy: options.schemaPolicy }),
  });
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: built.projectId,
    defaultEnvironment: ENV_ID,
  });
  return { env, state };
}

/** Writes a .env file for the test into a temp directory. */
async function writeEnvFile(content: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "maruhi-import-test-"));
  const path = join(dir, ".env.example");
  await writeFile(path, content);
  return path;
}

function lastServer(): MockServer {
  const server = servers[servers.length - 1];
  if (server === undefined) {
    throw new Error("no mock server started");
  }
  return server;
}

/** Shorthand that inspects only observeValue's observation (the value is passed wrapped). */
function observe(text: string): ReturnType<typeof observeValue> {
  return observeValue(Redacted.make(text));
}

describe("parseEnvFile (the minimal .env parser — env-file.ts)", () => {
  it("interprets KEY=VALUE, an export prefix, quoting, and a preceding comment into a description candidate", () => {
    const parsed = parseEnvFile(
      [
        "# Primary endpoint",
        "# of the shop",
        "SHOP_URL=https://shop.example",
        "",
        "# far away comment",
        "",
        'export QUOTED="hello world"',
        "PLAIN=v",
      ].join("\n"),
    );
    expect(parsed.skipped).toEqual([]);
    expect(parsed.entries.map((entry) => entry.name)).toEqual(["SHOP_URL", "QUOTED", "PLAIN"]);
    // Consecutive comments join into a candidate and a blank line
    // breaks them (a distant comment isn't attached)
    expect(parsed.entries[0]?.descriptionCandidate).toBe("Primary endpoint of the shop");
    expect(parsed.entries[1]?.descriptionCandidate).toBe("");
    // The value is Redacted (plaintext never appears on the default
    // display/log paths)
    expect(String(parsed.entries[0]?.value)).not.toContain("shop.example");
    expect(Redacted.value(parsed.entries[1]!.value)).toBe("hello world");
  });

  it("unacceptable lines are skipped with a line number and a reason only (the content isn't carried)", () => {
    const parsed = parseEnvFile(
      ["just some text", "1BAD=x", "GOOD=1", "GOOD=2", "lower-case=x"].join("\n"),
    );
    expect(parsed.entries.map((entry) => entry.name)).toEqual(["GOOD"]);
    expect(parsed.skipped).toEqual([
      { line: 1, reason: "not-an-assignment" },
      { line: 2, reason: "invalid-name" },
      { line: 4, reason: "duplicate-name", name: "GOOD" },
      { line: 5, reason: "invalid-name" },
    ]);
  });

  it("an inline # comment on an unquoted value isn't part of the value (the dotenv / docker --env-file convention)", () => {
    const parsed = parseEnvFile("PORT=8080 # listen port\n");
    expect(Redacted.value(parsed.entries[0]!.value)).toBe("8080");
    expect(parsed.entries[0]?.valueFaithful).toBe(true);
    // Type inference works on the comment-stripped value
    expect(observe("8080")).toEqual({ varType: "number", looksReal: true });
  });

  it("values that can't be faithfully parsed (an unclosed quote, an escape inside a quoted value) get valueFaithful = false", () => {
    const parsed = parseEnvFile(
      ['BROKEN="multi', 'ESCAPED="a\\nb"', "SINGLE='it''s'", 'FINE="plain value"'].join("\n"),
    );
    const byName = new Map(parsed.entries.map((entry) => [entry.name, entry]));
    expect(byName.get("BROKEN")?.valueFaithful).toBe(false);
    expect(byName.get("ESCAPED")?.valueFaithful).toBe(false);
    expect(byName.get("SINGLE")?.valueFaithful).toBe(false);
    expect(byName.get("FINE")?.valueFaithful).toBe(true);
    expect(Redacted.value(byName.get("FINE")!.value)).toBe("plain value");
  });

  it("observeValue returns only shape observations (boolean / number / url / unspecified, real-value likeness)", () => {
    expect(observe("true")).toEqual({ varType: "boolean", looksReal: true });
    expect(observe("8080")).toEqual({ varType: "number", looksReal: true });
    expect(observe("https://shop.example")).toEqual({ varType: "url", looksReal: true });
    expect(observe("some-opaque-token")).toEqual({ varType: "", looksReal: true });
    // Empty and placeholder idioms aren't treated as real values (no
    // push offer is made at all)
    expect(observe("")).toEqual({ varType: "", looksReal: false });
    expect(observe("changeme")).toEqual({ varType: "", looksReal: false });
    expect(observe("<your key here>")).toEqual({ varType: "", looksReal: false });
    expect(observe("${SECRET}")).toEqual({ varType: "", looksReal: false });
    expect(observe("your_api_key")).toEqual({ varType: "", looksReal: false });
  });
});

describe("ceremony-class deny (the ADR-0016 decision-7 pattern — the gate precedes reads and communication)", () => {
  it("refuses with a typed error on known-agent detection (touches neither the file nor the network)", async () => {
    const { env } = await startImportEnv();
    env.setAgent({ isAgent: true, name: "testbot" });
    // A nonexistent path: if the gate precedes the file read, no file
    // error is emitted
    expect(await runCli(["schema", "import", "/nonexistent/.env"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("AI agent environment was detected (testbot)");
    expect(errors).toContain("maruhi schema");
    expect(errors).not.toContain("Could not read");
    expect(lastServer().requests).toEqual([]);
  });

  it("refuses a non-interactive environment (stdout not a terminal), and no --yes-equivalent bypass exists", async () => {
    const { env } = await startImportEnv();
    env.setTerminal({ stdout: false });
    expect(await runCli(["schema", "import", "/nonexistent/.env"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("stdout is not an interactive terminal");
    expect(lastServer().requests).toEqual([]);
  });

  it("likewise refuses stdin being a non-terminal (a pipe)", async () => {
    const { env } = await startImportEnv();
    env.setTerminal({ stdin: false });
    expect(await runCli(["schema", "import", "/nonexistent/.env"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("stdin is not an interactive terminal");
  });
});

describe("approval → declared registration (values are never sent)", () => {
  it("registers the approved ones as declared (type candidate, required defaulting to true, description from the comment)", async () => {
    const { env, state } = await startImportEnv();
    const file = await writeEnvFile(
      ["# Primary endpoint of the shop", "SHOP_URL=https://shop.example", "", "PORT=8080"].join(
        "\n",
      ),
    );
    // SHOP_URL: approve → decline the value push / PORT: approve →
    // decline / deletion offer: default (no)
    env.setPromptResponses(["y", "n", "y", "n", ""]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(state.mutations.map((m) => m.kind)).toEqual(["create", "create"]);
    const first = state.mutations[0]?.request.body as {
      statement: Record<string, unknown>;
      value?: unknown;
      manifest: Record<string, unknown>;
    };
    // No value is bundled (declared creation — §12-5). The type comes
    // from observing the value's shape
    expect(first.value).toBeUndefined();
    expect(first.statement["status"]).toBe("declared");
    expect(first.statement["metaVersion"]).toBe(1);
    expect(first.statement["layoutVersion"]).toBe(2);
    expect(first.statement["name"]).toBe("SHOP_URL");
    expect(first.statement["varType"]).toBe("url");
    expect(first.statement["required"]).toBe(true);
    expect(first.statement["description"]).toBe("Primary endpoint of the shop");
    const second = state.mutations[1]?.request.body as { statement: Record<string, unknown> };
    expect(second.statement["name"]).toBe("PORT");
    expect(second.statement["varType"]).toBe("number");
    expect(second.statement["description"]).toBe("");
    // The value itself appears in no request (observed only, never
    // sent)
    expect(JSON.stringify(lastServer().requests)).not.toContain("shop.example");
    const output = env.logs.join("\n");
    expect(output).toContain("Declared SHOP_URL");
    expect(output).toContain("Declared PORT");
    expect(output).toContain(
      "Import finished: 2 variables declared (0 with a value pushed), 0 candidates skipped",
    );
    // Neither the value nor fragments of it appear on stdout / stderr
    expect([...env.logs, ...env.errors].join("\n")).not.toContain("shop.example");
    expect(existsSync(file)).toBe(true);
  });

  it("candidates named the same as an existing active / declared are skipped and shown by default", async () => {
    const existing = await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "v-existing",
      name: "SHOP_URL",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
      status: "declared",
      schema: { varType: "url", required: true, description: "" },
    });
    const { env, state } = await startImportEnv({ initialVariables: [existing] });
    const file = await writeEnvFile(["SHOP_URL=x", "NEW_ONE="].join("\n"));
    env.setPromptResponses(["y", ""]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain(
      "Skipped SHOP_URL (line 1): a variable with this name already exists",
    );
    expect(state.mutations.map((m) => m.kind)).toEqual(["create"]);
    const created = state.mutations[0]?.request.body as {
      statement: Record<string, unknown>;
    };
    expect(created.statement["name"]).toBe("NEW_ONE");
  });

  it("can approve after editing (e) the name, type, required, and description", async () => {
    const { env, state } = await startImportEnv();
    const file = await writeEnvFile("db_url=\n");
    // db_url is a valid POSIX env-var name even in lowercase — edit
    // via e to set the name DATABASE_URL, type url, optional, and a
    // description, then approve
    env.setPromptResponses([
      "e",
      "DATABASE_URL",
      "url",
      "n",
      "Postgres connection string",
      "y",
      "",
    ]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    const body = state.mutations[0]?.request.body as { statement: Record<string, unknown> };
    expect(body.statement["name"]).toBe("DATABASE_URL");
    expect(body.statement["varType"]).toBe("url");
    expect(body.statement["required"]).toBe(false);
    expect(body.statement["description"]).toBe("Postgres connection string");
  });

  it("skip (s) doesn't register, and q processes no further candidates (the deletion offer doesn't appear either)", async () => {
    const { env, state } = await startImportEnv();
    const file = await writeEnvFile(["A=", "B=", "C="].join("\n"));
    env.setPromptResponses(["s", "q"]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(state.mutations).toEqual([]);
    const output = env.logs.join("\n");
    expect(output).toContain("stopped before the end");
    // After q, neither C's prompt nor the deletion offer appears (a
    // drained queue isn't an error = no additional prompts are
    // demanded)
    expect(env.prompts).toHaveLength(2);
    expect(existsSync(file)).toBe(true);
  });

  it("a rename via edit (e) is checked for form and length with the same acceptance set as the parser (don't let it fall through to a late 400)", async () => {
    const { env, state } = await startImportEnv();
    const file = await writeEnvFile("SHORT=\n");
    // A 257-char rename → warns and keeps the current → approve as-is
    env.setPromptResponses(["e", "A".repeat(257), "", "", "", "y", ""]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("at most 256 characters");
    const body = state.mutations[0]?.request.body as { statement: Record<string, unknown> };
    expect(body.statement["name"]).toBe("SHORT");
  });

  it("a rename via edit (e) must not collide with unprocessed candidates in the file (an early warning on a local collision)", async () => {
    const { env, state } = await startImportEnv();
    const file = await writeEnvFile(["ALPHA=", "BETA="].join("\n"));
    // Trying to rename ALPHA to BETA (a later candidate's name) →
    // warns and keeps the current → approve as-is. BETA is approved
    // too
    env.setPromptResponses(["e", "BETA", "", "", "", "y", "y", ""]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("already exists in the environment or in this import");
    const names = state.mutations.map(
      (m) => (m.request.body as { statement: Record<string, unknown> }).statement["name"],
    );
    expect(names).toEqual(["ALPHA", "BETA"]);
  });
});

describe("the explicit choice of a value push (activation)", () => {
  it("a real-looking value is pushed only on a per-variable explicit y, and plaintext never hits the wire", async () => {
    const { env, state } = await startImportEnv();
    const file = await writeEnvFile("TOKEN=real-secret-value-xyz\n");
    env.setPromptResponses(["y", "y", ""]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(state.mutations.map((m) => m.kind)).toEqual(["create", "activate"]);
    const activate = state.mutations[1]?.request.body as {
      statement: Record<string, unknown>;
      value: { aad: Record<string, unknown>; ciphertextHex: string };
    };
    // The activation compound (§12-5): value version 1 + status
    // active (metaVersion + 1)
    expect(activate.value.aad["version"]).toBe(1);
    expect(activate.statement["status"]).toBe("active");
    expect(activate.statement["metaVersion"]).toBe(2);
    // Plaintext appears in no request and no output (E2EE)
    expect(JSON.stringify(lastServer().requests)).not.toContain("real-secret-value-xyz");
    expect([...env.logs, ...env.errors].join("\n")).not.toContain("real-secret-value-xyz");
    expect(env.logs.join("\n")).toContain("Pushed the value of TOKEN (version=1, epoch=1)");
  });

  it("empty or placeholder values don't produce a push offer at all (the default is always not to send)", async () => {
    const { env, state } = await startImportEnv();
    const file = await writeEnvFile(["EMPTY=", "PLACEHOLDER=changeme"].join("\n"));
    // Only 2 approvals + 1 deletion offer (no push prompt exists)
    env.setPromptResponses(["y", "y", ""]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(state.mutations.map((m) => m.kind)).toEqual(["create", "create"]);
    expect(env.prompts).toHaveLength(3);
  });

  it("a value that can't be faithfully parsed gets no push offer (fail-closed — never sends a misread value)", async () => {
    const { env, state } = await startImportEnv();
    // An unclosed quote (the shape of line 1 of a multi-line quoted
    // value) — a real value, but this parser can't claim to have
    // reconstructed it faithfully
    const file = await writeEnvFile('CERT="-----BEGIN RSA\n');
    env.setPromptResponses(["y", ""]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    // It's declared, but no activation happens and no push prompt
    // appears
    expect(state.mutations.map((m) => m.kind)).toEqual(["create"]);
    expect(env.prompts).toHaveLength(2);
    expect(env.errors.join("\n")).toContain("could not be parsed faithfully");
  });
});

describe("the entropy warning (ruling CW — applied to the description candidate)", () => {
  // A dummy that merely looks like a real value (not an actual secret)
  const FAKE_TOKEN = "x7Gh2kQ9pLmA3vB8nC4dE5fJ6hK7iL8m";

  it("approving a detection needs a dedicated explicit confirmation, and the warning text carries no detected value", async () => {
    const { env, state } = await startImportEnv();
    const file = await writeEnvFile([`# token ${FAKE_TOKEN} here`, "API_HINT=changeme"].join("\n"));
    env.setPromptResponses([
      "y", // tries to approve → routed to the explicit confirmation
      "no", // declines the confirmation → back to the approval loop
      "e", // edit strips the real-looking run from the description
      "", // keep the name
      "", // keep the type
      "", // keep required
      "API hint only", // replaces the description
      "y", // approves with no warning
      "", // the deletion offer (default no)
    ]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    const body = state.mutations[0]?.request.body as { statement: Record<string, unknown> };
    expect(body.statement["description"]).toBe("API hint only");
    const warningLines = env.errors.filter((line) => line.includes("secret-like high-entropy"));
    expect(warningLines.length).toBeGreaterThan(0);
    // The warning itself carries no detected value (which could be a
    // secret) — length and kind only
    for (const line of warningLines) {
      expect(line).not.toContain(FAKE_TOKEN);
      expect(line).toContain("32-character");
    }
    // The real-looking run never hits the wire (the edit removed it)
    expect(JSON.stringify(lastServer().requests)).not.toContain(FAKE_TOKEN);
  });
});

describe("the completion-time deletion offer (default is not to delete)", () => {
  it("the default (an empty answer) keeps the file and emits guidance", async () => {
    const { env } = await startImportEnv();
    const file = await writeEnvFile("A=\n");
    env.setPromptResponses(["y", ""]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(existsSync(file)).toBe(true);
    expect(env.errors.join("\n")).toContain("was kept");
  });

  it("deletes the source file only on an explicit y", async () => {
    const { env } = await startImportEnv();
    const file = await writeEnvFile("A=\n");
    env.setPromptResponses(["y", "y"]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(existsSync(file)).toBe(false);
    expect(env.logs.join("\n")).toContain("Deleted");
  });

  it("a run with skipped candidates doesn't make the offer (only when every candidate was declared)", async () => {
    const { env, state } = await startImportEnv();
    const file = await writeEnvFile(["A=", "B="].join("\n"));
    // A declared, B skipped → the file's 'last job' isn't finished
    env.setPromptResponses(["y", "s"]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(state.mutations.map((m) => m.kind)).toEqual(["create"]);
    // Only 2 approval prompts (no deletion offer)
    expect(env.prompts).toHaveLength(2);
    expect(existsSync(file)).toBe(true);
  });

  it("no offer either for a file that still has unparsed lines", async () => {
    const { env } = await startImportEnv();
    const file = await writeEnvFile(["A=", "not an assignment line"].join("\n"));
    env.setPromptResponses(["y"]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(1);
    expect(existsSync(file)).toBe(true);
  });
});

describe("around the acceptance surface (advisory, serial O(N) — finding F′)", () => {
  it("the disabled advisory is shown once across the whole import", async () => {
    const { env } = await startImportEnv({ schemaPolicy: "disabled" });
    const file = await writeEnvFile(["A=", "B="].join("\n"));
    env.setPromptResponses(["y", "y", ""]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    const notices = env.errors.filter((line) => line.includes("schema policy as disabled"));
    expect(notices).toHaveLength(1);
  });

  it("registration is serial per-variable compounds — 3 round trips per declaration (resolve + compound + effect check)", async () => {
    // The pinned measured shape of finding F′: N declarations = 1
    // initial resolve + N × (1 resolve + 1 create + 1 effect check). No
    // bulk compound acceptance
    const { env, state } = await startImportEnv();
    const file = await writeEnvFile(["A=", "B=", "C="].join("\n"));
    env.setPromptResponses(["y", "y", "y", ""]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(state.mutations.map((m) => m.kind)).toEqual(["create", "create", "create"]);
    const requests = lastServer().requests;
    expect(requests.filter((request) => request.path.endsWith("/chain"))).toHaveLength(1);
    expect(requests.filter((request) => request.path.endsWith("/pull/metadata"))).toHaveLength(
      1 + 3 * 2,
    );
    expect(
      requests.filter(
        (request) => request.method === "POST" && request.path.endsWith("/variables"),
      ),
    ).toHaveLength(3);
  });
});
