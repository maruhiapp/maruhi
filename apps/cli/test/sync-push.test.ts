import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { decryptVariable } from "@maruhi/crypto";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  distributedEnvironmentStatement,
  distributedValue,
  distributedVariableStatement,
  distributedWrap,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  headOf,
  hexBytes,
  testEnvironmentId,
  testProjectId,
  testVariableId,
  type WireDistributedEnvironmentStatement,
  type WireEncryptedPayload,
  type WireRecipientDek,
} from "@maruhi/test-kit";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { cliError } from "../src/errors.ts";
import { receiptVariableName } from "../src/sync.package/sync-receipt.ts";
import {
  type ExecCall,
  makeTestEnv,
  seedConfig,
  seedSession,
  type TestEnv,
} from "./support/env.ts";
import { MockServer } from "./support/server.ts";
import {
  makeValueEnvironmentServer,
  type StoredVariable,
  type ValueEnvironmentState,
} from "./support/value-env.ts";

const SOURCE_ENV = "prod";
const RECEIPTS_ENV = "sync-receipts";
const ALPHA_VALUE = "alpha-value-3";
const BETA_VALUE = "beta-value-1";
const NEW_VALUE = "alpha-value-4-pushed";
const SECRETS = [ALPHA_VALUE, BETA_VALUE, NEW_VALUE];
const OTHER_PROJECT = "f".repeat(64);

let owner: GeneratedIdentity;
let built: BuiltChain;
let dekSource: Uint8Array;
let dekReceipts: Uint8Array;
let wrapSource: WireRecipientDek;
let wrapReceipts: WireRecipientDek;
let sourceStatement: WireDistributedEnvironmentStatement;
let receiptsStatement: WireDistributedEnvironmentStatement;
let servers: MockServer[] = [];
const originalCwd = process.cwd();

beforeAll(async () => {
  owner = await generateIdentity("user-owner-1111");
  dekSource = crypto.getRandomValues(new Uint8Array(32));
  dekReceipts = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(SOURCE_ENV, dekSource) },
    { actor: owner, operation: createEnvironmentOp(RECEIPTS_ENV, dekReceipts) },
  ]);
  const common = { projectId: built.projectId, recipient: owner, signer: owner, epoch: 1 };
  wrapSource = await distributedWrap({ ...common, environmentId: SOURCE_ENV, dek: dekSource });
  wrapReceipts = await distributedWrap({
    ...common,
    environmentId: RECEIPTS_ENV,
    dek: dekReceipts,
  });
  const head = { seq: 1, hashHex: built.projectId };
  sourceStatement = await distributedEnvironmentStatement({
    projectId: built.projectId,
    environmentId: SOURCE_ENV,
    name: SOURCE_ENV,
    author: owner,
    head,
  });
  receiptsStatement = await distributedEnvironmentStatement({
    projectId: built.projectId,
    environmentId: RECEIPTS_ENV,
    name: RECEIPTS_ENV,
    author: owner,
    head,
  });
});

afterEach(async () => {
  process.chdir(originalCwd);
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function sourceVariable(input: {
  readonly variableId: string;
  readonly name: string;
  readonly version: number;
  readonly plaintext: string;
}): Promise<StoredVariable> {
  const statement = await distributedVariableStatement({
    projectId: built.projectId,
    environmentId: SOURCE_ENV,
    variableId: input.variableId,
    name: input.name,
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
  });
  const value = await distributedValue({
    dek: dekSource,
    projectId: built.projectId,
    environmentId: SOURCE_ENV,
    epoch: 1,
    variableId: input.variableId,
    version: input.version,
    plaintext: input.plaintext,
    writer: owner,
    head: headOf(built, 2),
  });
  return { variableId: input.variableId, statement, value };
}

async function storedReceipt(input: {
  readonly target: string;
  readonly variables: Readonly<Record<string, number>>;
  readonly version?: number;
}): Promise<StoredVariable> {
  const variableId = `receipt-${input.target}`;
  const statement = await distributedVariableStatement({
    projectId: built.projectId,
    environmentId: RECEIPTS_ENV,
    variableId,
    name: receiptVariableName(input.target),
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
  });
  const value = await distributedValue({
    dek: dekReceipts,
    projectId: built.projectId,
    environmentId: RECEIPTS_ENV,
    epoch: 1,
    variableId,
    version: input.version ?? 1,
    plaintext: JSON.stringify({
      version: 1,
      target: input.target,
      preset: "vercel",
      syncedAt: "2026-09-05T00:00:00.000Z",
      variables: input.variables,
    }),
    writer: owner,
    head: headOf(built, 3),
  });
  return { variableId, statement, value };
}

interface Fixture {
  readonly env: TestEnv;
  readonly source: ValueEnvironmentState;
  readonly receipts: ValueEnvironmentState;
  readonly configDir: string;
  readonly configPath: string;
  readonly server: MockServer;
}

function previewTarget(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    preset: "vercel",
    environment: SOURCE_ENV,
    variables: ["ALPHA", "BETA"],
    options: { environment: "preview" },
    onPush: "apply",
    ...overrides,
  };
}

function config(
  targets: Record<string, unknown>,
  root: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    version: 1,
    project: built.projectId,
    receipts: { environment: RECEIPTS_ENV },
    targets,
    ...root,
  };
}

async function startFixture(input: {
  readonly config: Record<string, unknown>;
  readonly receipts?: readonly StoredVariable[];
}): Promise<Fixture> {
  const source = makeValueEnvironmentServer({
    chain: built,
    owner,
    environmentId: SOURCE_ENV,
    envStatement: sourceStatement,
    wrap: wrapSource,
    initialVariables: await Promise.all([
      sourceVariable({ variableId: "va", name: "ALPHA", version: 3, plaintext: ALPHA_VALUE }),
      sourceVariable({ variableId: "vb", name: "BETA", version: 1, plaintext: BETA_VALUE }),
    ]),
  });
  const receipts = makeValueEnvironmentServer({
    chain: built,
    owner,
    environmentId: RECEIPTS_ENV,
    envStatement: receiptsStatement,
    wrap: wrapReceipts,
    initialVariables: input.receipts ?? [],
  });
  const server = await MockServer.start([...source.handlers, ...receipts.handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
  const configDir = await mkdtemp(join(tmpdir(), "maruhi-sync-push-test-"));
  const configPath = join(configDir, "maruhi.sync.json");
  await writeFile(configPath, JSON.stringify(input.config));
  return { env, source: source.state, receipts: receipts.state, configDir, configPath, server };
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function push(fixture: Fixture, value: string, ...args: string[]): Promise<number> {
  return pushNamed(fixture, "ALPHA", value, ...args);
}

function pushNamed(
  fixture: Fixture,
  name: string,
  value: string,
  ...args: string[]
): Promise<number> {
  fixture.env.setStdin(encoder.encode(value));
  return runCli(["push", name, "--env", SOURCE_ENV, ...args], fixture.env.layer);
}

function pushWithConfig(fixture: Fixture, value: string, ...args: string[]): Promise<number> {
  return push(fixture, value, "--config", fixture.configPath, ...args);
}

function allOutput(env: TestEnv): string {
  return [...env.logs, ...env.errors].join("\n");
}

function expectNoSecretLeak(env: TestEnv): void {
  const shown = [
    allOutput(env),
    ...env.execCalls.flatMap((call) => [...call.command, ...Object.values(call.extraEnv)]),
  ].join("\n");
  for (const secret of SECRETS) {
    expect(shown).not.toContain(secret);
  }
}

function stdinText(call: ExecCall): string {
  return decoder.decode(call.stdin);
}

function receiptsRequests(fixture: Fixture): number {
  return fixture.server.requests.filter((request) =>
    request.path.includes(`/environments/${RECEIPTS_ENV}/`),
  ).length;
}

async function decryptReceipt(fixture: Fixture, target: string): Promise<Record<string, unknown>> {
  const stored = fixture.receipts.variables.find(
    (entry) => entry.statement.name === receiptVariableName(target),
  );
  expect(stored).toBeDefined();
  const value = stored?.value as WireEncryptedPayload;
  const result = await decryptVariable({
    dek: dekReceipts,
    context: {
      ...value.aad,
      projectId: testProjectId(value.aad.projectId),
      environmentId: testEnvironmentId(value.aad.environmentId),
      variableId: testVariableId(value.aad.variableId),
    },
    nonce: hexBytes(value.nonceHex),
    ciphertext: hexBytes(value.ciphertextHex),
  });
  if (!result.ok) {
    throw new Error("receipt decrypt failed in test");
  }
  return JSON.parse(decoder.decode(result.value)) as Record<string, unknown>;
}

const PUSHED_LINE = "Pushed ALPHA (version=4, epoch=1)";

describe("maruhi push → direct apply (onPush: apply)", () => {
  it("after the push report, writes only the just-pushed variables to the vendor CLI's stdin and advances the receipt (unchanged rows are skipped)", async () => {
    const fixture = await startFixture({
      config: config({ web: previewTarget() }),
      receipts: [await storedReceipt({ target: "web", variables: { ALPHA: 3, BETA: 1 } })],
    });
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    const out = fixture.env.logs.join("\n");
    expect(out.indexOf(PUSHED_LINE)).toBeGreaterThanOrEqual(0);
    expect(out.indexOf("Syncing target web after the push")).toBeGreaterThan(
      out.indexOf(PUSHED_LINE),
    );
    expect(out).toContain(`Syncing target web after the push (onPush in ${fixture.configPath})`);
    expect(out).toContain("0 to add, 1 to update, 0 to delete, 1 unchanged, 0 blocked");
    expect(out).toContain("~ ALPHA\tversion 3 -> 4");
    expect(out).not.toContain("= BETA");
    expect(out).toContain(
      "Applied to target web: 1 variable written, 0 deleted. Receipt saved as version 2 of sync-receipt:web in environment sync-receipts",
    );
    const calls = fixture.env.execCalls;
    expect(calls.map((call) => call.command)).toEqual([
      ["vercel", "env", "add", "ALPHA", "preview", "--force", "--non-interactive"],
    ]);
    expect(calls.map(stdinText)).toEqual([NEW_VALUE]);
    expect(calls[0]?.cwd).toBe(fixture.configDir);
    expectNoSecretLeak(fixture.env);
    expect(await decryptReceipt(fixture, "web")).toMatchObject({
      target: "web",
      variables: { ALPHA: 4, BETA: 1 },
    });
    expect(fixture.env.errors.join("\n")).not.toMatch(
      /sync config|synced|Warning: (?!no reserve key)/,
    );
  });

  it("silently reads cwd's default path (maruhi.sync.json) when `project` matches", async () => {
    const fixture = await startFixture({
      config: config({ web: previewTarget() }),
      receipts: [await storedReceipt({ target: "web", variables: { ALPHA: 3, BETA: 1 } })],
    });
    process.chdir(fixture.configDir);
    expect(await push(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(
      "Syncing target web after the push (onPush in maruhi.sync.json)",
    );
    expect(fixture.env.execCalls).toHaveLength(1);
    expect(await decryptReceipt(fixture, "web")).toMatchObject({
      variables: { ALPHA: 4, BETA: 1 },
    });
  });

  it("pushing a first-time variable (a new name): the plan is +, the value hits stdin once, and version 1 lands on the receipt", async () => {
    const fixture = await startFixture({
      config: config({ web: previewTarget({ variables: ["ALPHA", "BETA", "GAMMA"] }) }),
      receipts: [await storedReceipt({ target: "web", variables: { ALPHA: 3, BETA: 1 } })],
    });
    expect(await pushNamed(fixture, "GAMMA", NEW_VALUE, "--config", fixture.configPath)).toBe(0);
    const out = fixture.env.logs.join("\n");
    expect(out).toContain("Pushed GAMMA (version=1, epoch=1)");
    expect(out).toContain("1 to add, 0 to update, 0 to delete, 2 unchanged, 0 blocked");
    expect(out).toContain("+ GAMMA\tversion 1 (new)");
    expect(fixture.env.execCalls.map((call) => call.command)).toEqual([
      ["vercel", "env", "add", "GAMMA", "preview", "--force", "--non-interactive"],
    ]);
    expect(fixture.env.execCalls.map(stdinText)).toEqual([NEW_VALUE]);
    expect(await decryptReceipt(fixture, "web")).toMatchObject({
      variables: { ALPHA: 3, BETA: 1, GAMMA: 1 },
    });
    expectNoSecretLeak(fixture.env);
  });

  it("--no-sync with --config is a usage error (2) and no push is sent", async () => {
    const fixture = await startFixture({ config: config({ web: previewTarget() }) });
    expect(await pushWithConfig(fixture, NEW_VALUE, "--no-sync")).toBe(2);
    expect(fixture.env.errors.join("\n")).toContain("--no-sync and --config cannot be combined");
    expect(fixture.source.writes).toEqual([]);
  });

  it("targets naming a runner in the default-path config (command / workflow.command) aren't run, with a note (an explicit --config would run them)", async () => {
    const fixture = await startFixture({
      config: config({
        tool: previewTarget({ command: "tools/vercel" }),
        web: previewTarget(),
        ci: previewTarget({
          options: { environment: "production" },
          onPush: "workflow",
          workflow: { file: "maruhi-sync.yml", command: "tools/gh" },
        }),
        spelled: previewTarget({ command: "vercel" }),
        dispatch: previewTarget({
          options: { environment: "production" },
          onPush: "workflow",
          workflow: { file: "maruhi-sync.yml" },
        }),
      }),
      receipts: [await storedReceipt({ target: "web", variables: { ALPHA: 3, BETA: 1 } })],
    });
    process.chdir(fixture.configDir);
    expect(await push(fixture, NEW_VALUE)).toBe(0);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "Note: target tool names the program to run (its command in maruhi.sync.json), and a config found in the working directory does not start one after a push. Run `maruhi sync apply tool` now, or pass --config maruhi.sync.json on the next push",
    );
    expect(errors).toContain("Note: target ci names the program to run");
    expect(errors).toContain("Note: target spelled names the program to run");
    expect(errors).not.toContain("Note: target dispatch names");
    expect(fixture.env.execCalls.map((call) => call.command[0])).toEqual(["vercel", "gh"]);
    expect(await decryptReceipt(fixture, "web")).toMatchObject({
      variables: { ALPHA: 4, BETA: 1 },
    });

    const explicit = await startFixture({
      config: config({ tool: previewTarget({ command: "tools/vercel" }) }),
    });
    expect(await pushWithConfig(explicit, NEW_VALUE)).toBe(0);
    expect(explicit.env.execCalls.map((call) => call.command[0])).toEqual([
      "tools/vercel",
      "tools/vercel",
    ]);
    expect(explicit.env.errors.join("\n")).not.toContain("names the program to run");
  });

  it("--no-sync: reads no config and only pushes (0 vendor CLIs, 0 requests to the receipts environment)", async () => {
    const fixture = await startFixture({ config: config({ web: previewTarget() }) });
    process.chdir(fixture.configDir);
    expect(await push(fixture, NEW_VALUE, "--no-sync")).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(PUSHED_LINE);
    expect(fixture.env.logs.join("\n")).not.toContain("Syncing");
    expect(fixture.env.execCalls).toEqual([]);
    expect(receiptsRequests(fixture)).toBe(0);
  });

  it("with no config in cwd it's the traditional push (reads nothing, says nothing)", async () => {
    const fixture = await startFixture({ config: config({ web: previewTarget() }) });
    expect(await push(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(PUSHED_LINE);
    expect(fixture.env.execCalls).toEqual([]);
    expect(receiptsRequests(fixture)).toBe(0);
    expect(fixture.env.errors.join("\n")).not.toMatch(
      /sync config|synced|Warning: (?!no reserve key)/,
    );
  });

  it("an explicit --config belonging to a different project is a usage error (2) and no push is sent", async () => {
    const fixture = await startFixture({
      config: config({ web: previewTarget() }, { project: OTHER_PROJECT }),
    });
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(2);
    expect(fixture.env.errors.join("\n")).toContain(
      "The sync config belongs to a different project",
    );
    expect(fixture.source.writes).toEqual([]);
    expect(fixture.env.execCalls).toEqual([]);
  });

  it("a default-path config for a different project lets the push proceed and notes it does nothing", async () => {
    const fixture = await startFixture({
      config: config({ web: previewTarget() }, { project: OTHER_PROJECT }),
    });
    process.chdir(fixture.configDir);
    expect(await push(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(PUSHED_LINE);
    expect(fixture.env.errors.join("\n")).toContain(
      "Note: the sync config maruhi.sync.json belongs to a different project, so nothing was synced after the push",
    );
    expect(fixture.env.execCalls).toEqual([]);
    expect(receiptsRequests(fixture)).toBe(0);
  });

  it("a config with no onPush at all never looks at project (not a 2 for a different project, and silent)", async () => {
    const fixture = await startFixture({
      config: config({ manual: previewTarget({ onPush: undefined }) }, { project: OTHER_PROJECT }),
    });
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(PUSHED_LINE);
    expect(fixture.env.errors.join("\n")).toContain("no target in the sync config copies");
    expect(fixture.env.errors.join("\n")).not.toContain("different project");
  });

  it("a broken default-path config fails before the push (not silently skipped)", async () => {
    const fixture = await startFixture({ config: config({ web: previewTarget() }) });
    await writeFile(fixture.configPath, "{ not json");
    process.chdir(fixture.configDir);
    expect(await push(fixture, NEW_VALUE)).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain("The sync config maruhi.sync.json is invalid");
    expect(fixture.server.requests).toEqual([]);
    expect(fixture.source.writes).toEqual([]);
  });

  it("no onPush target carrying from the pushed environment does nothing (an explicit --config gets a note)", async () => {
    const fixture = await startFixture({
      config: config({
        other: previewTarget({ environment: "staging" }),
        beta: previewTarget({ variables: ["BETA"] }),
        manual: previewTarget({ onPush: undefined }),
      }),
    });
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(PUSHED_LINE);
    expect(fixture.env.errors.join("\n")).toContain(
      "Note: no target in the sync config copies this variable from environment prod on push, so nothing was synced",
    );
    expect(fixture.env.execCalls).toEqual([]);
    expect(receiptsRequests(fixture)).toBe(0);

    const quiet = await startFixture({
      config: config({ manual: previewTarget({ onPush: undefined }) }),
    });
    process.chdir(quiet.configDir);
    expect(await push(quiet, NEW_VALUE)).toBe(0);
    expect(quiet.env.errors.join("\n")).not.toMatch(
      /sync config|synced|Warning: (?!no reserve key)/,
    );
  });

  it("after the push, the checkpoint proposal comes first and the sync after it", async () => {
    const fixture = await startFixture({
      config: config({ beta: previewTarget({ variables: ["BETA"] }) }),
    });
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    const errors = fixture.env.errors.join("\n");
    const proposal = errors.indexOf(
      "Note: this project's checkpoint baseline is more than 7 days behind (or was never issued). Run `maruhi project checkpoint` to refresh the rollback-detection baseline (CRYPTO_SPEC §6.3). If this project commits a repository anchor for CI",
    );
    expect(proposal).toBeGreaterThanOrEqual(0);
    expect(
      errors.indexOf(
        "Note: no target in the sync config copies this variable from environment prod on push",
      ),
    ).toBeGreaterThan(proposal);
  });

  it("a production target isn't pushed under onPush as-is (apply is refused at the config stage)", async () => {
    const fixture = await startFixture({
      config: config({
        web: previewTarget({ options: { environment: "production" } }),
      }),
    });
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      'targets.web.onPush cannot be "apply" for a production target',
    );
    expect(fixture.source.writes).toEqual([]);
  });

  it("a vendor-CLI failure is a warning and push's exit code stays 0 (the receipt doesn't advance)", async () => {
    const fixture = await startFixture({
      config: config({ web: previewTarget() }),
      receipts: [await storedReceipt({ target: "web", variables: { ALPHA: 3, BETA: 1 } })],
    });
    fixture.env.setExecHandler(() => ({ exitCode: 1, output: `nope ${NEW_VALUE}\n` }));
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    const errors = fixture.env.errors.join("\n");
    expect(fixture.env.logs.join("\n")).toContain(PUSHED_LINE);
    expect(errors).toContain(
      "Warning: the push is done, but target web could not be synced (vercel exited with code 1 while writing ALPHA",
    );
    expect(errors).toContain(
      "The next `maruhi sync plan web` shows the pushed variable as pending; `maruhi sync apply web` or CI delivers it",
    );
    expect(errors).toContain("  vercel: nope [redacted]");
    expectNoSecretLeak(fixture.env);
    expect(fixture.receipts.writes).toEqual([]);

    expect(
      await runCli(["sync", "plan", "web", "--config", fixture.configPath], fixture.env.layer),
    ).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain("~ ALPHA\tversion 3 -> 4");
  });

  it("a missing vendor CLI (launch failure) is also a warning with 0 (a launch failure is that invocation's failure — worded in failDriver's shape)", async () => {
    const fixture = await startFixture({ config: config({ web: previewTarget() }) });
    fixture.env.setExecHandler(() =>
      cliError("Cannot start vercel (ENOENT): is it installed and on PATH"),
    );
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "Warning: the push is done, but target web could not be synced (vercel could not be started while writing ALPHA (delivered before that: 0 variables written, 0 deleted). Cannot start vercel (ENOENT): is it installed and on PATH.",
    );
    expect(fixture.receipts.writes).toEqual([]);
  });

  it("an uncarryable value (Vercel's trailing newline) is a warning and the value is never sent", async () => {
    const fixture = await startFixture({ config: config({ web: previewTarget() }) });
    expect(await pushWithConfig(fixture, `${NEW_VALUE}\n\n`)).toBe(0);
    expect(fixture.env.errors.join("\n")).toContain(
      "Warning: the push is done, but target web could not be synced (Variable ALPHA is a single line ending with a newline",
    );
    expect(fixture.env.execCalls).toEqual([]);
    expectNoSecretLeak(fixture.env);
  });

  it("a verification refusal of the receipts environment (the evidence) isn't folded into a warning — it surfaces as a failure (the push report already went out)", async () => {
    const newer = await storedReceipt({
      target: "web",
      variables: { ALPHA: 3, BETA: 1 },
      version: 2,
    });
    const older = await storedReceipt({ target: "web", variables: { ALPHA: 3 }, version: 1 });
    const fixture = await startFixture({
      config: config({ web: previewTarget() }),
      receipts: [newer],
    });
    expect(
      await runCli(["sync", "plan", "web", "--config", fixture.configPath], fixture.env.layer),
    ).toBe(0);
    const stored = fixture.receipts.variables[0];
    if (stored === undefined) throw new Error("receipt missing");
    stored.value = older.value;
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(1);
    expect(fixture.env.logs.join("\n")).toContain(PUSHED_LINE);
    expect(fixture.env.errors.join("\n")).toContain("value-version rollback");
    expect(fixture.env.errors.join("\n")).not.toContain("could not be synced");
    expect(fixture.env.execCalls).toEqual([]);
  });
});

describe("maruhi push → CI trigger (onPush: workflow)", () => {
  const workflowTarget = (overrides: Record<string, unknown> = {}) =>
    previewTarget({
      options: { environment: "production" },
      onPush: "workflow",
      workflow: { file: "maruhi-sync.yml" },
      ...overrides,
    });

  it("gh workflow run's argv is just the target name and workflow (no values or variable names), stdin is empty, telemetry off, and the receipt is untouched", async () => {
    const fixture = await startFixture({
      config: config({
        web: workflowTarget({ workflow: { file: "maruhi-sync.yml", ref: "main" } }),
      }),
    });
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    const calls = fixture.env.execCalls;
    expect(calls.map((call) => call.command)).toEqual([
      ["gh", "workflow", "run", "maruhi-sync.yml", "-f", "target=web", "--ref", "main"],
    ]);
    expect(calls[0]?.cwd).toBe(fixture.configDir);
    expect(calls[0]?.extraEnv).toEqual({
      GH_TELEMETRY: "false",
      DO_NOT_TRACK: "1",
      GH_NO_UPDATE_NOTIFIER: "1",
      GH_PROMPT_DISABLED: "1",
    });
    expect(calls[0]?.stdin).toHaveLength(0);
    expect(calls[0]?.command.join(" ")).not.toContain("ALPHA");
    expectNoSecretLeak(fixture.env);
    const out = fixture.env.logs.join("\n");
    expect(out.indexOf("Triggered workflow")).toBeGreaterThan(out.indexOf(PUSHED_LINE));
    expect(out).toContain(
      `Triggered workflow maruhi-sync.yml for target web (\`gh workflow run\` in ${fixture.configDir}). CI applies it with \`maruhi ci sync\` and keeps no receipt, so the next local \`maruhi sync plan web\` still shows the pushed variable as pending`,
    );
    expect(receiptsRequests(fixture)).toBe(0);
    expect(fixture.receipts.writes).toEqual([]);
  });

  it("no --ref (default = gh picks the repo's default branch) and the command override", async () => {
    const fixture = await startFixture({
      config: config({
        web: workflowTarget({ workflow: { file: "maruhi-sync.yml", command: "tools/gh" } }),
      }),
    });
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.execCalls.map((call) => call.command)).toEqual([
      ["tools/gh", "workflow", "run", "maruhi-sync.yml", "-f", "target=web"],
    ]);
  });

  it("gh's exit code 4 = names 'not logged in' and warns with 0", async () => {
    const fixture = await startFixture({ config: config({ web: workflowTarget() }) });
    fixture.env.setExecHandler(() => ({ exitCode: 4, output: "" }));
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.errors.join("\n")).toContain(
      "Warning: the push is done, but workflow maruhi-sync.yml was not triggered for target web: gh is not signed in (run `gh auth login`, or trigger the workflow yourself). The next `maruhi sync plan web` shows the pushed variable as pending",
    );
  });

  it("gh's nonzero (workflow missing, no dispatch) warns with 0 and appends the output's tail", async () => {
    const fixture = await startFixture({ config: config({ web: workflowTarget() }) });
    fixture.env.setExecHandler(() => ({
      exitCode: 1,
      output: "could not find any workflows named maruhi-sync.yml\n\u001b[31mred\u001b[0m\n",
    }));
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain("  gh: could not find any workflows named maruhi-sync.yml");
    expect(errors).not.toContain("\u001b");
    expect(errors).toContain(
      'Warning: the push is done, but workflow maruhi-sync.yml was not triggered for target web (gh exited with code 1; its output is shown above). Check that the workflow exists on the branch gh dispatches to and has a workflow_dispatch trigger with a "target" input',
    );
  });

  it("no gh (launch failure) is a warning with 0", async () => {
    const fixture = await startFixture({ config: config({ web: workflowTarget() }) });
    fixture.env.setExecHandler(() =>
      cliError("Cannot start gh (ENOENT): is it installed and on PATH"),
    );
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.errors.join("\n")).toContain(
      "Warning: the push is done, but target web could not be synced (Cannot start gh (ENOENT)",
    );
  });

  it("multiple targets of the same environment: direct apply and the CI launch each run once in config order; one failure doesn't stop the rest", async () => {
    const fixture = await startFixture({
      config: config({
        preview: previewTarget(),
        web: workflowTarget(),
      }),
      receipts: [await storedReceipt({ target: "preview", variables: { ALPHA: 3, BETA: 1 } })],
    });
    fixture.env.setExecHandler((call) =>
      call.command[0] === "vercel" ? { exitCode: 1, output: "" } : { exitCode: 0, output: "" },
    );
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.execCalls.map((call) => call.command[0])).toEqual(["vercel", "gh"]);
    expect(fixture.env.errors.join("\n")).toContain("target preview could not be synced");
    expect(fixture.env.logs.join("\n")).toContain(
      "Triggered workflow maruhi-sync.yml for target web",
    );
  });
});
