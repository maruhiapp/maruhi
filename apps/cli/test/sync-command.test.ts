// Tests for `maruhi sync plan` / `sync apply`: repository config →
// reading the receipts environment → verifying the sync source (plan
// never decrypts) → driving the vendor CLIs (values on stdin only) →
// writing the receipts (a signed push per §4.1).
//
// Properties pinned down: values never appear on argv / stdout / stderr
// / error text, the stdin format (wrangler = a single JSON, Vercel = the
// value itself), the telemetry-off env vars, production defaults to plan
// only (`--yes`), only the receipt's diff is written, a failure leaves
// only what arrived on the receipt, blocked values send nothing, and
// config validation. The vendor CLIs are fake ProcessRunners (recording
// argv / cwd / env / stdin).

import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { decryptVariable } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { cliError } from "../src/errors.ts";
import { receiptVariableName } from "../src/sync-receipt.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  hexBytes,
  makeTestUser,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedVariableStatement,
  type WireEncryptedPayload,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
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
const BETA_VALUE = "beta line 1\nbeta line 2\n";
const SECRETS = [ALPHA_VALUE, "beta line 1", "beta line 2"];

let owner: TestUser;
let built: BuiltChain;
let dekSource: Uint8Array;
let dekReceipts: Uint8Array;
let wrapSource: WireRecipientDek;
let wrapReceipts: WireRecipientDek;
let sourceStatement: WireDistributedEnvironmentStatement;
let receiptsStatement: WireDistributedEnvironmentStatement;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dekSource = crypto.getRandomValues(new Uint8Array(32));
  dekReceipts = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(SOURCE_ENV, dekSource) },
    { actor: owner, operation: createEnvironmentOp(RECEIPTS_ENV, dekReceipts) },
  ]);
  const common = { projectId: built.projectId, recipient: owner, signer: owner, epoch: 1 };
  wrapSource = await wrapDekFor({ ...common, environmentId: SOURCE_ENV, dek: dekSource });
  wrapReceipts = await wrapDekFor({ ...common, environmentId: RECEIPTS_ENV, dek: dekReceipts });
  const head = { seq: 1, hashHex: built.projectId };
  sourceStatement = await environmentStatementFor({
    projectId: built.projectId,
    environmentId: SOURCE_ENV,
    name: SOURCE_ENV,
    author: owner,
    head,
  });
  receiptsStatement = await environmentStatementFor({
    projectId: built.projectId,
    environmentId: RECEIPTS_ENV,
    name: RECEIPTS_ENV,
    author: owner,
    head,
  });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

/** One variable on the sync source (statement + value; takes version and required). */
async function sourceVariable(input: {
  readonly variableId: string;
  readonly name: string;
  readonly version: number;
  readonly plaintext: string | Uint8Array;
  readonly required?: boolean;
}): Promise<StoredVariable> {
  const statement = await statementFor({
    projectId: built.projectId,
    environmentId: SOURCE_ENV,
    variableId: input.variableId,
    name: input.name,
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
    ...(input.required === undefined
      ? {}
      : { schema: { varType: "", required: input.required, description: "" } }),
  });
  const value = await encryptValueFor({
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

/** An existing receipt placed on the receipts environment (the previous sync's result). */
async function storedReceipt(input: {
  readonly target: string;
  readonly preset: "vercel" | "cloudflare-workers" | "github-actions";
  readonly variables: Readonly<Record<string, number>>;
  readonly version?: number;
}): Promise<StoredVariable> {
  const variableId = `receipt-${input.target}`;
  const statement = await statementFor({
    projectId: built.projectId,
    environmentId: RECEIPTS_ENV,
    variableId,
    name: receiptVariableName(input.target),
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
  });
  const value = await encryptValueFor({
    dek: dekReceipts,
    projectId: built.projectId,
    environmentId: RECEIPTS_ENV,
    epoch: 1,
    variableId,
    version: input.version ?? 1,
    plaintext: JSON.stringify({
      version: 1,
      target: input.target,
      preset: input.preset,
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
}

/** The default config (a Vercel production target `web` and a Workers staging target `worker`). */
function defaultConfig(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: 1,
    receipts: { environment: RECEIPTS_ENV },
    targets: {
      web: {
        preset: "vercel",
        environment: SOURCE_ENV,
        variables: ["ALPHA", "BETA"],
        options: { environment: "production" },
      },
      worker: {
        preset: "cloudflare-workers",
        environment: SOURCE_ENV,
        variables: "all",
        cwd: "apps/worker",
        options: { environment: "staging", name: "my-worker" },
      },
    },
    ...overrides,
  };
}

async function startFixture(input: {
  readonly sourceVariables?: readonly StoredVariable[];
  readonly declared?: readonly WireDistributedVariableStatement[];
  readonly receipts?: readonly StoredVariable[];
  readonly config?: Record<string, unknown> | string;
}): Promise<Fixture> {
  const sourceVariables =
    input.sourceVariables ??
    (await Promise.all([
      sourceVariable({ variableId: "va", name: "ALPHA", version: 3, plaintext: ALPHA_VALUE }),
      sourceVariable({ variableId: "vb", name: "BETA", version: 1, plaintext: BETA_VALUE }),
    ]));
  const source = makeValueEnvironmentServer({
    chain: built,
    owner,
    environmentId: SOURCE_ENV,
    envStatement: sourceStatement,
    wrap: wrapSource,
    initialVariables: sourceVariables,
    initialDeclared: input.declared ?? [],
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
  const configDir = await mkdtemp(join(tmpdir(), "maruhi-sync-test-"));
  const configPath = join(configDir, "maruhi.sync.json");
  const config = input.config ?? defaultConfig();
  await writeFile(configPath, typeof config === "string" ? config : JSON.stringify(config));
  return { env, source: source.state, receipts: receipts.state, configDir, configPath };
}

function sync(fixture: Fixture, ...args: string[]): Promise<number> {
  return runCli(["sync", ...args, "--config", fixture.configPath], fixture.env.layer);
}

function allOutput(env: TestEnv): string {
  return [...env.logs, ...env.errors].join("\n");
}

/** The value (and each line of a multi-line value) appears nowhere on stdout / stderr / argv. */
function expectNoSecretLeak(env: TestEnv): void {
  const shown = [
    allOutput(env),
    ...env.execCalls.flatMap((call) => [...call.command, ...Object.values(call.extraEnv)]),
  ].join("\n");
  for (const secret of SECRETS) {
    expect(shown).not.toContain(secret);
  }
}

const decoder = new TextDecoder();

async function decryptReceipt(fixture: Fixture, target: string): Promise<Record<string, unknown>> {
  const stored = fixture.receipts.variables.find(
    (entry) => entry.statement.name === receiptVariableName(target),
  );
  expect(stored).toBeDefined();
  const value = stored?.value as WireEncryptedPayload;
  const result = await decryptVariable({
    dek: dekReceipts,
    context: value.aad,
    nonce: hexBytes(value.nonceHex),
    ciphertext: hexBytes(value.ciphertextHex),
  });
  if (!result.ok) {
    throw new Error("receipt decrypt failed in test");
  }
  return JSON.parse(decoder.decode(result.value)) as Record<string, unknown>;
}

function stdinText(call: ExecCall): string {
  return decoder.decode(call.stdin);
}

describe("maruhi sync plan", () => {
  it("first run (no receipt): shows every variable as new with names and versions only, and neither decrypts nor launches a vendor CLI", async () => {
    const fixture = await startFixture({});
    expect(await sync(fixture, "plan", "web")).toBe(0);
    const out = fixture.env.logs.join("\n");
    expect(out).toContain(
      "Sync plan for target web (environment prod -> vercel production via exec): 2 to add, 0 to update, 0 to delete, 0 unchanged, 0 blocked",
    );
    expect(out).toContain("Last delivery: none");
    expect(out).toContain("+ ALPHA\tversion 3 (new)");
    expect(out).toContain("+ BETA\tversion 1 (new)");
    expect(fixture.env.execCalls).toEqual([]);
    // Guides that production's default is plan only (apply needs --yes)
    expect(fixture.env.errors.join("\n")).toContain("`maruhi sync apply web` needs --yes");
    expectNoSecretLeak(fixture.env);
    // Never calls the variable-write API (plan only reads; the
    // head-declaration PUT is part of the earlier sync and touches
    // neither values nor metadata)
    const server = servers[0] as MockServer;
    expect(
      server.requests.filter(
        (request) => request.method !== "GET" && request.path.includes("/variables"),
      ),
    ).toEqual([]);
  });

  it("cross-checks the receipt and versions and shows update / unchanged / delete (the sync target is never read back)", async () => {
    const fixture = await startFixture({
      receipts: [
        await storedReceipt({
          target: "web",
          preset: "vercel",
          variables: { ALPHA: 2, BETA: 1, OLD_NAME: 4 },
        }),
      ],
    });
    expect(await sync(fixture, "plan", "web")).toBe(0);
    const out = fixture.env.logs.join("\n");
    expect(out).toContain("0 to add, 1 to update, 1 to delete, 1 unchanged, 0 blocked");
    expect(out).toContain("~ ALPHA\tversion 2 -> 3");
    expect(out).toContain("= BETA\tversion 1 (unchanged)");
    expect(out).toContain("- OLD_NAME\t(no longer synced; last delivered version 4)");
    expect(out).toContain("Last delivery: 2026-09-05T00:00:00.000Z (receipt sync-receipt:web)");
    expect(fixture.env.execCalls).toEqual([]);
  });

  it("blocked values (Vercel: empty, over 16 KiB) are marked !, exit 1 (and apply sends nothing)", async () => {
    const fixture = await startFixture({
      sourceVariables: [
        await sourceVariable({ variableId: "ve", name: "EMPTY", version: 1, plaintext: "" }),
        await sourceVariable({
          variableId: "vl",
          name: "LARGE",
          version: 2,
          plaintext: "x".repeat(16 * 1024 + 1),
        }),
        await sourceVariable({
          variableId: "va",
          name: "ALPHA",
          version: 3,
          plaintext: ALPHA_VALUE,
        }),
      ],
      config: defaultConfig({
        targets: {
          web: {
            preset: "vercel",
            environment: SOURCE_ENV,
            variables: ["ALPHA", "EMPTY", "LARGE"],
            options: { environment: "production" },
          },
        },
      }),
    });
    expect(await sync(fixture, "plan", "web")).toBe(1);
    const out = fixture.env.logs.join("\n");
    expect(out).toContain("! EMPTY\tversion 1 (cannot be synced: empty value");
    expect(out).toContain(
      "! LARGE\tversion 2 (cannot be synced: 16385 bytes, above the 16384-byte limit",
    );
    expect(out).toContain("+ ALPHA\tversion 3 (new)");
    expect(fixture.env.errors.join("\n")).toContain(
      "2 variables cannot be synced with this driver",
    );
    expect(await sync(fixture, "apply", "web", "--yes")).toBe(1);
    expect(fixture.env.execCalls).toEqual([]);
    expect(fixture.receipts.writes).toEqual([]);
  });

  it("a name absent from the config's explicit list stops without carrying anything", async () => {
    const fixture = await startFixture({
      config: defaultConfig({
        targets: {
          web: {
            preset: "vercel",
            environment: SOURCE_ENV,
            variables: ["ALPHA", "MISSING"],
            options: { environment: "production" },
          },
        },
      }),
    });
    expect(await sync(fixture, "plan", "web")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      "The target lists variables that do not exist in environment prod: MISSING",
    );
  });

  it("a required declaration with no value in the selection stops by the same rules as run; a required active out of the selection warns", async () => {
    const declared = await statementFor({
      projectId: built.projectId,
      environmentId: SOURCE_ENV,
      variableId: "vd",
      name: "DECLARED_REQUIRED",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
      status: "declared",
      schema: { varType: "", required: true, description: "" },
    });
    const fixture = await startFixture({
      sourceVariables: [
        await sourceVariable({
          variableId: "va",
          name: "ALPHA",
          version: 3,
          plaintext: ALPHA_VALUE,
          required: true,
        }),
        await sourceVariable({ variableId: "vb", name: "BETA", version: 1, plaintext: BETA_VALUE }),
      ],
      declared: [declared],
      config: defaultConfig({
        targets: {
          web: {
            preset: "vercel",
            environment: SOURCE_ENV,
            variables: ["BETA", "DECLARED_REQUIRED"],
            options: { environment: "production" },
          },
        },
      }),
    });
    expect(await sync(fixture, "plan", "web")).toBe(1);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain("Required variables are declared but have no value yet");
    expect(errors).toContain("DECLARED_REQUIRED");
    expect(errors).toContain("required variables are not part of this target: ALPHA");
  });

  it("an unknown target is a usage error (2); a broken or missing config is a run failure (1)", async () => {
    const fixture = await startFixture({});
    expect(await sync(fixture, "plan", "nope")).toBe(2);
    expect(fixture.env.errors.join("\n")).toContain(
      "Unknown sync target (targets in the config: web, worker)",
    );
    const broken = await startFixture({ config: '{"version": 1, "targets": {}}' });
    expect(await sync(broken, "plan", "web")).toBe(1);
    expect(broken.env.errors.join("\n")).toContain("is invalid: receipts must be an object");
    const missing = await startFixture({});
    expect(
      await runCli(
        ["sync", "plan", "web", "--config", join(missing.configDir, "nope.json")],
        missing.env.layer,
      ),
    ).toBe(1);
    expect(missing.env.errors.join("\n")).toContain("Cannot read the sync config");
    // A disagreement between the config's project and the flag is a
    // usage error (2). It never hits the network
    const mismatched = await startFixture({
      config: defaultConfig({ project: "1".repeat(64) }),
    });
    expect(
      await runCli(
        ["sync", "plan", "web", "--config", mismatched.configPath, "--project", "2".repeat(64)],
        mismatched.env.layer,
      ),
    ).toBe(2);
    expect(mismatched.env.errors.join("\n")).toContain("--project does not match");
  });

  it("warns when a receipt variable nears the version ceiling (1,000 versions / variable)", async () => {
    const fixture = await startFixture({
      receipts: [
        await storedReceipt({
          target: "web",
          preset: "vercel",
          variables: { ALPHA: 3, BETA: 1 },
          version: 900,
        }),
      ],
    });
    expect(await sync(fixture, "plan", "web")).toBe(0);
    expect(fixture.env.errors.join("\n")).toContain(
      "Warning: the receipt variable sync-receipt:web is at version 900 of the 1000-version limit",
    );
  });
});

describe("maruhi sync apply", () => {
  it("a production target without --yes emits just the plan and sends nothing", async () => {
    const fixture = await startFixture({});
    expect(await sync(fixture, "apply", "web")).toBe(1);
    expect(fixture.env.logs.join("\n")).toContain("+ ALPHA\tversion 3 (new)");
    expect(fixture.env.errors.join("\n")).toContain(
      "Target web is a production target, so apply needs an explicit --yes",
    );
    expect(fixture.env.execCalls).toEqual([]);
    expect(fixture.receipts.writes).toEqual([]);
    expectNoSecretLeak(fixture.env);
  });

  it("Vercel: one process per name, values as stdin verbatim, argv is names and options only, telemetry off, and creates the receipt", async () => {
    const fixture = await startFixture({});
    expect(await sync(fixture, "apply", "web", "--yes")).toBe(0);
    const calls = fixture.env.execCalls;
    expect(calls.map((call) => call.command)).toEqual([
      ["vercel", "env", "add", "ALPHA", "production", "--force", "--non-interactive"],
      ["vercel", "env", "add", "BETA", "production", "--force", "--non-interactive"],
    ]);
    expect(calls.map(stdinText)).toEqual([ALPHA_VALUE, BETA_VALUE]);
    for (const call of calls) {
      expect(call.extraEnv).toEqual({ VERCEL_TELEMETRY_DISABLED: "1" });
      // cwd is the config file's location (no cwd specified)
      expect(call.cwd).toBe(fixture.configDir);
    }
    expectNoSecretLeak(fixture.env);
    // The receipt = the name → version mapping (no value-derived
    // digest). One creation push
    expect(fixture.receipts.writes.map((write) => write.kind)).toEqual(["create"]);
    const receipt = await decryptReceipt(fixture, "web");
    expect(receipt).toMatchObject({
      version: 1,
      target: "web",
      preset: "vercel",
      variables: { ALPHA: 3, BETA: 1 },
    });
    expect(JSON.stringify(receipt)).not.toContain(ALPHA_VALUE);
    expect(fixture.env.logs.join("\n")).toContain(`Running vercel in ${fixture.configDir}`);
    expect(fixture.env.logs.join("\n")).toContain(
      "Applied to target web: 2 variables written, 0 deleted. Receipt saved as version 1 of sync-receipt:web in environment sync-receipts",
    );

    // Second run: no diff → sends nothing, writes no receipt
    expect(await sync(fixture, "apply", "web", "--yes")).toBe(0);
    expect(fixture.env.execCalls).toHaveLength(2);
    expect(fixture.receipts.writes).toHaveLength(1);
    expect(fixture.env.logs.join("\n")).toContain("Nothing to apply");
    // plan too shows everything unchanged
    expect(await sync(fixture, "plan", "web")).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain("= ALPHA\tversion 3 (unchanged)");
  });

  it("Cloudflare Workers: every variable in one JSON, one process; a named environment doesn't count as production so no --yes needed; cwd is relative to the config", async () => {
    const fixture = await startFixture({});
    expect(await sync(fixture, "apply", "worker")).toBe(0);
    const calls = fixture.env.execCalls;
    expect(calls).toHaveLength(1);
    expect(calls[0]?.command).toEqual([
      "wrangler",
      "secret",
      "bulk",
      "--name",
      "my-worker",
      "--env",
      "staging",
    ]);
    expect(JSON.parse(stdinText(calls[0] as ExecCall))).toEqual({
      ALPHA: ALPHA_VALUE,
      BETA: BETA_VALUE,
    });
    expect(calls[0]?.extraEnv).toEqual({ WRANGLER_SEND_METRICS: "false", DO_NOT_TRACK: "1" });
    expect(calls[0]?.cwd).toBe(join(fixture.configDir, "apps/worker"));
    expectNoSecretLeak(fixture.env);
    expect(await decryptReceipt(fixture, "worker")).toMatchObject({
      preset: "cloudflare-workers",
      variables: { ALPHA: 3, BETA: 1 },
    });
  });

  it("updates and deletions: writes only the changed variables and deletes names dropped from the selection (wrangler uses null, Vercel uses env rm)", async () => {
    const vercel = await startFixture({
      receipts: [
        await storedReceipt({
          target: "web",
          preset: "vercel",
          variables: { ALPHA: 2, BETA: 1, OLD_NAME: 4 },
        }),
      ],
    });
    expect(await sync(vercel, "apply", "web", "--yes")).toBe(0);
    expect(vercel.env.execCalls.map((call) => call.command)).toEqual([
      ["vercel", "env", "add", "ALPHA", "production", "--force", "--non-interactive"],
      ["vercel", "env", "rm", "OLD_NAME", "production", "--yes", "--non-interactive"],
    ]);
    expect(vercel.env.execCalls.map(stdinText)).toEqual([ALPHA_VALUE, ""]);
    // A new version on the existing receipt (not a creation)
    expect(vercel.receipts.writes.map((write) => write.kind)).toEqual(["version"]);
    expect(await decryptReceipt(vercel, "web")).toMatchObject({
      variables: { ALPHA: 3, BETA: 1 },
    });
    expect(JSON.stringify(await decryptReceipt(vercel, "web"))).not.toContain("OLD_NAME");

    const workers = await startFixture({
      receipts: [
        await storedReceipt({
          target: "worker",
          preset: "cloudflare-workers",
          variables: { ALPHA: 3, BETA: 1, OLD_NAME: 4 },
        }),
      ],
    });
    expect(await sync(workers, "apply", "worker")).toBe(0);
    expect(workers.env.execCalls).toHaveLength(1);
    expect(JSON.parse(stdinText(workers.env.execCalls[0] as ExecCall))).toEqual({ OLD_NAME: null });
    expect(await decryptReceipt(workers, "worker")).toMatchObject({
      variables: { ALPHA: 3, BETA: 1 },
    });
  });

  it('variables: "all" + exclude carries none of the excluded names and turns an existing receipt name that got excluded into a delete', async () => {
    const fixture = await startFixture({
      config: defaultConfig({
        targets: {
          worker: {
            preset: "cloudflare-workers",
            environment: SOURCE_ENV,
            variables: "all",
            exclude: ["BETA"],
            options: { environment: "staging" },
          },
        },
      }),
      receipts: [
        await storedReceipt({
          target: "worker",
          preset: "cloudflare-workers",
          variables: { ALPHA: 3, BETA: 1 },
        }),
      ],
    });
    expect(await sync(fixture, "apply", "worker")).toBe(0);
    expect(JSON.parse(stdinText(fixture.env.execCalls[0] as ExecCall))).toEqual({ BETA: null });
  });

  it("a vendor-CLI failure leaves only what arrived on the receipt, and shows only the value-scrubbed tail of the output, exit 1", async () => {
    const fixture = await startFixture({});
    fixture.env.setExecHandler((call, index) =>
      index === 0
        ? { exitCode: 0, output: `Added ${ALPHA_VALUE} to project\n` }
        : {
            exitCode: 1,
            output: `Error: rejected ${stdinText(call)} and line beta line 2 here\nsecond line\n`,
          },
    );
    expect(await sync(fixture, "apply", "web", "--yes")).toBe(1);
    expect(fixture.env.execCalls).toHaveLength(2);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "maruhi: vercel exited with code 1 while writing BETA (delivered before that: 1 variable written, 0 deleted)",
    );
    expect(errors).toContain("  vercel: Error: rejected [redacted] and line [redacted] here");
    expect(errors).toContain("  vercel: second line");
    expectNoSecretLeak(fixture.env);
    // Only the successful ALPHA lands on the receipt → the next plan
    // shows BETA alone
    expect(await decryptReceipt(fixture, "web")).toMatchObject({ variables: { ALPHA: 3 } });
    expect(await sync(fixture, "plan", "web")).toBe(0);
    const out = fixture.env.logs.join("\n");
    expect(out).toContain("= ALPHA\tversion 3 (unchanged)");
    expect(out).toContain("+ BETA\tversion 1 (new)");
  });

  it("a deletion failure (the shape where the target already deleted it) guides toward rebuilding the receipt and keeps the name on it", async () => {
    const fixture = await startFixture({
      receipts: [
        await storedReceipt({
          target: "web",
          preset: "vercel",
          variables: { ALPHA: 3, BETA: 1, GONE: 2, GONE_TOO: 5 },
        }),
      ],
    });
    fixture.env.setExecHandler((call) =>
      call.command[2] === "rm"
        ? { exitCode: 1, output: "Error: Environment Variable was not found\n" }
        : { exitCode: 0, output: "" },
    );
    expect(await sync(fixture, "apply", "web", "--yes")).toBe(1);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain("vercel exited with code 1 while deleting GONE");
    expect(errors).toContain(
      "reset the receipt with `maruhi var rm sync-receipt:web --env sync-receipts` and apply again",
    );
    // It stops at the first deletion so the second is never attempted —
    // rebuilding the receipt would forget it, so it's named
    expect(errors).toContain("remove these at the target yourself first: GONE_TOO");
    // The unattempted deletion was never invoked (stopped at the
    // first)
    expect(fixture.env.execCalls.filter((call) => call.command[2] === "rm")).toHaveLength(1);
    // The unremovable name stays on the receipt (don't silently treat
    // it as gone)
    expect(fixture.receipts.writes).toEqual([]);
  });

  it("a one-line value ending in a single newline can't be sent to Vercel (every value is checked before sending)", async () => {
    const fixture = await startFixture({
      sourceVariables: [
        await sourceVariable({
          variableId: "va",
          name: "ALPHA",
          version: 3,
          plaintext: ALPHA_VALUE,
        }),
        await sourceVariable({
          variableId: "vn",
          name: "NEWLINE",
          version: 1,
          plaintext: "one line\n",
        }),
      ],
      config: defaultConfig({
        targets: {
          web: {
            preset: "vercel",
            environment: SOURCE_ENV,
            variables: ["ALPHA", "NEWLINE"],
            options: { environment: "production" },
          },
        },
      }),
    });
    expect(await sync(fixture, "apply", "web", "--yes")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      "Variable NEWLINE is a single line ending with a newline, which the vercel CLI strips from stdin",
    );
    expect(fixture.env.execCalls).toEqual([]);
    expect(fixture.receipts.writes).toEqual([]);
    // The same value can be carried to wrangler (JSON)
    const workers = await startFixture({
      sourceVariables: [
        await sourceVariable({
          variableId: "vn",
          name: "NEWLINE",
          version: 1,
          plaintext: "one line\n",
        }),
      ],
    });
    expect(await sync(workers, "apply", "worker")).toBe(0);
    expect(JSON.parse(stdinText(workers.env.execCalls[0] as ExecCall))).toEqual({
      NEWLINE: "one line\n",
    });
  });

  it("GitHub Actions: one `gh secret set` process per name, values on stdin only, -R / --app on argv, gh telemetry off, repository secrets need --yes, deletion via `gh secret delete`", async () => {
    const config = defaultConfig({
      targets: {
        actions: {
          preset: "github-actions",
          environment: SOURCE_ENV,
          variables: ["ALPHA"],
          options: { repo: "acme/app", app: "dependabot" },
        },
      },
    });
    const fixture = await startFixture({ config });
    // Repository secrets (no Environment) count as production
    expect(await sync(fixture, "apply", "actions")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      "Target actions is a production target, so apply needs an explicit --yes",
    );
    expect(fixture.env.execCalls).toEqual([]);

    expect(await sync(fixture, "apply", "actions", "--yes")).toBe(0);
    const calls = fixture.env.execCalls;
    expect(calls.map((call) => call.command)).toEqual([
      ["gh", "secret", "set", "ALPHA", "--repo", "acme/app", "--app", "dependabot"],
    ]);
    expect(calls.map(stdinText)).toEqual([ALPHA_VALUE]);
    expect(calls[0]?.extraEnv).toEqual({
      GH_TELEMETRY: "false",
      DO_NOT_TRACK: "1",
      GH_NO_UPDATE_NOTIFIER: "1",
      GH_PROMPT_DISABLED: "1",
    });
    expect(calls[0]?.cwd).toBe(fixture.configDir);
    expectNoSecretLeak(fixture.env);
    expect(fixture.env.logs.join("\n")).toContain(`Running gh in ${fixture.configDir}`);
    // The header line names the sync destination via the preset's
    // describeOptions (repo / environment / app)
    expect(fixture.env.logs.join("\n")).toContain(
      "Sync plan for target actions (environment prod -> github-actions acme/app dependabot via exec)",
    );
    expect(await decryptReceipt(fixture, "actions")).toMatchObject({
      preset: "github-actions",
      variables: { ALPHA: 3 },
    });

    // Names dropped from the selection go through `gh secret delete`
    // (deleted by name — never listed)
    const deleting = await startFixture({
      config,
      receipts: [
        await storedReceipt({
          target: "actions",
          preset: "github-actions",
          variables: { ALPHA: 3, OLD_NAME: 4 },
        }),
      ],
    });
    expect(await sync(deleting, "apply", "actions", "--yes")).toBe(0);
    expect(deleting.env.execCalls.map((call) => call.command)).toEqual([
      ["gh", "secret", "delete", "OLD_NAME", "--repo", "acme/app", "--app", "dependabot"],
    ]);
    expect(deleting.env.execCalls.map(stdinText)).toEqual([""]);
    expect(await decryptReceipt(deleting, "actions")).toMatchObject({ variables: { ALPHA: 3 } });
  });

  it("GitHub Actions: a trailing-newline value (even multi-line) and a lowercase name are stopped before sending (Nothing was sent)", async () => {
    // The default BETA is multi-line with a trailing newline (carriable
    // to Vercel but not to gh)
    const fixture = await startFixture({
      config: defaultConfig({
        targets: {
          actions: {
            preset: "github-actions",
            environment: SOURCE_ENV,
            variables: ["ALPHA", "BETA"],
            options: { environment: "staging" },
          },
        },
      }),
    });
    expect(await sync(fixture, "apply", "actions")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      "Variable BETA ends with a newline, which the gh CLI strips from stdin (every trailing CR or LF, from a single-line and a multi-line value alike). Push the value without the trailing newline (`printf %s` instead of `echo`), or leave this variable out of the target. Nothing was sent",
    );
    expect(fixture.env.execCalls).toEqual([]);
    expect(fixture.receipts.writes).toEqual([]);
    expectNoSecretLeak(fixture.env);

    const lower = await startFixture({
      sourceVariables: [
        await sourceVariable({
          variableId: "va",
          name: "ALPHA",
          version: 3,
          plaintext: ALPHA_VALUE,
        }),
        await sourceVariable({ variableId: "vl", name: "apiKey", version: 1, plaintext: "k" }),
      ],
      config: defaultConfig({
        targets: {
          actions: {
            preset: "github-actions",
            environment: SOURCE_ENV,
            variables: "all",
            options: { environment: "staging" },
          },
        },
      }),
    });
    // The name rules need no plaintext, so they become ! at plan time
    // (apply's check is a defense line)
    expect(await sync(lower, "plan", "actions")).toBe(1);
    expect(lower.env.logs.join("\n")).toContain(
      "! apiKey\tversion 1 (cannot be synced: a name the gh CLI cannot store as is: GitHub stores secret names in uppercase and accepts only uppercase letters, digits, and _, not starting with a digit or with GITHUB_)",
    );
    expect(await sync(lower, "apply", "actions")).toBe(1);
    expect(lower.env.errors.join("\n")).toContain(
      "1 variable cannot be synced with this driver (marked ! above): apiKey. Leave them out of the target, rename them, or push values the gh CLI can carry (each line above says which). Nothing was sent",
    );
    expect(lower.env.execCalls).toEqual([]);
  });

  it("a vendor CLI that can't launch is a failure (it doesn't chase it). When the first launch fails = nothing arrived, no receipt is written", async () => {
    // An exit-127 equivalent (the shape the shell returns for a missing
    // command) is also treated as a failure
    const fixture = await startFixture({});
    fixture.env.setExecHandler(() => ({ exitCode: 127, output: "vercel: command not found\n" }));
    expect(await sync(fixture, "apply", "web", "--yes")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain("vercel exited with code 127");
    // On a first-run failure where nothing arrived, don't write an
    // empty receipt (don't waste a version)
    expect(fixture.receipts.writes).toEqual([]);

    // A launch failure itself (a typed error — the execStartFailure
    // shape in live.ts; the production wording is pinned in
    // live-exec.test.ts) becomes that invocation's failure and likewise
    // writes no receipt
    const missing = await startFixture({});
    missing.env.setExecHandler(() =>
      cliError("Cannot start vercel (ENOENT): is it installed and on PATH"),
    );
    expect(await sync(missing, "apply", "web", "--yes")).toBe(1);
    const errors = missing.env.errors.join("\n");
    // The launch-failure reason (maruhi's own sentence) continues the
    // body. A process that never ran has no output, so it isn't phrased
    // in the vendor-output slot (`  vercel: …`) or as 'Its output is
    // shown above'
    expect(errors).toContain(
      "maruhi: vercel could not be started while writing ALPHA (delivered before that: 0 variables written, 0 deleted). Cannot start vercel (ENOENT): is it installed and on PATH.",
    );
    expect(errors).not.toContain("  vercel:");
    expect(errors).not.toContain("Its output is shown above");
    expect(missing.env.execCalls).toHaveLength(1);
    expect(missing.receipts.writes).toEqual([]);
  });

  it("even when the second vendor CLI can't launch, what already arrived stays on the receipt (a launch failure = that invocation's failure)", async () => {
    const fixture = await startFixture({});
    fixture.env.setExecHandler((_call, index) =>
      index === 0
        ? { exitCode: 0, output: "" }
        : cliError("Cannot start vercel (ENOENT): is it installed and on PATH"),
    );
    expect(await sync(fixture, "apply", "web", "--yes")).toBe(1);
    expect(fixture.env.execCalls).toHaveLength(2);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "maruhi: vercel could not be started while writing BETA (delivered before that: 1 variable written, 0 deleted). Cannot start vercel (ENOENT)",
    );
    expectNoSecretLeak(fixture.env);
    // Only the successful ALPHA lands on the receipt → the next plan
    // shows BETA alone
    expect(await decryptReceipt(fixture, "web")).toMatchObject({ variables: { ALPHA: 3 } });
    expect(await sync(fixture, "plan", "web")).toBe(0);
    const out = fixture.env.logs.join("\n");
    expect(out).toContain("= ALPHA\tversion 3 (unchanged)");
    expect(out).toContain("+ BETA\tversion 1 (new)");
  });

  it("a broken receipt variable is fail-closed (with how to fix it)", async () => {
    const receiptId = "receipt-web";
    const statement = await statementFor({
      projectId: built.projectId,
      environmentId: RECEIPTS_ENV,
      variableId: receiptId,
      name: receiptVariableName("web"),
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
    });
    const value = await encryptValueFor({
      dek: dekReceipts,
      projectId: built.projectId,
      environmentId: RECEIPTS_ENV,
      epoch: 1,
      variableId: receiptId,
      version: 1,
      plaintext: "not json",
      writer: owner,
      head: headOf(built, 3),
    });
    const fixture = await startFixture({ receipts: [{ variableId: receiptId, statement, value }] });
    expect(await sync(fixture, "plan", "web")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      "The receipt variable sync-receipt:web in environment sync-receipts is not a valid sync receipt (not valid JSON). Remove it with `maruhi var rm sync-receipt:web --env sync-receipts`",
    );
  });

  it("a receipt written by a different preset is refused (switching presets = a different destination; names the rebuild)", async () => {
    // The shape where the vercel-era receipt still has names 'as
    // delivered' that are illegal under gh's rules: it stops earlier as
    // a receipt mix-up, not as a name-rule error
    const fixture = await startFixture({
      sourceVariables: [
        await sourceVariable({ variableId: "vl", name: "apiKey", version: 1, plaintext: "k" }),
      ],
      config: defaultConfig({
        targets: {
          web: {
            preset: "github-actions",
            environment: SOURCE_ENV,
            variables: ["apiKey"],
            options: { repo: "acme/app", environment: "staging" },
          },
        },
      }),
      receipts: [
        await storedReceipt({ target: "web", preset: "vercel", variables: { apiKey: 1 } }),
      ],
    });
    expect(await sync(fixture, "plan", "web")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      "The receipt variable sync-receipt:web in environment sync-receipts was written by the vercel preset, but target web is now configured with preset github-actions, so its deliveries do not describe this destination. Those deliveries stay at the vercel destination and this receipt is their only record, so remove them there yourself first: apiKey. Remove it with `maruhi var rm sync-receipt:web --env sync-receipts` and apply again (the next apply rewrites every variable of the target)",
    );
    expect(fixture.env.execCalls).toEqual([]);
  });
});
