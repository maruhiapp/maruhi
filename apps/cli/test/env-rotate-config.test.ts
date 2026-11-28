import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  decryptValue,
  distributedEnvironmentStatement,
  distributedManifest,
  distributedValue,
  distributedVariableStatement,
  distributedWrap,
  genesisOp,
  headOf,
  rotateEpochOp,
  valueSignedBytesHashOf,
  type WireDistributedEnvironmentStatement,
  type WireRecipientDek,
} from "@maruhi/test-kit";
import { beforeAll, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { receiptVariableName } from "../src/sync.package/sync-receipt.ts";
import {
  chainBase,
  dek1,
  dek2,
  ENV_ID,
  makeServer,
  owner,
  type PulledVariable,
  type ServerOptions,
  servers,
  type ServerState,
  startEnv,
  variableAt,
} from "./support/env-rotate.ts";
import type { TestEnv } from "./support/env.ts";
import type { MockHandler } from "./support/server.ts";
import {
  makeValueEnvironmentServer,
  type StoredVariable,
  type ValueEnvironmentState,
} from "./support/value-env.ts";

const RECEIPTS_ENV = "ops";

function vercelTarget(environment: string, variables: readonly string[]): Record<string, unknown> {
  return { preset: "vercel", environment, variables, options: { environment: "production" } };
}

function output(env: TestEnv): string {
  return [...env.logs, ...env.errors].join("\n");
}

describe("maruhi env rotate --config (advancing the sync receipt — M1)", () => {
  let dekReceipts: Uint8Array;
  let chainWithReceipts: BuiltChain;
  let receiptsStatement: WireDistributedEnvironmentStatement;
  let wrapReceipts: WireRecipientDek;

  beforeAll(async () => {
    dekReceipts = crypto.getRandomValues(new Uint8Array(32));
    chainWithReceipts = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: createEnvironmentOp(RECEIPTS_ENV, dekReceipts) },
    ]);
    receiptsStatement = await distributedEnvironmentStatement({
      projectId: chainWithReceipts.projectId,
      environmentId: RECEIPTS_ENV,
      name: RECEIPTS_ENV,
      author: owner,
      head: headOf(chainWithReceipts, 1),
    });
    wrapReceipts = await distributedWrap({
      projectId: chainWithReceipts.projectId,
      environmentId: RECEIPTS_ENV,
      epoch: 1,
      dek: dekReceipts,
      recipient: owner,
      signer: owner,
    });
  });

  async function sourceVariables(built: BuiltChain, apiKeyVersion = 1): Promise<PulledVariable[]> {
    return [
      await variableAt({
        built,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
      await variableAt({
        built,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: apiKeyVersion,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
  }

  async function storedReceipt(input: {
    readonly target: string;
    readonly variables: Readonly<Record<string, number>>;
    readonly version?: number;
    readonly environmentId?: string;
    readonly dek?: Uint8Array;
    readonly built?: BuiltChain;
  }): Promise<StoredVariable> {
    const built = input.built ?? chainWithReceipts;
    const environmentId = input.environmentId ?? RECEIPTS_ENV;
    const variableId = `receipt-${input.target}`;
    const statement = await distributedVariableStatement({
      projectId: built.projectId,
      environmentId,
      variableId,
      name: receiptVariableName(input.target),
      author: owner,
      head: headOf(built, 1),
    });
    const value = await distributedValue({
      dek: input.dek ?? dekReceipts,
      projectId: built.projectId,
      environmentId,
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

  function defaultConfig(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      version: 1,
      receipts: { environment: RECEIPTS_ENV },
      targets: { web: vercelTarget(ENV_ID, ["DATABASE_URL", "API_KEY"]) },
      ...overrides,
    };
  }

  interface ReceiptFixture {
    readonly state: ServerState;
    readonly receipts: ValueEnvironmentState;
    readonly env: TestEnv;
    readonly configPath: string;
  }

  async function startFixture(input: {
    readonly server: Omit<ServerOptions, "built"> & { readonly built?: BuiltChain };
    readonly receipts?: readonly StoredVariable[];
    readonly config?: Record<string, unknown>;
    readonly before?: readonly MockHandler[];
  }): Promise<ReceiptFixture> {
    const built = input.server.built ?? chainWithReceipts;
    const state = makeServer({ ...input.server, built });
    const receipts = makeValueEnvironmentServer({
      chain: built,
      owner,
      environmentId: RECEIPTS_ENV,
      envStatement: receiptsStatement,
      wrap: wrapReceipts,
      initialVariables: input.receipts ?? [],
    });
    const env = await startEnv(
      [...(input.before ?? []), ...state.handlers, ...receipts.handlers],
      owner,
    );
    const configDir = await mkdtemp(join(tmpdir(), "maruhi-rotate-receipts-"));
    const configPath = join(configDir, "maruhi.sync.json");
    await writeFile(configPath, JSON.stringify(input.config ?? defaultConfig()));
    return { state, receipts: receipts.state, env, configPath };
  }

  async function devWrap(
    built: BuiltChain,
    epoch: number,
    dek: Uint8Array,
  ): Promise<WireRecipientDek> {
    return distributedWrap({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch,
      dek,
      recipient: owner,
      signer: owner,
    });
  }

  async function receiptVariablesOf(
    fixture: ReceiptFixture,
    target: string,
  ): Promise<Record<string, number>> {
    const stored = fixture.receipts.variables.find(
      (entry) => entry.statement.name === receiptVariableName(target),
    );
    if (stored === undefined) throw new Error(`receipt for ${target} missing`);
    const text = await decryptValue(dekReceipts, stored.value);
    return (JSON.parse(text) as { variables: Record<string, number> }).variables;
  }

  function rotate(fixture: ReceiptFixture, ...args: string[]): Promise<number> {
    return runCli(["env", "rotate", ENV_ID, ...args], fixture.env.layer);
  }

  it("advances the receipt to the new version only for completed re-encryptions; the following sync plan is all unchanged and apply writes nothing", async () => {
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
      },
      receipts: [
        await storedReceipt({ target: "web", variables: { DATABASE_URL: 1, API_KEY: 1 } }),
      ],
    });

    expect(await rotate(fixture, "--reason", "scheduled", "--config", fixture.configPath)).toBe(0);
    expect(fixture.state.pushes.map((push) => push.variableId).toSorted()).toEqual(["vaa", "vbb"]);
    expect(fixture.receipts.writes.map((write) => write.kind)).toEqual(["version"]);
    expect(await receiptVariablesOf(fixture, "web")).toEqual({ DATABASE_URL: 2, API_KEY: 2 });
    expect(fixture.env.logs.join("\n")).toContain(
      "Advanced the receipt for target web to the re-encrypted versions of 2 variables (saved as version 2 of sync-receipt:web in environment ops)",
    );
    expect(output(fixture.env)).not.toContain("left as delivered");
    expect(output(fixture.env)).not.toContain("postgres://example");
    expect(output(fixture.env)).not.toContain("key-abc");

    expect(
      await runCli(["sync", "plan", "web", "--config", fixture.configPath], fixture.env.layer),
    ).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(
      "0 to add, 0 to update, 0 to delete, 2 unchanged, 0 blocked",
    );
    expect(
      await runCli(
        ["sync", "apply", "web", "--yes", "--config", fixture.configPath],
        fixture.env.layer,
      ),
    ).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain("Nothing to apply");
    expect(fixture.env.execCalls).toHaveLength(0);
    expect(fixture.receipts.writes).toHaveLength(1);
  });

  it("without --config it never touches the receipt (the receipt environment is neither read nor written)", async () => {
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
      },
      receipts: [
        await storedReceipt({ target: "web", variables: { DATABASE_URL: 1, API_KEY: 1 } }),
      ],
    });
    const receiptsPulls: string[] = [];
    expect(await rotate(fixture, "--reason", "scheduled")).toBe(0);
    for (const server of servers) {
      receiptsPulls.push(
        ...server.requests
          .filter((request) => request.path.includes(`/environments/${RECEIPTS_ENV}/`))
          .map((request) => request.path),
      );
    }
    expect(receiptsPulls).toEqual([]);
    expect(fixture.receipts.writes).toEqual([]);
    expect(output(fixture.env)).not.toContain("receipt");
    expect(
      await runCli(["sync", "plan", "web", "--config", fixture.configPath], fixture.env.layer),
    ).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(
      "0 to add, 2 to update, 0 to delete, 0 unchanged, 0 blocked",
    );
  });

  it("a variable whose receipt lagged is not advanced (what reached the sync destination is old plaintext)", async () => {
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts, 2),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
      },
      receipts: [
        await storedReceipt({ target: "web", variables: { DATABASE_URL: 1, API_KEY: 1 } }),
      ],
    });

    expect(await rotate(fixture, "--reason", "scheduled", "--config", fixture.configPath)).toBe(0);
    expect(await receiptVariablesOf(fixture, "web")).toEqual({ DATABASE_URL: 2, API_KEY: 1 });
    expect(fixture.env.logs.join("\n")).toContain(
      "Advanced the receipt for target web to the re-encrypted versions of 1 variable (saved as version 2 of sync-receipt:web in environment ops); 1 variable left as delivered (API_KEY: the receipt was already behind before the rotation, so the next `maruhi sync plan` shows them as pending)",
    );
    expect(
      await runCli(["sync", "plan", "web", "--config", fixture.configPath], fixture.env.layer),
    ).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(
      "0 to add, 1 to update, 0 to delete, 1 unchanged, 0 blocked",
    );
    expect(fixture.env.logs.join("\n")).toContain("~ API_KEY\tversion 1 -> 3");
  });

  it("a name absent from the receipt (unsynced) is not advanced; with nothing to advance, no receipt is written", async () => {
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts, 2),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
      },
      receipts: [await storedReceipt({ target: "web", variables: { API_KEY: 1 } })],
    });

    expect(await rotate(fixture, "--reason", "scheduled", "--config", fixture.configPath)).toBe(0);
    expect(fixture.receipts.writes).toEqual([]);
    expect(fixture.env.logs.join("\n")).toContain(
      "Receipt for target web not advanced: 1 variable left as delivered (API_KEY: the receipt was already behind before the rotation, so the next `maruhi sync plan` shows them as pending)",
    );
    expect(
      await runCli(["sync", "plan", "web", "--config", fixture.configPath], fixture.env.layer),
    ).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(
      "1 to add, 1 to update, 0 to delete, 0 unchanged, 0 blocked",
    );
  });

  it("a variable already on the current epoch via a concurrent push (alreadyCurrent — its plaintext may differ) is not advanced", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: createEnvironmentOp(RECEIPTS_ENV, dekReceipts) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    ]);
    const [staleA, staleB] = await sourceVariables(built);
    if (staleA === undefined || staleB === undefined) throw new Error("fixture");
    const winner = await variableAt({
      built,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "key-def",
      headSeq: 4,
      prevValueSigHashHex: await valueSignedBytesHashOf(staleB.value, owner.userId),
    });
    const variables = [staleA, staleB];
    const fixture = await startFixture({
      server: {
        built,
        variables,
        deks: [await devWrap(built, 1, dek1), await devWrap(built, 2, dek2)],
        currentEpoch: 2,
        onPush: (_call, variableId) => {
          if (variableId !== "vbb") {
            return undefined;
          }
          variables[1] = winner;
          return { status: 409, json: { _tag: "VersionConflict", currentVersion: 2 } };
        },
      },
      receipts: [
        await storedReceipt({ target: "web", variables: { DATABASE_URL: 1, API_KEY: 1 }, built }),
      ],
    });

    expect(await rotate(fixture, "--config", fixture.configPath)).toBe(0);
    expect(fixture.state.pushes.map((push) => push.variableId)).toEqual(["vaa"]);
    expect(fixture.env.logs.join("\n")).toContain(
      "1 variable already re-encrypted by concurrent updates",
    );
    expect(await receiptVariablesOf(fixture, "web")).toEqual({ DATABASE_URL: 2, API_KEY: 1 });
    expect(output(fixture.env)).not.toContain("left as delivered");
    expect(
      await runCli(["sync", "plan", "web", "--config", fixture.configPath], fixture.env.layer),
    ).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain("~ API_KEY\tversion 1 -> 2");
  });

  it("on partial completion (remaining > 0) only the completed variables advance, and the exit code stays the rotation's report", async () => {
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
        onPush: (_call, variableId) =>
          variableId === "vbb" ? { status: 503, bodyText: "unavailable" } : undefined,
      },
      receipts: [
        await storedReceipt({ target: "web", variables: { DATABASE_URL: 1, API_KEY: 1 } }),
      ],
    });

    expect(await rotate(fixture, "--reason", "scheduled", "--config", fixture.configPath)).toBe(1);
    expect(fixture.env.logs.join("\n")).toContain("Partial completion");
    expect(await receiptVariablesOf(fixture, "web")).toEqual({ DATABASE_URL: 2, API_KEY: 1 });
    expect(output(fixture.env)).not.toContain("left as delivered");
  });

  it("on resume, only the resumed share advances (variables advanced in the previous run stay lagging)", async () => {
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
        onPush: (call, variableId) =>
          variableId === "vbb" && call < 4 ? { status: 503, bodyText: "unavailable" } : undefined,
      },
      receipts: [
        await storedReceipt({ target: "web", variables: { DATABASE_URL: 1, API_KEY: 1 } }),
      ],
    });

    expect(await rotate(fixture, "--reason", "first run")).toBe(1);
    expect(fixture.receipts.writes).toEqual([]);
    expect(await rotate(fixture, "--config", fixture.configPath)).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain("resumed re-encryption");
    expect(await receiptVariablesOf(fixture, "web")).toEqual({ DATABASE_URL: 1, API_KEY: 2 });
    expect(fixture.env.logs.join("\n")).toContain(
      "Advanced the receipt for target web to the re-encrypted versions of 1 variable (saved as version 2 of sync-receipt:web in environment ops)",
    );
    expect(output(fixture.env)).not.toContain("left as delivered");
    expect(
      await runCli(["sync", "plan", "web", "--config", fixture.configPath], fixture.env.layer),
    ).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain("~ DATABASE_URL\tversion 1 -> 2");
    expect(fixture.env.logs.join("\n")).toContain("= API_KEY\tversion 2 (unchanged)");
  });

  it("rotating the receipt environment itself only re-encrypts the receipt variable — no target is advanced (the following plan still passes)", async () => {
    const sourceInOps = await distributedVariableStatement({
      projectId: chainWithReceipts.projectId,
      environmentId: RECEIPTS_ENV,
      variableId: "vsrc",
      name: "DATABASE_URL",
      author: owner,
      head: headOf(chainWithReceipts, 1),
    });
    const sourceValue = await distributedValue({
      dek: dekReceipts,
      projectId: chainWithReceipts.projectId,
      environmentId: RECEIPTS_ENV,
      epoch: 1,
      variableId: "vsrc",
      version: 1,
      plaintext: "postgres://example",
      writer: owner,
      head: headOf(chainWithReceipts, 3),
    });
    const receiptInDev = await storedReceipt({
      target: "web",
      variables: { DATABASE_URL: 1 },
      environmentId: ENV_ID,
      dek: dek1,
    });
    const fixture = await startFixture({
      server: {
        variables: [receiptInDev],
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
      },
      receipts: [{ variableId: "vsrc", statement: sourceInOps, value: sourceValue }],
      config: {
        version: 1,
        receipts: { environment: ENV_ID },
        targets: { web: vercelTarget(RECEIPTS_ENV, ["DATABASE_URL"]) },
      },
    });

    expect(await rotate(fixture, "--reason", "scheduled", "--config", fixture.configPath)).toBe(0);
    expect(fixture.state.pushes.map((push) => push.variableId)).toEqual(["receipt-web"]);
    expect(fixture.env.logs.join("\n")).toContain(
      "No sync target in the config is synced from environment dev, so no receipt was advanced",
    );
    expect(
      await runCli(["sync", "plan", "web", "--config", fixture.configPath], fixture.env.layer),
    ).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(
      "0 to add, 0 to update, 0 to delete, 1 unchanged, 0 blocked",
    );
  });

  it("a target without a receipt is quietly skipped", async () => {
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
      },
    });
    expect(await rotate(fixture, "--reason", "scheduled", "--config", fixture.configPath)).toBe(0);
    expect(fixture.receipts.writes).toEqual([]);
    expect(output(fixture.env)).not.toContain("receipt");
  });

  it("every target synced from the same environment is processed; one write failure stops neither the rest nor the exit code", async () => {
    const base = `/projects/${chainWithReceipts.projectId}/environments/${RECEIPTS_ENV}`;
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
      },
      receipts: [
        await storedReceipt({ target: "web", variables: { DATABASE_URL: 1, API_KEY: 1 } }),
        await storedReceipt({ target: "worker", variables: { DATABASE_URL: 1 } }),
      ],
      config: defaultConfig({
        targets: {
          web: vercelTarget(ENV_ID, ["DATABASE_URL", "API_KEY"]),
          worker: vercelTarget(ENV_ID, ["DATABASE_URL"]),
        },
      }),
      before: [
        (request) =>
          request.method === "POST" && request.path === `${base}/variables/receipt-web/versions`
            ? { status: 503, bodyText: "unavailable" }
            : null,
      ],
    });

    expect(await rotate(fixture, "--reason", "scheduled", "--config", fixture.configPath)).toBe(0);
    expect(fixture.env.errors.join("\n")).toContain(
      "the rotation is done, but the receipt for target web could not be advanced (",
    );
    expect(fixture.env.errors.join("\n")).toContain(
      "The next `maruhi sync plan web` shows the re-encrypted variables as pending; applying again overwrites them with the same plaintext",
    );
    expect(await receiptVariablesOf(fixture, "web")).toEqual({ DATABASE_URL: 1, API_KEY: 1 });
    expect(await receiptVariablesOf(fixture, "worker")).toEqual({ DATABASE_URL: 2 });
    expect(fixture.env.logs.join("\n")).toContain(
      "Advanced the receipt for target worker to the re-encrypted versions of 1 variable",
    );
  });

  it("a failed post-rotation resync only warns as a cleanup failure — the exit code is unchanged", async () => {
    const pushed: string[] = [];
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
        onPush: (_call, variableId) => {
          pushed.push(variableId);
          return undefined;
        },
        onChain: () => (pushed.length === 2 ? { status: 503, bodyText: "unavailable" } : undefined),
      },
      receipts: [
        await storedReceipt({ target: "web", variables: { DATABASE_URL: 1, API_KEY: 1 } }),
      ],
    });

    expect(await rotate(fixture, "--reason", "scheduled", "--config", fixture.configPath)).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain("Done: rotated environment dev");
    expect(fixture.env.errors.join("\n")).toContain(
      "the rotation is done, but the receipts could not be advanced because the chain could not be re-verified (",
    );
    expect(fixture.receipts.writes).toEqual([]);
    expect(fixture.env.errors.join("\n")).toContain(
      "a committed repository anchor (if any) is now stale",
    );
  });

  it("a communication failure reading the receipt environment stays a warning — the exit code is unchanged (the scope of SY2 stage 2 2b ruling D)", async () => {
    const base = `/projects/${chainWithReceipts.projectId}/environments/${RECEIPTS_ENV}`;
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
      },
      receipts: [
        await storedReceipt({ target: "web", variables: { DATABASE_URL: 1, API_KEY: 1 } }),
      ],
      before: [
        (request) =>
          request.method === "GET" && request.path === `${base}/pull`
            ? { status: 503, bodyText: "unavailable" }
            : null,
      ],
    });

    expect(await rotate(fixture, "--reason", "scheduled", "--config", fixture.configPath)).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain("Done: rotated environment dev");
    expect(fixture.env.errors.join("\n")).toContain(
      "the rotation is done, but the receipt for target web could not be advanced (",
    );
    expect(fixture.receipts.writes).toEqual([]);
  });

  it("a verification refusal on the receipt environment (a floor violation = evidence) is never folded into a warning — it passes through as a failure", async () => {
    const newer = await storedReceipt({
      target: "web",
      variables: { DATABASE_URL: 1, API_KEY: 1 },
      version: 2,
    });
    const older = await storedReceipt({
      target: "web",
      variables: { DATABASE_URL: 1 },
      version: 1,
    });
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
      },
      receipts: [newer],
    });
    expect(
      await runCli(["sync", "plan", "web", "--config", fixture.configPath], fixture.env.layer),
    ).toBe(0);
    const stored = fixture.receipts.variables[0];
    if (stored === undefined) throw new Error("receipt missing");
    stored.value = older.value;

    expect(await rotate(fixture, "--reason", "scheduled", "--config", fixture.configPath)).toBe(1);
    expect(fixture.env.logs.join("\n")).toContain("Done: rotated environment dev");
    expect(fixture.env.errors.join("\n")).toContain("value-version rollback");
    expect(fixture.env.errors.join("\n")).not.toContain("could not be advanced");
    expect(fixture.receipts.writes).toEqual([]);
    expect(fixture.env.errors.join("\n")).toContain(
      "a committed repository anchor (if any) is now stale",
    );
  });

  it("detecting a chain swap on the cleanup resync fails as evidence (never folded into a warning)", async () => {
    const pushed: string[] = [];
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
        onPush: (_call, variableId) => {
          pushed.push(variableId);
          return undefined;
        },
        onChain: () =>
          pushed.length === 2
            ? {
                status: 200,
                json: {
                  projectId: chainBase.projectId,
                  entries: chainBase.entries,
                  headSeq: chainBase.entries.length,
                  headHashHex: chainBase.hashes[chainBase.hashes.length - 1],
                  attestations: [],
                },
              }
            : undefined,
      },
      receipts: [
        await storedReceipt({ target: "web", variables: { DATABASE_URL: 1, API_KEY: 1 } }),
      ],
    });

    expect(await rotate(fixture, "--reason", "scheduled", "--config", fixture.configPath)).toBe(1);
    expect(fixture.env.logs.join("\n")).toContain("Done: rotated environment dev");
    expect(fixture.env.errors.join("\n")).toContain("not an extension of the verified view");
    expect(fixture.env.errors.join("\n")).not.toContain("could not be advanced");
    expect(fixture.receipts.writes).toEqual([]);
    expect(fixture.env.errors.join("\n")).toContain(
      "a committed repository anchor (if any) is now stale",
    );
  });

  it("when the receipt environment's value signature fails verification, it fails as evidence", async () => {
    const receipt = await storedReceipt({
      target: "web",
      variables: { DATABASE_URL: 1, API_KEY: 1 },
    });
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
      },
      receipts: [{ ...receipt, value: { ...receipt.value, signatureHex: "00".repeat(64) } }],
    });

    expect(await rotate(fixture, "--reason", "scheduled", "--config", fixture.configPath)).toBe(1);
    expect(fixture.env.logs.join("\n")).toContain("Done: rotated environment dev");
    expect(fixture.env.errors.join("\n")).not.toContain("could not be advanced");
    expect(fixture.receipts.writes).toEqual([]);
    expect(fixture.env.errors.join("\n")).toContain(
      "a committed repository anchor (if any) is now stale",
    );
  });

  it("an unsupported layout on the receipt environment (an honest breaking format) is not evidence — it stays a cleanup warning", async () => {
    const receipt = await storedReceipt({
      target: "web",
      variables: { DATABASE_URL: 1, API_KEY: 1 },
    });
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
      },
      receipts: [
        {
          ...receipt,
          statement: {
            ...receipt.statement,
            layoutVersion: 4,
            varType: "",
            required: false,
            description: "",
            maxAgeDays: null,
          },
        },
      ],
    });

    fixture.receipts.manifest = await distributedManifest({
      projectId: chainWithReceipts.projectId,
      environmentId: RECEIPTS_ENV,
      epoch: 1,
      issuer: owner,
      head: headOf(chainWithReceipts, chainWithReceipts.entries.length),
      envStatement: receiptsStatement,
      statements: [receipt.statement],
    });

    expect(await rotate(fixture, "--reason", "scheduled", "--config", fixture.configPath)).toBe(0);
    expect(fixture.env.errors.join("\n")).toContain("could not be advanced (");
    expect(fixture.env.errors.join("\n")).toContain("This is not a tampering indication");
    expect(fixture.receipts.writes).toEqual([]);
  });

  it("warns when a receipt variable's version nears the cap (M1's writes consume versions too)", async () => {
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
      },
      receipts: [
        await storedReceipt({
          target: "web",
          variables: { DATABASE_URL: 1, API_KEY: 1 },
          version: 899,
        }),
      ],
    });
    expect(await rotate(fixture, "--reason", "scheduled", "--config", fixture.configPath)).toBe(0);
    expect(fixture.env.errors.join("\n")).toContain(
      "the receipt variable sync-receipt:web is at version 900 of the 1000-version limit per variable",
    );
  });

  it("when the config's project differs from the rotated project, it stops as a usage mistake (2) before advancing the epoch", async () => {
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
      },
      config: defaultConfig({ project: "2".repeat(64) }),
    });
    expect(await rotate(fixture, "--reason", "scheduled", "--config", fixture.configPath)).toBe(2);
    expect(fixture.state.rotateBodies).toHaveLength(0);
    expect(fixture.env.errors.join("\n")).toContain(
      "The sync config belongs to a different project (its `project` does not match the project being rotated)",
    );
  });

  it("when the config cannot be read, it stops before advancing the epoch (1)", async () => {
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
      },
    });
    expect(
      await rotate(fixture, "--reason", "scheduled", "--config", `${fixture.configPath}.missing`),
    ).toBe(1);
    expect(fixture.state.rotateBodies).toHaveLength(0);
    expect(fixture.env.errors).toEqual(
      expect.arrayContaining([
        `maruhi: Cannot read the sync config ${fixture.configPath}.missing. Create it with \`maruhi sync init\` (see the Deploy targets page in the docs), or pass --config <file>`,
      ]),
    );
  });

  it("a check-only run (up-to-date) re-encrypted nothing, so it never touches the receipt", async () => {
    const fixture = await startFixture({
      server: {
        variables: await sourceVariables(chainWithReceipts),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
      },
      receipts: [
        await storedReceipt({ target: "web", variables: { DATABASE_URL: 1, API_KEY: 1 } }),
      ],
    });
    expect(await rotate(fixture, "--config", fixture.configPath)).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain("Check complete");
    expect(fixture.receipts.writes).toEqual([]);
    expect(output(fixture.env)).not.toContain("receipt");
  });
});
