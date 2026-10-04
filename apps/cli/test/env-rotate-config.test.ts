import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { receiptVariableName } from "../src/sync.package/sync-receipt.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  manifestFor,
  rotateEpochOp,
  statementFor,
  valueHashOf,
  type WireDistributedEnvironmentStatement,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import {
  chainBase,
  decryptWire,
  dek1,
  dek2,
  ENV_ID,
  makeServer,
  owner,
  type PulledVariable,
  type ServerOptions,
  type ServerState,
  servers,
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

// ---------------------------------------------------------------------------
// `--config`: advancing the sync receipt (SY2 stage 2 2b — M1). The rotated
// environment (dev — makeServer models the rotation's composite acceptance
// and the re-encryption pushes) and the receipt environment (ops —
// makeValueEnvironmentServer, a stateful value environment pinned at epoch
// 1) are combined into one mock server, running rotate → receipt write →
// `sync plan` / `sync apply` on the same state.
// ---------------------------------------------------------------------------

const RECEIPTS_ENV = "ops";

function vercelTarget(environment: string, variables: readonly string[]): Record<string, unknown> {
  return { preset: "vercel", environment, variables, options: { environment: "production" } };
}

function output(env: TestEnv): string {
  return [...env.logs, ...env.errors].join("\n");
}

describe("maruhi env rotate --config (advancing the sync receipt — M1)", () => {
  let dekReceipts: Uint8Array;
  /** genesis + create dev (epoch 1, dek1) + create ops (epoch 1, dekReceipts). */
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
    receiptsStatement = await environmentStatementFor({
      projectId: chainWithReceipts.projectId,
      environmentId: RECEIPTS_ENV,
      name: RECEIPTS_ENV,
      author: owner,
      head: headOf(chainWithReceipts, 1),
    });
    wrapReceipts = await wrapDekFor({
      projectId: chainWithReceipts.projectId,
      environmentId: RECEIPTS_ENV,
      epoch: 1,
      dek: dekReceipts,
      recipient: owner,
      signer: owner,
    });
  });

  /** The rotated environment's 2 variables (DATABASE_URL v1 / API_KEY takes a version). */
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

  /** The existing receipt placed in the receipt environment (the previous sync's result). */
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
    const statement = await statementFor({
      projectId: built.projectId,
      environmentId,
      variableId,
      name: receiptVariableName(input.target),
      author: owner,
      head: headOf(built, 1),
    });
    const value = await encryptValueFor({
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

  /** The default config: a Vercel target `web` synced from dev; the receipt is ops. */
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
    /** Handlers injected at the front (e.g. injecting a receipt-environment write failure). */
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
    // The rotated environment's handlers go first (the chain follows makeServer's mutable current form)
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
    return wrapDekFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch,
      dek,
      recipient: owner,
      signer: owner,
    });
  }

  /** Decrypts the receipt environment's latest receipt and returns the variable mapping. */
  async function receiptVariablesOf(
    fixture: ReceiptFixture,
    target: string,
  ): Promise<Record<string, number>> {
    const stored = fixture.receipts.variables.find(
      (entry) => entry.statement.name === receiptVariableName(target),
    );
    if (stored === undefined) throw new Error(`receipt for ${target} missing`);
    const text = await decryptWire(dekReceipts, stored.value);
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
    // Re-encryption = the 2 variables' new versions (values unchanged). The receipt is written as a new version exactly once
    expect(fixture.state.pushes.map((push) => push.variableId).toSorted()).toEqual(["vaa", "vbb"]);
    expect(fixture.receipts.writes.map((write) => write.kind)).toEqual(["version"]);
    expect(await receiptVariablesOf(fixture, "web")).toEqual({ DATABASE_URL: 2, API_KEY: 2 });
    expect(fixture.env.logs.join("\n")).toContain(
      "Advanced the receipt for target web to the re-encrypted versions of 2 variables (saved as version 2 of sync-receipt:web in environment ops)",
    );
    expect(output(fixture.env)).not.toContain("left as delivered");
    // No plaintext appears in the output (the receipt carries only names and versions)
    expect(output(fixture.env)).not.toContain("postgres://example");
    expect(output(fixture.env)).not.toContain("key-abc");

    // The plan after that is all unchanged; apply has nothing to write (never writes twice)
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
    // Since it cannot be injected after startFixture, receipt-environment reads are counted via the server's records
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
    // Since nothing advanced, the plan is all changed (harmless — the next apply rewrites the same plaintext)
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
        // API_KEY was pushed once more after the sync to version 2 (the receipt stays at 1)
        variables: await sourceVariables(chainWithReceipts, 2),
        deks: [await devWrap(chainWithReceipts, 1, dek1)],
        currentEpoch: 1,
      },
      receipts: [
        await storedReceipt({ target: "web", variables: { DATABASE_URL: 1, API_KEY: 1 } }),
      ],
    });

    expect(await rotate(fixture, "--reason", "scheduled", "--config", fixture.configPath)).toBe(0);
    // DATABASE_URL: 1 → 2 (it pointed at the immediately prior one). API_KEY:
    // stays at 1 (advancing to 3 would hide version 2's unsynced diff)
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
      // DATABASE_URL has not reached the sync destination (absent from the receipt). API_KEY is lagging
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
    // The "winner another member wrote on the new epoch" visible on the re-fetch after the 409 (the plaintext differs)
    const winner = await variableAt({
      built,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "key-def",
      headSeq: 4,
      prevValueSigHashHex: await valueHashOf(staleB.value, owner.userId),
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

    // The resume path (unfinished against epoch 2): only DATABASE_URL is re-encrypted by us
    expect(await rotate(fixture, "--config", fixture.configPath)).toBe(0);
    expect(fixture.state.pushes.map((push) => push.variableId)).toEqual(["vaa"]);
    expect(fixture.env.logs.join("\n")).toContain(
      "1 variable already re-encrypted by concurrent updates",
    );
    expect(await receiptVariablesOf(fixture, "web")).toEqual({ DATABASE_URL: 2, API_KEY: 1 });
    expect(output(fixture.env)).not.toContain("left as delivered");
    // The winner's plaintext was never synced = plan shows update (never hidden)
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
        // Only vbb keeps failing throughout run 1 (never recovers even on in-pass retries)
        onPush: (call, variableId) =>
          variableId === "vbb" && call < 4 ? { status: 503, bodyText: "unavailable" } : undefined,
      },
      receipts: [
        await storedReceipt({ target: "web", variables: { DATABASE_URL: 1, API_KEY: 1 } }),
      ],
    });

    // Run 1 has no --config (the receipt is untouched)
    expect(await rotate(fixture, "--reason", "first run")).toBe(1);
    expect(fixture.receipts.writes).toEqual([]);
    // Run 2 = resume + --config: only API_KEY, which this run re-encrypted,
    // advances. DATABASE_URL (version 2), which advanced on run 1, has no
    // "unchanged" evidence on this run = left untouched (the next plan shows
    // update and apply rewrites the same plaintext — the harmless side)
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
    // The receipt sits on dev, and the sync source is ops (the value environment — pinned at epoch 1)
    const sourceInOps = await statementFor({
      projectId: chainWithReceipts.projectId,
      environmentId: RECEIPTS_ENV,
      variableId: "vsrc",
      name: "DATABASE_URL",
      author: owner,
      head: headOf(chainWithReceipts, 1),
    });
    const sourceValue = await encryptValueFor({
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
    // The receipt variable itself is re-encrypted (same as a normal variable). No receipt is written
    expect(fixture.state.pushes.map((push) => push.variableId)).toEqual(["receipt-web"]);
    expect(fixture.env.logs.join("\n")).toContain(
      "No sync target in the config is synced from environment dev, so no receipt was advanced",
    );
    // The new-version receipt's contents are unchanged = plan is unchanged
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
      // Only web's receipt write is failed
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
        // Only the chain fetch after re-encryption finished (= the cleanup resync) is failed
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
    // The guidance after the cleanup (the anchor update) also comes out
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
    // First establish the receipt environment's floor via plan (records version 2 as verified)
    expect(
      await runCli(["sync", "plan", "web", "--config", fixture.configPath], fixture.env.layer),
    ).toBe(0);
    // The server redistributes an old version (a rollback)
    const stored = fixture.receipts.variables[0];
    if (stored === undefined) throw new Error("receipt missing");
    stored.value = older.value;

    expect(await rotate(fixture, "--reason", "scheduled", "--config", fixture.configPath)).toBe(1);
    // The rotation itself is done (its report comes out first). The evidence never morphs into "re-run apply"
    expect(fixture.env.logs.join("\n")).toContain("Done: rotated environment dev");
    expect(fixture.env.errors.join("\n")).toContain("value-version rollback");
    expect(fixture.env.errors.join("\n")).not.toContain("could not be advanced");
    expect(fixture.receipts.writes).toEqual([]);
    // Since the epoch advanced, the anchor-update guidance comes out ahead of the evidence
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
        // After re-encryption finished, it serves a **shorter** chain on the
        // same genesis (a different consistent chain without the rotate) =
        // verifies, yet is not an extension of the verified view
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
      // Serves a value with a broken signature (models a forged distribution)
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
      // A layoutVersion this CLI does not know (a statement written by a
      // future CLI — the v2 fields are all present). Rejected before signature verification
      receipts: [
        {
          ...receipt,
          statement: {
            ...receipt.statement,
            layoutVersion: 4,
            varType: "",
            required: false,
            description: "",
          },
        },
      ],
    });

    // The mock's manifest is built from the original statement (so the mock's
    // own assembly does not trip on the unknown layout). The CLI rejects it at
    // the verification stage before the manifest stage
    fixture.receipts.manifest = await manifestFor({
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
    expect(fixture.env.errors.join("\n")).toContain("Cannot read the sync config");
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
