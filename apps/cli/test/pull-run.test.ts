// Tests for pull (§5.1 distribution-time verification + §12-7 all-epoch DEKs)
// and run (memory injection), and for the AI-agent-detection boundary
// (value display is refused / run is allowed).

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  removeMemberOp,
  rotateEpochOp,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "prod";

interface Fixture {
  readonly owner: TestUser;
  readonly built: BuiltChain;
  readonly dek1: Uint8Array;
  readonly dek2: Uint8Array;
  readonly wraps: readonly WireRecipientDek[];
  readonly valueAlpha: WireDistributedValue;
  readonly valueBeta: WireDistributedValue;
  readonly envStatement: WireDistributedEnvironmentStatement;
  readonly entryAlpha: {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  };
  readonly entryBeta: {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  };
}

let fixture: Fixture;
let servers: MockServer[] = [];

/** A declaration headed by genesis (seq 1's entry hash = projectId — exists in every extension view). */
function genesisHead(projectId: string): { seq: number; hashHex: string } {
  return { seq: 1, hashHex: projectId };
}

/**
 * One variable of a pull response (verified statement + value — the §12-7 wire shape).
 * The statement's declared head is genesis (meta carries no epoch anchor, so
 * any view verifies when author is member-or-above — §4.2).
 */
async function pullEntry(
  projectId: string,
  variableId: string,
  name: string,
  value: WireDistributedValue,
  author?: TestUser,
  environmentId = ENV_ID,
): Promise<{
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
}> {
  return {
    variableId,
    statement: await statementFor({
      projectId,
      environmentId,
      variableId,
      name,
      author: author ?? fixture.owner,
      head: genesisHead(projectId),
    }),
    value,
  };
}

/** The environment statement of a pull response (active · metaVersion 1 · genesis head). */
async function pullEnvStatement(
  projectId: string,
  author?: TestUser,
  environmentId = ENV_ID,
): Promise<WireDistributedEnvironmentStatement> {
  return environmentStatementFor({
    projectId,
    environmentId,
    name: environmentId,
    author: author ?? fixture.owner,
    head: genesisHead(projectId),
  });
}

beforeAll(async () => {
  const owner = await makeTestUser("user-owner-1111");
  const dek1 = crypto.getRandomValues(new Uint8Array(32));
  const dek2 = crypto.getRandomValues(new Uint8Array(32));
  // The chain carries the real DEK's commitment (§5.2 — real data down to the pull comparison)
  const built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  const wraps = [
    await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
    await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
  ];
  // The latest version's epoch differs per variable (§12-7): ALPHA is epoch 2,
  // BETA stays at epoch 1, never re-encrypted after the rotation.
  // The value signature (§4.1) declares the head where each epoch was current (inclusive):
  // ALPHA = seq 3(rotate)、BETA = seq 2(create)
  const valueAlpha = await encryptValueFor({
    dek: dek2,
    ...common,
    epoch: 2,
    variableId: "va",
    version: 3,
    plaintext: "alpha-value",
    writer: owner,
    head: headOf(built, 3),
  });
  const valueBeta = await encryptValueFor({
    dek: dek1,
    ...common,
    epoch: 1,
    variableId: "vb",
    version: 1,
    plaintext: "beta-value",
    writer: owner,
    head: headOf(built, 2),
  });
  const envStatement = await environmentStatementFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
  });
  const entryAlpha = {
    variableId: "va",
    statement: await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "va",
      name: "ALPHA",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
    }),
    value: valueAlpha,
  };
  const entryBeta = {
    variableId: "vb",
    statement: await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "vb",
      name: "BETA",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
    }),
    value: valueBeta,
  };
  fixture = {
    owner,
    built,
    dek1,
    dek2,
    wraps,
    valueAlpha,
    valueBeta,
    envStatement,
    entryAlpha,
    entryBeta,
  };
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function chainHandler(): MockHandler {
  const { built } = fixture;
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

/**
 * Distributed set (after overrides) → digest input. Overrides with duplicate
 * variableIds fold last-wins because the digest computation rejects them (the
 * duplicate itself is refused by the client before manifest verification).
 */
function digestStatementsOf(
  variables: readonly unknown[],
  deletedVariables: readonly unknown[],
  declaredVariables: readonly unknown[] = [],
): readonly WireDistributedVariableStatement[] {
  const digestInputs = new Map<string, WireDistributedVariableStatement>();
  for (const entry of variables as readonly {
    readonly statement: WireDistributedVariableStatement;
  }[]) {
    digestInputs.set(entry.statement.variableId, entry.statement);
  }
  for (const declared of declaredVariables as readonly WireDistributedVariableStatement[]) {
    digestInputs.set(declared.variableId, declared);
  }
  for (const tombstone of deletedVariables as readonly WireDistributedVariableStatement[]) {
    digestInputs.set(tombstone.variableId, tombstone);
  }
  return [...digestInputs.values()];
}

function pullHandler(overrides?: {
  readonly deks?: readonly unknown[];
  readonly variables?: readonly unknown[];
  readonly deletedVariables?: readonly unknown[];
  readonly declaredVariables?: readonly unknown[];
  readonly statement?: unknown;
  /** Overrides for the manifest's digest input (for building absence negatives). */
  readonly digestDeclared?: readonly unknown[];
}): MockHandler {
  const { built, wraps, entryAlpha, entryBeta, envStatement } = fixture;
  // Default + test overrides (spread replaces only existing keys)
  const resolved = {
    statement: envStatement as unknown,
    variables: [entryAlpha, entryBeta] as readonly unknown[],
    deletedVariables: [] as readonly unknown[],
    declaredVariables: [] as readonly unknown[],
    deks: wraps as readonly unknown[],
    digestDeclared: undefined as readonly unknown[] | undefined,
    ...overrides,
  };
  return onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull`, async () => {
    // The manifest (§12-7) is computed from **the distributed set itself**
    // (matching even sets tampered with / swapped via override — each test's
    // negative verifies it is rejected by statement / value verification, not by the manifest)
    const manifest = await manifestFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      issuer: fixture.owner,
      head: headOf(built, 3),
      envStatement: resolved.statement as WireDistributedEnvironmentStatement,
      statements: digestStatementsOf(
        resolved.variables,
        resolved.deletedVariables,
        resolved.digestDeclared ?? resolved.declaredVariables,
      ),
    });
    return {
      status: 200,
      json: {
        environmentId: ENV_ID,
        currentEpoch: 2,
        statement: resolved.statement,
        variables: resolved.variables,
        deletedVariables: resolved.deletedVariables,
        ...(resolved.declaredVariables.length === 0
          ? {}
          : { declaredVariables: resolved.declaredVariables }),
        deks: resolved.deks,
        manifest,
      },
    };
  });
}

async function startEnv(handlers: readonly MockHandler[]): Promise<TestEnv> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, fixture.owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: fixture.built.projectId,
    defaultEnvironment: ENV_ID,
  });
  return env;
}

describe("maruhi pull", () => {
  it("syncs + §5.1-verifies + decrypts, then shows only metadata (never the value)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain("ALPHA");
    expect(output).toContain("version=3");
    expect(output).toContain("epoch=2");
    expect(output).toContain("BETA");
    expect(output).not.toContain("alpha-value");
    expect(output).not.toContain("beta-value");
  });

  it("warns about epochs missing a wrap for self (self-side detection of the diff from §7's all-epoch distribution)", async () => {
    // All active values are epoch 2 = decryption succeeds (a silent gap that
    // current values alone would never surface). SHOULD-warns that no wrap for self exists at epoch 1
    const env = await startEnv([
      chainHandler(),
      pullHandler({ variables: [fixture.entryAlpha], deks: [fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("no DEK wraps for you exist at epochs 1");
    expect(errors).toContain("re-run `maruhi member add`");
    // The device-side scenario is a sibling device's pull, not a re-run of approval (DK K11-5)
    expect(errors).toContain(
      `fills the missing epochs when it runs \`maruhi pull --project ${fixture.built.projectId} --env ${ENV_ID}\``,
    );
    expect(errors).not.toContain("maruhi device approve");

    // No warning when every epoch is covered (no false positive)
    const complete = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull"], complete.layer)).toBe(0);
    expect(complete.errors.join("\n")).not.toContain("no DEK wraps for you exist at epochs");
  });

  it("--show displays the value to a human", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--show"], env.layer)).toBe(0);
    expect(env.logs).toContain("ALPHA=alpha-value");
    expect(env.logs).toContain("BETA=beta-value");
  });

  it("command output goes only through CliIo (no path that hits real fds directly)", async () => {
    // The layer the argument handling moved to (effect/unstable/cli) emits via
    // the `Console` / `Stdio` services, but an upstream addition of a rendering
    // path could open a hole that passes through to real fds. Put the safety
    // net on the one command where **a decrypted value** can appear
    const env = await startEnv([chainHandler(), pullHandler()]);
    const bypassed: string[] = [];
    // Capture the original methods themselves, not bound wrappers (no extra layer stacked on each restore)
    const realWrite = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array): boolean => {
      bypassed.push(typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      expect(await runCli(["pull", "--show"], env.layer)).toBe(0);
    } finally {
      process.stdout.write = realWrite;
    }
    // The window also mixes in vitest's reporter output, so judge by **maruhi's words**
    const written = bypassed.join("");
    expect(written).not.toContain("alpha-value");
    expect(written).not.toContain("beta-value");
    expect(written).not.toContain("Sync and verification OK");
  });

  it("--show=false / --show false are read **exactly as written** and do not display the value", async () => {
    // Both an inline boolean value (`--show=false`) and a space-separated one
    // (`--show false`) are read as false. Misreading into true would turn a
    // run that says "do not display" into one that prints every secret — the
    // point is **being read correctly**, not refusal (the previous test shows
    // --show actually emits the value on this same distribution data)
    const inline = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--show=false"], inline.layer)).toBe(0);
    expect(inline.logs.join("\n")).not.toContain("alpha-value");
    expect(inline.logs.join("\n")).toContain("Sync and verification OK");

    const spaced = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--show", "false"], spaced.layer)).toBe(0);
    expect(spaced.logs.join("\n")).not.toContain("alpha-value");
  });

  it("duplicate flags like `--no-show --show` fail without displaying the value", async () => {
    // Resolving a duplicate silently (bare Flag.Boolean stays silent with
    // first-wins) could drop the explicit `--no-show` and print every secret
    // to the terminal (the `maruhi pull --no-show $FLAGS` shape). Under any
    // rule **the result would depend on the order typed**, so Flag.atMost(1)
    // rejects it regardless of order
    const later = await startEnv([chainHandler(), pullHandler()]);
    const server = servers[servers.length - 1];
    expect(await runCli(["pull", "--no-show", "--show"], later.layer)).toBe(2);
    expect(later.logs.join("\n")).not.toContain("alpha-value");
    expect(later.errors.join("\n")).toContain("Flag --show was specified more than once");
    // The check precedes any communication (never produces the plaintext to decrypt in the first place)
    expect(server?.requests).toHaveLength(0);

    // The reverse order (--no-show last) is treated identically. A "pass when
    // the result leans safe" rule would hide that a written flag was dropped
    const earlier = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--show", "--no-show"], earlier.layer)).toBe(2);
    expect(earlier.errors.join("\n")).toContain("Flag --show was specified more than once");

    // Same-spelling duplicates are also rejected (`--show --show`)
    const same = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--show", "--show"], same.layer)).toBe(2);
    expect(same.logs.join("\n")).not.toContain("alpha-value");

    // A lone `--no-show` passes as false exactly as written (only duplicates are refused)
    const single = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--no-show"], single.layer)).toBe(0);
    expect(single.logs.join("\n")).not.toContain("alpha-value");
  });

  it("--show neutralizes ANSI/control sequences in the value while keeping newlines", async () => {
    // A value saved by a malicious co-editor (ESC + BEL) + a legitimate multi-line value (PEM-style)
    const evil = "sk-\u001b[31mFAKE\u0007\nline2";
    const value = await encryptValueFor({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "vs",
      version: 1,
      plaintext: evil,
      writer: fixture.owner,
      head: headOf(fixture.built, 3),
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [await pullEntry(fixture.built.projectId, "vs", "SECRET", value)],
      }),
    ]);
    expect(await runCli(["pull", "--show"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    // ESC / BEL never reach the terminal raw
    expect(output).not.toContain("\u001b");
    expect(output).not.toContain("\u0007");
    // Newlines are kept (multi-line secrets stay intact). But lines from the
    // second onward are marked: emitted raw, the value could forge a
    // `NAME=value` line
    expect(output).toContain("SECRET= (a 2-line value");
    expect(output).toContain("| sk-\uFFFD[31mFAKE\uFFFD\n| line2");
  });

  it("--show fails when a value is invalid UTF-8, and prints no value at all", async () => {
    // A value whose plaintext is an invalid UTF-8 byte sequence (0xff/0xfe never appear in UTF-8)
    const binary = await encryptValueFor({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "vbin",
      version: 1,
      plaintext: new Uint8Array([0x41, 0xff, 0xfe, 0x42]),
      writer: fixture.owner,
      head: headOf(fixture.built, 3),
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [
          fixture.entryAlpha,
          await pullEntry(fixture.built.projectId, "vbin", "BINARY", binary),
        ],
      }),
    ]);
    expect(await runCli(["pull", "--show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("not valid UTF-8 and cannot be displayed");
    // all-or-nothing: even ALPHA, which sorts first (decodes fine), is not partially printed
    expect(env.logs.join("\n")).not.toContain("ALPHA=alpha-value");
  });

  it("when an AI agent is detected, --show is refused (never suggests run as a workaround)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: true, name: "cursor" });
    expect(await runCli(["pull", "--show"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("AI agent environment was detected");
    // Never suggest run as a bypass for value display (do not hand the agent a bypass recipe)
    expect(errors).not.toContain("maruhi run");
    expect(env.logs.join("\n")).not.toContain("alpha-value");
    // The refusal is fixed at the command entrance (pre-decryption): it never proceeds to sync, decrypt, or metadata display
    expect(env.logs.join("\n")).not.toContain("Sync and verification OK");
  });

  it("--show is refused even for an **unknown** agent (TTY is the primary boundary = fail-closed)", async () => {
    // A deny-list (known env vars) would have let this through. When stdout is
    // a pipe / redirect, the value is never shown even if the detection list
    // misses it (`maruhi pull --show > secrets.txt` is refused by the same check)
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: false });
    env.setTerminal({ stdout: false });
    expect(await runCli(["pull", "--show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("stdout is not an interactive terminal");
    expect(env.logs.join("\n")).not.toContain("alpha-value");
    // Fixed before decryption (the plaintext is never produced in the first place)
    expect(env.logs.join("\n")).not.toContain("Sync and verification OK");
  });

  it("runs whose stdin is not a terminal (CI, heredoc) are refused too", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setTerminal({ stdin: false });
    expect(await runCli(["pull", "--show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("stdin is not an interactive terminal");
    expect(env.logs.join("\n")).not.toContain("alpha-value");
  });

  it("a pull that displays no value passes without a terminal (refusal is only for --show)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: true, name: "cursor" });
    env.setTerminal({ stdin: false, stdout: false });
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("Sync and verification OK");
  });

  it("refuses a wrap that forges the signer (a false signerUserId claim)", async () => {
    const stranger = await makeTestUser("user-stranger-9999");
    const spoofed = await wrapDekFor({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek: fixture.dek1,
      recipient: fixture.owner,
      signer: stranger,
    });
    // The server falsely claims the signer is owner (the signature stays stranger's)
    const lying = {
      ...spoofed,
      signerUserId: fixture.owner.userId,
      signerKeyFingerprintHex: fixture.owner.fingerprintHex,
    };
    const env = await startEnv([chainHandler(), pullHandler({ deks: [lying, fixture.wraps[1]] })]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("registration signature does not verify");
  });

  it("refuses a wrap whose signer does not exist in chain history", async () => {
    const stranger = await makeTestUser("user-stranger-9999");
    const foreign = await wrapDekFor({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek: fixture.dek1,
      recipient: fixture.owner,
      signer: stranger,
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [foreign, fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("signer does not exist in the chain history");
  });

  it("refuses a signature bit-flip", async () => {
    const wrap = fixture.wraps[0];
    if (wrap === undefined) {
      throw new Error("fixture");
    }
    const flipped = `${wrap.signatureHex.slice(0, -1)}${wrap.signatureHex.endsWith("0") ? "1" : "0"}`;
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [{ ...wrap, signatureHex: flipped }, fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("registration signature does not verify");
  });

  it("a variable whose declared-epoch DEK is not distributed is an error", async () => {
    const env = await startEnv([chainHandler(), pullHandler({ deks: [fixture.wraps[1]] })]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("your wrap is missing");
  });

  it("ciphertext swapped in from another variable (metadata / AAD mismatch) is refused before decryption", async () => {
    // Distribute BETA's ciphertext in ALPHA's slot. The value-signature
    // verification (the §6.3-5 coordinate match) detects the declared-AAD /
    // outer-metadata mismatch before decryption
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [await pullEntry(fixture.built.projectId, "va", "ALPHA", fixture.valueBeta)],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "declares AAD coordinates that do not match the requested context",
    );
  });

  it("refuses a wrap beyond the chain's current epoch (a phantom epoch)", async () => {
    // Even signed by a legitimate member (owner), a wrap for epoch 3 — which
    // has no rotate_epoch on the chain — is not accepted (the client side of §12-6 — the main line of server distrust)
    const phantom = await wrapDekFor({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 3,
      dek: crypto.getRandomValues(new Uint8Array(32)),
      recipient: fixture.owner,
      signer: fixture.owner,
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [...fixture.wraps, phantom] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("beyond the chain's current epoch (2)");
  });

  it("refuses a variable whose declared epoch exceeds the chain's current epoch", async () => {
    // An epoch that does not exist on the chain (3) never matches "the current
    // epoch at the declared head", whichever head is declared — the value-
    // signature verification (§6.3-4) refuses before decryption
    const phantomValue = await encryptValueFor({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 3,
      variableId: "vp",
      version: 1,
      plaintext: "phantom",
      writer: fixture.owner,
      head: headOf(fixture.built, 3),
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [await pullEntry(fixture.built.projectId, "vp", "PHANTOM", phantomValue)],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=epoch-not-current-at-head");
  });

  it("refuses a DEK that does not match the on-chain commitment (a poisoned wrap = fake-DEK injection) (§5.2)", async () => {
    // Even a wrap §5.1-signed by a legitimate member (owner) for a real epoch
    // is refused before use when its contents are a DEK that does not match
    // the on-chain commitment (blocking fake-DEK injection by collusion of a
    // malicious server + a key holder in chain history —
    // CRYPTO_SPEC §14.2-1)
    const forgedDek = crypto.getRandomValues(new Uint8Array(32));
    const poison = await wrapDekFor({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek: forgedDek,
      recipient: fixture.owner,
      signer: fixture.owner,
    });
    const env = await startEnv([chainHandler(), pullHandler({ deks: [poison, fixture.wraps[1]] })]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not match the commitment on the chain");
  });

  it("refuses a commitment-mismatched DEK even pre-push (via listMine) (the §5.2 confidentiality side)", async () => {
    // §5.2 (2): blocks the push toward encrypting with a fake DEK (a push the
    // attacker can read) via a comparison before the DEK is used. Mix a poisoned wrap into the listMine distribution
    const forgedDek = crypto.getRandomValues(new Uint8Array(32));
    const poison = await wrapDekFor({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      dek: forgedDek,
      recipient: fixture.owner,
      signer: fixture.owner,
    });
    const env = await startEnv([
      chainHandler(),
      // GAMMA does not exist → the create path's name resolution pulls only
      // metadata (§12-7); the DEK is fetched exactly once via listMine (mix the poisoned wrap into that distribution)
      onRequest(
        "GET",
        `/projects/${fixture.built.projectId}/environments/${ENV_ID}/pull/metadata`,
        async () => ({
          status: 200,
          json: {
            environmentId: ENV_ID,
            currentEpoch: 2,
            statement: fixture.envStatement,
            variables: [fixture.entryAlpha.statement, fixture.entryBeta.statement],
            deletedVariables: [],
            manifest: await manifestFor({
              projectId: fixture.built.projectId,
              environmentId: ENV_ID,
              epoch: 2,
              issuer: fixture.owner,
              head: headOf(fixture.built, 3),
              envStatement: fixture.envStatement,
              statements: [fixture.entryAlpha.statement, fixture.entryBeta.statement],
            }),
          },
        }),
      ),
      onRequest("GET", `/projects/${fixture.built.projectId}/environments/${ENV_ID}/deks`, () => ({
        status: 200,
        json: { deks: [fixture.wraps[0], poison] },
      })),
    ]);
    env.setStdin(new TextEncoder().encode("new-value"));
    expect(await runCli(["push", "GAMMA"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not match the commitment on the chain");
  });

  it("refuses a distribution for an environment with no create_environment on the chain (a phantom environment)", async () => {
    // Never grant the default epoch to an environment the chain does not know
    // (§6.2): the value is rejected by the value-signature verification
    // (§6.3-4 — refusal of a pre-creation head) before decryption
    const ghostValue = await encryptValueFor({
      dek: fixture.dek1,
      projectId: fixture.built.projectId,
      environmentId: "ghost",
      epoch: 1,
      variableId: "vg",
      version: 1,
      plaintext: "ghost",
      writer: fixture.owner,
      head: headOf(fixture.built, 3),
    });
    const ghostWrap = await wrapDekFor({
      projectId: fixture.built.projectId,
      environmentId: "ghost",
      epoch: 1,
      dek: fixture.dek1,
      recipient: fixture.owner,
      signer: fixture.owner,
    });
    const ghostEnvStatement = await pullEnvStatement(fixture.built.projectId, undefined, "ghost");
    const ghostEntry = await pullEntry(
      fixture.built.projectId,
      "vg",
      "GHOST",
      ghostValue,
      undefined,
      "ghost",
    );
    const env = await startEnv([
      chainHandler(),
      onRequest("GET", `/projects/${fixture.built.projectId}/environments/ghost/pull`, () => ({
        status: 200,
        json: {
          environmentId: "ghost",
          currentEpoch: 1,
          // A meta statement never checks the environment's existence (the
          // §12-4 asymmetry), so the ghost environment's statement itself
          // verifies; the value signature (§6.3-4) rejects it
          statement: ghostEnvStatement,
          variables: [ghostEntry],
          deletedVariables: [],
          deks: [ghostWrap],
        },
      })),
    ]);
    expect(await runCli(["pull", "--env", "ghost"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=environment-not-created-at-head");
  });

  it("refuses a wrap whose signer FP matches no key in chain history", async () => {
    const wrap = fixture.wraps[0];
    if (wrap === undefined) {
      throw new Error("fixture");
    }
    const wrongFp = { ...wrap, signerKeyFingerprintHex: "00".repeat(16) };
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [wrongFp, fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("signer does not exist in the chain history");
  });

  it("refuses duplicate DEK wraps for the same epoch", async () => {
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [fixture.wraps[0], fixture.wraps[0], fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Duplicate DEK wraps");
  });

  it("ciphertext swapped in that was encrypted under another environment's coordinates is refused before decryption", async () => {
    // Distribute a value whose environmentId alone is elsewhere's (other-env)
    // as if it were prod → the declared-AAD coordinate match (§6.3-5) detects it before decryption
    const crossEnv = await encryptValueFor({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: "other-env",
      epoch: 2,
      variableId: "va",
      version: 3,
      plaintext: "cross",
      writer: fixture.owner,
      head: headOf(fixture.built, 3),
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [await pullEntry(fixture.built.projectId, "va", "ALPHA", crossEnv)],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "declares AAD coordinates that do not match the requested context",
    );
  });

  it("a removed→re-added (new key) member's past signature verifies under the key of its time (§5.1)", async () => {
    // signer signs with the keyset of its membership time (keysetA), is then
    // removed → the same user_id is re-added with a new keyset (keysetB).
    // keyHistory holds 2 bindings; the FP match selects the key of that time (the chain is append-only — CRYPTO_SPEC §5.1)
    const oldKeys = await makeTestUser("user-rotated-5555");
    const newKeys = await makeTestUser("user-rotated-5555");
    const owner = fixture.owner;
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(oldKeys, "member") },
      { actor: oldKeys, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: removeMemberOp(oldKeys) },
      { actor: owner, operation: addMemberOp(newKeys, "member") },
    ]);
    const wrap = await wrapDekFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: oldKeys,
    });
    // The value is also signed with the key of that time (§4.1): the declared
    // head is within the membership interval (seq 3 = its own create_environment
    // entry) — it verifies against the whole post-removal chain too (§6.3-1)
    const value = await encryptValueFor({
      dek,
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "vr",
      version: 1,
      plaintext: "historic",
      writer: oldKeys,
      head: headOf(built, 3),
    });
    const historicEnvStatement = await pullEnvStatement(built.projectId, owner);
    const historicEntry = await pullEntry(built.projectId, "vr", "HISTORIC", value, owner);
    const pullJson = {
      environmentId: ENV_ID,
      currentEpoch: 1,
      statement: historicEnvStatement,
      variables: [historicEntry],
      deletedVariables: [],
      deks: [wrap],
      manifest: await manifestFor({
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        issuer: owner,
        head: headOf(built, 5),
        envStatement: historicEnvStatement,
        statements: [historicEntry.statement],
      }),
    };
    const server = await MockServer.start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
        },
      })),
      onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull`, () => ({
        status: 200,
        json: pullJson,
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("HISTORIC");
  });

  it("tokens / secret-key material never appear in the output", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).not.toContain("maruhi_pat_");
    expect(output).not.toContain(fixture.owner.encSkHex);
    expect(output).not.toContain(fixture.owner.sigSkSeedHex);
  });

  it("control characters in variable names (ANSI, newlines) are sanitized in terminal output", async () => {
    const evilName = "EVIL\u001b[2J\nNAME";
    const value = await encryptValueFor({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "ve",
      version: 1,
      plaintext: "v",
      writer: fixture.owner,
      head: headOf(fixture.built, 3),
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [await pullEntry(fixture.built.projectId, "ve", evilName, value)],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const output = [...env.logs, ...env.errors].join("\n");
    // Raw ESC never flows to the terminal (control characters are replaced)
    expect(output).not.toContain("\u001b");
    expect(output).toContain("EVIL\uFFFD[2J\uFFFDNAME");
  });

  it("refuses duplicate variable names (a server-response inconsistency)", async () => {
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [
          fixture.entryAlpha,
          await pullEntry(fixture.built.projectId, "vb", "ALPHA", fixture.valueBeta),
        ],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Multiple live statements with the same name");
  });

  it("refuses a value-signature bit-flip before decryption (§4.1)", async () => {
    const value = fixture.valueAlpha;
    const flipped = `${value.signatureHex.slice(0, -1)}${
      value.signatureHex.endsWith("0") ? "1" : "0"
    }`;
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ ...fixture.entryAlpha, value: { ...value, signatureHex: flipped } }],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=signature-invalid");
  });

  it("refuses a false writer claim (the signature stays someone else's) (the §4.1 attribution)", async () => {
    // The signature stays owner's while writer is claimed as another user_id +
    // another FP → no such binding exists in chain history, so no verification key can be selected
    const stranger = await makeTestUser("user-stranger-9999");
    const lying = {
      ...fixture.valueAlpha,
      writerUserId: stranger.userId,
      writerKeyFingerprintHex: stranger.fingerprintHex,
    };
    const env = await startEnv([
      chainHandler(),
      pullHandler({ variables: [{ ...fixture.entryAlpha, value: lying }] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=writer-unknown");
  });

  it("refuses a value whose removed writer declared a post-removal head (§6.3-3)", async () => {
    // oldKeys is removed at seq 4. A value declaring head 5 (post-removal) is
    // refused on "membership at the declared head" even with a valid signature (fresh injection by a removed member's key)
    const oldKeys = await makeTestUser("user-rotated-5555");
    const owner = fixture.owner;
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(oldKeys, "member") },
      { actor: oldKeys, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: removeMemberOp(oldKeys) },
      { actor: owner, operation: addMemberOp(await makeTestUser("user-other-7777"), "member") },
    ]);
    const wrap = await wrapDekFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: owner,
    });
    const forged = await encryptValueFor({
      dek,
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "vf",
      version: 1,
      plaintext: "forged-after-removal",
      writer: oldKeys,
      head: headOf(built, 5),
    });
    const pullJson = {
      environmentId: ENV_ID,
      currentEpoch: 1,
      statement: await pullEnvStatement(built.projectId, owner),
      variables: [await pullEntry(built.projectId, "vf", "FORGED", forged, owner)],
      deletedVariables: [],
      deks: [wrap],
    };
    const server = await MockServer.start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
        },
      })),
      onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull`, () => ({
        status: 200,
        json: pullJson,
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=writer-not-member-at-head");
  });

  it("refuses duplicate variableIds within one response (the carriage form of equivocation)", async () => {
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [
          fixture.entryAlpha,
          { ...fixture.entryAlpha, statement: { ...fixture.entryAlpha.statement, name: "ALPHA2" } },
        ],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Duplicate variable IDs within one response");
  });

  it("a value written by a member added in the unsynced gap is accepted via bounded resync", async () => {
    // Old view = genesis only (seq 1). A new member is added at seq 2 and writes
    // the environment + value at seq 3. Under the old view the writer is
    // unknown (writer-unknown), but the declared seq is beyond our head, so it resyncs instead of refusing outright, and accepts
    const owner = fixture.owner;
    const newcomer = await makeTestUser("user-newcomer-2222");
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const shortBuilt = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const fullBuilt = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(newcomer, "member") },
      { actor: newcomer, operation: createEnvironmentOp(ENV_ID, dek) },
    ]);
    expect(shortBuilt.projectId).toBe(fullBuilt.projectId);
    const wrap = await wrapDekFor({
      projectId: fullBuilt.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: newcomer,
    });
    const value = await encryptValueFor({
      dek,
      projectId: fullBuilt.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "vn",
      version: 1,
      plaintext: "by-newcomer",
      writer: newcomer,
      head: headOf(fullBuilt, 3),
    });
    const newcomerEnvStatement = await pullEnvStatement(fullBuilt.projectId, owner);
    const newcomerEntry = await pullEntry(fullBuilt.projectId, "vn", "NEWCOMER", value, owner);
    const newcomerPullJson = {
      environmentId: ENV_ID,
      currentEpoch: 1,
      statement: newcomerEnvStatement,
      variables: [newcomerEntry],
      deletedVariables: [],
      deks: [wrap],
      manifest: await manifestFor({
        projectId: fullBuilt.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        issuer: owner,
        head: headOf(fullBuilt, 3),
        envStatement: newcomerEnvStatement,
        statements: [newcomerEntry.statement],
      }),
    };
    let chainCalls = 0;
    const server = await MockServer.start([
      onRequest("GET", `/projects/${fullBuilt.projectId}/chain`, () => {
        chainCalls += 1;
        const source = chainCalls === 1 ? shortBuilt : fullBuilt;
        return {
          status: 200,
          json: {
            projectId: fullBuilt.projectId,
            entries: source.entries,
            headSeq: source.entries.length,
            headHashHex: source.hashes[source.hashes.length - 1],
          },
        };
      }),
      onRequest("GET", `/projects/${fullBuilt.projectId}/environments/${ENV_ID}/pull`, () => ({
        status: 200,
        json: newcomerPullJson,
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: fullBuilt.projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(chainCalls).toBe(2);
    expect(env.logs.join("\n")).toContain("NEWCOMER");
  });

  it("a future head (a declared seq beyond our view) is accepted via the bounded-resync extension check (§6.3-2b)", async () => {
    // Old view = up to seq 2 (the rotate is unobserved). The value declares
    // seq 3 (the rotate) as head. First verification is chain-head-future →
    // the resync reveals a 3-entry extension; re-verification accepts
    const { built } = fixture;
    const shortChain = built.entries.slice(0, 2);
    let chainCalls = 0;
    const progressiveChain = onRequest("GET", `/projects/${built.projectId}/chain`, () => {
      chainCalls += 1;
      const entries = chainCalls === 1 ? shortChain : built.entries;
      return {
        status: 200,
        json: {
          projectId: built.projectId,
          entries,
          headSeq: entries.length,
          headHashHex: built.hashes[entries.length - 1],
        },
      };
    });
    const env = await startEnv([
      progressiveChain,
      pullHandler({
        variables: [fixture.entryAlpha],
        deks: fixture.wraps,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    // The chain is fetched twice: the first sync + the future-head resync
    expect(chainCalls).toBe(2);
    expect(env.logs.join("\n")).toContain("ALPHA");
  });

  it("refuses when the future-head resync is not an extension of the old view (a swapped different-history chain)", async () => {
    // Old view = the honest 3 entries. The value declares seq 4 → the resync
    // returns "a different 4-entry chain branched off the same genesis" = the old head's (seq 3) hash mismatches
    const { built, owner } = fixture;
    const forkDek = crypto.getRandomValues(new Uint8Array(32));
    const forked = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, fixture.dek1) },
      // An entry differing from the honest chain's seq 3 (rotate epoch 2) = a branch
      { actor: owner, operation: createEnvironmentOp("side", forkDek) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, fixture.dek2) },
    ]);
    expect(forked.projectId).toBe(built.projectId);
    const futureValue = await encryptValueFor({
      dek: fixture.dek2,
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "va",
      version: 1,
      plaintext: "future",
      writer: owner,
      head: headOf(forked, 4),
    });
    let chainCalls = 0;
    const progressiveChain = onRequest("GET", `/projects/${built.projectId}/chain`, () => {
      chainCalls += 1;
      const source = chainCalls === 1 ? built : forked;
      return {
        status: 200,
        json: {
          projectId: built.projectId,
          entries: source.entries,
          headSeq: source.entries.length,
          headHashHex: source.hashes[source.hashes.length - 1],
        },
      };
    });
    const env = await startEnv([
      progressiveChain,
      pullHandler({
        variables: [{ ...fixture.entryAlpha, value: futureValue }],
        deks: fixture.wraps,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("not an extension of the verified view");
  });

  it("a head declaration whose seq is at-or-below our view but whose hash mismatches is refused immediately (§6.3-2a)", async () => {
    const bogus = await encryptValueFor({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "va",
      version: 1,
      plaintext: "bogus-head",
      writer: fixture.owner,
      head: { seq: 3, hashHex: "ee".repeat(32) },
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({ variables: [{ ...fixture.entryAlpha, value: bogus }] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=chain-head-mismatch");
  });
});

describe("distribution-time verification of meta statements (§4.2 / §6.3)", () => {
  it("refuses a statement-signature bit-flip before decryption", async () => {
    const statement = fixture.entryAlpha.statement;
    const flipped = `${statement.signatureHex.slice(0, -1)}${
      statement.signatureHex.endsWith("0") ? "1" : "0"
    }`;
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ ...fixture.entryAlpha, statement: { ...statement, signatureHex: flipped } }],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("meta statement failed");
  });

  it("refuses a name swap (a statement with only its name replaced) (the carriage form of a name-swap)", async () => {
    // Keep the signature honest but rewrite only the name field = rejected by the byte-exact signature
    const swapped = { ...fixture.entryAlpha.statement, name: "DEBUG_ENDPOINT" };
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ ...fixture.entryAlpha, statement: swapped }],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=signature-invalid");
  });

  it("refuses a statement transplanted from another variable (variableId mismatch)", async () => {
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ ...fixture.entryAlpha, statement: fixture.entryBeta.statement }],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "statement coordinates that do not match the requested context",
    );
  });

  it("refuses a false author claim (the signature stays someone else's) (the §4.2 attribution)", async () => {
    const stranger = await makeTestUser("user-stranger-9999");
    const lying = {
      ...fixture.entryAlpha.statement,
      authorUserId: stranger.userId,
      authorKeyFingerprintHex: stranger.fingerprintHex,
    };
    const env = await startEnv([
      chainHandler(),
      pullHandler({ variables: [{ ...fixture.entryAlpha, statement: lying }] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=author-unknown");
  });

  it("refuses tampered / deleted environment-statement distribution", async () => {
    // Signature bit-flip
    const flipped = `${fixture.envStatement.signatureHex.slice(0, -1)}${
      fixture.envStatement.signatureHex.endsWith("0") ? "1" : "0"
    }`;
    const tampered = await startEnv([
      chainHandler(),
      pullHandler({ statement: { ...fixture.envStatement, signatureHex: flipped } }),
    ]);
    expect(await runCli(["pull"], tampered.layer)).toBe(1);
    expect(tampered.errors.join("\n")).toContain("meta statement failed");

    // Distributing a deleted statement (pulling a deleted environment should 404 on the server)
    const deletedStatement = await pullEnvStatement(fixture.built.projectId);
    const deleted = await startEnv([
      chainHandler(),
      pullHandler({
        statement: {
          ...(await environmentStatementFor({
            projectId: fixture.built.projectId,
            environmentId: ENV_ID,
            name: ENV_ID,
            author: fixture.owner,
            head: genesisHead(fixture.built.projectId),
            status: "deleted",
            metaVersion: 2,
          })),
        },
      }),
    ]);
    void deletedStatement;
    expect(await runCli(["pull"], deleted.layer)).toBe(1);
    expect(deleted.errors.join("\n")).toContain("was served a deleted statement");
  });

  it("a deleted variable's tombstone is verified; co-listing it with active (the carriage form of unauthorized resurrection) is refused", async () => {
    // Happy path: a distribution of only a deleted statement is accepted and never surfaces in values
    const tombstone = await statementFor({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      variableId: "v-deleted",
      name: "RETIRED_KEY",
      author: fixture.owner,
      head: genesisHead(fixture.built.projectId),
      status: "deleted",
      metaVersion: 2,
    });
    const ok = await startEnv([chainHandler(), pullHandler({ deletedVariables: [tombstone] })]);
    expect(await runCli(["pull"], ok.layer)).toBe(0);
    expect(ok.logs.join("\n")).not.toContain("RETIRED_KEY");

    // The same variableId distributed as both active and deleted = refusal
    const revived = { ...tombstone, variableId: fixture.entryAlpha.variableId };
    const conflict = await startEnv([chainHandler(), pullHandler({ deletedVariables: [revived] })]);
    expect(await runCli(["pull"], conflict.layer)).toBe(1);
    expect(conflict.errors.join("\n")).toContain(
      "served as both live (active or declared) and deleted",
    );

    // A tampered tombstone signature is refused too (as long as it is distributed, it is verified)
    const flipped = `${tombstone.signatureHex.slice(0, -1)}${
      tombstone.signatureHex.endsWith("0") ? "1" : "0"
    }`;
    const tampered = await startEnv([
      chainHandler(),
      pullHandler({ deletedVariables: [{ ...tombstone, signatureHex: flipped }] }),
    ]);
    expect(await runCli(["pull"], tampered.layer)).toBe(1);
    expect(tampered.errors.join("\n")).toContain("meta statement failed");
  });

  it("distributing a non-NFC name is warned (SHOULD — §12-1; processing continues)", async () => {
    const nfdName = "CAFE\u0301_URL";
    expect(nfdName.normalize("NFC")).not.toBe(nfdName);
    const value = await encryptValueFor({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "vnfd",
      version: 1,
      plaintext: "v",
      writer: fixture.owner,
      head: headOf(fixture.built, 3),
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [await pullEntry(fixture.built.projectId, "vnfd", nfdName, value)],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("not NFC-normalized");
  });

  it("a removed author's statement verifies under a during-membership head (the §6.3-1 counterpart)", async () => {
    // author (oldKeys) is removed at seq 4. A statement declaring head seq 3
    // (during membership) verifies under the key of that time against the whole post-removal chain
    const oldKeys = await makeTestUser("user-rotated-5555");
    const owner = fixture.owner;
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(oldKeys, "member") },
      { actor: oldKeys, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: removeMemberOp(oldKeys) },
    ]);
    const wrap = await wrapDekFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: owner,
    });
    const value = await encryptValueFor({
      dek,
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "vh",
      version: 1,
      plaintext: "historic",
      writer: oldKeys,
      head: headOf(built, 3),
    });
    const historicEnvStatement = await environmentStatementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      name: ENV_ID,
      author: oldKeys,
      head: headOf(built, 3),
    });
    const historicStatement = await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "vh",
      name: "HISTORIC",
      author: oldKeys,
      head: headOf(built, 3),
    });
    const pullJson = {
      environmentId: ENV_ID,
      currentEpoch: 1,
      statement: historicEnvStatement,
      variables: [{ variableId: "vh", statement: historicStatement, value }],
      deletedVariables: [],
      deks: [wrap],
      // The manifest issuer is a current member (owner) — the author's removal
      // is independent of whether the manifest may be issued (the §4.3 issuer-membership check applies only to the issuer itself)
      manifest: await manifestFor({
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        issuer: owner,
        head: headOf(built, 4),
        envStatement: historicEnvStatement,
        statements: [historicStatement],
      }),
    };
    const server = await MockServer.start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
        },
      })),
      onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull`, () => ({
        status: 200,
        json: pullJson,
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("HISTORIC");
  });

  it("refuses a statement whose removed author declared a post-removal head", async () => {
    const oldKeys = await makeTestUser("user-rotated-5555");
    const owner = fixture.owner;
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(oldKeys, "member") },
      { actor: oldKeys, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: removeMemberOp(oldKeys) },
    ]);
    const wrap = await wrapDekFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: owner,
    });
    const value = await encryptValueFor({
      dek,
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "vf",
      version: 1,
      plaintext: "v",
      writer: owner,
      head: headOf(built, 3),
    });
    // Of meta forward-injections, "declaring a post-removal head" is rejected
    // by the membership check (§6.3-3. A forward injection declaring a
    // during-membership head has no epoch anchor and is undetected in v1 — §14.3-5)
    const forgedStatement = await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "vf",
      name: "FORGED_NAME",
      author: oldKeys,
      head: headOf(built, 4),
      metaVersion: 2,
    });
    const pullJson = {
      environmentId: ENV_ID,
      currentEpoch: 1,
      statement: await environmentStatementFor({
        projectId: built.projectId,
        environmentId: ENV_ID,
        name: ENV_ID,
        author: owner,
        head: headOf(built, 1),
      }),
      variables: [{ variableId: "vf", statement: forgedStatement, value }],
      deletedVariables: [],
      deks: [wrap],
    };
    const server = await MockServer.start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
        },
      })),
      onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull`, () => ({
        status: 200,
        json: pullJson,
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=author-not-member-at-head");
  });

  it("a statement's future head is accepted via bounded resync too (reusing the same mechanism as values — §6.3-2b)", async () => {
    // Old view = up to seq 2. The statement declares seq 3 (the rotate) as
    // head. First verification is chain-head-future → the resync reveals the extension; re-verification accepts
    const { built } = fixture;
    const futureStatement = await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "va",
      name: "ALPHA",
      author: fixture.owner,
      head: headOf(built, 3),
    });
    const shortChain = built.entries.slice(0, 2);
    let chainCalls = 0;
    const progressiveChain = onRequest("GET", `/projects/${built.projectId}/chain`, () => {
      chainCalls += 1;
      const entries = chainCalls === 1 ? shortChain : built.entries;
      return {
        status: 200,
        json: {
          projectId: built.projectId,
          entries,
          headSeq: entries.length,
          headHashHex: built.hashes[entries.length - 1],
        },
      };
    });
    const env = await startEnv([
      progressiveChain,
      pullHandler({
        variables: [{ ...fixture.entryAlpha, statement: futureStatement }],
        deks: fixture.wraps,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(chainCalls).toBe(2);
    expect(env.logs.join("\n")).toContain("ALPHA");
  });
});

describe("maruhi run", () => {
  it("injects decrypted values as child-process environment variables (memory injection)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "printenv", "ALPHA"], env.layer)).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
    expect(env.runnerCalls[0]?.command).toEqual(["printenv", "ALPHA"]);
    expect(env.runnerCalls[0]?.extraEnv).toEqual({
      ALPHA: "alpha-value",
      BETA: "beta-value",
    });
  });

  it("run is allowed even when an AI agent is detected (the boundary)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: true, name: "cursor" });
    // It passes without a terminal (CI / pipe). run is not a path that *shows*
    // the value but a consumption path injecting it into the child's
    // environment variables — outside the TTY boundary
    env.setTerminal({ stdin: false, stdout: false });
    expect(await runCli(["run", "--", "true"], env.layer)).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
  });

  it("the value appears only in the child-process environment, never in terminal output", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "true"], env.layer)).toBe(0);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).not.toContain("alpha-value");
    expect(output).not.toContain("beta-value");
    expect(env.runnerCalls[0]?.extraEnv["ALPHA"]).toBe("alpha-value");
  });

  it("propagates the child process's exit code", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setRunnerExitCode(3);
    expect(await runCli(["run", "--", "false"], env.layer)).toBe(3);
  });

  it("no command specified errors without pulling or decrypting", async () => {
    // A run with nothing to execute is a usage mistake (usage error). Letting
    // it through would fetch the distribution and decrypt every variable
    // before saying the same thing = producing plaintext that is never used
    const env = await startEnv([chainHandler(), pullHandler()]);
    const server = servers[servers.length - 1];
    expect(await runCli(["run"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify the command to run after `--`");
    expect(server?.requests).toHaveLength(0);
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("the same when `--` is given but nothing follows it", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    const server = servers[servers.length - 1];
    expect(await runCli(["run", "--"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify the command to run after `--`");
    expect(server?.requests).toHaveLength(0);
  });

  it("passes empty-string arguments after `--` through without dropping them", async () => {
    // Dropping an empty-string argument on a truthiness check silently shrinks
    // the child's argv by one and misfires the argument check too. Everything
    // after `--` is passed through as an argv token verbatim
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "printenv", "", "ALPHA"], env.layer)).toBe(0);
    expect(env.runnerCalls[0]?.command).toEqual(["printenv", "", "ALPHA"]);
  });

  it("catches an empty argument before `--` even when the child side has a whitespace argument", async () => {
    // The tokens before and after `--` merge into one array (the upstream
    // parser), so a leading empty string lands in the executable position.
    // `Argument.filter` rejects it as "nothing to execute" — a whitespace-only
    // child argument (`" "`) is not rejected (the second onward pass through as-is)
    const env = await startEnv([chainHandler(), pullHandler()]);
    const server = servers[servers.length - 1];
    expect(await runCli(["run", "", "--", "printenv", " "], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify the command to run after `--`");
    expect(server?.requests).toHaveLength(0);
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("an executable placed **before** `--` never becomes the child process (only what follows `--` is taken)", async () => {
    // Because the upstream parser merges the positional args around `--` into
    // one array, `maruhi run stray -- printenv` would morph into **running
    // stray** on declaration alone. It is rejected by matching `--`'s position
    // and count in `Stdio.args` (ADR-0016 decision 8)
    const env = await startEnv([chainHandler(), pullHandler()]);
    const server = servers[servers.length - 1];
    expect(await runCli(["run", "stray", "--", "printenv"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unexpected extra arguments (1;");
    expect(errors).toContain("Write the command to run after `--`");
    // Never print the contents (a positional arg could contain plaintext)
    expect(errors).not.toContain("stray");
    expect(env.runnerCalls).toHaveLength(0);
    expect(server?.requests).toHaveLength(0);
  });

  it("a nested `--` (`npm test -- --watch`) also passes through to the child verbatim", async () => {
    // Only the first `--` is treated as maruhi's terminator; inner `--`s stay
    // as child arguments (dropping them would break npm / cargo / docker-style argument forwarding)
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "npm", "test", "--", "--watch"], env.layer)).toBe(0);
    expect(env.runnerCalls[0]?.command).toEqual(["npm", "test", "--", "--watch"]);
  });

  it("everything after `--` skips maruhi's argument checks and passes to the child verbatim", async () => {
    // If the strict argument-usage check reached the child's arguments,
    // `maruhi run -- <cmd>` could no longer run arbitrary commands. Everything
    // past `--` is never interpreted as a maruhi flag or positional arg, so it is outside the check's scope
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(
      await runCli(["run", "--", "printenv", "--show=false", "--shwo", "extra"], env.layer),
    ).toBe(0);
    expect(env.runnerCalls[0]?.command).toEqual(["printenv", "--show=false", "--shwo", "extra"]);
  });
});
