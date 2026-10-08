// Tests for `maruhi var history` / `maruhi var rollback` (2026-09-27 VH —
// docs/notes/vh-design.md rulings V3 / V4).
//
// Invariants pinned down:
//  1. history is metadata only: newest first, the lineage kind derived
//     (re-encryption / rollback), the flagsIfCurrent warning, labeled
//     server-declared; it never fetches a value (no value-range request) and
//     runs in an agent environment (zero values)
//  2. rollback restores the old plaintext as a new version declaring
//     `sameValueAs` (AUTH_SPEC §12-5), re-encrypted under the current epoch,
//     and never prints any value
//  3. the target is trusted only as an ancestor of the verified latest: a
//     substituted old version (validly signed, but not the one the chain
//     links to) is refused as evidence and nothing is pushed
//  4. confirmation: non-interactive needs --force; interactive asks y/N; the
//     exposure count is part of the confirmation
//  5. refusals before any send: the current version, a missing version, an
//     identical value, a declared variable, a missing --to
//  6. a push by someone else after the rollback was verified is never
//     silently overwritten with the restored value
//  7. `maruhi push` of a value identical to the latest declares the lineage
//     (sameValueAs = the latest) — re-pushing the same value is not a new value

import { decryptVariable } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
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
  valueHashOf,
  type WireDistributedEnvironmentStatement,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { testProjectId } from "./support/crypto.ts";
import { testEnvironmentId, testVariableId } from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { MockServer } from "./support/server.ts";
import { makeValueEnvironmentServer, type ValueEnvironmentState } from "./support/value-env.ts";

const ENV_ID = "prod";
const VARIABLE_ID = "v-api-key";
const NAME = "API_KEY";
const PLAINTEXTS = ["alpha-secret-1", "beta-secret-2", "gamma-secret-3"];

let owner: TestUser;
let built: BuiltChain;
let dek: Uint8Array;
let wrap: WireRecipientDek;
let envStatement: WireDistributedEnvironmentStatement;
let statement: WireDistributedVariableStatement;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dek = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
  ]);
  wrap = await wrapDekFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    recipient: owner,
    signer: owner,
    epoch: 1,
    dek,
  });
  const head = { seq: 1, hashHex: built.projectId };
  envStatement = await environmentStatementFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head,
  });
  statement = await statementFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    variableId: VARIABLE_ID,
    name: NAME,
    author: owner,
    head,
  });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

/** A correctly chained version sequence (v1 … vN) of the given plaintexts. */
async function versionChain(plaintexts: readonly string[]): Promise<WireDistributedValue[]> {
  const values: WireDistributedValue[] = [];
  for (const [index, plaintext] of plaintexts.entries()) {
    const previous = values.at(-1);
    values.push(
      await encryptValueFor({
        dek,
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        variableId: VARIABLE_ID,
        version: index + 1,
        plaintext,
        writer: owner,
        head: headOf(built, 2),
        ...(previous === undefined
          ? {}
          : { prevValueSigHashHex: await valueHashOf(previous, owner.userId) }),
      }),
    );
  }
  return values;
}

async function startEnv(
  input: {
    readonly plaintexts?: readonly string[];
    readonly flagsIfCurrent?: (variableId: string, version: number) => number;
    readonly tamperRange?: (values: readonly WireDistributedValue[]) => WireDistributedValue[];
    readonly declared?: boolean;
  } = {},
): Promise<{ env: TestEnv; state: ValueEnvironmentState; server: MockServer }> {
  const chain = await versionChain(input.plaintexts ?? PLAINTEXTS);
  const latest = chain.at(-1);
  if (latest === undefined) {
    throw new Error("empty chain");
  }
  const declaredStatement =
    input.declared === true
      ? await statementFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          variableId: VARIABLE_ID,
          name: NAME,
          author: owner,
          head: { seq: 1, hashHex: built.projectId },
          status: "declared",
          schema: { varType: "", required: true, description: "" },
        })
      : null;
  const valueEnv = makeValueEnvironmentServer({
    chain: built,
    owner,
    environmentId: ENV_ID,
    envStatement,
    wrap,
    initialVariables:
      declaredStatement === null ? [{ variableId: VARIABLE_ID, statement, value: latest }] : [],
    initialDeclared: declaredStatement === null ? [] : [declaredStatement],
    initialHistory: new Map([[VARIABLE_ID, chain]]),
    ...(input.flagsIfCurrent === undefined ? {} : { flagsIfCurrent: input.flagsIfCurrent }),
    ...(input.tamperRange === undefined ? {} : { tamperRange: input.tamperRange }),
  });
  const server = await MockServer.start(valueEnv.handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: built.projectId,
    defaultEnvironment: ENV_ID,
  });
  return { env, state: valueEnv.state, server };
}

async function decryptWire(value: WireDistributedValue): Promise<string> {
  const result = await decryptVariable({
    dek,
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
    throw new Error("decrypt failed in test");
  }
  return new TextDecoder().decode(result.value);
}

function allOutput(env: TestEnv): string {
  return [...env.logs, ...env.errors, ...env.prompts].join("\n");
}

function expectNoValueShown(env: TestEnv): void {
  const output = allOutput(env);
  for (const plaintext of PLAINTEXTS) {
    expect(output).not.toContain(plaintext);
  }
}

const rangeRequests = (server: MockServer) =>
  server.requests.filter((request) => request.path.endsWith("/versions/values"));

describe("maruhi var history (metadata only — AUTH_SPEC §12-7)", () => {
  it("lists versions newest first with the derived lineage and the flag exposure, labeled server-declared, without fetching any value", async () => {
    const { env, state, server } = await startEnv({
      plaintexts: ["alpha-secret-1", "beta-secret-2", "beta-secret-2", "alpha-secret-1"],
      flagsIfCurrent: (_variableId, version) => (version === 1 || version === 4 ? 2 : 0),
    });
    // Lineage as the pushes declared it (v3 = re-encryption of v2, v4 = rollback to v1)
    const history = state.history.get(VARIABLE_ID) ?? [];
    state.history.set(
      VARIABLE_ID,
      history.map((entry, index) =>
        index === 2
          ? { ...entry, sameValueAs: 2 }
          : index === 3
            ? { ...entry, sameValueAs: 1 }
            : entry,
      ),
    );
    // A zero-value command runs under an agent too (no gate)
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["var", "history", NAME], env.layer)).toBe(0);
    const lines = env.logs.filter((line) => line.startsWith("  v"));
    expect(lines.map((line) => line.split("\t")[0])).toEqual(["  v4", "  v3", "  v2", "  v1"]);
    expect(lines[0]).toContain(
      "current; rollback to v1; 2 rotation flags while this value is current",
    );
    expect(lines[1]).toContain("re-encryption of v2");
    expect(lines[1]).not.toContain("rotation flag");
    expect(lines[0]).toContain(`writer=${owner.userId}`);
    expect(env.logs.join("\n")).toContain("Server-declared metadata (not signature-verified)");
    expect(rangeRequests(server)).toHaveLength(0);
    expect(server.requests.some((request) => request.path.endsWith("/pull"))).toBe(false);
    expectNoValueShown(env);
  });

  it("--json prints the server-declared rows as one document", async () => {
    const { env } = await startEnv();
    expect(await runCli(["var", "history", NAME, "--json"], env.layer)).toBe(0);
    const document = JSON.parse(env.logs.join("\n")) as {
      name: string;
      variableId: string;
      status: string;
      serverDeclared: boolean;
      versions: { version: number; flagsIfCurrent: number }[];
    };
    expect(document).toMatchObject({
      name: NAME,
      variableId: VARIABLE_ID,
      status: "active",
      serverDeclared: true,
    });
    expect(document.versions.map((entry) => entry.version)).toEqual([1, 2, 3]);
  });

  it("a declared variable has no history; an unknown name is an explicit error", async () => {
    const { env } = await startEnv({ declared: true });
    expect(await runCli(["var", "history", NAME], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("declared — no value has been pushed yet");
    expect(await runCli(["var", "history", "NO_SUCH"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not exist in this environment");
  });
});

describe("maruhi var rollback (AUTH_SPEC §12-5 / §12-7)", () => {
  it("--force restores the old plaintext as a new version declaring sameValueAs, verifying the range first and showing no value", async () => {
    const { env, state, server } = await startEnv();
    env.setTerminal({ stdin: false, stdout: false });
    expect(await runCli(["var", "rollback", NAME, "--to", "1", "--force"], env.layer)).toBe(0);
    expect(rangeRequests(server).map((request) => request.query["fromVersion"])).toEqual(["1"]);
    const pushes = state.writes.filter((write) => write.kind === "version");
    expect(pushes).toHaveLength(1);
    const body = pushes[0]?.request.body as {
      value: WireDistributedValue;
      sameValueAs?: number;
    };
    expect(body.sameValueAs).toBe(1);
    expect(body.value.aad).toMatchObject({ version: 4, epoch: 1, variableId: VARIABLE_ID });
    expect(
      await decryptWire({ ...body.value, writerUserId: "", writerKeyFingerprintHex: "" }),
    ).toBe(PLAINTEXTS[0]);
    // The new version chains onto the verified latest (v3)
    const v3 = state.history.get(VARIABLE_ID)?.[2]?.value;
    if (v3 === undefined) throw new Error("v3 missing");
    expect(body.value.prevValueSigHashHex).toBe(await valueHashOf(v3, owner.userId));
    expect(env.logs.join("\n")).toContain(
      `Rolled back ${NAME} to the value of version 1 (new version=4, epoch=1; was version 3)`,
    );
    expect(env.errors.join("\n")).toContain("without confirmation (--force)");
    expect(env.prompts).toHaveLength(0);
    expectNoValueShown(env);
  });

  it("a non-interactive run without --force is refused before anything is sent", async () => {
    const { env, state } = await startEnv();
    env.setTerminal({ stdin: false, stdout: false });
    expect(await runCli(["var", "rollback", NAME, "--to", "1"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Re-run with --force");
    expect(state.writes).toEqual([]);
  });

  it("interactive: y proceeds, anything else aborts; the exposure count is part of the confirmation", async () => {
    const exposed = await startEnv({ flagsIfCurrent: (_id, version) => (version === 2 ? 1 : 0) });
    exposed.env.setPromptResponses(["y"]);
    expect(await runCli(["var", "rollback", NAME, "--to", "2"], exposed.env.layer)).toBe(0);
    expect(exposed.env.errors.join("\n")).toContain(
      "The value of version 2 was readable by the subject of 1 rotation flag",
    );
    expect(exposed.env.errors.join("\n")).toContain("see `maruhi rotation list`");
    expect(exposed.state.writes.filter((write) => write.kind === "version")).toHaveLength(1);

    const declined = await startEnv();
    declined.env.setPromptResponses(["n"]);
    expect(await runCli(["var", "rollback", NAME, "--to", "2"], declined.env.layer)).toBe(1);
    expect(declined.env.errors.join("\n")).toContain("Aborted: nothing was signed or sent");
    expect(declined.env.errors.join("\n")).not.toContain("rotation flag");
    expect(declined.state.writes).toEqual([]);
  });

  it("a substituted old version (validly signed, but not the one the chain links to) is refused as evidence", async () => {
    const forged = await encryptValueFor({
      dek,
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: VARIABLE_ID,
      version: 1,
      plaintext: "attacker-chosen",
      writer: owner,
      head: headOf(built, 2),
    });
    const { env, state } = await startEnv({
      tamperRange: (values) => values.map((value) => (value.aad.version === 1 ? forged : value)),
    });
    expect(await runCli(["var", "rollback", NAME, "--to", "1", "--force"], env.layer)).not.toBe(0);
    expect(env.errors.join("\n")).toContain("prev-hash-mismatch");
    expect(state.writes).toEqual([]);
    expect(allOutput(env)).not.toContain("attacker-chosen");
  });

  it("refuses the current version, a missing version, an identical value, a declared variable, and a missing --to", async () => {
    const { env, state } = await startEnv();
    expect(await runCli(["var", "rollback", NAME, "--to", "3", "--force"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("already the current version");
    expect(await runCli(["var", "rollback", NAME, "--to", "9", "--force"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("has no version 9 (the current version is 3)");
    expect(await runCli(["var", "rollback", NAME, "--force"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--to <version> is required");
    expect(state.writes).toEqual([]);

    const same = await startEnv({ plaintexts: ["same-value", "other-value", "same-value"] });
    expect(await runCli(["var", "rollback", NAME, "--to", "1", "--force"], same.env.layer)).toBe(1);
    expect(same.env.errors.join("\n")).toContain("already equals the value of version 1");
    expect(same.state.writes).toEqual([]);

    const declared = await startEnv({ declared: true });
    expect(
      await runCli(["var", "rollback", NAME, "--to", "1", "--force"], declared.env.layer),
    ).toBe(1);
    expect(declared.env.errors.join("\n")).toContain("has no value yet");
  });
});

describe("maruhi var rollback under a concurrent push", () => {
  it("refuses when another member pushed after the rollback was verified (nothing is overwritten)", async () => {
    const chain = await versionChain([...PLAINTEXTS, "delta-secret-4"]);
    const [v1, v2, v3, v4] = chain;
    if (v1 === undefined || v2 === undefined || v3 === undefined || v4 === undefined) {
      throw new Error("chain");
    }
    const valueEnv = makeValueEnvironmentServer({
      chain: built,
      owner,
      environmentId: ENV_ID,
      envStatement,
      wrap,
      initialVariables: [{ variableId: VARIABLE_ID, statement, value: v3 }],
      initialHistory: new Map([[VARIABLE_ID, [v1, v2, v3]]]),
    });
    // Another member's v4 lands right after the rollback fetched and
    // verified its range (before its own push resolves the target again)
    let injected = false;
    const concurrentPush = (request: { readonly path: string }) => {
      if (!injected && request.path.endsWith("/versions/values")) {
        injected = true;
        const stored = valueEnv.state.variables.find((entry) => entry.variableId === VARIABLE_ID);
        if (stored !== undefined) {
          stored.value = v4;
        }
        valueEnv.state.history.get(VARIABLE_ID)?.push({ value: v4 });
      }
      return null;
    };
    const server = await MockServer.start([concurrentPush, ...valueEnv.handlers]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(await runCli(["var", "rollback", NAME, "--to", "1", "--force"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "changed while the rollback was being prepared (the latest is now version 4, not the confirmed version 3)",
    );
    expect(valueEnv.state.writes).toEqual([]);
    expectNoValueShown(env);
  });
});

describe("maruhi push of an unchanged value (AUTH_SPEC §12-5 lineage — VH re-check round)", () => {
  it("declares sameValueAs = the latest when the value is identical, and nothing for a new value", async () => {
    const { env, state } = await startEnv();
    const pushOf = async (plaintext: string) => {
      env.setStdin(new TextEncoder().encode(plaintext));
      expect(await runCli(["push", NAME, "--no-sync"], env.layer)).toBe(0);
      const writes = state.writes.filter((write) => write.kind === "version");
      return writes.at(-1)?.request.body as { value: WireDistributedValue; sameValueAs?: number };
    };
    const same = await pushOf(PLAINTEXTS[2] ?? "");
    expect(same.value.aad.version).toBe(4);
    expect(same.sameValueAs).toBe(3);
    const fresh = await pushOf("epsilon-secret-5");
    expect(fresh.value.aad.version).toBe(5);
    expect(fresh.sameValueAs).toBeUndefined();
    expectNoValueShown(env);
  });
});
