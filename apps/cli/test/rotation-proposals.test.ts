// Tests for `maruhi rotation proposals | accept | reject` (CRYPTO_SPEC §5.3
// / AUTH_SPEC §14-5 — PF7b), driven through runCli against the honest
// in-memory value environment plus a stateful proposals mock.
//
// Properties pinned down:
//  1. accept opens this device's wrap, checks the proposal still targets the
//     verified current version, pushes the plaintext as an ordinary signed
//     version, then resolves the proposal naming that version
//  2. no value is ever printed (not the proposed one, not the current one)
//  3. a non-interactive accept needs --yes; a stale proposal is refused with
//     the reject-and-rerun guidance; a prefix of the id is accepted
//  4. reject only resolves, and names the facts so the credential at the
//     issuer can be retired by hand
//  5. the list shows each proposal with its environment, variables, minter,
//     facts and next step; `rotation list` counts them
//  6. a list holding a proposal of an environment the verified chain shows
//     as deleted is refused as a resurrection (CRYPTO_SPEC §6.3), and
//     nothing is resolved from it

import {
  decryptVariable,
  encodeHex,
  importEncryptionPublicKey,
  sealProposedValue,
} from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  buildChain,
  createEnvironmentOp,
  deleteEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  hexBytes,
  makeTestUser,
  statementFor,
  testEnvironmentId,
  testProjectId,
  testVariableId,
  type BuiltChain,
  type TestUser,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockRequest, MockServer, onRequest } from "./support/server.ts";
import { makeValueEnvironmentServer, type ValueEnvironmentState } from "./support/value-env.ts";

const ENV_ID = "prod";
const PROPOSAL_ID = "00112233445566778899aabbccddeeff";
const OLD_KEY = "sk_live_old_dummy";
const NEW_KEY = "sk_live_new_dummy";
const OLD_ID = "rk_id_old_dummy";
const NEW_ID = "rk_id_new_dummy";
const FACT = "./rotate.sh: new credential produced";

let owner: TestUser;
let built: BuiltChain;
/** `built` plus an environment created and then deleted (seq 3 / 4). */
let withDeleted: BuiltChain;
const DELETED_ENV_ID = "old";
let dek: Uint8Array;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dek = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
  ]);
  // Same prefix (Ed25519 signing is deterministic)
  withDeleted = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
    {
      actor: owner,
      operation: createEnvironmentOp(DELETED_ENV_ID, crypto.getRandomValues(new Uint8Array(32))),
    },
    { actor: owner, operation: deleteEnvironmentOp(DELETED_ENV_ID) },
  ]);
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

interface WireWrap {
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

interface WireProposal {
  readonly proposalId: string;
  readonly environmentId: string;
  readonly connector: string;
  readonly facts: readonly string[];
  readonly claimsDigestHex: string;
  readonly grantChainSeq: number;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly variables: readonly {
    readonly variableId: string;
    readonly baseVersion: number;
    readonly wraps: readonly WireWrap[];
  }[];
}

interface ProposedVariableSpec {
  readonly variableId: string;
  readonly baseVersion: number;
  readonly plaintext: string;
}

/** Seals one proposed value to a device under the §5.3 info. */
async function sealedWrap(recipient: TestUser, spec: ProposedVariableSpec): Promise<WireWrap> {
  const publicKey = await importEncryptionPublicKey(hexBytes(recipient.encPubHex));
  if (!publicKey.ok) {
    throw new Error("recipient key import failed");
  }
  const sealed = await sealProposedValue({
    recipientPublicKey: publicKey.value,
    value: new TextEncoder().encode(spec.plaintext),
    context: {
      projectId: testProjectId(built.projectId),
      environmentId: testEnvironmentId(ENV_ID),
      proposalId: PROPOSAL_ID,
      variableId: testVariableId(spec.variableId),
      baseVersion: spec.baseVersion,
      recipientUserId: recipient.userId,
    },
  });
  if (!sealed.ok) {
    throw new Error("seal failed");
  }
  return {
    recipientUserId: recipient.userId,
    recipientEncPubHex: recipient.encPubHex,
    encHex: encodeHex(sealed.value.enc),
    ciphertextHex: encodeHex(sealed.value.ciphertext),
  };
}

/** A proposal sealed to the owner's device (the minting job's step — ci-rotate.ts). */
async function proposalFor(input: {
  readonly baseVersion?: number;
  readonly recipient?: TestUser;
  readonly plaintext?: string;
  /** The proposed variables in the minted order (default: STRIPE_SECRET_KEY alone). */
  readonly variables?: readonly ProposedVariableSpec[];
}): Promise<WireProposal> {
  const recipient = input.recipient ?? owner;
  const specs = input.variables ?? [
    {
      variableId: "vs",
      baseVersion: input.baseVersion ?? 3,
      plaintext: input.plaintext ?? NEW_KEY,
    },
  ];
  return {
    proposalId: PROPOSAL_ID,
    environmentId: ENV_ID,
    connector: "exec",
    facts: [FACT],
    claimsDigestHex: "ab".repeat(32),
    grantChainSeq: 2,
    createdAtMs: 1_700_000_000_000,
    expiresAtMs: Date.now() + 7 * 24 * 60 * 60 * 1000,
    variables: await Promise.all(
      specs.map(async (spec) => ({
        variableId: spec.variableId,
        baseVersion: spec.baseVersion,
        wraps: [await sealedWrap(recipient, spec)],
      })),
    ),
  };
}

interface Fixture {
  readonly env: TestEnv;
  readonly state: ValueEnvironmentState;
  readonly resolutions: { proposalId: string; body: unknown }[];
  /** The number of resolutions to refuse with a 500 before accepting (the push-ok / resolve-failed path). */
  failResolutions: number;
}

async function startEnv(proposals: WireProposal[], chain: BuiltChain = built): Promise<Fixture> {
  const wrap: WireRecipientDek = await wrapDekFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    recipient: owner,
    signer: owner,
    epoch: 1,
    dek,
  });
  const head = { seq: 1, hashHex: built.projectId };
  const envStatement = await environmentStatementFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head,
  });
  const statement = await statementFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    variableId: "vs",
    name: "STRIPE_SECRET_KEY",
    author: owner,
    head,
  });
  const value = await encryptValueFor({
    dek,
    projectId: built.projectId,
    environmentId: ENV_ID,
    epoch: 1,
    variableId: "vs",
    version: 3,
    plaintext: OLD_KEY,
    writer: owner,
    head: headOf(built, 2),
  });
  // A second variable (the key id companion of a JSON-answer exec rule)
  const idStatement = await statementFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    variableId: "vk",
    name: "STRIPE_KEY_ID",
    author: owner,
    head,
  });
  const idValue = await encryptValueFor({
    dek,
    projectId: built.projectId,
    environmentId: ENV_ID,
    epoch: 1,
    variableId: "vk",
    version: 1,
    plaintext: OLD_ID,
    writer: owner,
    head: headOf(built, 2),
  });
  const valueEnv = makeValueEnvironmentServer({
    chain,
    owner,
    environmentId: ENV_ID,
    envStatement,
    wrap,
    initialVariables: [
      { variableId: "vs", statement, value },
      { variableId: "vk", statement: idStatement, value: idValue },
    ],
  });
  const resolutions: { proposalId: string; body: unknown }[] = [];
  const pending = [...proposals];
  const fixture: { failResolutions: number } = { failResolutions: 0 };
  const resolutionPattern = new RegExp(
    `^/projects/${built.projectId}/rotation/proposals/([0-9a-f]{32})/resolution$`,
  );
  const handlers: MockHandler[] = [
    onRequest("GET", `/projects/${built.projectId}/rotation/flags`, () => ({
      status: 200,
      json: { flags: [] },
    })),
    onRequest("GET", `/projects/${built.projectId}/rotation/proposals`, () => ({
      status: 200,
      json: { proposals: pending },
    })),
    (request: MockRequest) => {
      const match = request.method === "POST" ? resolutionPattern.exec(request.path) : null;
      const id = match?.[1];
      if (id === undefined) {
        return null;
      }
      const index = pending.findIndex((proposal) => proposal.proposalId === id);
      if (index < 0) {
        return { status: 404, json: { _tag: "RotationProposalNotFound", proposalId: id } };
      }
      if (fixture.failResolutions > 0) {
        fixture.failResolutions -= 1;
        return { status: 500, json: { message: "injected resolution failure" } };
      }
      pending.splice(index, 1);
      resolutions.push({ proposalId: id, body: request.body });
      return { status: 204 };
    },
    ...valueEnv.handlers,
  ];
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
  return {
    env,
    state: valueEnv.state,
    resolutions,
    get failResolutions() {
      return fixture.failResolutions;
    },
    set failResolutions(count: number) {
      fixture.failResolutions = count;
    },
  };
}

async function latestPlaintext(
  state: ValueEnvironmentState,
  variableId = "vs",
): Promise<{ plaintext: string; version: number }> {
  const stored = state.variables.find((entry) => entry.variableId === variableId);
  if (stored === undefined) {
    throw new Error("variable missing");
  }
  const result = await decryptVariable({
    dek,
    nonce: hexBytes(stored.value.nonceHex),
    ciphertext: hexBytes(stored.value.ciphertextHex),
    context: {
      projectId: testProjectId(built.projectId),
      environmentId: testEnvironmentId(ENV_ID),
      epoch: stored.value.aad.epoch,
      variableId: testVariableId(variableId),
      version: stored.value.aad.version,
    },
  });
  if (!result.ok) {
    throw new Error("decrypt failed");
  }
  return { plaintext: new TextDecoder().decode(result.value), version: stored.value.aad.version };
}

function expectNoSecretLeak(env: TestEnv): void {
  const shown = [...env.logs, ...env.errors].join("\n");
  expect(shown).not.toContain(OLD_KEY);
  expect(shown).not.toContain(NEW_KEY);
  expect(shown).not.toContain(OLD_ID);
  expect(shown).not.toContain(NEW_ID);
}

describe("maruhi rotation accept (PF7b)", () => {
  it("opens this device's wrap, pushes the value as a new signed version, and resolves the proposal naming it", async () => {
    const fixture = await startEnv([await proposalFor({})]);
    expect(await runCli(["rotation", "accept", PROPOSAL_ID, "--yes"], fixture.env.layer)).toBe(0);
    const latest = await latestPlaintext(fixture.state);
    expect(latest).toEqual({ plaintext: NEW_KEY, version: 4 });
    expect(fixture.resolutions).toEqual([
      {
        proposalId: PROPOSAL_ID,
        body: { outcome: "accepted", versions: [{ variableId: "vs", version: 4 }] },
      },
    ]);
    const logs = fixture.env.logs.join("\n");
    expect(logs).toContain(
      `Accepted proposal ${PROPOSAL_ID} in environment prod: STRIPE_SECRET_KEY version=4`,
    );
    expect(logs).toContain("--finalize");
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "minted with the exec connector by the workload whose lease claims digest is abababababababab",
    );
    expect(errors).toContain(FACT);
    // The value's shape, from the opened plaintext on this device (D-8)
    expect(errors).toContain(
      "STRIPE_SECRET_KEY: 17 bytes, 1 line (opened on this device; the current value: 17 bytes, 1 line)",
    );
    expect(errors).not.toContain("where the current value has");
    expectNoSecretLeak(fixture.env);
  });

  it("a proposed value whose line count differs from the current value's is warned about before the push, never refused (D-18)", async () => {
    // A rotate script whose child wrote to its stdout within the settle
    // produced "junk\n<credential>": the acceptance shows both shapes and
    // warns where the decision is made; the push is the member's
    const polluted = `junk_line_dummy\n${NEW_KEY}`;
    const fixture = await startEnv([await proposalFor({ plaintext: polluted })]);
    expect(await runCli(["rotation", "accept", PROPOSAL_ID, "--yes"], fixture.env.layer)).toBe(0);
    expect(await latestPlaintext(fixture.state)).toEqual({ plaintext: polluted, version: 4 });
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "STRIPE_SECRET_KEY: 33 bytes, 2 lines (opened on this device; the current value: 17 bytes, 1 line)",
    );
    expect(errors).toContain(
      "Warning: the new value of STRIPE_SECRET_KEY has 2 lines where the current value has 1 line: check that the rotate script printed only the credential",
    );
    expectNoSecretLeak(fixture.env);
    expect(errors).not.toContain("junk_line_dummy");
  });

  it("a prefix of the id works; a non-interactive accept without --yes refuses before pushing", async () => {
    const fixture = await startEnv([await proposalFor({})]);
    fixture.env.setTerminal({ stdin: false, stdout: false });
    expect(await runCli(["rotation", "accept", PROPOSAL_ID.slice(0, 10)], fixture.env.layer)).toBe(
      1,
    );
    expect(fixture.env.errors.join("\n")).toContain(
      `Refusing to accept proposal ${PROPOSAL_ID} in a non-interactive environment without --yes`,
    );
    expect((await latestPlaintext(fixture.state)).version).toBe(3);
    expect(fixture.resolutions).toEqual([]);
    expectNoSecretLeak(fixture.env);
  });

  it("refuses a proposal whose target moved since it was minted (the current value is not the proposed one), with the reject-and-rerun guidance", async () => {
    const fixture = await startEnv([await proposalFor({ baseVersion: 2 })]);
    expect(await runCli(["rotation", "accept", PROPOSAL_ID, "--yes"], fixture.env.layer)).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      "STRIPE_SECRET_KEY moved since the proposal was minted (it replaces version 2, the current version is 3). Reject the proposal",
    );
    expect((await latestPlaintext(fixture.state)).version).toBe(3);
    expect(fixture.resolutions).toEqual([]);
    expectNoSecretLeak(fixture.env);
  });

  it("refuses a proposal that carries no wrap for this device", async () => {
    const other = await makeTestUser("user-other-9999");
    const fixture = await startEnv([await proposalFor({ recipient: other })]);
    expect(await runCli(["rotation", "accept", PROPOSAL_ID, "--yes"], fixture.env.layer)).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain("carries no value sealed to this device");
    expect(fixture.resolutions).toEqual([]);
  });

  it("pushes a two-variable proposal in the minted order (companion first) and resolves naming both versions", async () => {
    const fixture = await startEnv([
      await proposalFor({
        variables: [
          { variableId: "vk", baseVersion: 1, plaintext: NEW_ID },
          { variableId: "vs", baseVersion: 3, plaintext: NEW_KEY },
        ],
      }),
    ]);
    expect(await runCli(["rotation", "accept", PROPOSAL_ID, "--yes"], fixture.env.layer)).toBe(0);
    expect(await latestPlaintext(fixture.state, "vk")).toEqual({ plaintext: NEW_ID, version: 2 });
    expect(await latestPlaintext(fixture.state, "vs")).toEqual({ plaintext: NEW_KEY, version: 4 });
    // The companion was stored first (a deploy between the two pushes sees a consistent pair)
    const order = fixture.state.writes
      .filter((write) => write.kind === "version")
      .map((write) => /variables\/([^/]+)\/versions/.exec(write.request.path)?.[1]);
    expect(order).toEqual(["vk", "vs"]);
    expect(fixture.resolutions).toEqual([
      {
        proposalId: PROPOSAL_ID,
        body: {
          outcome: "accepted",
          versions: [
            { variableId: "vk", version: 2 },
            { variableId: "vs", version: 4 },
          ],
        },
      },
    ]);
    expect(fixture.env.logs.join("\n")).toContain(
      "STRIPE_KEY_ID version=2, epoch=1; STRIPE_SECRET_KEY version=4, epoch=1",
    );
    expect(fixture.env.errors.join("\n")).not.toContain("where the current value has");
    // A companion is compared too (every proposed variable is opened on
    // this device): only its line count differs here
    const companionPolluted = await startEnv([
      await proposalFor({
        variables: [
          { variableId: "vk", baseVersion: 1, plaintext: `junk_line_dummy\n${NEW_ID}` },
          { variableId: "vs", baseVersion: 3, plaintext: NEW_KEY },
        ],
      }),
    ]);
    expect(
      await runCli(["rotation", "accept", PROPOSAL_ID, "--yes"], companionPolluted.env.layer),
    ).toBe(0);
    const warnings = companionPolluted.env.errors
      .join("\n")
      .split("\n")
      .filter((line) => line.includes("where the current value has"));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(
      "the new value of STRIPE_KEY_ID has 2 lines where the current value has 1 line",
    );
    expectNoSecretLeak(companionPolluted.env);
    expectNoSecretLeak(fixture.env);
  });

  it("after a push that succeeded but a resolution that failed, accepting again pushes nothing and only resolves (never a rejection)", async () => {
    const fixture = await startEnv([await proposalFor({})]);
    fixture.failResolutions = 1;
    expect(await runCli(["rotation", "accept", PROPOSAL_ID, "--yes"], fixture.env.layer)).toBe(1);
    expect(await latestPlaintext(fixture.state)).toEqual({ plaintext: NEW_KEY, version: 4 });
    const firstErrors = fixture.env.errors.join("\n");
    expect(firstErrors).toContain(
      "The new versions are stored (STRIPE_SECRET_KEY version 4) but resolving the proposal failed",
    );
    expect(firstErrors).toContain(`Run \`maruhi rotation accept ${PROPOSAL_ID}\` again`);
    expect(firstErrors).not.toContain("rotation reject");
    expect(fixture.resolutions).toEqual([]);
    // The second accept recognizes its own push: no new version, the resolution names version 4
    fixture.env.logs.length = 0;
    fixture.env.errors.length = 0;
    expect(await runCli(["rotation", "accept", PROPOSAL_ID, "--yes"], fixture.env.layer)).toBe(0);
    expect(await latestPlaintext(fixture.state)).toEqual({ plaintext: NEW_KEY, version: 4 });
    expect(fixture.resolutions).toEqual([
      {
        proposalId: PROPOSAL_ID,
        body: { outcome: "accepted", versions: [{ variableId: "vs", version: 4 }] },
      },
    ]);
    expect(fixture.env.errors.join("\n")).toContain(
      "every proposed value is already stored in environment prod (STRIPE_SECRET_KEY version 4 — an earlier accept pushed it)",
    );
    expect(fixture.env.logs.join("\n")).toContain("STRIPE_SECRET_KEY version=4 (already stored)");
    expectNoSecretLeak(fixture.env);
  });

  it("an unknown id is reported with the listing command", async () => {
    const fixture = await startEnv([]);
    expect(await runCli(["rotation", "accept", PROPOSAL_ID, "--yes"], fixture.env.layer)).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      `No pending sealed proposal has the id ${PROPOSAL_ID}`,
    );
  });
});

describe("maruhi rotation proposals / reject (PF7b)", () => {
  it("lists each pending proposal with its variables, minter, facts, and next step; rotation list counts them", async () => {
    const fixture = await startEnv([await proposalFor({})]);
    expect(await runCli(["rotation", "proposals"], fixture.env.layer)).toBe(0);
    const logs = fixture.env.logs.join("\n");
    expect(logs).toContain("Pending sealed proposals: 1 proposal");
    expect(logs).toContain(`${PROPOSAL_ID}\tenvironment=prod\tconnector=exec`);
    expect(logs).toContain("variables: STRIPE_SECRET_KEY (vs) replacing version 3");
    expect(logs).toContain("lease claims digest is abababababababab");
    expect(logs).toContain(FACT);
    expect(logs).toContain(`maruhi rotation accept ${PROPOSAL_ID}`);
    expectNoSecretLeak(fixture.env);
    fixture.env.logs.length = 0;
    expect(await runCli(["rotation", "list"], fixture.env.layer)).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(
      "Pending sealed proposals: 1 proposal minted by CI jobs await a member",
    );
  });

  it("reject resolves the proposal without pushing and names the credential to retire", async () => {
    const fixture = await startEnv([await proposalFor({})]);
    expect(await runCli(["rotation", "reject", PROPOSAL_ID], fixture.env.layer)).toBe(0);
    expect(fixture.resolutions).toEqual([
      { proposalId: PROPOSAL_ID, body: { outcome: "rejected" } },
    ]);
    expect((await latestPlaintext(fixture.state)).version).toBe(3);
    const logs = fixture.env.logs.join("\n");
    expect(logs).toContain(`Rejected proposal ${PROPOSAL_ID} (environment prod`);
    expect(logs).toContain(FACT);
    expect(await runCli(["rotation", "proposals"], fixture.env.layer)).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain("No sealed proposals are pending");
  });

  it("refuses a list holding a proposal of a chain-deleted environment as a resurrection, and resolves nothing", async () => {
    const stale = { ...(await proposalFor({})), environmentId: DELETED_ENV_ID };
    const fixture = await startEnv([stale], withDeleted);
    expect(await runCli(["rotation", "proposals"], fixture.env.layer)).toBe(1);
    const resurrection = `The server listed sealed proposal ${PROPOSAL_ID} for environment old, which is deleted on the verified chain (delete_environment at seq 4)`;
    expect(fixture.env.errors.join("\n")).toContain(resurrection);
    fixture.env.errors.length = 0;
    expect(await runCli(["rotation", "reject", PROPOSAL_ID], fixture.env.layer)).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(resurrection);
    expect(fixture.resolutions).toEqual([]);
  });
});
