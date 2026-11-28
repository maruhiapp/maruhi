import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  distributedEnvironmentStatement,
  distributedManifest,
  distributedManifestHashOf,
  distributedValue,
  distributedVariableStatement,
  distributedWrap,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  headOf,
  rotateEpochOp,
  testEnvironmentId,
  testProjectId,
  valueSignedBytesHashOf,
  type WireDistributedEnvironmentStatement,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  type WireRecipientDek,
} from "@maruhi/test-kit";
import { Effect } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { makeFileFloorStore } from "../src/floor-log.ts";
import type { ProjectFloor } from "../src/floor.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "prod";

let owner: GeneratedIdentity;
let dek1: Uint8Array;
let dek2: Uint8Array;
let chain1: BuiltChain;
let chain2: BuiltChain;
let chainB: BuiltChain;
let wrap1: WireRecipientDek;
let wrap2: WireRecipientDek;
let envStatement: WireDistributedEnvironmentStatement;
let projectId: string;

let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await generateIdentity("user-owner-1111");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  const dekB = crypto.getRandomValues(new Uint8Array(32));
  const steps = [
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
  ];
  chain1 = await buildChain(steps);
  chain2 = await buildChain([
    ...steps,
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
  chainB = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dekB) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dekB) },
  ]);
  projectId = chain1.projectId;
  expect(chain2.projectId).toBe(projectId);
  expect(chain2.hashes[1]).toBe(chain1.hashes[1]);
  expect(chainB.projectId).toBe(projectId);
  expect(chainB.hashes[1]).not.toBe(chain1.hashes[1]);
  const common = { projectId, environmentId: ENV_ID };
  wrap1 = await distributedWrap({
    ...common,
    epoch: 1,
    dek: dek1,
    recipient: owner,
    signer: owner,
  });
  wrap2 = await distributedWrap({
    ...common,
    epoch: 2,
    dek: dek2,
    recipient: owner,
    signer: owner,
  });
  envStatement = await distributedEnvironmentStatement({
    projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: { seq: 1, hashHex: projectId },
  });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function genesisHead(): { seq: number; hashHex: string } {
  return { seq: 1, hashHex: projectId };
}

async function valueOf(input: {
  readonly variableId: string;
  readonly version: number;
  readonly epoch: 1 | 2;
  readonly plaintext: string;
  readonly prevValueSigHashHex?: string;
}): Promise<WireDistributedValue> {
  return distributedValue({
    dek: input.epoch === 1 ? dek1 : dek2,
    projectId,
    environmentId: ENV_ID,
    epoch: input.epoch,
    variableId: input.variableId,
    version: input.version,
    plaintext: input.plaintext,
    writer: owner,
    head: input.epoch === 1 ? headOf(chain1, 2) : headOf(chain2, 3),
    ...(input.prevValueSigHashHex === undefined
      ? {}
      : { prevValueSigHashHex: input.prevValueSigHashHex }),
  });
}

async function statementOf(input: {
  readonly variableId: string;
  readonly name: string;
  readonly metaVersion?: number;
  readonly status?: "active" | "deleted";
  readonly prevMetaSigHashHex?: string;
}): Promise<WireDistributedVariableStatement> {
  return distributedVariableStatement({
    projectId,
    environmentId: ENV_ID,
    variableId: input.variableId,
    name: input.name,
    author: owner,
    head: genesisHead(),
    ...(input.metaVersion === undefined ? {} : { metaVersion: input.metaVersion }),
    ...(input.status === undefined ? {} : { status: input.status }),
    ...(input.prevMetaSigHashHex === undefined
      ? {}
      : { prevMetaSigHashHex: input.prevMetaSigHashHex }),
  });
}

interface PullPayload {
  readonly statement?: WireDistributedEnvironmentStatement;
  readonly variables: readonly {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  }[];
  readonly deletedVariables?: readonly WireDistributedVariableStatement[];
  readonly deks: readonly WireRecipientDek[];
  readonly currentEpoch?: number;
  readonly manifestVersion?: number;
  readonly prevManifestSigHashHex?: string;
}

interface ManifestPayload {
  readonly statement?: WireDistributedEnvironmentStatement;
  readonly variables: readonly WireDistributedVariableStatement[];
  readonly deletedVariables?: readonly WireDistributedVariableStatement[];
  readonly currentEpoch?: number;
  readonly manifestVersion?: number;
  readonly prevManifestSigHashHex?: string;
}

async function manifestOf(payload: ManifestPayload): Promise<unknown> {
  const epoch = payload.currentEpoch ?? 1;
  return distributedManifest({
    projectId,
    environmentId: ENV_ID,
    epoch,
    issuer: owner,
    head: epoch === 1 ? headOf(chain1, 2) : headOf(chain2, 3),
    envStatement: payload.statement ?? envStatement,
    statements: [...payload.variables, ...(payload.deletedVariables ?? [])],
    manifestVersion: payload.manifestVersion ?? 1,
    ...(payload.prevManifestSigHashHex === undefined
      ? {}
      : { prevManifestSigHashHex: payload.prevManifestSigHashHex }),
  });
}

async function prevOfPhase(payload: ManifestPayload): Promise<string> {
  return distributedManifestHashOf(
    projectId,
    (await manifestOf(payload)) as Parameters<typeof distributedManifestHashOf>[1],
  );
}

function chainHandlerFor(chains: readonly BuiltChain[]): MockHandler {
  let call = 0;
  return onRequest("GET", `/projects/${projectId}/chain`, () => {
    const built = chains[Math.min(call, chains.length - 1)] as BuiltChain;
    call += 1;
    return {
      status: 200,
      json: {
        projectId,
        entries: built.entries,
        headSeq: built.entries.length,
        headHashHex: built.hashes[built.hashes.length - 1],
        attestations: [],
      },
    };
  });
}

function pullHandlerFor(payload: PullPayload): MockHandler {
  return onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull`, async () => ({
    status: 200,
    json: {
      environmentId: ENV_ID,
      currentEpoch: payload.currentEpoch ?? 1,
      statement: payload.statement ?? envStatement,
      variables: payload.variables,
      deletedVariables: payload.deletedVariables ?? [],
      deks: payload.deks,
      manifest: await manifestOf({
        ...payload,
        variables: payload.variables.map((variable) => variable.statement),
      }),
      schemaPolicy: "enabled" as const,
    },
  }));
}

function deksHandlerFor(deks: readonly WireRecipientDek[]): MockHandler {
  return onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/deks`, () => ({
    status: 200,
    json: { deks },
  }));
}

function pullMetadataHandlerFor(payload: ManifestPayload): MockHandler {
  return onRequest(
    "GET",
    `/projects/${projectId}/environments/${ENV_ID}/pull/metadata`,
    async () => ({
      status: 200,
      json: {
        environmentId: ENV_ID,
        currentEpoch: payload.currentEpoch ?? 1,
        statement: envStatement,
        variables: payload.variables,
        deletedVariables: payload.deletedVariables ?? [],
        manifest: await manifestOf(payload),
        schemaPolicy: "enabled" as const,
      },
    }),
  );
}

async function startPhase(env: TestEnv, handlers: readonly MockHandler[]): Promise<MockServer> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: projectId,
    defaultEnvironment: ENV_ID,
  });
  return server;
}

async function readFloorFile(env: TestEnv): Promise<ProjectFloor> {
  const loaded = await Effect.runPromise(
    makeFileFloorStore(env.floorDir).load(testProjectId(projectId)),
  );
  expect(loaded.state).toBe("loaded");
  expect(loaded.floor).not.toBeNull();
  return loaded.floor as ProjectFloor;
}

async function readFloorRaw(env: TestEnv): Promise<string> {
  return readFile(join(env.floorDir, `${projectId}.jsonl`), "utf8");
}

async function establishFloor(env: TestEnv, payload: PullPayload, chain = chain1): Promise<void> {
  await startPhase(env, [chainHandlerFor([chain]), pullHandlerFor(payload)]);
  expect(await runCli(["pull"], env.layer)).toBe(0);
}

describe("floor establishment and fail-open (§6.3 / no floor · corruption)", () => {
  it("the first sync issues a no-floor notice and creates the floor file (non-sensitive digests only)", async () => {
    const env = await makeTestEnv();
    const beta = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "beta-value" });
    await establishFloor(env, {
      variables: [
        {
          variableId: "vb",
          statement: await statementOf({ variableId: "vb", name: "BETA" }),
          value: beta,
        },
      ],
      deks: [wrap1],
    });
    expect(env.errors.join("\n")).toContain("first sync");
    const floor = await readFloorFile(env);
    expect(floor.chainHead).toEqual({ seq: 2, hashHex: chain1.hashes[1] });
    const record = floor.environments[ENV_ID];
    expect(record?.pullEpoch).toBe(1);
    expect(record?.variables["vb"]).toMatchObject({ status: "active", version: 1, epoch: 1 });
    const raw = await readFloorRaw(env);
    expect(raw).not.toContain("beta-value");
    expect(raw).not.toContain("BETA");
  });

  it("floor-log corruption fails open with a warning distinct from the first-run one, and resumes appending from the next successful pull", async () => {
    const env = await makeTestEnv();
    const beta = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const entry = {
      variableId: "vb",
      statement: await statementOf({ variableId: "vb", name: "BETA" }),
      value: beta,
    };
    await establishFloor(env, { variables: [entry], deks: [wrap1] });
    await writeFile(join(env.floorDir, `${projectId}.jsonl`), "{broken-json");
    env.errors.length = 0;
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [entry], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("corrupt");
    expect(errors).not.toContain("first sync");
    const floor = await readFloorFile(env);
    expect(floor.environments[ENV_ID]?.variables["vb"]).toMatchObject({ version: 1 });
  });
});

describe("persistent detection of rollback (§6.3 rule (a))", () => {
  it("refuses a version regression and emits both signed-bytes hashes and the declared head as evidence", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const v1 = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "old" });
    const v2 = await valueOf({
      variableId: "vb",
      version: 2,
      epoch: 1,
      plaintext: "new",
      prevValueSigHashHex: await valueSignedBytesHashOf(v1, owner.userId),
    });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value: v2 }],
      deks: [wrap1],
    });

    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [{ variableId: "vb", statement, value: v1 }], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("value-version rollback");
    expect(errors).toContain(await valueSignedBytesHashOf(v2, owner.userId));
    expect(errors).toContain(await valueSignedBytesHashOf(v1, owner.userId));
    expect(errors).toContain(`variable=vb`);
    expect(errors).toContain(`declared head: seq=2`);
    expect(errors).not.toContain("old");
    expect(errors).not.toContain("new");
  });

  it("floor establishment and rollback detection work even for variableId `constructor` (a legitimate ID)", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "constructor", name: "CTOR_VAR" });
    const v1 = await valueOf({ variableId: "constructor", version: 1, epoch: 1, plaintext: "a" });
    const v2 = await valueOf({ variableId: "constructor", version: 2, epoch: 1, plaintext: "b" });
    await establishFloor(env, {
      variables: [{ variableId: "constructor", statement, value: v2 }],
      deks: [wrap1],
    });
    const floor = await readFloorFile(env);
    expect(floor.environments[ENV_ID]?.variables["constructor"]).toMatchObject({ version: 2 });

    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        variables: [{ variableId: "constructor", statement, value: v1 }],
        deks: [wrap1],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("value-version rollback");
  });

  it("a refused pull never advances the floor (the update-ordering norm — checks run against the previous baseline)", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const v1 = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "old" });
    const v2 = await valueOf({ variableId: "vb", version: 2, epoch: 1, plaintext: "new" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value: v2 }],
      deks: [wrap1],
    });
    const before = await readFloorFile(env);

    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [{ variableId: "vb", statement, value: v1 }], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const after = await readFloorFile(env);
    expect(after.environments[ENV_ID]).toEqual(before.environments[ENV_ID]);
  });

  it("refuses a variable metaVersion regression", async () => {
    const env = await makeTestEnv();
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const metaV2 = await statementOf({ variableId: "vb", name: "BETA", metaVersion: 2 });
    const metaV1 = await statementOf({ variableId: "vb", name: "BETA" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement: metaV2, value }],
      deks: [wrap1],
    });

    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement: metaV1, value }],
        deks: [wrap1],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("meta-statement rollback");
  });

  it("refuses an environment metaVersion regression", async () => {
    const env = await makeTestEnv();
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const envMetaV2 = await distributedEnvironmentStatement({
      projectId,
      environmentId: ENV_ID,
      name: "prod-renamed",
      author: owner,
      head: genesisHead(),
      metaVersion: 2,
    });
    await establishFloor(env, {
      statement: envMetaV2,
      variables: [{ variableId: "vb", statement, value }],
      deks: [wrap1],
    });

    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        statement: envStatement,
        variables: [{ variableId: "vb", statement, value }],
        deks: [wrap1],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("meta-statement rollback");
  });

  it("refuses different signed bytes under the same environment-meta metaVersion (an environment-name swap)", async () => {
    const env = await makeTestEnv();
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value }],
      deks: [wrap1],
    });

    const swapped = await distributedEnvironmentStatement({
      projectId,
      environmentId: ENV_ID,
      name: "prod-swapped",
      author: owner,
      head: genesisHead(),
    });
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        statement: swapped,
        variables: [{ variableId: "vb", statement, value }],
        deks: [wrap1],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("signed bytes served for the same metaVersion");
    expect(errors).toContain(`coordinates: project=${projectId} environment=${ENV_ID}\n`);
  });

  it("refuses an epoch regression (distributing below the floor's epoch under an advancing version)", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "va", name: "ALPHA" });
    const v3e2 = await valueOf({ variableId: "va", version: 3, epoch: 2, plaintext: "cur" });
    await establishFloor(
      env,
      {
        variables: [{ variableId: "va", statement, value: v3e2 }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
      },
      chain2,
    );

    const v4e1 = await valueOf({ variableId: "va", version: 4, epoch: 1, plaintext: "regressed" });
    await startPhase(env, [
      chainHandlerFor([chain2]),
      pullHandlerFor({
        variables: [{ variableId: "va", statement, value: v4e1 }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("monotonicity violation");
  });

  it("refuses a chain-length regression (shortening) — when bounded resync cannot resolve it", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    await establishFloor(
      env,
      {
        variables: [{ variableId: "vb", statement, value }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
      },
      chain2,
    );

    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [{ variableId: "vb", statement, value }], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("chain shortening");
    expect(errors).toContain(`seq=3 hash=${chain2.hashes[2]}`);
    expect(errors).toContain(`seq=2 hash=${chain1.hashes[1]}`);
  });

  it("an honest race where the floor head is beyond our view (a sibling process's advance) resolves via bounded resync", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    await establishFloor(
      env,
      {
        variables: [{ variableId: "vb", statement, value }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
      },
      chain2,
    );

    await startPhase(env, [
      chainHandlerFor([chain1, chain2]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement, value }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
  });
});

describe("persistent detection of omission (§6.3 rule (a))", () => {
  async function twoVariablePhases(env: TestEnv): Promise<void> {
    const alpha = await valueOf({ variableId: "va", version: 1, epoch: 1, plaintext: "a" });
    const beta = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const alphaEntry = {
      variableId: "va",
      statement: await statementOf({ variableId: "va", name: "ALPHA" }),
      value: alpha,
    };
    const betaEntry = {
      variableId: "vb",
      statement: await statementOf({ variableId: "vb", name: "BETA" }),
      value: beta,
    };
    await establishFloor(env, { variables: [alphaEntry, betaEntry], deks: [wrap1] });
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [alphaEntry], deks: [wrap1] }),
      pullMetadataHandlerFor({ variables: [alphaEntry.statement] }),
      deksHandlerFor([wrap1]),
    ]);
  }

  it("pull: refuses the omission of a verified variable", async () => {
    const env = await makeTestEnv();
    await twoVariablePhases(env);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("omission of a verified variable");
    expect(errors).toContain("variable=vb");
  });

  it("run: never executes the command on a distribution with an omission (non-zero exit)", async () => {
    const env = await makeTestEnv();
    await twoVariablePhases(env);
    expect(await runCli(["run", "--", "printenv"], env.layer)).toBe(1);
    expect(env.runnerCalls).toHaveLength(0);
    expect(env.errors.join("\n")).toContain("omission of a verified variable");
  });

  it("push: never pushes on a distribution with an omission (the floor check fires on the resolution pull)", async () => {
    const env = await makeTestEnv();
    await twoVariablePhases(env);
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "ALPHA"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("omission of a verified variable");
  });

  it("refuses a tombstone omission (concealment of the deletion record)", async () => {
    const env = await makeTestEnv();
    const beta = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const betaEntry = {
      variableId: "vb",
      statement: await statementOf({ variableId: "vb", name: "BETA" }),
      value: beta,
    };
    const tombstone = await statementOf({
      variableId: "vd",
      name: "DELETED_VAR",
      metaVersion: 2,
      status: "deleted",
    });
    await establishFloor(env, {
      variables: [betaEntry],
      deletedVariables: [tombstone],
      deks: [wrap1],
    });

    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [betaEntry], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("omission of a verified variable");
    expect(errors).toContain("variable=vd");
  });
});

describe("floor detection of forward injection without false refusal (§6.3 rule (c) — both edges: detection and no false refusal)", () => {
  it("accepts a legitimate pre-rotation old-epoch new version, and refuses an old-epoch new version after the criterion advances", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const v1 = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "v1" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value: v1 }],
      deks: [wrap1],
    });

    const v2 = await valueOf({
      variableId: "vb",
      version: 2,
      epoch: 1,
      plaintext: "v2",
      prevValueSigHashHex: await valueSignedBytesHashOf(v1, owner.userId),
    });
    const prevHash = await prevOfPhase({ variables: [statement] });
    await startPhase(env, [
      chainHandlerFor([chain2]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement, value: v2 }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
        manifestVersion: 2,
        prevManifestSigHashHex: prevHash,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const floor = await readFloorFile(env);
    expect(floor.environments[ENV_ID]?.pullEpoch).toBe(2);
    expect(floor.environments[ENV_ID]?.variables["vb"]).toMatchObject({ version: 2, epoch: 1 });

    const v3 = await valueOf({
      variableId: "vb",
      version: 3,
      epoch: 1,
      plaintext: "v3",
      prevValueSigHashHex: await valueSignedBytesHashOf(v2, owner.userId),
    });
    await startPhase(env, [
      chainHandlerFor([chain2]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement, value: v3 }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
        manifestVersion: 2,
        prevManifestSigHashHex: prevHash,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("forward injection");
    expect(errors).toContain("pull-time epoch baseline=2");
  });

  it("applies rule (c) to a new variable absent from the floor too (a new distribution below the criterion's epoch is the injection shape)", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const beta = await valueOf({ variableId: "vb", version: 1, epoch: 2, plaintext: "b" });
    await establishFloor(
      env,
      {
        variables: [{ variableId: "vb", statement, value: beta }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
      },
      chain2,
    );

    const injected = await valueOf({ variableId: "vc", version: 1, epoch: 1, plaintext: "x" });
    const injectedEntry = {
      variableId: "vc",
      statement: await statementOf({ variableId: "vc", name: "GAMMA" }),
      value: injected,
    };
    const betaEntry = { variableId: "vb", statement, value: beta };
    await startPhase(env, [
      chainHandlerFor([chain2]),
      pullHandlerFor({
        variables: [betaEntry, injectedEntry],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
        manifestVersion: 2,
        prevManifestSigHashHex: await prevOfPhase({ variables: [statement], currentEpoch: 2 }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("forward injection");
    expect(errors).toContain("variable=vc");
    expect(errors).toContain("version=0 (0 = no floor record)");
  });
});

describe("evidencing differing signed bytes at the same coordinates (§6.3 rule (b) / §14.2-5)", () => {
  it("refuses a distribution of different signed bytes under the same version as evidence of equivocation", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const original = await valueOf({
      variableId: "vb",
      version: 1,
      epoch: 1,
      plaintext: "original",
    });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value: original }],
      deks: [wrap1],
    });

    const replaced = await valueOf({
      variableId: "vb",
      version: 1,
      epoch: 1,
      plaintext: "replaced",
    });
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement, value: replaced }],
        deks: [wrap1],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("equivocation");
    expect(errors).toContain(await valueSignedBytesHashOf(original, owner.userId));
    expect(errors).toContain(await valueSignedBytesHashOf(replaced, owner.userId));
  });

  it("refuses different signed bytes under the same metaVersion (a name swap)", async () => {
    const env = await makeTestEnv();
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const original = await statementOf({ variableId: "vb", name: "BETA" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement: original, value }],
      deks: [wrap1],
    });

    const renamed = await statementOf({ variableId: "vb", name: "BETA_SWAPPED" });
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement: renamed, value }],
        deks: [wrap1],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("signed bytes served for the same metaVersion");
  });
});

describe("the floor semantics of deletion (§6.3 rule (a) — deleted is a terminal state)", () => {
  const tombstoneOf = () =>
    statementOf({ variableId: "vb", name: "BETA", metaVersion: 2, status: "deleted" });

  it("accepts a legitimate deletion (a tombstone advancing metaVersion) and advances the floor to deleted", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value }],
      deks: [wrap1],
    });

    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        variables: [],
        deletedVariables: [await tombstoneOf()],
        deks: [wrap1],
        manifestVersion: 2,
        prevManifestSigHashHex: await prevOfPhase({ variables: [statement] }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const floor = await readFloorFile(env);
    expect(floor.environments[ENV_ID]?.variables["vb"]).toMatchObject({
      status: "deleted",
      metaVersion: 2,
    });
  });

  it.each([
    ["metaVersion advance", 3],
    ["same metaVersion", 2],
    ["metaVersion regression", 1],
  ])(
    "refuses unauthorized undeletion (an active distribution of a deleted-recorded variable — %s)",
    async (_label, metaVersion) => {
      const env = await makeTestEnv();
      await establishFloor(env, {
        variables: [],
        deletedVariables: [await tombstoneOf()],
        deks: [wrap1],
      });

      const revived = await statementOf({ variableId: "vb", name: "BETA", metaVersion });
      const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
      await startPhase(env, [
        chainHandlerFor([chain1]),
        pullHandlerFor({
          variables: [{ variableId: "vb", statement: revived, value }],
          deks: [wrap1],
        }),
      ]);
      expect(await runCli(["pull"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain("unauthorized undeletion");
    },
  );

  it("refuses the tombstone (deleted is a terminal state — demanding strict agreement with the floor)", async () => {
    const env = await makeTestEnv();
    await establishFloor(env, {
      variables: [],
      deletedVariables: [await tombstoneOf()],
      deks: [wrap1],
    });

    const forged = await statementOf({
      variableId: "vb",
      name: "BETA",
      metaVersion: 3,
      status: "deleted",
    });
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [], deletedVariables: [forged], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("tombstone");
  });
});

describe("distinguishing the two kinds of divergence (§6.3-2)", () => {
  it("a hash mismatch at-or-below the floor seq (a different branch of the same genesis) is refused as immediate evidence", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value }],
      deks: [wrap1],
    });

    await startPhase(env, [chainHandlerFor([chainB]), pullHandlerFor({ variables: [], deks: [] })]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("distribution of a branch diverging");
    expect(errors).toContain(chain1.hashes[1] as string);
    expect(errors).toContain(chainB.hashes[1] as string);
  });

  it("a declared head beyond the floor resolves via bounded resync; if it is an extension, accept and advance the floor", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const v1 = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value: v1 }],
      deks: [wrap1],
    });

    const v2 = await valueOf({
      variableId: "vb",
      version: 2,
      epoch: 2,
      plaintext: "b2",
      prevValueSigHashHex: await valueSignedBytesHashOf(v1, owner.userId),
    });
    await startPhase(env, [
      chainHandlerFor([chain1, chain2]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement, value: v2 }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
        manifestVersion: 2,
        prevManifestSigHashHex: await prevOfPhase({ variables: [statement] }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const floor = await readFloorFile(env);
    expect(floor.chainHead).toEqual({ seq: 3, hashHex: chain2.hashes[2] });
    expect(floor.environments[ENV_ID]?.pullEpoch).toBe(1);
    expect(floor.environments[ENV_ID]?.variables["vb"]).toMatchObject({ version: 2, epoch: 2 });
  });

  it("refuses as evidence when a declared head beyond the floor is not resolved even by resync", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const v1 = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value: v1 }],
      deks: [wrap1],
    });

    const forged = await distributedValue({
      dek: dek1,
      projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "vb",
      version: 2,
      plaintext: "forged",
      writer: owner,
      head: { seq: 3, hashHex: "ef".repeat(32) },
    });
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement, value: forged }],
        deks: [wrap1],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("chain divergence or forgery");
  });
});

describe("floor advancement after push acceptance (§6.3 — detecting rollback of your own write)", () => {
  it("push advances the floor, and a pull of an older distribution right after is refused", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const v1 = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const entry = { variableId: "vb", statement, value: v1 };
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullMetadataHandlerFor({ variables: [statement] }),
      pullHandlerFor({ variables: [entry], deks: [wrap1] }),
      deksHandlerFor([wrap1]),
      onRequest(
        "POST",
        `/projects/${projectId}/environments/${ENV_ID}/variables/vb/versions`,
        () => ({ status: 200, json: { variableId: "vb", version: 2, epoch: 1 } }),
      ),
    ]);
    env.setStdin(new TextEncoder().encode("updated"));
    expect(await runCli(["push", "BETA"], env.layer)).toBe(0);
    const floor = await readFloorFile(env);
    expect(floor.environments[ENV_ID]?.variables["vb"]).toMatchObject({ version: 2, epoch: 1 });
    expect(floor.environments[ENV_ID]?.pullEpoch).toBe(1);

    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [entry], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("value-version rollback");
  });
});

describe("meta forward injection is not detected even by the floor (§14.3-5 — stating the non-guarantee)", () => {
  it("an advancing-metaVersion injection (a name swap) is accepted even with a floor (the known residue)", async () => {
    const env = await makeTestEnv();
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const original = await statementOf({ variableId: "vb", name: "BETA" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement: original, value }],
      deks: [wrap1],
    });

    const injected = await statementOf({
      variableId: "vb",
      name: "BETA_INJECTED",
      metaVersion: 2,
    });
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement: injected, value }],
        deks: [wrap1],
        manifestVersion: 2,
        prevManifestSigHashHex: await prevOfPhase({ variables: [original] }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("BETA_INJECTED");
  });

  it("environment-meta forward injection is also undetected by the floor (§14.3-5 — holds for any variable's / environment's meta)", async () => {
    const env = await makeTestEnv();
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value }],
      deks: [wrap1],
    });

    const injectedEnvMeta = await distributedEnvironmentStatement({
      projectId,
      environmentId: ENV_ID,
      name: "prod-injected",
      author: owner,
      head: genesisHead(),
      metaVersion: 2,
    });
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        statement: injectedEnvMeta,
        variables: [{ variableId: "vb", statement, value }],
        deks: [wrap1],
        manifestVersion: 2,
        prevManifestSigHashHex: await prevOfPhase({ variables: [statement] }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
  });
});

describe("startup reconciliation of unresolved intents (settled by entry identity at the declared-head position)", () => {
  it("a leftover intent is classified as accepted / rejected / pending by the declared-head position (never promotes an old attempt sharing the same commitment)", async () => {
    const env = await makeTestEnv();
    const store = makeFileFloorStore(env.floorDir);
    const rotateEntry = chain2.entries[2];
    if (rotateEntry?.op !== "rotate_epoch") throw new Error("rotate entry missing");
    const commitment = rotateEntry.payload.dekCommitmentHex;
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const servedManifest = {
      variables: [statement],
      currentEpoch: 2,
      manifestVersion: 2,
      prevManifestSigHashHex: await prevOfPhase({ variables: [statement] }),
    };
    const acceptedManifestHash = await prevOfPhase(servedManifest);
    await Effect.runPromise(
      store.appendIntent(testProjectId(projectId), {
        op: "rotate_epoch",
        environmentId: testEnvironmentId(ENV_ID),
        epoch: 2,
        dekCommitmentHex: commitment,
        variableId: null,
        manifestVersion: 2,
        manifestSigHashHex: acceptedManifestHash,
        declaredHead: { seq: 2, hashHex: chain1.hashes[1] as string },
      }),
    );
    await Effect.runPromise(
      store.appendIntent(testProjectId(projectId), {
        op: "rotate_epoch",
        environmentId: testEnvironmentId(ENV_ID),
        epoch: 2,
        dekCommitmentHex: commitment,
        variableId: null,
        manifestVersion: 2,
        manifestSigHashHex: "9a".repeat(32),
        declaredHead: { seq: 1, hashHex: projectId },
      }),
    );
    await Effect.runPromise(
      store.appendIntent(testProjectId(projectId), {
        op: "rotate_epoch",
        environmentId: testEnvironmentId(ENV_ID),
        epoch: 3,
        dekCommitmentHex: "8b".repeat(32),
        variableId: null,
        manifestVersion: 3,
        manifestSigHashHex: "8c".repeat(32),
        declaredHead: { seq: 3, hashHex: chain2.hashes[2] as string },
      }),
    );

    const value = await valueOf({ variableId: "vb", version: 1, epoch: 2, plaintext: "b" });
    await startPhase(env, [
      chainHandlerFor([chain2]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement, value }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
        manifestVersion: 2,
        prevManifestSigHashHex: servedManifest.prevManifestSigHashHex,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("confirmed as accepted on the chain");
    expect(errors).toContain("it was not accepted");
    expect(errors).toContain("still awaiting confirmation");
    const floor = await readFloorFile(env);
    expect(floor.conflicts).toEqual([]);
    expect(floor.environments[ENV_ID]?.manifest).toEqual({
      manifestVersion: 2,
      epoch: 2,
      manifestSigHashHex: acceptedManifestHash,
    });
    expect(floor.intents).toHaveLength(1);
    expect(floor.intents[0]).toMatchObject({ epoch: 3 });
  });
});

describe("interplay with a commitHead-only floor (project verify first)", () => {
  it("a later pull can establish the environment floor from a head-only floor created by verify", async () => {
    const env = await makeTestEnv();
    await startPhase(env, [chainHandlerFor([chain1])]);
    expect(await runCli(["project", "verify"], env.layer)).toBe(0);
    let floor = await readFloorFile(env);
    expect(floor.chainHead).toEqual({ seq: 2, hashHex: chain1.hashes[1] });
    expect(floor.environments[ENV_ID]).toBeUndefined();

    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [{ variableId: "vb", statement, value }], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    floor = await readFloorFile(env);
    expect(floor.environments[ENV_ID]?.pullEpoch).toBe(1);
    expect(floor.environments[ENV_ID]?.variables["vb"]).toMatchObject({ version: 1 });
  });
});
