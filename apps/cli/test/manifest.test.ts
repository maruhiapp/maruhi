import type { ChainEntry } from "@maruhi/crypto";
import { computeChainEntryHash, computeEnvValuesDigest, SUITE_ID } from "@maruhi/crypto";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  checkpointSnapshotValuesOf,
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
  testVariableId,
  type WireCheckpointSnapshot,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  type WireRecipientDek,
} from "@maruhi/test-kit";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { lastHashOf, servedChain } from "./support/chain-handler.ts";
import type { WireRotateBody } from "./support/env-rotate.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, offSpec, onEndpoint } from "./support/server.ts";

const ENV_ID = "prod";

let owner: GeneratedIdentity;
let reader: GeneratedIdentity;
let member2: GeneratedIdentity;
let dek1: Uint8Array;
let dek2: Uint8Array;
let chain1: BuiltChain;
let chain2: BuiltChain;
let wrap1: WireRecipientDek;
let wrap2: WireRecipientDek;
let envStatement: WireDistributedEnvironmentStatement;
let alphaStatement: WireDistributedVariableStatement;
let alphaValue1: WireDistributedValue;
let alphaValue2: WireDistributedValue;
let projectId: string;

let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await generateIdentity("user-owner-1111");
  reader = await generateIdentity("user-reader-2222");
  member2 = await generateIdentity("user-member2-3333");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  const steps = [
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: addMemberOp(reader, "reader") },
    { actor: owner, operation: addMemberOp(member2, "member") },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
  ];
  chain1 = await buildChain(steps);
  chain2 = await buildChain([
    ...steps,
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
  projectId = chain1.projectId;
  expect(chain2.projectId).toBe(projectId);
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
  alphaStatement = await distributedVariableStatement({
    projectId,
    environmentId: ENV_ID,
    variableId: "va",
    name: "ALPHA",
    author: owner,
    head: { seq: 1, hashHex: projectId },
  });
  alphaValue1 = await distributedValue({
    dek: dek1,
    ...common,
    epoch: 1,
    variableId: "va",
    version: 1,
    plaintext: "alpha-value",
    writer: owner,
    head: headOf(chain1, 4),
  });
  alphaValue2 = await distributedValue({
    dek: dek2,
    ...common,
    epoch: 2,
    variableId: "va",
    version: 2,
    plaintext: "alpha-value-2",
    writer: owner,
    head: headOf(chain2, 5),
  });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function chainHandler(built: BuiltChain): MockHandler {
  return onEndpoint("membership.get", { projectId }, () => ({
    status: 200,
    json: servedChain(projectId, built.entries, built.hashes),
  }));
}

interface PullJson {
  readonly currentEpoch: number;
  readonly variables: readonly {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  }[];
  readonly deletedVariables?: readonly WireDistributedVariableStatement[];
  readonly deks: readonly WireRecipientDek[];
  readonly manifest?: WireDistributedManifest;
  readonly checkpointSnapshot?: WireCheckpointSnapshot;
}

function pullHandler(payload: PullJson): MockHandler {
  return onEndpoint("variables.pull", { projectId, environmentId: ENV_ID }, () => {
    const json = {
      environmentId: ENV_ID,
      currentEpoch: payload.currentEpoch,
      statement: envStatement,
      variables: payload.variables,
      deletedVariables: payload.deletedVariables ?? [],
      deks: payload.deks,
      ...(payload.checkpointSnapshot === undefined
        ? {}
        : { checkpointSnapshot: payload.checkpointSnapshot }),
      schemaPolicy: "enabled" as const,
    };
    return payload.manifest === undefined
      ? offSpec({ status: 200, json })
      : { status: 200, json: { ...json, manifest: payload.manifest } };
  });
}

async function startEnv(handlers: readonly MockHandler[]): Promise<TestEnv> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: projectId,
    defaultEnvironment: ENV_ID,
  });
  return env;
}

async function startPhase(env: TestEnv, handlers: readonly MockHandler[]): Promise<void> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: projectId,
    defaultEnvironment: ENV_ID,
  });
}

const alphaEntry = () => ({ variableId: "va", statement: alphaStatement, value: alphaValue1 });

function manifestV1(
  overrides: {
    readonly statements?: readonly WireDistributedVariableStatement[];
    readonly epoch?: number;
    readonly head?: { readonly seq: number; readonly hashHex: string };
    readonly issuer?: GeneratedIdentity;
    readonly manifestVersion?: number;
    readonly prevManifestSigHashHex?: string;
  } = {},
): Promise<WireDistributedManifest> {
  const { manifestVersion, prevManifestSigHashHex } = overrides;
  return distributedManifest({
    projectId,
    environmentId: ENV_ID,
    epoch: overrides.epoch ?? 1,
    issuer: overrides.issuer ?? owner,
    head: overrides.head ?? headOf(chain1, 4),
    envStatement,
    statements: overrides.statements ?? [alphaStatement],
    ...(manifestVersion === undefined ? {} : { manifestVersion }),
    ...(prevManifestSigHashHex === undefined ? {} : { prevManifestSigHashHex }),
  });
}

describe("manifest distribution-time verification (§6.3 — wiring into crypto's shared implementation)", () => {
  it("absence is uniformly refused", async () => {
    const env = await startEnv([
      chainHandler(chain1),
      pullHandler({ currentEpoch: 1, variables: [alphaEntry()], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.at(-1)).toBe(
      "maruhi: The server did not distribute an environment manifest. A missing manifest is treated as manifest suppression (statement omission cannot be ruled out — CRYPTO_SPEC §6.3) and the response is rejected",
    );
  });

  it("refuses a missing variable (distributing a variable that is not in the digest = the carriage form of an omission in reverse)", async () => {
    const env = await startEnv([
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1({ statements: [] }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=variables-digest-mismatch");
  });

  it("refuses a missing tombstone (a digest that excludes the deletion record)", async () => {
    const tombstone = await distributedVariableStatement({
      projectId,
      environmentId: ENV_ID,
      variableId: "vd",
      name: "RETIRED",
      author: owner,
      head: { seq: 1, hashHex: projectId },
      status: "deleted",
      metaVersion: 2,
    });
    const env = await startEnv([
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deletedVariables: [tombstone],
        deks: [wrap1],
        manifest: await manifestV1({ statements: [alphaStatement] }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=variables-digest-mismatch");
  });

  it("refuses an epoch mismatch (not the current epoch at the declared head)", async () => {
    const env = await startEnv([
      chainHandler(chain2),
      pullHandler({
        currentEpoch: 2,
        variables: [alphaEntry()],
        deks: [wrap1, wrap2],
        manifest: await manifestV1({ epoch: 1, head: headOf(chain2, 5) }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=epoch-not-current-at-head");
  });

  it("refuses an insufficient issuer role (reader issuance) — every issuance trigger is member-or-above (§4.3)", async () => {
    const env = await startEnv([
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1({ issuer: reader }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=issuer-role-insufficient-at-head");
  });

  it("refuses a signature bit-flip", async () => {
    const honest = await manifestV1();
    const flipped = `${honest.signatureHex.slice(0, -1)}${
      honest.signatureHex.endsWith("0") ? "1" : "0"
    }`;
    const env = await startEnv([
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: { ...honest, signatureHex: flipped },
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=signature-invalid");
  });
});

describe("the floor's manifest extension (applying §6.3 rules (a)(b)(c) to manifests)", () => {
  it("refuses a manifestVersion regression (rule (a))", async () => {
    const env = await makeTestEnv();
    await startPhase(env, [
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1({ manifestVersion: 2 }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);

    await startPhase(env, [
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1({ manifestVersion: 1 }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("environment-manifest rollback");
    expect(errors).toContain("manifestVersion=2");
    expect(errors).toContain("manifestVersion=1");
  });

  it("the chain's checkpoint baseline (F3) does not substitute for the floor's rule (a) (F2) — a distribution at-or-above the baseline but below the floor is refused by the floor (PR-F4 cross-layer)", async () => {
    const v1 = await manifestV1();
    const snapshotValues = await checkpointSnapshotValuesOf([alphaValue1]);
    const valuesDigest = await computeEnvValuesDigest(
      SUITE_ID,
      snapshotValues.map((entry) => ({ ...entry, variableId: testVariableId(entry.variableId) })),
    );
    if (!valuesDigest.ok) throw new Error("values digest failed");
    const checkpointChain = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(reader, "reader") },
      { actor: owner, operation: addMemberOp(member2, "member") },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      {
        actor: owner,
        operation: {
          op: "checkpoint",
          payload: {
            environments: [
              {
                environmentId: testEnvironmentId(ENV_ID),
                epoch: 1,
                manifestVersion: 1,
                manifestSigHashHex: await distributedManifestHashOf(projectId, v1),
                valuesDigestHex: valuesDigest.value,
              },
            ],
            auditHeadHashHex: "",
          },
        },
      },
    ]);
    expect(checkpointChain.projectId).toBe(projectId);
    const checkpointSnapshot: WireCheckpointSnapshot = {
      chainSeq: 5,
      entryHashHex: checkpointChain.hashes[4] ?? "",
      values: snapshotValues,
    };
    const env = await makeTestEnv();
    await startPhase(env, [
      chainHandler(checkpointChain),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1({ manifestVersion: 3, head: headOf(checkpointChain, 5) }),
        checkpointSnapshot,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);

    await startPhase(env, [
      chainHandler(checkpointChain),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1({ manifestVersion: 2, head: headOf(checkpointChain, 5) }),
        checkpointSnapshot,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("environment-manifest rollback");
    expect(errors).not.toContain("checkpoint-regressed");
  });

  it("refuses differing signed bytes under the same manifestVersion (rule (b) — equivocation)", async () => {
    const env = await makeTestEnv();
    await startPhase(env, [
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1(),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);

    await startPhase(env, [
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1({ issuer: member2 }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("signed bytes served for the same manifestVersion");
  });

  it("refuses an advancing manifestVersion that burns in an old epoch (applying rule (c) to manifests)", async () => {
    const env = await makeTestEnv();
    await startPhase(env, [
      chainHandler(chain2),
      pullHandler({
        currentEpoch: 2,
        variables: [{ variableId: "va", statement: alphaStatement, value: alphaValue2 }],
        deks: [wrap1, wrap2],
        manifest: await manifestV1({
          epoch: 2,
          head: headOf(chain2, 5),
          manifestVersion: 2,
        }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);

    await startPhase(env, [
      chainHandler(chain2),
      pullHandler({
        currentEpoch: 2,
        variables: [{ variableId: "va", statement: alphaStatement, value: alphaValue2 }],
        deks: [wrap1, wrap2],
        manifest: await manifestV1({ epoch: 1, head: headOf(chain2, 4), manifestVersion: 4 }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("below the epoch baseline");
    expect(errors).toContain("forward meta injection");
  });

  it("rule (c)'s criterion also covers the floor manifest's own epoch (the window where pullEpoch lags)", async () => {
    const env = await makeTestEnv();
    let chainCalls = 0;
    const progressiveChain: MockHandler = onEndpoint("membership.get", { projectId }, () => {
      chainCalls += 1;
      const built = chainCalls === 1 ? chain1 : chain2;
      return {
        status: 200,
        json: servedChain(projectId, built.entries, built.hashes),
      };
    });
    await startPhase(env, [
      progressiveChain,
      pullHandler({
        currentEpoch: 2,
        variables: [{ variableId: "va", statement: alphaStatement, value: alphaValue2 }],
        deks: [wrap1, wrap2],
        manifest: await manifestV1({
          epoch: 2,
          head: headOf(chain2, 5),
          manifestVersion: 2,
        }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);

    await startPhase(env, [
      chainHandler(chain2),
      pullHandler({
        currentEpoch: 2,
        variables: [{ variableId: "va", statement: alphaStatement, value: alphaValue2 }],
        deks: [wrap1, wrap2],
        manifest: await manifestV1({ epoch: 1, head: headOf(chain2, 4), manifestVersion: 4 }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("below the epoch baseline");
    expect(errors).toContain("epoch baseline=2");
  });
});

describe("prev-chain verification of adjacent manifestVersions (§4.3 verification rule (1) — session-31 M1-A1)", () => {
  function metadataHandler(manifest: WireDistributedManifest): MockHandler {
    return onEndpoint("variables.pullMetadata", { projectId, environmentId: ENV_ID }, () => ({
      status: 200,
      json: {
        environmentId: ENV_ID,
        currentEpoch: 1,
        statement: envStatement,
        variables: [alphaStatement],
        deletedVariables: [],
        manifest,
        schemaPolicy: "enabled" as const,
      },
    }));
  }

  async function establishV1Floor(env: TestEnv): Promise<string> {
    await startPhase(env, [
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1(),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    return distributedManifestHashOf(projectId, await manifestV1());
  }

  it("floor v1 → v2 with the correct prev: accepted", async () => {
    const env = await makeTestEnv();
    const v1Hash = await establishV1Floor(env);
    await startPhase(env, [
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1({ manifestVersion: 2, prevManifestSigHashHex: v1Hash }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
  });

  it("floor v1 → v2 with a different prev: refused as evidence of branching (even with a valid signature and correct digest)", async () => {
    const env = await makeTestEnv();
    const v1Hash = await establishV1Floor(env);
    const forged = await manifestV1({
      manifestVersion: 2,
      prevManifestSigHashHex: "ab".repeat(32),
    });
    await startPhase(env, [
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: forged,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("declares a prev that does not match the verified predecessor");
    expect(errors).toContain(v1Hash);
    expect(errors).toContain("ab".repeat(32));
    expect(errors).toContain(`issuer=${owner.userId}`);
    expect(errors).toContain("declared head:");
  });

  it("floor v1 → v3 (version gap ≥ 2): accepted per the known latest-only constraint (§14.3)", async () => {
    const env = await makeTestEnv();
    await establishV1Floor(env);
    await startPhase(env, [
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1({ manifestVersion: 3 }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
  });

  it("the same prev check works on the metadata-only pull path (fired by push's name resolution)", async () => {
    const env = await makeTestEnv();
    await establishV1Floor(env);
    const forged = await manifestV1({
      manifestVersion: 2,
      prevManifestSigHashHex: "ab".repeat(32),
    });
    await startPhase(env, [chainHandler(chain1), metadataHandler(forged)]);
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "ALPHA"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "declares a prev that does not match the verified predecessor",
    );
  });

  it("an adjacent v2 that chains prev correctly but regresses the epoch is refused as epoch-regressed", async () => {
    const env = await makeTestEnv();
    await startPhase(env, [
      chainHandler(chain2),
      pullHandler({
        currentEpoch: 2,
        variables: [{ variableId: "va", statement: alphaStatement, value: alphaValue2 }],
        deks: [wrap1, wrap2],
        manifest: await manifestV1({ epoch: 2, head: headOf(chain2, 5), manifestVersion: 2 }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const v2Hash = await distributedManifestHashOf(
      projectId,
      await manifestV1({ epoch: 2, head: headOf(chain2, 5), manifestVersion: 2 }),
    );
    await startPhase(env, [
      chainHandler(chain2),
      pullHandler({
        currentEpoch: 2,
        variables: [{ variableId: "va", statement: alphaStatement, value: alphaValue2 }],
        deks: [wrap1, wrap2],
        manifest: await manifestV1({
          epoch: 1,
          head: headOf(chain2, 4),
          manifestVersion: 3,
          prevManifestSigHashHex: v2Hash,
        }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("epoch-regressed");
  });
});

function makeRotateAcceptingServer(input: {
  readonly serveManifestAfterAccept?: boolean;
  readonly initialManifest: WireDistributedManifest;
  readonly built?: BuiltChain;
  readonly currentEpoch?: number;
  readonly variables?: {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  }[];
  readonly initialDeks?: readonly WireRecipientDek[];
}): {
  readonly handlers: readonly MockHandler[];
  readonly rotateBodies: WireRotateBody[];
  readonly pushes: string[];
} {
  const built = input.built ?? chain1;
  const entries: ChainEntry[] = [...built.entries];
  const hashes: string[] = [...built.hashes];
  const deks: WireRecipientDek[] = [...(input.initialDeks ?? [wrap1])];
  const variables = input.variables ?? [];
  const rotateBodies: WireRotateBody[] = [];
  const pushes: string[] = [];
  let currentEpoch = input.currentEpoch ?? 1;
  let manifest: WireDistributedManifest = input.initialManifest;
  let checkpointSnapshot: WireCheckpointSnapshot | null = null;
  const handlers: MockHandler[] = [
    onEndpoint("membership.get", { projectId }, () => ({
      status: 200,
      json: servedChain(projectId, entries, hashes),
    })),
    onEndpoint("variables.pull", { projectId, environmentId: ENV_ID }, () => ({
      status: 200,
      json: {
        environmentId: ENV_ID,
        currentEpoch,
        statement: envStatement,
        variables,
        deletedVariables: [],
        deks,
        manifest,
        ...(checkpointSnapshot === null ? {} : { checkpointSnapshot }),
        schemaPolicy: "enabled" as const,
      },
    })),
    (request) => {
      const prefix = `/projects/${projectId}/environments/${ENV_ID}/variables/`;
      if (
        request.method !== "POST" ||
        !request.path.startsWith(prefix) ||
        !request.path.endsWith("/versions")
      ) {
        return null;
      }
      const variableId = request.path.slice(prefix.length, -"/versions".length);
      pushes.push(variableId);
      const body = request.body as { readonly value: WireDistributedValue };
      const stored: WireDistributedValue = {
        ...body.value,
        writerUserId: owner.userId,
        writerKeyFingerprintHex: owner.fingerprintHex,
      };
      const target = variables.find((variable) => variable.variableId === variableId);
      if (target !== undefined) {
        target.value = stored;
      }
      return {
        status: 200,
        json: { variableId, version: body.value.aad.version, epoch: body.value.aad.epoch },
      };
    },
    async (request) => {
      if (
        request.method !== "POST" ||
        request.path !== `/projects/${projectId}/environments/${ENV_ID}/rotate`
      ) {
        return null;
      }
      const body = request.body as WireRotateBody;
      rotateBodies.push(body);
      entries.push(body.entry, body.checkpoint);
      hashes.push(
        await computeChainEntryHash(body.entry),
        await computeChainEntryHash(body.checkpoint),
      );
      checkpointSnapshot = {
        chainSeq: entries.length,
        entryHashHex: hashes[hashes.length - 1] ?? "",
        values: await checkpointSnapshotValuesOf(variables.map((variable) => variable.value)),
      };
      currentEpoch = body.entry.payload.newEpoch;
      for (const wrap of body.deks) {
        if (wrap.recipientUserId !== owner.userId) {
          continue;
        }
        deks.push({
          suite: wrap.suite,
          epoch: wrap.epoch,
          recipientEncPubHex: wrap.recipientEncPubHex,
          encHex: wrap.encHex,
          ciphertextHex: wrap.ciphertextHex,
          signatureHex: wrap.signatureHex,
          signerUserId: owner.userId,
          signerKeyFingerprintHex: owner.fingerprintHex,
        });
      }
      if (input.serveManifestAfterAccept !== false) {
        manifest = {
          ...body.manifest,
          issuerUserId: owner.userId,
          issuerKeyFingerprintHex: owner.fingerprintHex,
        };
      }
      return {
        status: 200,
        json: {
          environmentId: ENV_ID,
          currentEpoch,
          headSeq: entries.length,
          headHashHex: lastHashOf(hashes),
        },
      };
    },
  ];
  return { handlers, rotateBodies, pushes };
}

describe("rollback detection after rotate acceptance (§6.3 / §4.3 (4))", () => {
  it("a server that keeps distributing an old manifestVersion after acceptance is detected by the same run's rescan", async () => {
    const staleManifest = await manifestV1({ statements: [] });
    const state = makeRotateAcceptingServer({
      initialManifest: staleManifest,
      serveManifestAfterAccept: false,
    });
    const env = await startEnv(state.handlers);
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "swallow"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(1);
    expect(env.errors.join("\n")).toContain("checkpoint-regressed");
  });

  it("even when the floor write fails, the accepted-version detection criterion still works via the same run's rescan", async () => {
    const staleManifest = await manifestV1({ statements: [] });
    const state = makeRotateAcceptingServer({
      initialManifest: staleManifest,
      serveManifestAfterAccept: false,
    });
    const env = await startEnv(state.handlers);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    env.failFloorPushCommits();
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "floor failure"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("could not be recorded in the local floor");
    expect(errors).toContain("checkpoint-regressed");
  });
});
