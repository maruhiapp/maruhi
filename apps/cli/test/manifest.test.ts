// CLI wiring tests for the environment manifest (CRYPTO_SPEC §4.3 / §6.3,
// AUTH_SPEC §12 — the manifest clause of session-27 §13-5).
//
// Pillars of verification:
//  1. Distribution-time verification: absence = uniform refusal · digest
//     recomputation (missing variable / tombstone) · epoch consistency ·
//     issuer role insufficiency (wiring into crypto's shared implementation)
//  2. Manifest extension of the floor: rules (a) regression, (b) same-version
//     difference, (c) old-epoch burn-in on an advancing version
//     (persistent detection across sessions)
//  3. Migration path (session-27 §14 PR-M1): operations against a server with
//     an uninitialized manifest are refused by default, and only
//     `env rotate --init-manifest` tolerates the absence to issue
//     manifestVersion 1 (verification of a distributed manifest is not relaxed)

import type { ChainEntry } from "@maruhi/crypto";
import { computeChainEntryHash, computeEnvValuesDigest, SUITE_ID } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  checkpointSnapshotValuesOf,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  manifestHashOf,
  rotateEpochOp,
  statementFor,
  type TestUser,
  type WireCheckpointSnapshot,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "prod";

let owner: TestUser;
/** A member with role reader (for the issuer-role-insufficiency negative). */
let reader: TestUser;
/** A second member with role member (for same-version difference = equivocation's different issuer). */
let member2: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;
/** [genesis, add reader, add member2, create ENV](epoch 1)。 */
let chain1: BuiltChain;
/** chain1 + rotate_epoch(2) (a strict extension of chain1). */
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
  owner = await makeTestUser("user-owner-1111");
  reader = await makeTestUser("user-reader-2222");
  member2 = await makeTestUser("user-member2-3333");
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
  wrap1 = await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner });
  wrap2 = await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner });
  envStatement = await environmentStatementFor({
    projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: { seq: 1, hashHex: projectId },
  });
  alphaStatement = await statementFor({
    projectId,
    environmentId: ENV_ID,
    variableId: "va",
    name: "ALPHA",
    author: owner,
    head: { seq: 1, hashHex: projectId },
  });
  alphaValue1 = await encryptValueFor({
    dek: dek1,
    ...common,
    epoch: 1,
    variableId: "va",
    version: 1,
    plaintext: "alpha-value",
    writer: owner,
    head: headOf(chain1, 4),
  });
  alphaValue2 = await encryptValueFor({
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
  return onRequest("GET", `/projects/${projectId}/chain`, () => ({
    status: 200,
    json: {
      projectId,
      entries: built.entries,
      headSeq: built.entries.length,
      headHashHex: built.hashes[built.hashes.length - 1],
    },
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
  /** undefined = do not distribute a manifest (for the absence negative). */
  readonly manifest?: WireDistributedManifest;
  /** A fixture that stacks a baseline checkpoint on the chain bundles the corresponding enumeration (§12-7). */
  readonly checkpointSnapshot?: WireCheckpointSnapshot;
}

function pullHandler(payload: PullJson): MockHandler {
  return onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull`, () => ({
    status: 200,
    json: {
      environmentId: ENV_ID,
      currentEpoch: payload.currentEpoch,
      statement: envStatement,
      variables: payload.variables,
      deletedVariables: payload.deletedVariables ?? [],
      deks: payload.deks,
      ...(payload.manifest === undefined ? {} : { manifest: payload.manifest }),
      ...(payload.checkpointSnapshot === undefined
        ? {}
        : { checkpointSnapshot: payload.checkpointSnapshot }),
    },
  }));
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

/** Phase switch into the same TestEnv (= the same floor) — same style as floor-detection. */
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

/** The honest manifest (epoch 1 · chain1 head · [ALPHA]). Overrides build the negatives. */
function manifestV1(
  overrides: {
    readonly statements?: readonly WireDistributedVariableStatement[];
    readonly epoch?: number;
    readonly head?: { readonly seq: number; readonly hashHex: string };
    readonly issuer?: TestUser;
    readonly manifestVersion?: number;
    /** prev for version > 1 (for fixtures satisfying the adjacent prev check — M1-A1). */
    readonly prevManifestSigHashHex?: string;
  } = {},
): Promise<WireDistributedManifest> {
  const { manifestVersion, prevManifestSigHashHex } = overrides;
  return manifestFor({
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
  it("absence is uniformly refused and the migration procedure (--init-manifest) is shown", async () => {
    const env = await startEnv([
      chainHandler(chain1),
      pullHandler({ currentEpoch: 1, variables: [alphaEntry()], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("did not distribute an environment manifest");
    expect(errors).toContain("manifest suppression");
    expect(errors).toContain("--init-manifest");
  });

  it("refuses a missing variable (distributing a variable that is not in the digest = the carriage form of an omission in reverse)", async () => {
    // The manifest is signed with the digest of the empty set → the
    // distribution contains ALPHA = recomputation mismatch. The reverse
    // direction (omitting from the distribution) is covered by the same single check
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
    const tombstone = await statementFor({
      projectId,
      environmentId: ENV_ID,
      variableId: "vd",
      name: "RETIRED",
      author: owner,
      head: { seq: 1, hashHex: projectId },
      status: "deleted",
      metaVersion: 2,
    });
    // The manifest's digest is signed over actives only (without the tombstone)
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
    // A manifest that burns epoch 1 into the post-rotate head (seq 5 = epoch 2)
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
    // Phase 1: establish the floor with the v2 manifest
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

    // Phase 2: v1 over the same set (an old valid manifest that passes every check standalone)
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
    // The latest checkpoint on the chain notarizes mv1 (the boundary-checkpoint
    // shape). The floor knows v3 from the pull. A v2 distribution passes the
    // §4.3 (4) baseline (mv1 or above) so checkpoint-regressed does not fire,
    // but the floor's rule (a) (below v3) rejects it — pinning that the coarse
    // shared criterion (the chain, which lags the floor because meta operations
    // do not issue checkpoints) never short-circuits the fine local criterion (the floor)
    const v1 = await manifestV1();
    // The baseline checkpoint's values_digest is the actual computed value of
    // the distributed set ([ALPHA v1]) — the corresponding enumeration
    // (checkpointSnapshot) is bundled into the pull (rule 2 — PR-M3)
    const snapshotValues = await checkpointSnapshotValuesOf([alphaValue1]);
    const valuesDigest = await computeEnvValuesDigest(SUITE_ID, snapshotValues);
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
                environmentId: ENV_ID,
                epoch: 1,
                manifestVersion: 1,
                manifestSigHashHex: await manifestHashOf(projectId, v1),
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
    // Phase 1: establish the floor with v3 (a different version from the mv1 tuple — verified on the strict path)
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

    // Phase 2: v2 (at-or-above the chain baseline mv1, below the floor's v3)
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

    // Same version, same set, but a different issuer = valid signatures over different signed bytes
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
    // Phase 1: establish an epoch-2 floor (pull-time epoch criterion = 2)
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

    // Phase 2: the version advances (4 — a gap of ≥2 from the floor's v2 means
    // the adjacent-prev check [M1-A1] does not apply, and the actual-equality
    // of an intermediate predecessor is uncheckable per the known latest-only
    // constraint), but the manifest burns in epoch 1 (declaring membership
    // head seq 4 from the old epoch is cryptographically valid). Rejecting
    // this gap-shaped advancing injection is exactly the floor's rule (c)
    // applied to manifests (the adjacent shape is rejected earlier by the
    // shared verifier's predecessor-epoch-non-decrease check — the test below)
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
    // In the bounded-resync shape, pullEpoch stays at the pre-response view
    // (= the old epoch), while the floor manifest already knows epoch 2 as
    // verified. If the criterion were pullEpoch alone, an advancing
    // manifestVersion burning in the old epoch (cryptographically valid via a
    // declaration of the old membership head) would slip through
    const env = await makeTestEnv();
    let chainCalls = 0;
    const progressiveChain: MockHandler = onRequest("GET", `/projects/${projectId}/chain`, () => {
      chainCalls += 1;
      const built = chainCalls === 1 ? chain1 : chain2;
      return {
        status: 200,
        json: {
          projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
        },
      };
    });
    // Phase 1: starting from the old view (chain1), the epoch-2 value + v2
    // manifest (head seq 5 = future) is accepted by bounded resync → floor:
    // pullEpoch 1, manifest {v2, epoch 2}
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

    // Phase 2: the version advances (4 — gap ≥2 = outside the adjacent-prev
    // check), but the manifest burns in epoch 1. It would slip through on the
    // pullEpoch (1) criterion, but is rejected because the floor manifest's
    // epoch (2) joins the criterion (the transitive form of epoch
    // non-decrease across the manifest chain)
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
  /** The response of a metadata-only pull (§12-7) — for pinning push's name-resolution path = the metadata path. */
  function metadataHandler(manifest: WireDistributedManifest): MockHandler {
    return onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull/metadata`, () => ({
      status: 200,
      json: {
        environmentId: ENV_ID,
        currentEpoch: 1,
        statement: envStatement,
        variables: [alphaStatement],
        deletedVariables: [],
        manifest,
      },
    }));
  }

  /** Phase 1: establish the floor with a v1 manifest and return its signed-bytes hash. */
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
    return manifestHashOf(projectId, await manifestV1());
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
    // Holds a valid signature, correct digest, and correct epoch, but prev is an arbitrary 64-hex
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
    // Evidence: the floor-side hash, the distributed prev, issuer, declared head (M1-A1 amendment 3)
    expect(errors).toContain(v1Hash);
    expect(errors).toContain("ab".repeat(32));
    expect(errors).toContain(`issuer=${owner.userId}`);
    expect(errors).toContain("declared head:");
  });

  it("floor v1 → v3 (version gap ≥ 2): accepted per the known latest-only constraint (§14.3)", async () => {
    const env = await makeTestEnv();
    await establishV1Floor(env);
    // Intermediate versions (v2) are never distributed by design, so prev's
    // actual-equality is uncheckable — do not pretend it is checkable (prev
    // stays a fixture dummy)
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
    // The floor's predecessor carries both hash and epoch (the shared
    // verifier's §4.1 isomorphic check). An old-epoch burn-in in adjacent
    // advance is rejected here (the gap shape is the floor's rule (c))
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
    const v2Hash = await manifestHashOf(
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

/* -------------------------------------------------------------------------- */
/* Migration path (session-27 §14 PR-M1 — v1 init for pre-manifest envs)    */
/* -------------------------------------------------------------------------- */

interface RotateBody {
  readonly parentHeadHashHex: string;
  readonly entry: ChainEntry & {
    readonly op: "rotate_epoch";
    readonly payload: {
      readonly environmentId: string;
      readonly newEpoch: number;
      readonly reason: string;
      readonly dekCommitmentHex: string;
    };
  };
  readonly deks: readonly {
    readonly suite: "maruhi/v1";
    readonly epoch: number;
    readonly recipientUserId: string;
    readonly encHex: string;
    readonly ciphertextHex: string;
    readonly signatureHex: string;
  }[];
  readonly manifest: Omit<WireDistributedManifest, "issuerUserId" | "issuerKeyFingerprintHex">;
  /** The boundary checkpoint (H+2 — the mandatory bundle of §12-4). */
  readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
}

/**
 * The server of an environment created before manifests: no stored manifest
 * (pull does not bundle manifest). Once it accepts a rotate composite, it distributes the accepted manifest thereafter.
 */
function makeLegacyServer(input: {
  readonly serveManifestAfterAccept?: boolean;
  /** The initially distributed manifest (undefined = uninitialized server). */
  readonly initialManifest?: WireDistributedManifest;
  /** The initial chain (default = chain1). */
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
  readonly rotateBodies: RotateBody[];
  readonly pushes: string[];
} {
  const built = input.built ?? chain1;
  const entries: ChainEntry[] = [...built.entries];
  const hashes: string[] = [...built.hashes];
  const deks: WireRecipientDek[] = [...(input.initialDeks ?? [wrap1])];
  const variables = input.variables ?? [];
  const rotateBodies: RotateBody[] = [];
  const pushes: string[] = [];
  let currentEpoch = input.currentEpoch ?? 1;
  let manifest: WireDistributedManifest | null = input.initialManifest ?? null;
  // The stored checkpoint snapshot (§16-2 — saved when a boundary checkpoint
  // is accepted and bundled into later value-bearing pulls. Material for rule 2 — PR-M3)
  let checkpointSnapshot: WireCheckpointSnapshot | null = null;
  const handlers: MockHandler[] = [
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: {
        projectId,
        entries,
        headSeq: entries.length,
        headHashHex: hashes[hashes.length - 1],
      },
    })),
    onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull`, () => ({
      status: 200,
      json: {
        environmentId: ENV_ID,
        currentEpoch,
        statement: envStatement,
        variables,
        deletedVariables: [],
        deks,
        ...(manifest === null ? {} : { manifest }),
        ...(checkpointSnapshot === null ? {} : { checkpointSnapshot }),
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
      const body = request.body as RotateBody;
      rotateBodies.push(body);
      // Accepts the 2 entries rotate + boundary checkpoint (§12-4)
      entries.push(body.entry, body.checkpoint);
      hashes.push(
        await computeChainEntryHash(body.entry),
        await computeChainEntryHash(body.checkpoint),
      );
      // Snapshot save in the same transaction as acceptance (§16-2 — the
      // enumeration of the distributed set at acceptance time)
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
          headHashHex: hashes[hashes.length - 1],
        },
      };
    },
  ];
  return { handlers, rotateBodies, pushes };
}

describe("rollback detection after rotate acceptance (§6.3 / §4.3 (4))", () => {
  it("a server that keeps distributing an old manifestVersion after acceptance is detected by the same run's rescan", async () => {
    // rotate promotes the next manifestVersion it signed into the floor right
    // after acceptance. Because the boundary checkpoint (PR-F3b) also pins the
    // accepted-version baseline on the chain, a server that keeps distributing
    // the old manifest (swallowing the accepted v2) is rejected by §4.3
    // verification rule (4) (checkpoint-regressed) before the floor check
    // (rule (a)) — one more detection layer, but the fixed point that the
    // swallow is rejected within the same run is unchanged
    const staleManifest = await manifestV1({ statements: [] });
    const state = makeLegacyServer({
      initialManifest: staleManifest,
      // Keeps distributing v1 without storing the accepted v2 (models a rollback server)
      serveManifestAfterAccept: false,
    });
    const env = await startEnv(state.handlers);
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "swallow"], env.layer)).toBe(1);
    // The composite itself was accepted (the refusal is the verification of the post-acceptance rescan pull)
    expect(state.rotateBodies).toHaveLength(1);
    expect(env.errors.join("\n")).toContain("checkpoint-regressed");
  });

  it("even when the floor write fails, the accepted-version detection criterion still works via the same run's rescan", async () => {
    // Even if commitManifest's disk write fails, the accepted rotate's boundary
    // checkpoint remains the baseline on the chain — a server that keeps
    // distributing the old version after acceptance is rejected as
    // checkpoint-regressed within the same run (the missing floor persistence is disclosed via a warning)
    const staleManifest = await manifestV1({ statements: [] });
    const state = makeLegacyServer({
      initialManifest: staleManifest,
      serveManifestAfterAccept: false,
    });
    const env = await startEnv(state.handlers);
    // Establish the floor via a prior pull (only the write during rotate fails)
    expect(await runCli(["pull"], env.layer)).toBe(0);
    env.failFloorPushCommits();
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "floor failure"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("could not be recorded in the local floor");
    expect(errors).toContain("checkpoint-regressed");
  });
});

describe("--init-manifest (migration path — session-27 §14 PR-M1)", () => {
  it("rotate against a manifest-uninitialized server is refused by default (absence = refusal stays even under migration)", async () => {
    const state = makeLegacyServer({});
    const env = await startEnv(state.handlers);
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "pre-migration"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("did not distribute an environment manifest");
    // The refusal precedes composite submission (the stage of the pull that detected the absence)
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("--init-manifest tolerates only the absence and bundles manifestVersion 1 (empty prev · new_epoch)", async () => {
    const state = makeLegacyServer({});
    const env = await startEnv(state.handlers);
    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--init-manifest", "--reason", "migration"],
        env.layer,
      ),
    ).toBe(0);
    expect(state.rotateBodies).toHaveLength(1);
    const body = state.rotateBodies[0];
    if (body === undefined) throw new Error("rotate body missing");
    // Initialization is v1 with empty prev. The epoch is after applying the
    // bundled entry = new_epoch (§12-5 (4)); the declared head is the current
    // head before the append (§12-4)
    expect(body.manifest.manifestVersion).toBe(1);
    expect(body.manifest.prevManifestSigHashHex).toBe("");
    expect(body.manifest.epoch).toBe(2);
    expect(body.manifest.chainHeadSeq).toBe(chain1.entries.length);
    expect(body.manifest.chainHeadHashHex).toBe(chain1.hashes[chain1.hashes.length - 1]);
    // The explicit warning that this is a migration (down to saying that after initialization, absence = refusal)
    const errors = env.errors.join("\n");
    expect(errors).toContain("no manifest yet");
    expect(errors).toContain("initializes manifestVersion 1");
  });

  it("in an environment where a manifest is distributed, --init-manifest relaxes nothing (a warned no-op)", async () => {
    // A server already initialized (distributing v1)
    const state = makeLegacyServer({});
    const env = await startEnv(state.handlers);
    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--init-manifest", "--reason", "initialization"],
        env.layer,
      ),
    ).toBe(0);

    // Second run: even with --init-manifest while v1 is distributed, it becomes
    // a normal issuance of the next version (v2, prev = hash of v1's signed bytes)
    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--init-manifest", "--reason", "re-rotation"],
        env.layer,
      ),
    ).toBe(0);
    expect(state.rotateBodies).toHaveLength(2);
    const second = state.rotateBodies[1];
    if (second === undefined) throw new Error("second rotate body missing");
    expect(second.manifest.manifestVersion).toBe(2);
    expect(second.manifest.prevManifestSigHashHex).toMatch(/^[0-9a-f]{64}$/);
    expect(second.manifest.epoch).toBe(3);
    expect(env.errors.join("\n")).toContain("The flag is not needed");
  });

  it("an absence in an environment whose floor holds a manifest record is refused as a swallow even with --init-manifest", async () => {
    // Phase 1: establish the floor (with the manifest record) via a manifest-bearing pull
    const env = await makeTestEnv();
    await startPhase(env, [
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [],
        deks: [wrap1],
        manifest: await manifestV1({ statements: [] }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);

    // Phase 2: rotate a server that no longer distributes a manifest, with
    // --init-manifest. An absence against an already-established manifest
    // floor is outside migration tolerance (an initialized manifest never
    // disappears — if it did, that is evidence of a swallow)
    const state = makeLegacyServer({});
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(
      await runCli(["env", "rotate", ENV_ID, "--init-manifest", "--reason", "swallow"], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("omission of the environment manifest");
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("--init-manifest does not take the 'just checking' early completion (no --reason is a usage error)", async () => {
    // Uninitialized environment + nothing pending + no --reason = conventionally
    // an up-to-date early return. Taking it on a run that needs initialization
    // looks like success while no v1 is issued. Collapse into the composite-submission path and require a reason
    const state = makeLegacyServer({});
    const env = await startEnv(state.handlers);
    expect(await runCli(["env", "rotate", ENV_ID, "--init-manifest"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify the rotation reason with --reason");
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("--init-manifest does not take interruption recovery (resume without a composite); it issues v1 via a new-epoch composite", async () => {
    // The shape where the epoch has advanced to 2 while a stale epoch-1 value
    // remains (the interruption-recovery entry). The conventional resume path
    // sends no composite, so no v1 is issued. A run that needs initialization
    // collapses into a new-epoch composite, same as --new-epoch
    const staleEntry = {
      variableId: "va",
      statement: alphaStatement,
      value: alphaValue1,
    };
    const state = makeLegacyServer({
      built: chain2,
      currentEpoch: 2,
      variables: [staleEntry],
      initialDeks: [wrap1, wrap2],
    });
    const env = await startEnv(state.handlers);
    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--init-manifest", "--reason", "migration"],
        env.layer,
      ),
    ).toBe(0);
    expect(state.rotateBodies).toHaveLength(1);
    const body = state.rotateBodies[0];
    if (body === undefined) throw new Error("rotate body missing");
    expect(body.entry.payload.newEpoch).toBe(3);
    expect(body.manifest.manifestVersion).toBe(1);
    expect(body.manifest.prevManifestSigHashHex).toBe("");
    expect(body.manifest.epoch).toBe(3);
    // The stale value is re-encrypted into the new epoch (the same all-at-once alignment as --new-epoch)
    expect(state.pushes).toEqual(["va"]);
  });

  it("verification of a distributed manifest is not relaxed even with --init-manifest", async () => {
    // A server distributing a malformed manifest (digest mismatch) is refused
    // even with --init-manifest (tolerating absence ≠ relaxing verification)
    const env = await startEnv([
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1({ statements: [] }),
      }),
    ]);
    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--init-manifest", "--reason", "tampering"],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=variables-digest-mismatch");
  });
});
