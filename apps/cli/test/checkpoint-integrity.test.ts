// Wiring tests for client rule 2 of checkpoint integrity (CRYPTO_SPEC §6.3 —
// value non-regression; session-27 §13-5's bundled snapshot verification).
//
// Pillars verified:
//  1. Accepting positive cases: matching enumeration, post-checkpoint
//     advanced versions (at or above the baseline epoch), disappearances
//     explained by tombstones, and post-checkpoint new creations (new epoch)
//  2. Every rejection path: missing enumeration (with a baseline), digest
//     mismatch, version regression, same-version hash mismatch, an advanced
//     version on an old epoch, disappearance without a tombstone, an old-epoch
//     creation of a variable outside the snapshot, and locator forgery
//  3. The two locator classes (ruling S): attested seq > own head = bounded
//     resync (pull) / on a lease it's an immediate self-contradiction
//  4. Cross-layer (ruling W): even a distribution that passes rule 2 is
//     dropped independently by floor rule (a) (the chain's coarse baseline
//     must not short-circuit the local finer one)
//  5. Lease path: reaches the same implementation + warns on a valued
//     distribution for a baseline-less environment (SHOULD)

import type { ChainOperation } from "@maruhi/crypto";
import { computeEnvValuesDigest, SUITE_ID } from "@maruhi/crypto";
import { Effect, Exit } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { checkCheckpointIntegrity } from "../src/checkpoint-integrity.ts";
import { runCli } from "../src/cli.ts";
import { verifyChainSnapshot } from "../src/sync.ts";
import { verifyLeaseDistribution } from "../src/values.ts";
import {
  buildChain,
  type BuiltChain,
  type ChainStep,
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
/** Position of the baseline checkpoint (baseSteps' 3 entries + checkpoint = seq 4). */
const CHECKPOINT_SEQ = 4;

let owner: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;
/** [genesis, create ENV (epoch 1), rotate (epoch 2)] (no checkpoint). */
let baseChain: BuiltChain;
/** baseChain + a checkpoint covering ENV appended (rule 2's baseline). */
let chain: BuiltChain;
let projectId: string;
let envStatement: WireDistributedEnvironmentStatement;
let stmtA: WireDistributedVariableStatement;
let stmtB: WireDistributedVariableStatement;
/** va v2 epoch 2 (latest as of the checkpoint). */
let valueA: WireDistributedValue;
/** vb v1 epoch 1 (the legitimate state after rotation, before re-encryption — §12-7). */
let valueB: WireDistributedValue;
/** The correct enumeration corresponding to the checkpoint on the chain (model of the server-stored rows). */
let snapshot: WireCheckpointSnapshot;
/** The mv1 manifest the checkpoint tuple binds ([A active, B active]). */
let manifestMain: WireDistributedManifest;
/** A checkpoint op covering ENV (the benign-race test reuses it as a second checkpoint). */
let checkpointOperation: ChainOperation;
let wraps: WireRecipientDek[];
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  const baseSteps: ChainStep[] = [
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ];
  // Two-pass construction: signing (Ed25519) and timestamps are
  // deterministic, so rebuilding the same steps yields the same entry list
  // (build base first to fix the distributed head / digest, then rebuild
  // with a checkpoint carrying those baked-in values appended)
  baseChain = await buildChain(baseSteps);
  projectId = baseChain.projectId;
  const genesisHead = { seq: 1, hashHex: projectId };
  envStatement = await environmentStatementFor({
    projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: genesisHead,
  });
  stmtA = await statementFor({
    projectId,
    environmentId: ENV_ID,
    variableId: "va",
    name: "ALPHA",
    author: owner,
    head: genesisHead,
  });
  stmtB = await statementFor({
    projectId,
    environmentId: ENV_ID,
    variableId: "vb",
    name: "BETA",
    author: owner,
    head: genesisHead,
  });
  const common = { projectId, environmentId: ENV_ID };
  valueA = await encryptValueFor({
    dek: dek2,
    ...common,
    epoch: 2,
    variableId: "va",
    version: 2,
    plaintext: "alpha-2",
    writer: owner,
    head: headOf(baseChain, 3),
  });
  valueB = await encryptValueFor({
    dek: dek1,
    ...common,
    epoch: 1,
    variableId: "vb",
    version: 1,
    plaintext: "beta-1",
    writer: owner,
    head: headOf(baseChain, 2),
  });
  manifestMain = await manifestFor({
    projectId,
    environmentId: ENV_ID,
    epoch: 2,
    issuer: owner,
    head: headOf(baseChain, 3),
    envStatement,
    statements: [stmtA, stmtB],
    manifestVersion: 1,
  });
  const snapshotValues = await checkpointSnapshotValuesOf([valueA, valueB]);
  const digest = await computeEnvValuesDigest(SUITE_ID, snapshotValues);
  if (!digest.ok) throw new Error("values digest failed");
  checkpointOperation = {
    op: "checkpoint",
    payload: {
      environments: [
        {
          environmentId: ENV_ID,
          epoch: 2,
          manifestVersion: 1,
          manifestSigHashHex: await manifestHashOf(projectId, manifestMain),
          valuesDigestHex: digest.value,
        },
      ],
      auditHeadHashHex: "",
    },
  };
  chain = await buildChain([...baseSteps, { actor: owner, operation: checkpointOperation }]);
  expect(chain.projectId).toBe(projectId);
  snapshot = {
    chainSeq: CHECKPOINT_SEQ,
    entryHashHex: chain.hashes[CHECKPOINT_SEQ - 1] ?? "",
    values: snapshotValues,
  };
  wraps = [
    await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
    await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
  ];
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

interface PullOverrides {
  readonly variables?: readonly {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  }[];
  readonly deletedVariables?: readonly WireDistributedVariableStatement[];
  readonly manifest?: WireDistributedManifest;
  /** null = distribute no enumeration (missing-enumeration negative). Omitted = the correct enumeration. */
  readonly checkpointSnapshot?: WireCheckpointSnapshot | null;
}

function pullHandler(overrides: PullOverrides = {}): MockHandler {
  const served =
    overrides.checkpointSnapshot === undefined ? snapshot : overrides.checkpointSnapshot;
  return onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull`, () => ({
    status: 200,
    json: {
      environmentId: ENV_ID,
      currentEpoch: 2,
      statement: envStatement,
      variables: overrides.variables ?? [
        { variableId: "va", statement: stmtA, value: valueA },
        { variableId: "vb", statement: stmtB, value: valueB },
      ],
      deletedVariables: overrides.deletedVariables ?? [],
      deks: wraps,
      manifest: overrides.manifest ?? manifestMain,
      ...(served === null ? {} : { checkpointSnapshot: served }),
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

/** Phase switch within the same TestEnv (= the same floor) — same idiom as floor-detection. */
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

/** The mv2 manifest (prev = mv1's real hash; for negatives/positives where the served set changes). */
async function manifestNext(
  statements: readonly WireDistributedVariableStatement[],
): Promise<WireDistributedManifest> {
  return manifestFor({
    projectId,
    environmentId: ENV_ID,
    epoch: 2,
    issuer: owner,
    head: headOf(baseChain, 3),
    envStatement,
    statements,
    manifestVersion: 2,
    prevManifestSigHashHex: await manifestHashOf(projectId, manifestMain),
  });
}

describe("accepting positive cases of rule 2 (§6.3 checkpoint integrity 2)", () => {
  it("accepts a distribution identical to checkpoint time plus a matching enumeration", async () => {
    const env = await startEnv([chainHandler(chain), pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
  });

  it("accepts a post-checkpoint advanced version (at or above the baseline epoch)", async () => {
    const advanced = await encryptValueFor({
      dek: dek2,
      projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "vb",
      version: 2,
      plaintext: "beta-2",
      writer: owner,
      head: headOf(baseChain, 3),
    });
    const env = await startEnv([
      chainHandler(chain),
      pullHandler({
        variables: [
          { variableId: "va", statement: stmtA, value: valueA },
          { variableId: "vb", statement: stmtB, value: advanced },
        ],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
  });

  it("accepts a snapshot variable's disappearance when a verified tombstone explains it", async () => {
    const tombstoneB = await statementFor({
      projectId,
      environmentId: ENV_ID,
      variableId: "vb",
      name: "BETA",
      author: owner,
      head: { seq: 1, hashHex: projectId },
      status: "deleted",
      metaVersion: 2,
    });
    const env = await startEnv([
      chainHandler(chain),
      pullHandler({
        variables: [{ variableId: "va", statement: stmtA, value: valueA }],
        deletedVariables: [tombstoneB],
        manifest: await manifestNext([stmtA, tombstoneB]),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
  });

  it("accepts a new variable absent from the snapshot as a post-checkpoint creation when its epoch is at or above baseline", async () => {
    const stmtC = await statementFor({
      projectId,
      environmentId: ENV_ID,
      variableId: "vc",
      name: "GAMMA",
      author: owner,
      head: { seq: 1, hashHex: projectId },
    });
    const valueC = await encryptValueFor({
      dek: dek2,
      projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "vc",
      version: 1,
      plaintext: "gamma-1",
      writer: owner,
      head: headOf(baseChain, 3),
    });
    const env = await startEnv([
      chainHandler(chain),
      pullHandler({
        variables: [
          { variableId: "va", statement: stmtA, value: valueA },
          { variableId: "vb", statement: stmtB, value: valueB },
          { variableId: "vc", statement: stmtC, value: valueC },
        ],
        manifest: await manifestNext([stmtA, stmtB, stmtC]),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
  });

  it("accepts a missing enumeration as-is for an environment with no baseline (no checkpoint on the chain)", async () => {
    const env = await startEnv([
      chainHandler(baseChain),
      pullHandler({ checkpointSnapshot: null, manifest: manifestMain }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
  });

  it("resolves an enumeration attested at a seq beyond the own head via bounded resync (same shape as §6.3-2b — ruling S)", async () => {
    // The first chain fetch = a view without the checkpoint; later fetches =
    // the extended whole. The pull response carries the new checkpoint's
    // enumeration (models a benign race where the checkpoint landed right
    // before the response was built)
    let chainCalls = 0;
    const staleChain: MockHandler = (request) => {
      if (request.method !== "GET" || request.path !== `/projects/${projectId}/chain`) {
        return null;
      }
      const built = chainCalls === 0 ? baseChain : chain;
      chainCalls += 1;
      return {
        status: 200,
        json: {
          projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
        },
      };
    };
    const env = await startEnv([staleChain, pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(chainCalls).toBeGreaterThan(1);
  });
});

describe("rule 2's rejection paths (session-27 §13-5 — every one a contradiction between verified data and the chain's notarization)", () => {
  async function expectRejected(
    overrides: PullOverrides,
    fragment: string,
    built: BuiltChain = chain,
  ): Promise<void> {
    const env = await startEnv([chainHandler(built), pullHandler(overrides)]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(fragment);
  }

  it("baseline present + no enumeration = reject (MUST — an omission must not degrade into skipping rule 2)", async () => {
    await expectRejected({ checkpointSnapshot: null }, "omitted the checkpoint value snapshot");
  });

  it("rejects when the enumeration's recomputed digest differs from the chain's values_digest", async () => {
    const first = snapshot.values[0];
    if (first === undefined) throw new Error("fixture snapshot is empty");
    await expectRejected(
      {
        checkpointSnapshot: {
          ...snapshot,
          values: [{ ...first, version: first.version + 1 }, ...snapshot.values.slice(1)],
        },
      },
      "does not match the values digest notarized by checkpoint",
    );
  });

  it("rejects a version regression below the snapshot", async () => {
    const rolledBack = await encryptValueFor({
      dek: dek2,
      projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "va",
      version: 1,
      plaintext: "alpha-old",
      writer: owner,
      head: headOf(baseChain, 3),
    });
    await expectRejected(
      {
        variables: [
          { variableId: "va", statement: stmtA, value: rolledBack },
          { variableId: "vb", statement: stmtB, value: valueB },
        ],
      },
      "a value rollback below the checkpointed state",
    );
  });

  it("rejects a distribution with different signed bytes at the same version (equivocation vs the checkpoint)", async () => {
    // A different ciphertext at the same coordinates (va, v2, epoch 2) — the
    // nonce differs so the signed bytes differ too
    const substituted = await encryptValueFor({
      dek: dek2,
      projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "va",
      version: 2,
      plaintext: "alpha-substituted",
      writer: owner,
      head: headOf(baseChain, 3),
    });
    await expectRejected(
      {
        variables: [
          { variableId: "va", statement: stmtA, value: substituted },
          { variableId: "vb", statement: stmtB, value: valueB },
        ],
      },
      "signed bytes differing from the checkpointed hash",
    );
  });

  it("rejects an advanced version on an old epoch (below baseline) — the checkpoint version of floor rule (c)", async () => {
    const injected = await encryptValueFor({
      dek: dek2,
      projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "va",
      version: 3,
      plaintext: "alpha-forged",
      writer: owner,
      // A declared head positioned where epoch 1 was current (still passes
      // signature verification)
      head: headOf(baseChain, 2),
    });
    await expectRejected(
      {
        variables: [
          { variableId: "va", statement: stmtA, value: injected },
          { variableId: "vb", statement: stmtB, value: valueB },
        ],
      },
      "evidence of forward injection with an old epoch key",
    );
  });

  it("rejects a disappearance with no tombstone (an unexplained omission of a checkpointed value)", async () => {
    await expectRejected(
      {
        variables: [{ variableId: "va", statement: stmtA, value: valueA }],
        manifest: await manifestNext([stmtA]),
      },
      "missing from the response without a verified deletion tombstone",
    );
  });

  it("rejects an old-epoch creation of a variable outside the snapshot (a backdated creation)", async () => {
    const stmtC = await statementFor({
      projectId,
      environmentId: ENV_ID,
      variableId: "vc",
      name: "GAMMA",
      author: owner,
      head: { seq: 1, hashHex: projectId },
    });
    const backdated = await encryptValueFor({
      dek: dek1,
      projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "vc",
      version: 1,
      plaintext: "gamma-forged",
      writer: owner,
      head: headOf(baseChain, 2),
    });
    await expectRejected(
      {
        variables: [
          { variableId: "va", statement: stmtA, value: valueA },
          { variableId: "vb", statement: stmtB, value: valueB },
          { variableId: "vc", statement: stmtC, value: backdated },
        ],
        manifest: await manifestNext([stmtA, stmtB, stmtC]),
      },
      "evidence of a backdated creation with an old epoch key",
    );
  });

  it("rejects a forged locator hash (seq ≤ own head, disagreeing with the chain)", async () => {
    await expectRejected(
      { checkpointSnapshot: { ...snapshot, entryHashHex: "ef".repeat(32) } },
      "does not match the verified chain",
    );
  });

  it("rejects an enumeration claiming a position other than the latest containing checkpoint", async () => {
    await expectRejected(
      {
        checkpointSnapshot: {
          ...snapshot,
          chainSeq: 2,
          entryHashHex: chain.hashes[1] ?? "",
        },
      },
      "the latest checkpoint covering environment",
    );
  });

  it("rejects a response that distributes an enumeration (seq ≤ own head) to a chain with no baseline", async () => {
    await expectRejected(
      {
        checkpointSnapshot: { ...snapshot, chainSeq: 2, entryHashHex: baseChain.hashes[1] ?? "" },
        manifest: manifestMain,
      },
      "derives no checkpoint covering this environment",
      baseChain,
    );
  });
});

describe("classifying a benign race (baseline advancing after the fetch view is not evidence)", () => {
  it("rejects an honest response where a second checkpoint landed inside the resync window as retriable, not evidence", async () => {
    // The view at fetch = baseChain (no checkpoint). The response carries
    // checkpoint (seq 4)'s enumeration, but the post-resync chain includes a
    // second checkpoint (seq 5) — the response's locator (4) disagrees with
    // the latest baseline (5), yet the baseline advanced after the fetch view
    // (head 3), which an honest response can produce. Don't escalate to
    // evidence (which a re-run cannot clear); reject with re-pull guidance
    const doubleChain = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
      { actor: owner, operation: checkpointOperation },
      { actor: owner, operation: checkpointOperation },
    ]);
    expect(doubleChain.projectId).toBe(projectId);
    let chainCalls = 0;
    const racingChain: MockHandler = (request) => {
      if (request.method !== "GET" || request.path !== `/projects/${projectId}/chain`) {
        return null;
      }
      const built = chainCalls === 0 ? baseChain : doubleChain;
      chainCalls += 1;
      return {
        status: 200,
        json: {
          projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
        },
      };
    };
    const env = await startEnv([racingChain, pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("retry the pull");
    expect(errors).not.toContain("stale or fabricated");
  });

  it("the baseline-advance classification is keyed on the fetch view (fetchedAtHeadSeq) (unit)", async () => {
    const verified = await Effect.runPromise(
      verifyChainSnapshot({
        projectId: projectId as never,
        entries: chain.entries,
        claimedHeadSeq: chain.entries.length,
        claimedHeadHashHex: chain.hashes[chain.hashes.length - 1] ?? "",
      }),
    );
    // No enumeration + baseline landed after the fetch view (head 3) →
    // retriable
    const missingAfterFetch = await checkCheckpointIntegrity({
      history: verified.history,
      environmentId: ENV_ID,
      snapshot: undefined,
      variables: [],
      tombstoneIds: new Set(),
      fetchedAtHeadSeq: 3,
    });
    expect(missingAfterFetch).toMatchObject({ kind: "rejected", evidence: false });
    // No enumeration + baseline already stored at the fetch view → MUST
    // evidence rejection
    const missingStored = await checkCheckpointIntegrity({
      history: verified.history,
      environmentId: ENV_ID,
      snapshot: undefined,
      variables: [],
      tombstoneIds: new Set(),
      fetchedAtHeadSeq: CHECKPOINT_SEQ,
    });
    expect(missingStored).toMatchObject({ kind: "rejected", evidence: true });
    // An enumeration at the old position + baseline already stored at the
    // fetch view → stale-distribution evidence rejection
    const staleStored = await checkCheckpointIntegrity({
      history: verified.history,
      environmentId: ENV_ID,
      snapshot: { chainSeq: 2, entryHashHex: chain.hashes[1] ?? "", values: [] },
      variables: [],
      tombstoneIds: new Set(),
      fetchedAtHeadSeq: CHECKPOINT_SEQ,
    });
    expect(staleStored).toMatchObject({ kind: "rejected", evidence: true });
  });
});

describe("cross-layer: rule 2 does not substitute for floor rule (a) (ruling W)", () => {
  it("the floor rejects a value distribution at/above the checkpoint baseline but below the floor", async () => {
    // Phase 1: establish the floor with va v3 (advanced past baseline v2,
    // epoch 2)
    const v3 = await encryptValueFor({
      dek: dek2,
      projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "va",
      version: 3,
      plaintext: "alpha-3",
      writer: owner,
      head: headOf(baseChain, 3),
    });
    const env = await makeTestEnv();
    await startPhase(env, [
      chainHandler(chain),
      pullHandler({
        variables: [
          { variableId: "va", statement: stmtA, value: v3 },
          { variableId: "vb", statement: stmtB, value: valueB },
        ],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);

    // Phase 2: roll back to checkpoint-time va v2. Rule 2 passes (v2 = same
    // version and hash as the snapshot), but floor rule (a) drops it (below
    // v3)
    await startPhase(env, [chainHandler(chain), pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("value-version rollback");
  });
});

describe("the lease path (§14-2 — reaching the same implementation and the baseline-less warning)", () => {
  async function verifiedOf(built: BuiltChain) {
    return Effect.runPromise(
      verifyChainSnapshot({
        projectId: projectId as never,
        entries: built.entries,
        claimedHeadSeq: built.entries.length,
        claimedHeadHashHex: built.hashes[built.hashes.length - 1] ?? "",
      }),
    );
  }

  type LeaseWire = Parameters<typeof verifyLeaseDistribution>[0]["wire"];

  function leaseWire(overrides: PullOverrides = {}): LeaseWire {
    const served =
      overrides.checkpointSnapshot === undefined ? snapshot : overrides.checkpointSnapshot;
    // The test's Wire* structural types match the api-schema distribution
    // types structurally (support/crypto.ts)
    return {
      statement: envStatement,
      variables: overrides.variables ?? [
        { variableId: "va", statement: stmtA, value: valueA },
        { variableId: "vb", statement: stmtB, value: valueB },
      ],
      deletedVariables: overrides.deletedVariables ?? [],
      manifest: overrides.manifest ?? manifestMain,
      ...(served === null ? {} : { checkpointSnapshot: served }),
    } as LeaseWire;
  }

  async function expectLeaseRejected(
    built: BuiltChain,
    overrides: PullOverrides,
    fragment: string,
  ): Promise<void> {
    const verified = await verifiedOf(built);
    const exit = await Effect.runPromiseExit(
      verifyLeaseDistribution({
        verified,
        environmentId: ENV_ID as never,
        wire: leaseWire(overrides),
      }),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain(fragment);
  }

  it("rejects a lease response with a baseline and no enumeration (same rule as pull)", async () => {
    await expectLeaseRejected(
      chain,
      { checkpointSnapshot: null },
      "omitted the checkpoint value snapshot",
    );
  });

  it("immediately rejects as self-contradictory an enumeration claiming a checkpoint beyond the bundled chain (no resync)", async () => {
    await expectLeaseRejected(
      baseChain,
      { manifest: manifestMain },
      "the response contradicts itself",
    );
  });

  it("accepts but warns on a valued lease response for a baseline-less environment (§6.3 SHOULD)", async () => {
    const verified = await verifiedOf(baseChain);
    const result = await Effect.runPromise(
      verifyLeaseDistribution({
        verified,
        environmentId: ENV_ID as never,
        wire: leaseWire({ checkpointSnapshot: null }),
      }),
    );
    expect(result.variables).toHaveLength(2);
    expect(result.warnings.join("\n")).toContain("No checkpoint on the verified chain covers");
  });

  it("accepts a lease response with a baseline and matching enumeration without warning", async () => {
    const verified = await verifiedOf(chain);
    const result = await Effect.runPromise(
      verifyLeaseDistribution({
        verified,
        environmentId: ENV_ID as never,
        wire: leaseWire(),
      }),
    );
    expect(result.variables).toHaveLength(2);
    expect(result.warnings.join("\n")).not.toContain("No checkpoint on the verified chain covers");
  });
});
