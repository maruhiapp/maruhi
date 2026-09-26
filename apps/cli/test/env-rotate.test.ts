// Tests for epoch rotation (`maruhi env rotate`).
//
// Pillars verified:
//  1. The composite request (§12-4): a rotate_epoch entry (new_epoch = current
//     + 1 · reason · the new epoch's commitment — §5.2 / §6.2) + a complete
//     wrap set matching the current member set exactly. Each wrap carries a
//     §5.1 signature, and the DEK the recipient opens matches the entry's commitment
//  2. Re-encryption of current values (§7 / §4.1): the latest value of every
//     active variable is re-encrypted under the new DEK and sent via a normal
//     push signed by the runner as writer
//  3. **Interruption recovery**: a state interrupted after the composite was
//     accepted but before re-encryption finished (= the epoch advanced yet a
//     latest value's epoch is below the current epoch) is detected on re-run,
//     and the remainder alone is re-encrypted without advancing the epoch (idempotent resume)
//  4. The branches: CAS conflict · concurrent rotation · partial completion · authorization
//
// The mock server mimics the real server's state transitions (appends accepted
// entries to the chain, puts the composite's wraps into the distribution set,
// and reflects pushes into latest values) — so "crash on run 1 → resume on
// run 2" can be exercised end-to-end on a single fixture.

import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { WrappedDek } from "@maruhi/api-schema";
import type { ChainEntry } from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeEnvValuesDigest,
  decryptVariable,
  signChainEntry,
  SUITE_ID,
  importEncryptionKeyPair,
  importSigningPublicKey,
  unwrapDek,
  verifyDekCommitment,
  verifyDekWrapSignature,
} from "@maruhi/crypto";
import { Effect } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { makeFileFloorStore } from "../src/floor-log.ts";
import type { ProjectFloor } from "../src/floor.ts";
import { receiptVariableName } from "../src/sync-receipt.ts";
import {
  addMemberOp,
  addScopedMemberOp,
  removeMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  grantServerOp,
  headOf,
  hexBytes,
  makeTestUser,
  manifestFor,
  manifestHashOf,
  rotateEpochOp,
  checkpointSnapshotValuesOf,
  statementFor,
  type TestUser,
  valueHashOf,
  variablesDigestOf,
  type WireCheckpointSnapshot,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockResponse, MockServer, onRequest } from "./support/server.ts";
import {
  makeValueEnvironmentServer,
  type StoredVariable,
  type ValueEnvironmentState,
} from "./support/value-env.ts";

const ENV_ID = "dev";

/** The body of the rotate composite request (api-schema's environments.rotate payload). */
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
  readonly deks: readonly WrappedDek[];
  /** The bundled manifest (§12-4 — issuance form. issuer is what the caller contracts). */
  readonly manifest: Omit<WireDistributedManifest, "issuerUserId" | "issuerKeyFingerprintHex">;
  /** The boundary checkpoint (H+2 — §12-4's mandatory bundle). */
  readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
}

/** One variable of a pull response (verified statement + distribution-form value). */
interface PulledVariable {
  readonly variableId: string;
  readonly statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
}

let owner: TestUser;
let reader: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;
let dek3: Uint8Array;
/** genesis + create_environment(epoch 1)。 */
let chainBase: BuiltChain;
/** The shape with rotate_epoch (epoch 2, DEK = dek2) stacked onto the same genesis. */
let chainRotated: BuiltChain;
/** The shape with a further rotate_epoch (epoch 3, DEK = dek3) stacked on top. */
let chainRotatedTwice: BuiltChain;
let envStatement: WireDistributedEnvironmentStatement;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  reader = await makeTestUser("user-reader-2222");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  dek3 = crypto.getRandomValues(new Uint8Array(32));
  chainBase = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
  ]);
  chainRotated = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
  chainRotatedTwice = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 3, dek3) },
  ]);
  envStatement = await environmentStatementFor({
    projectId: chainBase.projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: headOf(chainBase, 1),
  });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

/** A pull response for one variable (the value signature's declared head is where that epoch was the current epoch). */
async function variableAt(input: {
  readonly built: BuiltChain;
  readonly variableId: string;
  readonly name: string;
  readonly dek: Uint8Array;
  readonly epoch: number;
  readonly version: number;
  readonly plaintext: string;
  readonly headSeq: number;
  /** The prev of a version > 1 (default is the fixture's dummy — for the negative of the chain check). */
  readonly prevValueSigHashHex?: string;
}): Promise<PulledVariable> {
  return {
    variableId: input.variableId,
    statement: await statementFor({
      projectId: chainBase.projectId,
      environmentId: ENV_ID,
      variableId: input.variableId,
      name: input.name,
      author: owner,
      head: headOf(input.built, 1),
    }),
    value: await encryptValueFor({
      dek: input.dek,
      projectId: chainBase.projectId,
      environmentId: ENV_ID,
      epoch: input.epoch,
      variableId: input.variableId,
      version: input.version,
      plaintext: input.plaintext,
      writer: owner,
      head: headOf(input.built, input.headSeq),
      ...(input.prevValueSigHashHex === undefined
        ? {}
        : { prevValueSigHashHex: input.prevValueSigHashHex }),
    }),
  };
}

interface ServerOptions {
  readonly built: BuiltChain;
  readonly variables: PulledVariable[];
  /** A deleted variable's tombstone (§12-5 — kept stored and distributed). */
  readonly deletedVariables?: WireDistributedVariableStatement[];
  readonly deks: WireRecipientDek[];
  readonly currentEpoch: number;
  /** A per-rotate-call injected response (undefined = normal acceptance). */
  readonly onRotate?: (call: number) => MockResponse | undefined;
  /**
   * A hook called **right after accepting** the rotate composite (models an
   * attack / concurrent operation where the server swaps the distribution
   * state post-acceptance). The argument is the chain's current form post-acceptance.
   */
  readonly onRotateAccepted?: (chain: {
    readonly entries: readonly ChainEntry[];
    readonly hashes: readonly string[];
  }) => Promise<void> | void;
  /**
   * A response injected **after acceptance** (models a lost response / 502).
   * The chain append and the wrap distribution do happen, but the client only sees the error.
   */
  readonly onRotateAfterAccept?: (call: number) => MockResponse | undefined;
  /** A per-push-call injected response (undefined = normal acceptance). */
  readonly onPush?: (call: number, variableId: string) => MockResponse | undefined;
  /** A per-pull-call injected response (undefined = normal response). Used to break the pass-end rescan. */
  readonly onPull?: (call: number) => MockResponse | undefined;
  /** A per-chain-fetch injected response (undefined = normal response). Used to break the acceptance check. */
  readonly onChain?: (call: number) => MockResponse | undefined;
  /**
   * The chain to serve **after** a rotate is attempted (models another
   * member's concurrent rotation). Timestamps are deterministic, so it
   * verifies as an extension of the original chain.
   */
  readonly chainAfterRotateAttempt?: BuiltChain | undefined;
  /**
   * After accepting, additionally append one more member's rotation (models
   * the shape where the current epoch overtakes the target epoch).
   */
  readonly appendRotateAfterAccept?: { readonly epoch: number; readonly dek: Uint8Array };
  /**
   * Never append the accepted boundary checkpoint to the distribution chain
   * (models a "checkpoint-hiding" server that distributes only the rotate
   * entry — PR-F4 cross-layer. Checkpoints are optional under the chain's
   * consensus rule, so the chain itself stays valid while only the §4.3 (2) bound tuple disappears).
   */
  readonly dropCheckpointFromChain?: boolean;
  /**
   * Enable acceptance of a standalone checkpoint (generic append) + /auth/me
   * + /audit-head (models trigger (i) — the periodic checkpoint issued after
   * rotate + re-encryption complete — PR-M2). When omitted, stays unimplemented
   * as before (issuance fails and becomes a warning — never changes existing tests' premise).
   */
  readonly standaloneCheckpoint?: { readonly auditHeadHashHex: string };
}

interface ServerState {
  readonly handlers: readonly MockHandler[];
  readonly rotateBodies: RotateBody[];
  readonly pushes: {
    readonly variableId: string;
    readonly value: WireDistributedValue;
    /** The request's re-encryption marker (AUTH_SPEC §12-5 — omitted is recorded as false). */
    readonly reencryption: boolean;
  }[];
  /** The distribution chain's current form (for checking the standalone-checkpoint append). */
  readonly chainEntries: readonly ChainEntry[];
}

/**
 * Handlers mimicking the real server's state transitions: append the accepted
 * rotate_epoch entry to the chain, put the composite's bundled wraps into the
 * distribution set, and reflect an accepted push into the latest value. This
 * lets "crash → re-run" run on the same state.
 */
function makeServer(options: ServerOptions): ServerState {
  const projectId = chainBase.projectId;
  const entries: ChainEntry[] = [...options.built.entries];
  const hashes: string[] = [...options.built.hashes];
  const variables = options.variables;
  const deletedVariables = options.deletedVariables ?? [];
  const deks = options.deks;
  const rotateBodies: RotateBody[] = [];
  const pushes: { variableId: string; value: WireDistributedValue; reencryption: boolean }[] = [];
  let currentEpoch = options.currentEpoch;
  let rotateCalls = 0;
  let pushCalls = 0;
  let pullCalls = 0;
  let chainCalls = 0;
  // The stored latest manifest (§12-5 — only one is kept). Re-issued at the
  // next manifestVersion whenever the distribution state (epoch · meta set)
  // changes (the test swapping the variable set = models another member's
  // meta operation). An accepted rotate's bundled manifest replaces it as the latest
  let manifestState: {
    key: string;
    manifest: WireDistributedManifest;
    version: number;
  } | null = null;
  // The stored checkpoint snapshot (§16-2 — the enumeration of the
  // distribution set at checkpoint-acceptance time + the corresponding
  // checkpoint position). Bundled into later value-carrying pulls (§12-7)
  let checkpointSnapshot: WireCheckpointSnapshot | null = null;
  /** Upsert only when a checkpoint entry is accepted (§16-2 — other ops pass through). */
  const storeCheckpointSnapshot = async (entry: ChainEntry): Promise<void> => {
    if (entry.op !== "checkpoint") {
      return;
    }
    checkpointSnapshot = {
      chainSeq: entries.length,
      entryHashHex: hashes[hashes.length - 1] ?? "",
      values: await checkpointSnapshotValuesOf(variables.map((variable) => variable.value)),
    };
  };
  const manifestKey = (): string =>
    JSON.stringify([
      currentEpoch,
      entries.length,
      variables.map((entry) => [entry.variableId, entry.statement.signatureHex]),
      deletedVariables.map((tombstone) => [tombstone.variableId, tombstone.signatureHex]),
    ]);
  const serveManifest = async (): Promise<WireDistributedManifest> => {
    const key = manifestKey();
    if (manifestState !== null && manifestState.key === key) {
      return manifestState.manifest;
    }
    const version = (manifestState?.version ?? 0) + 1;
    // Re-issuance chains prev into the previous manifest (models an honest
    // meta operation satisfying the adjacent-version prev check — M1-A1. Same
    // as the real server's §12-5 (5))
    const previous = manifestState?.manifest;
    const manifest = await manifestFor({
      projectId,
      environmentId: ENV_ID,
      epoch: currentEpoch,
      issuer: owner,
      head: { seq: entries.length, hashHex: hashes[hashes.length - 1] ?? "" },
      envStatement,
      statements: [...variables.map((variable) => variable.statement), ...deletedVariables],
      manifestVersion: version,
      ...(previous === undefined
        ? {}
        : { prevManifestSigHashHex: await manifestHashOf(projectId, previous) }),
    });
    manifestState = { key, manifest, version };
    return manifest;
  };

  /** Acceptance: append the 2 entries — rotate + boundary checkpoint — and put the bundled wraps into the distribution set (§12-4). */
  const acceptRotate = async (body: RotateBody): Promise<void> => {
    if (options.dropCheckpointFromChain === true) {
      // A checkpoint-hiding server stores no snapshot either (models
      // consistent hiding — distributing an enumeration with no checkpoint on
      // the chain would fail rule 2 right there)
      entries.push(body.entry);
      hashes.push(await computeChainEntryHash(body.entry));
    } else {
      entries.push(body.entry, body.checkpoint);
      hashes.push(
        await computeChainEntryHash(body.entry),
        await computeChainEntryHash(body.checkpoint),
      );
      // Store the snapshot in the same transaction as the boundary
      // checkpoint's acceptance (§16-2 — acceptance time = the pre-re-encryption distribution set)
      await storeCheckpointSnapshot(body.checkpoint);
    }
    currentEpoch = body.entry.payload.newEpoch;
    // Distribution form = the accepted issuance form + the caller's issuer
    // info (§12-2). Only when the bundled digest covers the current set is it
    // pinned as "latest" — if the test swapped the variable set before
    // acceptance (= another member's meta operation), the key is left empty
    // and the next pull re-issues the next version
    const digestNow = await variablesDigestOf(projectId, [
      ...variables.map((variable) => variable.statement),
      ...deletedVariables,
    ]);
    manifestState = {
      key: digestNow === body.manifest.variablesDigestHex ? manifestKey() : "",
      manifest: {
        ...body.manifest,
        issuerUserId: owner.userId,
        issuerKeyFingerprintHex: owner.fingerprintHex,
      },
      version: body.manifest.manifestVersion,
    };
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
    await options.onRotateAccepted?.({ entries, hashes });
  };

  /** Appends one rotation by another member to the current chain's tail. */
  const appendOtherRotate = async (target: {
    readonly epoch: number;
    readonly dek: Uint8Array;
  }): Promise<void> => {
    const operation = rotateEpochOp(ENV_ID, target.epoch, target.dek);
    const resolved = typeof operation === "function" ? await operation(projectId) : operation;
    const signed = await signChainEntry({
      entry: {
        ...resolved,
        suite: SUITE_ID,
        seq: entries.length + 1,
        prevHashHex: hashes[hashes.length - 1] ?? "",
        actor: { userId: owner.userId, keyFingerprintHex: owner.fingerprintHex },
        timestampMs: Date.now(),
      },
      signingKey: owner.sigKeyPair.privateKey,
    });
    if (!signed.ok) {
      throw new Error("failed to sign the concurrent rotate entry");
    }
    entries.push(signed.value);
    hashes.push(await computeChainEntryHash(signed.value));
    currentEpoch = target.epoch;
  };

  // Extra endpoints for the trigger (i) periodic checkpoint issuance (PR-M2) (optional)
  const standaloneHandlers: MockHandler[] =
    options.standaloneCheckpoint === undefined
      ? []
      : [
          onRequest("GET", "/auth/me", () => ({
            status: 200,
            json: {
              userId: owner.userId,
              orgs: [],
              tokenScopes: [{ project: projectId, permission: "admin" }],
            },
          })),
          onRequest("GET", `/projects/${projectId}/audit-head`, () => ({
            status: 200,
            json: { auditHeadHashHex: options.standaloneCheckpoint?.auditHeadHashHex ?? "" },
          })),
          async (request) => {
            if (
              request.method !== "POST" ||
              request.path !== `/projects/${projectId}/chain/entries`
            ) {
              return null;
            }
            const body = request.body as { readonly entry: ChainEntry };
            entries.push(body.entry);
            hashes.push(await computeChainEntryHash(body.entry));
            // Accepting a standalone checkpoint also upserts the snapshot
            // (§16-2 — the storage discipline is the same regardless of path)
            await storeCheckpointSnapshot(body.entry);
            return {
              status: 200,
              json: {
                projectId,
                headSeq: entries.length,
                headHashHex: hashes[hashes.length - 1],
              },
            };
          },
        ];
  const handlers: MockHandler[] = [
    ...standaloneHandlers,
    onRequest("GET", `/projects/${projectId}/chain`, () => {
      const injected = options.onChain?.(chainCalls);
      chainCalls += 1;
      return (
        injected ?? {
          status: 200,
          json: {
            projectId,
            entries,
            headSeq: entries.length,
            headHashHex: hashes[hashes.length - 1],
          },
        }
      );
    }),
    onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull`, async () => {
      const injected = options.onPull?.(pullCalls);
      pullCalls += 1;
      return (
        injected ?? {
          status: 200,
          json: {
            environmentId: ENV_ID,
            currentEpoch,
            statement: envStatement,
            variables,
            deletedVariables,
            deks,
            manifest: await serveManifest(),
            // Whenever a stored row for the base checkpoint exists, it is always bundled (§12-7 — the material of rule 2)
            ...(checkpointSnapshot === null ? {} : { checkpointSnapshot }),
          },
        }
      );
    }),
    async (request) => {
      if (
        request.method !== "POST" ||
        request.path !== `/projects/${projectId}/environments/${ENV_ID}/rotate`
      ) {
        return null;
      }
      const body = request.body as RotateBody;
      rotateBodies.push(body);
      if (options.chainAfterRotateAttempt !== undefined) {
        // Swap to the shape where another member appended first (or concurrently)
        entries.splice(0, entries.length, ...options.chainAfterRotateAttempt.entries);
        hashes.splice(0, hashes.length, ...options.chainAfterRotateAttempt.hashes);
      }
      const injected = options.onRotate?.(rotateCalls);
      const injectedAfterAccept = options.onRotateAfterAccept?.(rotateCalls);
      rotateCalls += 1;
      if (injected !== undefined) {
        return injected;
      }
      await acceptRotate(body);
      if (options.appendRotateAfterAccept !== undefined) {
        await appendOtherRotate(options.appendRotateAfterAccept);
      }
      return (
        injectedAfterAccept ?? {
          status: 200,
          json: {
            environmentId: ENV_ID,
            currentEpoch,
            headSeq: entries.length,
            headHashHex: hashes[hashes.length - 1],
          },
        }
      );
    },
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
      const body = request.body as {
        readonly value: WireDistributedValue;
        readonly reencryption?: boolean;
      };
      const injected = options.onPush?.(pushCalls, variableId);
      pushCalls += 1;
      if (injected !== undefined) {
        return injected;
      }
      // The distribution form is "the accepted payload + the caller's writer info" (§12-2)
      const stored: WireDistributedValue = {
        ...body.value,
        writerUserId: owner.userId,
        writerKeyFingerprintHex: owner.fingerprintHex,
      };
      pushes.push({ variableId, value: stored, reencryption: body.reencryption === true });
      const index = variables.findIndex((variable) => variable.variableId === variableId);
      const target = variables[index];
      if (target !== undefined) {
        target.value = stored;
      }
      return {
        status: 200,
        json: {
          variableId,
          version: body.value.aad.version,
          epoch: body.value.aad.epoch,
        },
      };
    },
  ];
  return { handlers, rotateBodies, pushes, chainEntries: entries };
}

/** Reads the floor (the fold of the observation log) — for pinning M1-A4's floor advance / non-advance. */
async function loadFloor(env: TestEnv): Promise<ProjectFloor | null> {
  const loaded = await Effect.runPromise(
    makeFileFloorStore(env.floorDir).load(chainBase.projectId),
  );
  return loaded.floor;
}

async function startEnv(handlers: readonly MockHandler[], user: TestUser): Promise<TestEnv> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, user);
  await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });
  return env;
}

/** §5.1 signature verification of one wrap + the recipient's opening (same shape as env-create.test.ts). */
async function verifyAndUnwrap(input: {
  readonly wrap: WrappedDek;
  readonly recipient: TestUser;
  readonly signer: TestUser;
}): Promise<Uint8Array> {
  const { wrap, recipient, signer } = input;
  const signerKey = await importSigningPublicKey(hexBytes(signer.sigPubHex));
  if (!signerKey.ok) {
    throw new Error("sig key import failed");
  }
  const verified = await verifyDekWrapSignature({
    context: {
      suite: wrap.suite,
      projectId: chainBase.projectId,
      environmentId: ENV_ID,
      epoch: wrap.epoch,
      recipientUserId: wrap.recipientUserId,
      recipientEncPubHex: wrap.recipientEncPubHex,
      encHex: wrap.encHex,
      ciphertextHex: wrap.ciphertextHex,
      signerUserId: signer.userId,
    },
    signatureHex: wrap.signatureHex,
    signerPublicKey: signerKey.value,
  });
  expect(verified.ok).toBe(true);
  const pair = await importEncryptionKeyPair({
    publicKey: hexBytes(recipient.encPubHex),
    privateKey: hexBytes(recipient.encSkHex),
  });
  if (!pair.ok) {
    throw new Error("enc key import failed");
  }
  const dek = await unwrapDek({
    recipientKeyPair: pair.value,
    wrapped: { enc: hexBytes(wrap.encHex), ciphertext: hexBytes(wrap.ciphertextHex) },
    context: {
      projectId: chainBase.projectId,
      environmentId: ENV_ID,
      epoch: wrap.epoch,
      recipientUserId: wrap.recipientUserId,
    },
  });
  if (!dek.ok) {
    throw new Error("unwrap failed");
  }
  return dek.value;
}

async function decryptWire(dek: Uint8Array, value: WireDistributedValue): Promise<string> {
  const result = await decryptVariable({
    dek,
    context: value.aad,
    nonce: hexBytes(value.nonceHex),
    ciphertext: hexBytes(value.ciphertextHex),
  });
  if (!result.ok) {
    throw new Error("decrypt failed in test");
  }
  return new TextDecoder().decode(result.value);
}

/** Extracts the new-epoch DEK the runner generated, from the composite's bundled wraps. */
async function newEpochDekOf(body: RotateBody): Promise<Uint8Array> {
  const wrap = body.deks.find((candidate) => candidate.recipientUserId === owner.userId);
  if (wrap === undefined) {
    throw new Error("owner wrap missing");
  }
  return verifyAndUnwrap({ wrap, recipient: owner, signer: owner });
}

describe("maruhi env rotate", () => {
  it("composite request: sends a rotate_epoch entry (with commitment) + the complete wrap set, and re-encrypts current values under the new DEK", async () => {
    const member = await makeTestUser("user-member-3333");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "member") },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const head = built.hashes[built.hashes.length - 1] ?? "";
    const variables = [
      await variableAt({
        built,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 3,
      }),
      await variableAt({
        built,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 2,
        plaintext: "key-abc",
        headSeq: 3,
      }),
    ];
    const state = makeServer({
      built,
      variables,
      deks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--reason", "preventive rotation upon member removal"],
        env.layer,
      ),
    ).toBe(0);

    expect(state.rotateBodies).toHaveLength(1);
    const body = state.rotateBodies[0];
    if (body === undefined) throw new Error("rotate was not called");
    // Parent-head CAS + the entry sits right after the current head (seq = head + 1), actor = the caller
    expect(body.parentHeadHashHex).toBe(head);
    expect(body.entry.op).toBe("rotate_epoch");
    expect(body.entry.seq).toBe(built.entries.length + 1);
    expect(body.entry.prevHashHex).toBe(head);
    expect(body.entry.actor.userId).toBe(owner.userId);
    // new_epoch = current epoch + 1; reason lands on the chain (§6.2)
    expect(body.entry.payload.environmentId).toBe(ENV_ID);
    expect(body.entry.payload.newEpoch).toBe(2);
    expect(body.entry.payload.reason).toBe("preventive rotation upon member removal");
    // Wrap targets = exactly the verified current member set (§6.3)
    expect(body.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, member.userId].toSorted(),
    );
    expect(body.deks.every((wrap) => wrap.epoch === 2)).toBe(true);
    // Every recipient gets the same new DEK, matching the entry's commitment (§5.2)
    const deks: string[] = [];
    for (const wrap of body.deks) {
      const unwrapped = await verifyAndUnwrap({
        wrap,
        recipient: wrap.recipientUserId === owner.userId ? owner : member,
        signer: owner,
      });
      deks.push(Buffer.from(unwrapped).toString("hex"));
    }
    expect(new Set(deks).size).toBe(1);
    const newDek = await newEpochDekOf(body);
    const matched = await verifyDekCommitment({
      context: { suite: "maruhi/v1", projectId: built.projectId, environmentId: ENV_ID, epoch: 2 },
      dek: newDek,
      expectedCommitmentHex: body.entry.payload.dekCommitmentHex,
    });
    expect(matched.ok).toBe(true);
    // Re-encryption: every active variable is pushed at the new epoch, next version
    expect(state.pushes.map((push) => push.variableId).toSorted()).toEqual(["vaa", "vbb"]);
    const pushedA = state.pushes.find((push) => push.variableId === "vaa");
    const pushedB = state.pushes.find((push) => push.variableId === "vbb");
    if (pushedA === undefined || pushedB === undefined) throw new Error("missing pushes");
    expect(pushedA.value.aad).toMatchObject({ epoch: 2, version: 2, variableId: "vaa" });
    expect(pushedB.value.aad).toMatchObject({ epoch: 2, version: 3, variableId: "vbb" });
    // Plaintext is preserved (decryptable under the new DEK)
    expect(await decryptWire(newDek, pushedA.value)).toBe("postgres://example");
    expect(await decryptWire(newDek, pushedB.value)).toBe("key-abc");
    // prev is the signed-bytes hash of the verified immediately-prior version (the §4.1 chain)
    expect(pushedA.value.prevValueSigHashHex).toMatch(/^[0-9a-f]{64}$/);
    expect(env.logs.join("\n")).toContain("epoch 1 → 2");
    expect(env.logs.join("\n")).toContain("re-encrypted 2 variables");
  });

  it("the complete wrap set = R(E): a current member whose scope excludes the environment gets no new-DEK wrap (ES K4 — CRYPTO_SPEC §6.2 / §6.3)", async () => {
    const insider = await makeTestUser("user-insider-7777");
    const outsider = await makeTestUser("user-outsider-8888");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: createEnvironmentOp("env-other", dek1) },
      { actor: owner, operation: addScopedMemberOp(insider, "reader", [ENV_ID]) },
      { actor: owner, operation: addScopedMemberOp(outsider, "member", ["env-other"]) },
    ]);
    const state = makeServer({
      built,
      variables: [],
      deks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
    });
    const env = await startEnv(state.handlers, owner);
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "scope test"], env.layer)).toBe(0);
    const body = state.rotateBodies[0];
    if (body === undefined) throw new Error("rotate was not called");
    expect(body.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, insider.userId].toSorted(),
    );

    // An out-of-scope environment is refused before communication (before a value-carrying pull = a var.read record — §6.3)
    const outsiderEnv = await startEnv(state.handlers, outsider);
    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "scope test"], outsiderEnv.layer),
    ).toBe(1);
    expect(outsiderEnv.errors.join("\n")).toContain("outside your environment scope");
    expect(state.rotateBodies).toHaveLength(1);
  });

  it("trigger (i): issues a periodic checkpoint for the environment after rotate + re-encryption complete (CRYPTO_SPEC §6.3 — PR-M2)", async () => {
    const auditHead = "ab".repeat(32);
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      standaloneCheckpoint: { auditHeadHashHex: auditHead },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "periodic"], env.layer)).toBe(0);
    // The tail = the periodic checkpoint after re-encryption completes (standalone, after the boundary's H+2)
    const tail = state.chainEntries[state.chainEntries.length - 1];
    if (tail === undefined || tail.op !== "checkpoint") {
      throw new Error("the post-rotation periodic checkpoint was not appended");
    }
    expect(tail.payload.environments).toHaveLength(1);
    const tuple = tail.payload.environments[0];
    if (tuple === undefined) throw new Error("missing tuple");
    expect(tuple.environmentId).toBe(ENV_ID);
    // The notarized subject = the data state **after** re-encryption completed (new-epoch values)
    expect(tuple.epoch).toBe(2);
    const reencrypted = state.pushes.find((push) => push.variableId === "vaa");
    if (reencrypted === undefined) throw new Error("missing re-encrypted push");
    const digest = await computeEnvValuesDigest(SUITE_ID, [
      {
        variableId: "vaa",
        version: reencrypted.value.aad.version,
        valueSigHashHex: await valueHashOf(reencrypted.value, owner.userId),
      },
    ]);
    if (!digest.ok) throw new Error("digest failed");
    expect(tuple.valuesDigestHex).toBe(digest.value);
    // Effective permission admin (the mock's /auth/me = admin scope), so it notarizes the audit head
    expect(tail.payload.auditHeadHashHex).toBe(auditHead);
    expect(env.logs.join("\n")).toContain("post-rotation periodic checkpoint");
  });

  it("interruption recovery: from a state that crashed after the composite was accepted, resumes the remaining re-encryption without advancing the epoch", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
      await variableAt({
        built: chainBase,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    // The server falls on the second variable's push (= a crash mid-re-encryption)
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      // Only vbb keeps failing throughout run 1 (never recovers even on in-pass retries)
      onPush: (call, variableId) =>
        variableId === "vbb" && call < 4 ? { status: 503, bodyText: "unavailable" } : undefined,
    });
    const env = await startEnv(state.handlers, owner);

    // Run 1: the rotation was accepted, but re-encryption interrupts at 1 variable
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "first run"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.pushes).toHaveLength(1);
    const first = state.rotateBodies[0];
    if (first === undefined) throw new Error("rotate was not called");
    const newDek = await newEpochDekOf(first);

    // Run 2 (same config, same local floor): the epoch stays 2, and only the
    // remaining 1 variable is re-encrypted. rotate is **never called** (never
    // advances the epoch twice). Because --reason was passed = a rotation was
    // requested, a run that switched to resuming must not exit successfully
    // (a script must not mistake it for "a new epoch was made")
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "re-run"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.pushes).toHaveLength(2);
    const resumed = state.pushes[1];
    if (resumed === undefined) throw new Error("resume push missing");
    expect(resumed.variableId).toBe("vbb");
    expect(resumed.value.aad).toMatchObject({ epoch: 2, version: 2 });
    expect(await decryptWire(newDek, resumed.value)).toBe("key-abc");
    // That it resumed is made explicit (also that the --reason is never recorded on the chain)
    expect(env.errors.join("\n")).toContain("with incomplete re-encryption");
    expect(env.logs.join("\n")).toContain("resumed re-encryption");
    // A resume is not "the requested rotation": the completion report never
    // hides the fact that no new epoch was made (blocks the shape where a run
    // after member removal looks successful)
    expect(env.logs.join("\n")).toContain("No new epoch was created");
    expect(env.errors.join("\n")).toContain("the requested rotation was not performed");
    // On a run that had a request, state explicitly "switched without running the request"
    expect(env.errors.join("\n")).toContain("The requested rotation will not be performed");
  });

  it("trigger (i): a periodic checkpoint is also issued when re-encryption completes on the resume path", async () => {
    const auditHead = "cd".repeat(32);
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
      await variableAt({
        built: chainBase,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      // Only vbb keeps failing throughout run 1 = a crash mid-re-encryption.
      // Run 1 never reaches full completion, so no periodic checkpoint is issued
      onPush: (call, variableId) =>
        variableId === "vbb" && call < 4 ? { status: 503, bodyText: "unavailable" } : undefined,
      standaloneCheckpoint: { auditHeadHashHex: auditHead },
    });
    const env = await startEnv(state.handlers, owner);

    // Run 1: rotate was accepted but re-encryption interrupted — the chain's
    // tail gains no checkpoint (only the 2 entries: rotate + boundary checkpoint)
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "first run"], env.layer)).toBe(1);
    const afterCrash = state.chainEntries.length;
    expect(state.chainEntries[afterCrash - 1]?.op).toBe("checkpoint"); // the boundary's (H+2)
    expect(state.chainEntries[afterCrash - 2]?.op).toBe("rotate_epoch");

    // Run 2 (no reason = the guided resume): re-encrypts the remaining 1
    // variable and **completes** → the environment's periodic checkpoint is
    // issued at the completion boundary
    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(state.chainEntries.length).toBe(afterCrash + 1);
    const tail = state.chainEntries[state.chainEntries.length - 1];
    if (tail === undefined || tail.op !== "checkpoint") {
      throw new Error("the post-resume periodic checkpoint was not appended");
    }
    expect(tail.payload.environments).toHaveLength(1);
    const tuple = tail.payload.environments[0];
    if (tuple === undefined) throw new Error("missing tuple");
    expect(tuple.environmentId).toBe(ENV_ID);
    // The notarized subject = the data state **after** re-encryption completed (both variables on the new epoch)
    expect(tuple.epoch).toBe(2);
    const pushedA = state.pushes.find((push) => push.variableId === "vaa");
    const pushedB = state.pushes.find((push) => push.variableId === "vbb");
    if (pushedA === undefined || pushedB === undefined) throw new Error("missing pushes");
    const digest = await computeEnvValuesDigest(SUITE_ID, [
      {
        variableId: "vaa",
        version: pushedA.value.aad.version,
        valueSigHashHex: await valueHashOf(pushedA.value, owner.userId),
      },
      {
        variableId: "vbb",
        version: pushedB.value.aad.version,
        valueSigHashHex: await valueHashOf(pushedB.value, owner.userId),
      },
    ]);
    if (!digest.ok) throw new Error("digest failed");
    expect(tuple.valuesDigestHex).toBe(digest.value);
    expect(tail.payload.auditHeadHashHex).toBe(auditHead);
    expect(env.logs.join("\n")).toContain("post-rotation periodic checkpoint");
  });

  it("a post-rotation push failure reports the fact that the epoch advanced as a partial completion", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onPush: () => ({ status: 503, bodyText: "unavailable" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "first run"], env.layer)).toBe(1);
    // The composite was accepted = the epoch did advance. Never end on the raw
    // error alone — convey "the epoch advanced and re-encryption remains" plus the means to resume
    expect(state.rotateBodies).toHaveLength(1);
    // All passes were spent (= each pass's rescan did run), so the remaining
    // count is measured. Says neither "interrupted" nor "includes unverified"
    expect(env.logs.join("\n")).toContain("Partial completion");
    expect(env.logs.join("\n")).toContain("1 variable incomplete");
    expect(env.logs.join("\n")).not.toContain("may include unconfirmed ones");
    const errors = env.errors.join("\n");
    expect(errors).toContain("re-encryption did not complete");
    expect(errors).not.toContain("re-encryption was interrupted");
    expect(errors).toContain("resume from the remainder without advancing the epoch");
  });

  it("the partial-completion cause shows the latest failure (a resolved transient failure must not hide the real cause)", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      // Pass 1 is a transient 503; from then on it keeps returning 404 (= the cause blocking it now)
      onPush: (call, variableId) =>
        call === 0
          ? { status: 503, bodyText: "unavailable" }
          : { status: 404, json: { _tag: "VariableNotFound", variableId } },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "cause freshness"], env.layer)).toBe(
      1,
    );
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "re-encryption did not complete: Re-encryption of variable DATABASE_URL was rejected with 404 (possible concurrent deletion)",
    );
    expect(errors).not.toContain("re-encryption did not complete: Failed to re-encrypt");
  });

  it("a resolved transient failure is not kept as the cause (an unresolved conflict is reported as a conflict)", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
      await variableAt({
        built: chainBase,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      // vaa is a 502 only on pass 1 (succeeds on pass 2). vbb keeps conflicting to the end
      onPush: (call, variableId) => {
        if (variableId === "vaa") {
          return call === 0 ? { status: 502, bodyText: "bad gateway" } : undefined;
        }
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "mixed"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    // Only the conflicting share remains, so the cause is conflict. Raising
    // the resolved 502 would mislead the investigation toward verification
    // failure / floor violation
    expect(errors).toContain("conflicts with concurrent pushes did not resolve");
    expect(errors).not.toContain("re-encryption did not complete");
    // The fact that a now-resolved failure happened is kept as a warning
    expect(errors).toContain("There were failures during re-encryption");
  });

  it("only when the pass-end rescan was never reached is the remaining count reported as 'includes unverified'", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onPush: () => ({ status: 503, bodyText: "unavailable" }),
      // Let the first pull through, then fail the pass-end rescan (= the actual state cannot be checked)
      onPull: (call) => (call === 0 ? undefined : { status: 503, bodyText: "unavailable" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "rescan failure"], env.layer)).toBe(
      1,
    );
    // The conflicting share may have been resolved by another member, so it is never asserted
    expect(env.logs.join("\n")).toContain("1 variable incomplete (may include unconfirmed ones)");
    expect(env.errors.join("\n")).toContain("re-encryption was interrupted");
  });

  it("a reasonless re-run is a request to resume only (already re-encrypted variables are excluded and it exits successfully)", async () => {
    const variables = [
      // Already re-encrypted to epoch 2 (declared head = the rotate entry itself)
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek2,
        epoch: 2,
        version: 2,
        plaintext: "postgres://example",
        headSeq: 3,
      }),
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
    });
    const env = await startEnv(state.handlers, owner);

    // The partial-completion guidance says "re-run to resume from the
    // remainder without advancing the epoch". A run per that guidance (no
    // reason) is a request to resume only, so it exits successfully once
    // nothing is left (only a --reason'd run gets exit 1)
    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
    const pushed = state.pushes[0];
    if (pushed === undefined) throw new Error("resume push missing");
    expect(pushed.value.aad).toMatchObject({ epoch: 2, version: 2 });
    expect(await decryptWire(dek2, pushed.value)).toBe("key-abc");
    // The re-encryption push carries the self-declaration marker (AUTH_SPEC
    // §12-5 — so it is not counted as resolving the rotation-needed flag — AUDIT_SPEC §4.1-5)
    expect(pushed.reencryption).toBe(true);
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("the requested rotation was not performed");
    // Never tell a run that requested nothing "switched without running the request"
    expect(errors).toContain("with incomplete re-encryption. Resuming this re-encryption");
    expect(errors).not.toContain("The requested rotation will not be performed");
  });

  it("completion check: a variable made in the window between the first pull and composite acceptance gets 422 → re-pull puts it in the target set and it completes only after re-encryption", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    // In the window between the first pull and the composite's acceptance,
    // another member creates a variable on the old epoch. The real server
    // rejects such a concurrent creation with 422 via the acceptance-time
    // match (§12-4 — the boundary checkpoint's values_digest), so the post-
    // re-pull retry lands it in the target set (an accepted checkpoint's
    // snapshot always covers the distribution set — the premise of rule 2)
    const late = await variableAt({
      built: chainBase,
      variableId: "vlate",
      name: "LATE_VAR",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "late-value",
      headSeq: 2,
    });
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onRotate: (call) => {
        if (call === 0) {
          variables.push(late);
          return {
            status: 422,
            json: { _tag: "CheckpointStateMismatch", reason: "values-digest-mismatch" },
          };
        }
        return undefined;
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "window"], env.layer)).toBe(0);
    // vlate, created in the window, also enters the retry's target set and completes only after re-encryption
    expect(state.pushes.map((push) => push.variableId).toSorted()).toEqual(["vaa", "vlate"]);
    expect(state.rotateBodies).toHaveLength(2);
    const body = state.rotateBodies[1];
    if (body === undefined) throw new Error("rotate retry missing");
    // The retry's boundary checkpoint notarizes the value set including vlate
    expect(body.checkpoint.payload.environments[0]?.valuesDigestHex).not.toBe(
      state.rotateBodies[0]?.checkpoint.payload.environments[0]?.valuesDigestHex,
    );
    const newDek = await newEpochDekOf(body);
    const pushedLate = state.pushes.find((push) => push.variableId === "vlate");
    if (pushedLate === undefined) throw new Error("late push missing");
    expect(pushedLate.value.aad).toMatchObject({ epoch: 2, version: 2 });
    expect(await decryptWire(newDek, pushedLate.value)).toBe("late-value");
  });

  it("--new-epoch creates a new epoch even with an unfinished re-encryption (for §7's all-environment rotation)", async () => {
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--reason", "member removal", "--new-epoch"],
        env.layer,
      ),
    ).toBe(0);
    // Not a resume but a rotation: an epoch-3 entry is made, and old-epoch
    // values go straight to epoch 3 without passing through the middle epoch
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.newEpoch).toBe(3);
    const pushed = state.pushes[0];
    if (pushed === undefined) throw new Error("push missing");
    expect(pushed.value.aad).toMatchObject({ epoch: 3, version: 2 });
    // A forced rotation's re-encryption push also carries the self-declaration marker (§12-5)
    expect(pushed.reencryption).toBe(true);
    expect(env.logs.join("\n")).toContain("epoch 2 → 3");
  });

  it("the resume path does not require --reason (never blocks recovery over a field that is not recorded)", async () => {
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
  });

  it("ChainHeadConflict (409) re-syncs, re-signs the entry, and retries (§12-4)", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onRotate: (call) =>
        call === 0
          ? {
              status: 409,
              json: {
                _tag: "ChainHeadConflict",
                currentHeadSeq: chainBase.entries.length,
                currentHeadHashHex: chainBase.hashes[chainBase.hashes.length - 1],
              },
            }
          : undefined,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "conflict test"], env.layer)).toBe(0);
    expect(state.rotateBodies).toHaveLength(2);
    const [first, second] = state.rotateBodies;
    if (first === undefined || second === undefined) throw new Error("missing bodies");
    // Re-signed (timestamp · signature change), but the generated DEK's
    // commitment and the wrap set are reused as-is for the same epoch
    expect(second.entry.payload.dekCommitmentHex).toBe(first.entry.payload.dekCommitmentHex);
    expect(second.deks).toEqual(first.deks);
  });

  it("CheckpointStateMismatch (422) retries bounded, restarting from a verified pull (§12-4)", async () => {
    // A 422 from the boundary checkpoint's values_digest match = a concurrent
    // push after the declared head was fixed. Re-signing does not resolve it
    // (the value set must be re-fetched), so the retry restarts from a
    // verified pull rather than the composite-send re-sign loop (session-33 §5 F-2)
    const state = makeServer({
      built: chainBase,
      variables: [],
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onRotate: (call) =>
        call === 0
          ? {
              status: 422,
              json: { _tag: "CheckpointStateMismatch", reason: "values-digest-mismatch" },
            }
          : undefined,
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "value-conflict test"], env.layer),
    ).toBe(0);
    expect(state.rotateBodies).toHaveLength(2);
    const [first, second] = state.rotateBodies;
    if (first === undefined || second === undefined) throw new Error("missing bodies");
    // A retry restarts from a pull = a new DEK is generated (the previous
    // attempt's composite was never accepted and the epoch never advanced — safe to discard)
    expect(second.entry.payload.dekCommitmentHex).not.toBe(first.entry.payload.dekCommitmentHex);
    // The boundary checkpoint is bundled on the retry too (the value set is unchanged, so the digest is identical)
    expect(second.checkpoint.payload.environments[0]?.valuesDigestHex).toBe(
      first.checkpoint.payload.environments[0]?.valuesDigestHex,
    );
    expect(env.logs.join("\n")).toContain("re-pulling and retrying the rotation");
    // The intent discipline (3-F) × bounded retries (F-2) cross-layer (PR-F4):
    // attempt 1's intent is closed by the 422 (definite rejection), attempt
    // 2's intent is closed by the acceptance check — the retry loop never leaves an unresolved intent behind
    const floor = await loadFloor(env);
    expect(floor?.intents).toEqual([]);
    expect(floor?.environments[ENV_ID]?.manifest).toMatchObject({ epoch: 2 });
  });

  it("when CheckpointStateMismatch does not resolve, it aborts bounded and guides toward a re-run (§12-4)", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onRotate: () => ({
        status: 422,
        json: { _tag: "CheckpointStateMismatch", reason: "values-digest-mismatch" },
      }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "value-conflict test"], env.layer),
    ).toBe(1);
    // Abort after the bound (3 attempts) — never pulls forever
    expect(state.rotateBodies).toHaveLength(3);
    const errors = env.errors.join("\n");
    expect(errors).toContain("values-digest-mismatch");
    expect(errors).toContain("Re-run `maruhi env rotate` to rebuild the checkpoint");
    // The intent discipline (3-F) × bounded retries cross-layer (PR-F4): 422
    // is a definite rejection (isServerRejection), so all 3 attempts' intents
    // close as rejected — no unresolved intent piles up and the floor never
    // advances (no match obligation left for the next run). The floor stays at
    // mv1 distributed by the first pull (pins the correct post-abort floor
    // state itself — a loose inequality would also let a vanished manifest through)
    const floor = await loadFloor(env);
    expect(floor?.intents).toEqual([]);
    expect(floor?.environments[ENV_ID]?.manifest).toMatchObject({
      manifestVersion: 1,
      epoch: 1,
    });
  });

  it("a server that drops the accepted boundary checkpoint from chain distribution is detected by the post-acceptance rescan's strict verification (PR-F4 cross-layer)", async () => {
    // The end-to-end pinning of the 2-G' consequence: the manifest issued
    // with the composite (epoch = new_epoch · declared head = before the
    // append) verifies only on an exact match against the boundary-checkpoint
    // tuple (no H+1 exception exists — §4.3 (2)). A server that hides the
    // accepted checkpoint from chain distribution (the chain itself stays
    // valid under the consensus rule) is detected when the post-acceptance
    // rescan pull's manifest verification falls to strict and fails with
    // epoch-not-current-at-head — pinning that no path exists for "checkpoint
    // hiding" to revert to an H+1-equivalent loose acceptance
    const state = makeServer({
      built: chainBase,
      variables: [],
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      dropCheckpointFromChain: true,
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "checkpoint hiding"], env.layer),
    ).toBe(1);
    // The composite itself is accepted (detection happens in the post-acceptance rescan pull's distribution-time verification)
    expect(state.rotateBodies).toHaveLength(1);
    expect(env.errors.join("\n")).toContain("reason=epoch-not-current-at-head");
    // The acceptance check (self commitment matching on the chain) holds
    // independently of the checkpoint's presence, so the floor's
    // self-issued-manifest promotion (M1-A4) itself does happen
    const floor = await loadFloor(env);
    expect(floor?.environments[ENV_ID]?.manifest).toMatchObject({
      manifestVersion: 2,
      epoch: 2,
    });
  });

  it("detecting another member's concurrent rotation mid-CAS-retry aborts without using the generated DEK", async () => {
    const projectId = chainBase.projectId;
    const entries: ChainEntry[] = [...chainBase.entries];
    const hashes: string[] = [...chainBase.hashes];
    let chainCalls = 0;
    const rotateBodies: RotateBody[] = [];
    const handlers: MockHandler[] = [
      onRequest("GET", `/projects/${projectId}/chain`, () => {
        // From the second sync on, the other member's rotate_epoch is stacked
        if (chainCalls > 0 && entries.length === chainBase.entries.length) {
          entries.push(...chainRotated.entries.slice(chainBase.entries.length));
          hashes.push(...chainRotated.hashes.slice(chainBase.hashes.length));
        }
        chainCalls += 1;
        return {
          status: 200,
          json: {
            projectId,
            entries,
            headSeq: entries.length,
            headHashHex: hashes[hashes.length - 1],
          },
        };
      }),
      onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull`, async () => ({
        status: 200,
        json: {
          environmentId: ENV_ID,
          currentEpoch: 1,
          statement: envStatement,
          variables: [],
          deletedVariables: [],
          deks: [],
          manifest: await manifestFor({
            projectId,
            environmentId: ENV_ID,
            epoch: 1,
            issuer: owner,
            head: headOf(chainBase, 2),
            envStatement,
            statements: [],
          }),
        },
      })),
      onRequest("POST", `/projects/${projectId}/environments/${ENV_ID}/rotate`, (request) => {
        rotateBodies.push(request.body as RotateBody);
        return {
          status: 409,
          json: {
            _tag: "ChainHeadConflict",
            currentHeadSeq: chainRotated.entries.length,
            currentHeadHashHex: chainRotated.hashes[chainRotated.hashes.length - 1],
          },
        };
      }),
    ];
    const env = await startEnv(handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "concurrent"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("concurrent rotation");
    // Stops the moment the concurrent rotation is detected (never resends to the bound)
    expect(rotateBodies).toHaveLength(1);
  });

  it("a re-encryption VersionConflict verifies the actual state via re-fetch; if the winner is already on the current epoch, re-encryption is treated as unneeded", async () => {
    const stale = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "key-abc",
      headSeq: 2,
    });
    // The "winner another member wrote on the new epoch" visible on the
    // re-fetch after the 409. An honest concurrent writer chains prev into the verified version 1
    const winner = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "key-def",
      headSeq: 3,
      prevValueSigHashHex: await valueHashOf(stale.value, owner.userId),
    });
    const variables = [stale];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      onPush: (call) => {
        if (call !== 0) {
          return undefined;
        }
        // Returns the 409 after settling the state where the concurrent push's winner won
        variables[0] = winner;
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 2 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    // The winner was accepted on the current epoch = re-encryption unneeded. Never goes to overwrite
    expect(state.pushes).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("1 variable already re-encrypted by concurrent updates");
  });

  it("if the 409's winner chains into a diverged history, it aborts without re-pointing prev (§12-5)", async () => {
    const stale = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "key-abc",
      headSeq: 2,
    });
    // The winner's prev not pointing at the verified version-1 signed-bytes
    // hash = a diverged history (evidence of equivocation). Our signature
    // never chains into it. Also pins at the same time that the consistency
    // check runs before the "re-encryption unneeded" shortcut, and that the
    // current-epoch winner never trips the floor's rule (c)
    const forked = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "key-forked",
      headSeq: 3,
      prevValueSigHashHex: "ab".repeat(32),
    });
    const variables = [stale];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      onPush: (call) => {
        if (call !== 0) {
          return undefined;
        }
        variables[0] = forked;
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 2 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "divergence"], env.layer)).toBe(1);
    expect(state.pushes).toHaveLength(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("chaining onto a diverged history");
    // Even on abort, collected warnings are not lost (the no-floor proviso matters most exactly on abort)
    expect(errors).toContain("the omission cannot be detected");
    // Cryptographic evidence is not "a failure a re-run fixes": never collapse
    // it into partial completion + resume guidance — it surfaces as an
    // immediate abort that prompts investigation (same treatment as the push path)
    expect(errors).toContain("This is evidence that re-running will not resolve");
    expect(env.logs.join("\n")).not.toContain("Partial completion");
  });

  it("a conflict on the final pass is also verified via re-fetch (never misreports unfinished when the winner is on the current epoch)", async () => {
    const stale = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "key-abc",
      headSeq: 2,
    });
    const winner = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "key-def",
      headSeq: 3,
      prevValueSigHashHex: await valueHashOf(stale.value, owner.userId),
    });
    const variables = [stale];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      // Right after the final pass's (3rd) conflict, another member's current-epoch write settles
      onPush: (call) => {
        if (call === 2) {
          variables[0] = winner;
        }
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(state.pushes).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("1 variable already re-encrypted by concurrent updates");
    expect(env.errors.join("\n")).not.toContain("has not completed");
  });

  it("a concurrent deletion (404) mid-re-encryption warns and continues (never takes the remaining variables down with it)", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DOOMED",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "doomed-value",
        headSeq: 2,
      }),
      await variableAt({
        built: chainBase,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    // The deletion is a tombstone (status deleted · metaVersion + 1) + deletion of all versions (§12-5)
    const tombstone = await statementFor({
      projectId: chainBase.projectId,
      environmentId: ENV_ID,
      variableId: "vaa",
      name: "DOOMED",
      author: owner,
      head: headOf(chainBase, 1),
      status: "deleted",
      metaVersion: 2,
    });
    const deletedVariables: WireDistributedVariableStatement[] = [];
    const state = makeServer({
      built: chainBase,
      variables,
      deletedVariables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onPush: (call, variableId) => {
        if (call !== 0) {
          return undefined;
        }
        // Another member deleted it right before the re-encryption
        variables.splice(
          variables.findIndex((variable) => variable.variableId === variableId),
          1,
        );
        deletedVariables.push(tombstone);
        return { status: 404, json: { _tag: "VariableNotFound", variableId } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "deletion race"], env.layer)).toBe(0);
    // The deleted variable drops out of the target set; the rest are re-encrypted
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
    expect(env.errors.join("\n")).toContain("deleted concurrently by another member");
    // The 404 is recorded as the abort's cause, and at completion it becomes a
    // "happened but resolved" warning (the partial-completion cause never morphs into "conflict with a concurrent push")
    expect(env.errors.join("\n")).toContain("rejected with 404");
  });

  it("on a server that keeps returning 404 while still distributing the variable, the 404 surfaces as the partial-completion cause", async () => {
    // "Refuses with 404 yet keeps distributing it as active on pull" = neither
    // deletion nor conflict. Without recording the cause, the partial-
    // completion report morphs into the default wording (conflict with a
    // concurrent push) and the operator chases a nonexistent conflict
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onPush: (_call, variableId) => ({
        status: 404,
        json: { _tag: "VariableNotFound", variableId },
      }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "persistent 404"], env.layer)).toBe(
      1,
    );
    expect(state.rotateBodies).toHaveLength(1);
    const errors = env.errors.join("\n");
    expect(env.logs.join("\n")).toContain("Partial completion");
    expect(errors).toContain(
      "re-encryption did not complete: Re-encryption of variable API_KEY was rejected with 404 (possible concurrent deletion)",
    );
    expect(errors).not.toContain("conflicts with concurrent pushes did not resolve");
  });

  it("a response distributing only values older than the 409's claim is never adopted as the winner — it aborts (§12-5)", async () => {
    const stale = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "key-abc",
      headSeq: 2,
    });
    const variables = [stale];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      // Claims "latest is version 9" yet distributes only version 1 on re-fetch
      onPush: (call) =>
        call === 0
          ? { status: 409, json: { _tag: "VersionConflict", currentVersion: 9 } }
          : undefined,
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "self-contradiction"], env.layer),
    ).toBe(1);
    expect(state.pushes).toHaveLength(0);
    expect(env.errors.join("\n")).toContain("known latest version");
  });

  it("a re-encryption left with an unresolved conflict warns as a partial completion and exits non-zero", async () => {
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      // 409 every time. Even on re-fetch the latest value stays on the old epoch = re-encryption never completes
      onPush: () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "conflict"], env.layer)).toBe(1);
    expect(state.pushes).toHaveLength(0);
    // Never ends with a "completed" face (the summary itself declares partial completion)
    expect(env.logs.join("\n")).toContain("Partial completion");
    expect(env.logs.some((line) => line.startsWith("Done:"))).toBe(false);
    expect(env.logs.join("\n")).toContain("1 variable incomplete");
    const errors = env.errors.join("\n");
    expect(errors).toContain("has not completed");
    // Explicitly states that old-epoch DEK holders can still read the current values
    expect(errors).toContain("DEKs older than epoch 2");
  });

  it("on the resume path too, the guard is re-applied against the advanced verified view (the case where self was deleted mid-pull)", async () => {
    // The 4th entry removes the runner (member). The first sync sees only 3
    // entries, and the environment statement declares seq 4 (a future head),
    // so a bounded resync runs. The resume path only pushes and never builds
    // the wrap set, so grant_server does not stop the resume. The guard's
    // re-application itself is pinned on membership · role
    const runner = await makeTestUser("user-member-3333");
    const granted = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(runner, "member") },
      { actor: runner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: runner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
      { actor: owner, operation: removeMemberOp(runner) },
    ]);
    const futureEnvStatement = await environmentStatementFor({
      projectId: granted.projectId,
      environmentId: ENV_ID,
      name: ENV_ID,
      author: owner,
      head: headOf(granted, 5),
    });
    const variables = [
      await variableAt({
        built: granted,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 3,
      }),
    ];
    let chainCalls = 0;
    const pushPaths: string[] = [];
    const handlers: MockHandler[] = [
      onRequest("GET", `/projects/${granted.projectId}/chain`, () => {
        // First serves 4 entries without the removal (runner is a member · epoch 2); the resync serves 5
        const count = chainCalls === 0 ? 4 : 5;
        chainCalls += 1;
        return {
          status: 200,
          json: {
            projectId: granted.projectId,
            entries: granted.entries.slice(0, count),
            headSeq: count,
            headHashHex: granted.hashes[count - 1],
          },
        };
      }),
      onRequest("GET", `/projects/${granted.projectId}/environments/${ENV_ID}/pull`, async () => ({
        status: 200,
        json: {
          environmentId: ENV_ID,
          currentEpoch: 2,
          statement: futureEnvStatement,
          variables,
          deletedVariables: [],
          deks: [],
          manifest: await manifestFor({
            projectId: granted.projectId,
            environmentId: ENV_ID,
            epoch: 2,
            issuer: owner,
            head: headOf(granted, 5),
            envStatement: futureEnvStatement,
            statements: variables.map((variable) => variable.statement),
          }),
        },
      })),
      (request) => {
        if (request.method === "POST") {
          pushPaths.push(request.path);
        }
        return null;
      },
    ];
    const server = await MockServer.start(handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, runner);
    await seedConfig(env, { server: server.origin, defaultProject: granted.projectId });

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("not a chain-derived member");
    // Even on the resume path it never proceeds to writing
    expect(pushPaths).toHaveLength(0);
  });

  it("the server's EpochConflict claim never decides the cause — it defers to the rescan's chain verification", async () => {
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      // The chain stays at epoch 2, yet the server claims an epoch conflict every time
      onPush: () => ({ status: 409, json: { _tag: "EpochConflict", currentEpoch: 3 } }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "claim"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    // Never swallows the claim whole and reports "another member rotated
    // concurrently". As long as the chain-derived current epoch is unchanged, this is a contradictory response
    expect(errors).not.toContain("concurrent rotation");
    expect(errors).toContain("the server's response contradicts the chain");
    expect(errors).toContain("re-running will not resolve this");
  });

  it("even with an EpochConflict claim, if every variable is in place on the rescan it completes (the warning stays)", async () => {
    const stale = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "key-abc",
      headSeq: 2,
    });
    // Behind the claim, another member wrote everything on **the same epoch**
    const winner = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "key-def",
      headSeq: 3,
      prevValueSigHashHex: await valueHashOf(stale.value, owner.userId),
    });
    const variables = [stale];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      onPush: (call) => {
        if (call !== 0) {
          return undefined;
        }
        variables[0] = winner;
        return { status: 409, json: { _tag: "EpochConflict", currentEpoch: 3 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    // What decides re-encryption's completion is the verified actual state,
    // not the server's self-claim. The in-place fact is never covered over by
    // a "contradictory response" abort
    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(state.pushes).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("1 variable already re-encrypted by concurrent updates");
    const errors = env.errors.join("\n");
    // The contradictory claim itself stays as an investigation target (but no abort)
    expect(errors).toContain("the server's response contradicts the chain");
    expect(errors).not.toContain("re-running will not resolve this");
  });

  it("when an EpochConflict-claimed variable resolves, the rest get ordinary partial-completion guidance", async () => {
    // The claimed vaa is resolved because another member wrote it out on the
    // current epoch. What remains is only vbb for a different reason (502) —
    // declaring "a re-run will not resolve this" here would leave a re-
    // runnable state with neither resume guidance nor a remaining count
    const staleA = await variableAt({
      built: chainRotated,
      variableId: "vaa",
      name: "DATABASE_URL",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "postgres://example",
      headSeq: 2,
    });
    const winnerA = await variableAt({
      built: chainRotated,
      variableId: "vaa",
      name: "DATABASE_URL",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "postgres://example",
      headSeq: 3,
      prevValueSigHashHex: await valueHashOf(staleA.value, owner.userId),
    });
    const variables = [
      staleA,
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      onPush: (_call, variableId) => {
        if (variableId === "vaa") {
          // Simultaneously with the claim, another member's current-epoch write settles
          variables[0] = winnerA;
          return { status: 409, json: { _tag: "EpochConflict", currentEpoch: 3 } };
        }
        return { status: 502, bodyText: "bad gateway" };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    // The contradictory claim itself stays as an investigation target (but no abort)
    // Never says "confirmed everything is in place": all the rescan shows is
    // that nothing is left in the unfinished set — whether it was written on
    // the current epoch or deleted is unknown
    expect(errors).toContain("The reported variable is not in the rescanned incomplete set");
    // An abort would never reach the partial-completion reporting path = neither the remaining count nor the resume guidance comes out
    expect(env.logs.join("\n")).toContain("Partial completion");
    expect(env.logs.join("\n")).toContain("1 variable incomplete");
    expect(errors).toContain("resume from the remainder without advancing the epoch");
  });

  it("when the chain has actually advanced on an EpochConflict, it is treated as a concurrent rotation, not a contradiction", async () => {
    const rotatedTwice = chainRotatedTwice;
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const deks = [
      await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
      await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
    ];
    let chainCalls = 0;
    const pushPaths: string[] = [];
    const handlers: MockHandler[] = [
      onRequest("GET", `/projects/${chainBase.projectId}/chain`, () => {
        // The first sync is epoch 2. Mid-re-encryption, another member advances to epoch 3
        const built = chainCalls === 0 ? chainRotated : rotatedTwice;
        chainCalls += 1;
        return {
          status: 200,
          json: {
            projectId: chainBase.projectId,
            entries: built.entries,
            headSeq: built.entries.length,
            headHashHex: built.hashes[built.hashes.length - 1],
          },
        };
      }),
      onRequest(
        "GET",
        `/projects/${chainBase.projectId}/environments/${ENV_ID}/pull`,
        async () => ({
          status: 200,
          json: {
            environmentId: ENV_ID,
            currentEpoch: 2,
            statement: envStatement,
            variables,
            deletedVariables: [],
            deks,
            manifest: await manifestFor({
              projectId: chainBase.projectId,
              environmentId: ENV_ID,
              epoch: 2,
              issuer: owner,
              head: headOf(chainRotated, 3),
              envStatement,
              statements: variables.map((variable) => variable.statement),
            }),
          },
        }),
      ),
      (request) => {
        if (request.method !== "POST" || !request.path.endsWith("/versions")) {
          return null;
        }
        pushPaths.push(request.path);
        return { status: 409, json: { _tag: "EpochConflict", currentEpoch: 3 } };
      },
    ];
    const env = await startEnv(handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    // The forced resync confirmed the chain actually advanced, so this is not
    // a server contradiction (a benign race is not mistaken for foul play)
    expect(errors).toContain("concurrent rotation");
    expect(errors).not.toContain("the server's response contradicts the chain");
    expect(pushPaths).toHaveLength(1);
  });

  it("--new-epoch advances the epoch even with an undecryptable value (revocation wins — §7)", async () => {
    // The member-removal run. If one unopenable value stopped the epoch from
    // advancing at all, the removed member's old DEK would stay valid for **every** variable
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "OLD_ONE",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "unreadable-here",
        headSeq: 2,
      }),
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek2,
        epoch: 2,
        version: 1,
        plaintext: "key-abc",
        headSeq: 3,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      // No wrap addressed to self at epoch 1
      deks: [await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner })],
      currentEpoch: 2,
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--reason", "member removal", "--new-epoch"],
        env.layer,
      ),
    ).toBe(1);
    // **The epoch did advance** (the revocation itself is achieved)
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.newEpoch).toBe(3);
    // Openable values go to the new epoch; unopenable ones are reported unfinished
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Some values cannot be re-encrypted");
    expect(env.logs.join("\n")).toContain("Partial completion");
  });

  it("even when the composite send fails, if it was accepted it reports 'the epoch advanced'", async () => {
    // A lost response (502 / timeout). The DO accepted it, yet the client only
    // sees the transport error — ending on the raw error would read as
    // "nothing happened" and hide the most dangerous state: an epoch advanced
    // with 0 re-encryptions
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      // Accepts it (appended to the chain), but the response returns 502
      onRotateAfterAccept: () => ({ status: 502, bodyText: "bad gateway" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "lost response"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("this rotation itself was accepted");
    expect(errors).toContain("resume re-encryption without advancing the epoch");
    // M1-A4: the moment the self commitment is confirmed matching on the
    // chain, the floor (the self-issued manifest) has advanced even if the
    // command exits with an error
    const floor = await loadFloor(env);
    expect(floor?.environments[ENV_ID]?.manifest).toMatchObject({
      manifestVersion: 2,
      epoch: 2,
    });
    // With the effect confirmed, the intent (3-F) is closed too
    expect(floor?.intents).toEqual([]);
  });

  it("if not even one value can be re-encrypted, the epoch never advances (an idle spin is no revocation)", async () => {
    // A member with not a single wrap addressed to them (or a response that
    // drops every wrap). Advancing only the epoch here would leave every
    // current value under the old epoch's DEK, and the chain would carry just
    // a "rotated" record with no revocation achieved
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const state = makeServer({ built: chainBase, variables, deks: [], currentEpoch: 1 });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "idle spin"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("No values can be re-encrypted");
    expect(errors).toContain("nothing is actually revoked");
  });

  it("if what advanced behind the send failure was another member's rotation, it says so", async () => {
    // The epoch has reached the target value, but what landed is another
    // member's DEK commitment — our revocation rotation was never accepted
    const state = makeServer({
      built: chainBase,
      variables: [],
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      // The send is a 502. Behind it, another member has already rotated to epoch 2
      onRotate: () => ({ status: 502, bodyText: "bad gateway" }),
      chainAfterRotateAttempt: chainRotated,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "other member"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("another member's rotation");
    expect(errors).toContain("this run's entry was not accepted");
    // Never reads as our share having been accepted
    expect(errors).not.toContain("this rotation itself was accepted");
    // M1-A4: the commitment on the chain differs = the floor never advances
    // (no self-issued manifest recorded). Since non-acceptance is confirmed,
    // the intent closes as not-accepted
    const floor = await loadFloor(env);
    expect(floor?.environments[ENV_ID]?.manifest?.manifestVersion ?? 1).toBeLessThanOrEqual(1);
    expect(floor?.intents).toEqual([]);
  });

  it("even when another member has advanced further after the acceptance, our share's acceptance is not missed", async () => {
    // Between acceptance → lost response → confirmation, another member
    // rotates further. Judging by current-epoch match would misreport "not
    // accepted", but commitments for every epoch remain, so our share is distinguishable
    const state = makeServer({
      built: chainBase,
      variables: [],
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      // Accepts it (our entry lands on the chain) but the response is 502.
      // After that another member advances further to epoch 3
      onRotateAfterAccept: () => ({ status: 502, bodyText: "bad gateway" }),
      appendRotateAfterAccept: { epoch: 3, dek: dek3 },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "overtaken"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("this rotation itself was accepted");
    expect(errors).toContain("resume re-encryption without advancing the epoch");
    expect(errors).not.toContain("was not accepted");
    // M1-A4: even when overtaken, our manifest (v2) stays as the minimum floor
    const floor = await loadFloor(env);
    expect(floor?.environments[ENV_ID]?.manifest).toMatchObject({
      manifestVersion: 2,
      epoch: 2,
    });
    expect(floor?.intents).toEqual([]);
  });

  it("when the post-acceptance check sees an overtake by another rotate right after the 200, our manifest still stays as the minimum floor (M1-A4)", async () => {
    // The 200 returned (acceptance is certain), but the shape where another
    // member advanced to epoch 3 before the post-acceptance check's resync.
    // The command errors out on current epoch (3) ≠ target (2), yet the epoch-
    // 2 commitment on the chain is ours, so the floor advances
    const state = makeServer({
      built: chainBase,
      variables: [],
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      appendRotateAfterAccept: { epoch: 3, dek: dek3 },
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "post-acceptance overtake"], env.layer),
    ).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("possibly a concurrent rotation right after acceptance");
    expect(errors).toContain(
      "This rotation itself was accepted and its manifest was recorded in the local floor",
    );
    const floor = await loadFloor(env);
    expect(floor?.environments[ENV_ID]?.manifest).toMatchObject({
      manifestVersion: 2,
      epoch: 2,
    });
    expect(floor?.intents).toEqual([]);
  });

  it("a resume-only run with an unneeded --init-manifest never claims the next version will be re-issued (M1-B2)", async () => {
    // The interruption-recovery shape (epoch 2 · latest values still on epoch
    // 1) + an unneeded --init-manifest. The path is resume = no rotate
    // composite is sent = saying "the next version will be re-issued" is a lie
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const wraps = [
      await wrapDekFor({
        projectId: chainBase.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        dek: dek1,
        recipient: owner,
        signer: owner,
      }),
      await wrapDekFor({
        projectId: chainBase.projectId,
        environmentId: ENV_ID,
        epoch: 2,
        dek: dek2,
        recipient: owner,
        signer: owner,
      }),
    ];
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: wraps,
      currentEpoch: 2,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--init-manifest"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("The flag is not needed");
    expect(errors).toContain(
      "only resumes the incomplete re-encryption and issues no new manifest",
    );
    expect(errors).not.toContain("re-issues the next manifestVersion");
    // No rotate composite was actually sent (resume only pushes)
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("a check-only run with an unneeded --init-manifest says nothing is issued (M1-B2)", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--init-manifest"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("The flag is not needed");
    expect(errors).toContain("issues nothing");
    expect(errors).not.toContain("re-issues the next manifestVersion");
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("a rotate onto a deleted environment (404) is treated as a definite rejection — it never suggests re-running", async () => {
    // Rejected in the server's own error body = acceptance is definitively
    // known. No acceptance-check probe (a second chain fetch) is needed, and
    // "you can re-run as-is" must never be added to §7's interruption message
    // (a 404 is definitive and recurs)
    const state = makeServer({
      built: chainBase,
      variables: [],
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onRotate: () => ({
        status: 404,
        json: { _tag: "EnvironmentNotFound", environmentId: ENV_ID },
      }),
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    const chainCallsBefore = server.requests.filter((request) =>
      request.path.endsWith("/chain"),
    ).length;
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "deleted"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    // §7's dedicated message comes out (never collapsed into the generic "environment not found")
    expect(errors).toContain("may be selectively blocking rotation");
    expect(errors).not.toContain("safe to simply re-run");
    expect(errors).not.toContain("was accepted");
    // No chain re-fetch for the acceptance check (only the first sync's one)
    const chainCalls = server.requests.filter((request) => request.path.endsWith("/chain")).length;
    expect(chainCalls - chainCallsBefore).toBe(1);
  });

  it("when acceptance cannot be confirmed, it explicitly states the epoch may have advanced", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onRotate: () => ({ status: 502, bodyText: "bad gateway" }),
      // The chain re-fetch for confirmation also fails (the connectivity failure persists)
      onChain: (call) => (call === 0 ? undefined : { status: 503, bodyText: "unavailable" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "unverifiable"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("may already have advanced to epoch 2");
    expect(errors).toContain("Restore connectivity and re-run");
    // M1-A4: a probe failure = acceptance-unknown — the fact that acceptance
    // was never confirmed is never written to the floor (no advance). The
    // confirmation-obligation record (the intent — 3-F) stays unresolved and
    // the next run's match (the chain sync) resolves it
    const floor = await loadFloor(env);
    expect(floor?.environments[ENV_ID]?.manifest?.manifestVersion ?? 1).toBeLessThanOrEqual(1);
    expect(floor?.intents).toHaveLength(1);
    expect(floor?.intents[0]).toMatchObject({
      op: "rotate_epoch",
      environmentId: ENV_ID,
      epoch: 2,
    });
  });

  it("when the composite send fails and it was never accepted, it conveys 'you can re-run as-is'", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onRotate: () => ({ status: 502, bodyText: "bad gateway" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "undelivered"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    // The chain still sits at the declared head = a request in transit could
    // land later, so it never asserts "not accepted" (send-pending)
    expect(errors).toContain("does not show it as accepted yet");
    expect(errors).toContain("safe to simply re-run");
    // The intent (3-F) is left unresolved rather than settled — the match
    // after the chain moves settles accepted / rejected
    const floor = await loadFloor(env);
    expect(floor?.intents).toHaveLength(1);
  });

  it("when the intent (3-F) append fails, the composite is never sent (journal-before-send is fail-closed)", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
    });
    const env = await startEnv(state.handlers, owner);
    env.failFloorIntentAppends();

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "journal"], env.layer)).toBe(1);
    // A security-critical mutation is never fired without a confirmation-obligation record
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.errors.join("\n")).toContain("intent");
  });

  it("a value that cannot be opened despite holding the wrap aborts immediately as a suspected swap", async () => {
    // A wrap addressed to self exists yet decryption fails = a ciphertext swap
    // or an inconsistency with the verified view. It must never be collapsed
    // into a benign "waiting for a wrap" with guidance to step over it via
    // --new-epoch (it aborts immediately, same as pull / run).
    // The shape: a current-epoch value, but the encryption key differs (= AEAD authentication fails)
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "CORRUPT",
        dek: dek1,
        epoch: 2,
        version: 1,
        plaintext: "unreadable-here",
        headSeq: 3,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "normal"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("possibly replaced by the server");
    // Never treated as a benign gap = no means to step over it is offered
    expect(errors).not.toContain("run with --new-epoch");
    expect(errors).not.toContain("a member holding wraps");
  });

  it("an unopenable value appearing mid-pass is also never demoted to partial completion — it aborts as evidence", async () => {
    // The case above is at the first pull (before rotation), so failing it
    // only loses "a run that never started". The dangerous case is it
    // appearing **after the epoch advanced** — treating it like a rescan's
    // transient failure morphs it into "a partial completion including
    // unverified — re-run to resume" (the sign of a swap swallowed by guidance for a re-run that returns the same result forever)
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    // An old-epoch value absent from the first pull that appears only after
    // the composite's acceptance (= the pass-end rescan). The signature is
    // sound, but it is an old-epoch "creation" absent from the boundary
    // checkpoint's snapshot, and rule 2 (CRYPTO_SPEC §6.3 — PR-M3) rejects the
    // whole pull as evidence of backdated creation
    const tampered = await variableAt({
      built: chainBase,
      variableId: "vtamper",
      name: "TAMPERED",
      dek: dek3,
      epoch: 1,
      version: 1,
      plaintext: "unreadable-here",
      headSeq: 2,
    });
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onRotateAccepted: () => {
        variables.push(tampered);
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "mid-pass"], env.layer)).toBe(1);
    // Unlike the first-pull case, the rotation itself did happen here
    expect(state.rotateBodies).toHaveLength(1);
    const errors = env.errors.join("\n");
    // Rejected as evidence of rule-2 backdated creation (PR-M3)
    expect(errors).toContain("below the checkpoint baseline epoch");
    expect(errors).toContain("This is evidence that re-running will not resolve");
    // Never demoted into "a re-run will clear it" style guidance
    expect(errors).not.toContain("resume from the remainder");
    expect(errors).not.toContain("may include unconfirmed ones");
  });

  it("even with one undecryptable value, resume re-encrypts the openable share (the epoch has already advanced)", async () => {
    // A member in the §12-7 transitional state: holds the epoch-2 wrap but not
    // epoch 1's (added after the rotation / the epoch-1 re-wrap is unregistered)
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "OLD_ONE",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "unreadable-here",
        headSeq: 2,
      }),
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek2,
        epoch: 2,
        version: 1,
        plaintext: "key-abc",
        headSeq: 3,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotatedTwice,
      variables,
      // No wrap addressed to self at epoch 1 (only epochs 2 / 3)
      deks: [
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 3, dek: dek3, recipient: owner, signer: owner }),
      ],
      currentEpoch: 3,
    });
    const env = await startEnv(state.handlers, owner);

    // The 1 unopenable value is reported unfinished, but the 1 openable one is pushed
    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
    const pushed = state.pushes[0];
    if (pushed === undefined) throw new Error("push missing");
    expect(pushed.value.aad).toMatchObject({ epoch: 3 });
    const errors = env.errors.join("\n");
    expect(errors).toContain("Some values cannot be re-encrypted");
    expect(errors).toContain("No DEK for epoch 1");
    // The cause never morphs into the default wording (conflict)
    expect(errors).not.toContain("conflicts with concurrent pushes did not resolve");
    expect(env.logs.join("\n")).toContain("1 variable incomplete");
    // The same variable's warning appears only once (if the wording split
    // between the resume path and the pass-end rescan, dedupeWarnings would
    // let both through as distinct)
    expect(
      env.errors.filter((line) => line.includes("Some values cannot be re-encrypted")),
    ).toHaveLength(1);
  });

  it("a winner re-picked after a non-409 failure also gets the consistency check (preventing a chain into a diverged prev)", async () => {
    const stale = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "key-abc",
      headSeq: 2,
    });
    // The "on the current epoch but prev does not connect" successor visible on the rescan after the 502
    const forked = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "key-forked",
      headSeq: 3,
      prevValueSigHashHex: "ab".repeat(32),
    });
    const variables = [stale];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      // A transient failure rather than a 409 (this variable never enters the conflicted set)
      onPush: (call) => {
        if (call !== 0) {
          return undefined;
        }
        variables[0] = forked;
        return { status: 502, bodyText: "bad gateway" };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    expect(state.pushes).toHaveLength(0);
    expect(env.errors.join("\n")).toContain("chaining onto a diverged history");
  });

  it("on a floorless run it warns that a variable dropped from the response cannot be detected", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
    });
    const env = await startEnv(state.handlers, owner);

    // First sync (no floor): the target set's only provenance is the server
    // response, so a consistent omission cannot be detected. On a revocation-
    // purpose rotation this is never kept silent
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "no floor"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("the omission cannot be detected");

    // It does not appear on run 2 (with floor)
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "with floor"], env.layer)).toBe(0);
    const secondRunErrors = env.errors.filter((line) =>
      line.includes("the omission cannot be detected"),
    );
    expect(secondRunErrors).toHaveLength(1);
  });

  it("a response pushing back an already-accepted write of ours is detected as a rollback without relying on the floor", async () => {
    const stale = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "key-abc",
      headSeq: 2,
    });
    const other = await variableAt({
      built: chainRotated,
      variableId: "vcc",
      name: "OTHER",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "other-value",
      headSeq: 2,
    });
    const variables = [stale, other];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      // vcc is made to conflict and carried into pass 2. vbb's accepted write
      // (version 2) is never reflected — the rescan keeps distributing it at
      // version 1 = a push-back
      onPush: (_call, variableId) => {
        if (variableId === "vbb") {
          // It accepts but never persists (the shape where the server swallows our write)
          return {
            status: 200,
            json: { variableId, version: 2, epoch: 2 },
          };
        }
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } };
      },
    });
    const env = await startEnv(state.handlers, owner);
    // Fail only the floor commit of the accepted push: the floor is a SHOULD,
    // and this pins that the detection works even when it cannot be written (corruption · permission)
    env.failFloorPushCommits();

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    // Even without a floor, regressing from a version we signed is evidence of a rollback
    expect(env.errors.join("\n")).toContain(
      "older than the known latest version (2) — inconsistent",
    );
  });

  it("the same SHOULD warning is not displayed twice across passes", async () => {
    // A non-NFC name (uncomposed Á) warns on every pull — still one line across 3 passes
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "ÁPI_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      onPush: () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "duplicates"], env.layer)).toBe(1);
    const nfcWarnings = env.errors.filter((line) => line.includes("not NFC-normalized"));
    expect(nfcWarnings).toHaveLength(1);
  });

  it("one variable's permanent failure never takes other variables' re-encryption down with it", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "POISON",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "poison-value",
        headSeq: 2,
      }),
      await variableAt({
        built: chainBase,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
      await variableAt({
        built: chainBase,
        variableId: "vcc",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      // Only the leading 1 variable always fails (since the order is stable,
      // aborting would leave the following variables unreachable on any re-run)
      onPush: (_call, variableId) =>
        variableId === "vaa" ? { status: 502, bodyText: "bad gateway" } : undefined,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "poison variable"], env.layer)).toBe(
      1,
    );
    // The 2 following variables did move to the new epoch (the partial completion is the poison variable only)
    expect(state.pushes.map((push) => push.variableId).toSorted()).toEqual(["vbb", "vcc"]);
    expect(env.logs.join("\n")).toContain("1 variable incomplete");
  });

  it("even on a pass aborted because no pushable target remained, the cause is reported without collapsing to conflict", async () => {
    // The conflicting vbb is written out by another member on pass 2, leaving
    // only the unopenable vaa. The pass aborts via stalledOnUndecryptable
    // because no pushable target remains — but collapsing the cause to the
    // default wording (conflict) here would have the operator chase a
    // nonexistent concurrent writer (the shape that runs to the final pass is the next test's job)
    const undecryptable = await variableAt({
      built: chainRotatedTwice,
      variableId: "vaa",
      name: "OLD_ONE",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "unreadable-here",
      headSeq: 2,
    });
    const stale = await variableAt({
      built: chainRotatedTwice,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 1,
      plaintext: "key-abc",
      headSeq: 3,
    });
    const winner = await variableAt({
      built: chainRotatedTwice,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek3,
      epoch: 3,
      version: 2,
      plaintext: "key-def",
      headSeq: 4,
      prevValueSigHashHex: await valueHashOf(stale.value, owner.userId),
    });
    const variables = [undecryptable, stale];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotatedTwice,
      variables,
      // No wrap addressed to self at epoch 1 (= vaa cannot be opened)
      deks: [
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 3, dek: dek3, recipient: owner, signer: owner }),
      ],
      currentEpoch: 3,
      // vbb keeps conflicting, but another member writes it out on the current epoch after pass 2
      onPush: (call) => {
        if (call === 1) {
          variables[1] = winner;
        }
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("No DEK for epoch 1");
    expect(errors).not.toContain("conflicts with concurrent pushes did not resolve");
    expect(env.logs.join("\n")).toContain("1 variable incomplete");
  });

  it("even on the final pass (the non-decrypting pass), an unopenable value is collected as a cause from wrap presence alone", async () => {
    // The pushable target (vbb) keeps conflicting to the end, so no abort
    // happens and the passes run out. The final pass's rescan **never
    // decrypts** (it makes no plaintext that will never be pushed), so
    // targets comes back empty — but wrap presence for self is known from a
    // Map lookup alone. Skipping this would leave the unopenable vaa behind
    // while the cause morphs into the conflict default wording
    const variables = [
      await variableAt({
        built: chainRotatedTwice,
        variableId: "vaa",
        name: "OLD_ONE",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "unreadable-here",
        headSeq: 2,
      }),
      await variableAt({
        built: chainRotatedTwice,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek2,
        epoch: 2,
        version: 1,
        plaintext: "key-abc",
        headSeq: 3,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotatedTwice,
      variables,
      // No wrap addressed to self at epoch 1 (= vaa cannot be opened)
      deks: [
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 3, dek: dek3, recipient: owner, signer: owner }),
      ],
      currentEpoch: 3,
      // vbb keeps conflicting to the end (= a push target remains on every pass, so it never aborts)
      onPush: () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    // No push is accepted (409 on every pass). vbb remains as "a pushable
    // target" every pass, so no abort happens and it reaches the final pass's
    // decryption-free rescan
    expect(state.pushes).toHaveLength(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("No DEK for epoch 1");
    expect(errors).not.toContain("conflicts with concurrent pushes did not resolve");
    expect(env.logs.join("\n")).toContain("2 variables incomplete");
  });

  it("when resume is impossible for lack of the current epoch's DEK, it guides toward the --new-epoch escape", async () => {
    // A member who joined after the interrupted rotation: no wrap for the
    // current epoch (2) addressed to them yet. Resume is impossible, but
    // --new-epoch works (they make a new DEK themselves, so the current
    // epoch's DEK is unneeded) — without this guidance the revocation deadlocks
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner })],
      currentEpoch: 2,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "member removal"], env.layer)).toBe(
      1,
    );
    const errors = env.errors.join("\n");
    expect(errors).toContain("Cannot resume the incomplete re-encryption");
    expect(errors).toContain("run with --new-epoch");
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("a permanently failing variable's reason is kept as a warning even when it never reaches the cause field", async () => {
    // Only 1 item is raised as the cause. Dropping the second onward would
    // leave a permanently failing variable's reason (a too-large value, say)
    // never surfaced on any run, left behind on the old epoch forever
    const common = { built: chainBase, dek: dek1, epoch: 1, version: 1, headSeq: 2 } as const;
    const variables = [
      await variableAt({ ...common, variableId: "vaa", name: "TRANSIENT", plaintext: "a" }),
      await variableAt({ ...common, variableId: "vbb", name: "TOO_BIG", plaintext: "b" }),
    ];
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onPush: (_call, variableId) =>
        variableId === "vaa"
          ? { status: 502, bodyText: "bad gateway" }
          : { status: 413, json: { _tag: "ValueTooLarge", limitBytes: 8 } },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "mixed failures"], env.layer)).toBe(
      1,
    );
    const errors = env.errors.join("\n");
    // Both reasons remain with variable names (even though only one reaches the cause field)
    expect(errors).toContain("Failed to re-encrypt variable TRANSIENT");
    expect(errors).toContain("Failed to re-encrypt variable TOO_BIG");
  });

  it("when not a single current value can be opened, it never recommends the unsatisfiable --new-epoch", async () => {
    // With not a single wrap addressed to self, even proceeding to
    // --new-epoch is rejected by ensureRotationIsUseful. Recommending it would
    // bounce the user between two contradictory errors
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const state = makeServer({ built: chainRotated, variables, deks: [], currentEpoch: 2 });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "member removal"], env.layer)).toBe(
      1,
    );
    const errors = env.errors.join("\n");
    expect(errors).toContain("You cannot open any current value");
    expect(errors).not.toContain("run with --new-epoch");
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("options not applicable to the operation and misspellings are refused, never silently dropped", async () => {
    // Mistakes in the invocation itself (undeclared options · a value for a
    // boolean · extra positional args · a positional arg written as an option)
    // are owned by the check shared across all commands (args.test.ts). Here
    // we pin the env-specific applicability and that rotate fails the same way
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    // A misspelling (left alone, the intent "always a new epoch" silently falls to the weaker resume path)
    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "x", "--new-epochs"], env.layer),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("Unknown flag");
    // A create-only option passed to rotate is also refused (the env-specific check)
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "x", "--name", "n"], env.layer)).toBe(
      2,
    );
    expect(env.errors.join("\n")).toContain("Unknown flag");
    // A value for a boolean: effect/unstable/cli **interprets** both the
    // inline form (`=false`) and the space-separated form (`--new-epoch
    // false`) as the boolean's value, so these are not mistakes — they are normal runs read as written
    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "x", "--new-epoch=false"], env.layer),
    ).toBe(0);
    expect(env.logs.join("\n")).toContain("epoch 1 → 2");
    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "x", "--new-epoch", "false"], env.layer),
    ).toBe(0);
    // The value is not dropped into an extra positional arg — it is consumed as the flag's value
    expect(env.errors.join("\n")).not.toContain("Unexpected extra arguments");
    // Writing the positional arg's name as an option is refused without
    // discarding the value (blocks the shape where `env rotate dev
    // --environment-id other` rotates dev). An environment ID is unique
    // across all chain history (§6.2), so a mix-up is permanent
    const beforeSwap = server.requests.length;
    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--reason", "x", "--environment-id", "other-env"],
        env.layer,
      ),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("--environment-id is a positional argument");
    // The mix-up check runs before any communication (never leaves a var.read under the wrong ID)
    expect(server.requests.length).toBe(beforeSwap);
    // Declared options that are not operation-only (--project etc.) are not
    // refused. The allowed set is derived from the argument table, so a
    // hand-written list never falls out of sync and rejects them (pins that
    // they **succeed**, not merely "are not refused" — so a loosened check
    // surfacing as a failure of the rotation itself is still noticed)
    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--reason", "x", "--project", chainBase.projectId],
        env.layer,
      ),
    ).toBe(0);
    // On the refused examples no HTTP happens at all (only the 2 normal-run examples communicate)
    expect(server.requests.length).toBeGreaterThan(0);
  });

  it("when the target environment sits inside a grant_server's disclosure scope, the complete set includes the server-addressed wrap and rotates (§12-4 / §7)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp([ENV_ID]) },
    ]);
    const grantEntry = built.entries[2];
    if (grantEntry?.op !== "grant_server") throw new Error("grant entry missing");
    const state = makeServer({
      built,
      variables: [],
      deks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "with grant"], env.layer)).toBe(0);
    expect(state.rotateBodies).toHaveLength(1);
    const body = state.rotateBodies[0] as {
      deks: readonly {
        recipientClass?: string;
        recipientUserId: string;
        recipientEncPubHex: string;
      }[];
    };
    // The complete set = the current members (owner) + the server key of an
    // in-scope grant (§7's re-wrap obligation — without the re-wrap the lease path stops)
    expect(body.deks).toHaveLength(2);
    const serverWrap = body.deks.find((wrap) => wrap.recipientClass === "server");
    expect(serverWrap?.recipientUserId).toBe(grantEntry.payload.serverKeyFingerprintHex);
    expect(serverWrap?.recipientEncPubHex).toBe(grantEntry.payload.serverEncPubHex);
  });

  it("a grant_server disclosing only a different environment never stops this environment's revocation rotation (§7)", async () => {
    // Epochs advance independently per environment (§3). If a grant
    // disclosing only dev blocked prod's rotation, the sole means needed for
    // member removal would stall on another environment's setting — the
    // judgment uses scope (§6.2's "subset of target environments")
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp(["other-env"]) },
    ]);
    const state = makeServer({
      built,
      variables: [],
      deks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "member removal"], env.layer)).toBe(
      0,
    );
    expect(state.rotateBodies).toHaveLength(1);
  });

  it("a reader cannot rotate (member or above — §6.2). Refused before any value fetch", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(reader, "reader") },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const state = makeServer({ built, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, reader);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "test"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reader");
    // It never even reaches a pull (a var.read record)
    expect(server.requests.filter((request) => request.path.endsWith("/pull"))).toHaveLength(0);
  });

  it("a run with nothing unfinished and no --reason only checks and writes nothing", async () => {
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    // The landing point of the re-run the partial-completion guidance
    // recommends. Requiring --reason here would demand a reason from the user
    // who re-ran as guided — and specifying one would trigger a second rotation
    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("Check complete");
    expect(env.logs.join("\n")).toContain("To create a new epoch, pass --reason");
    expect(server.requests.filter((request) => request.method === "POST")).toHaveLength(0);
  });

  it("a --new-epoch run without --reason fails before fetching values (leaves no var.read)", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    // --new-epoch always signs an entry = a reason is mandatory. Never goes to
    // fetch every variable's ciphertext for an unsatisfiable argument check
    // and leaves a per-variable var.read in the audit log (the same discipline as ensureRotatable)
    // A usage mistake (the missing reason) is a usage error (2) — so the same
    // `--reason` mistake never splits by exit code
    expect(await runCli(["env", "rotate", ENV_ID, "--new-epoch"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify the rotation reason with --reason");
    expect(server.requests.filter((request) => request.path.endsWith("/pull"))).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("an empty --reason fails instead of collapsing into 'check only' (never makes a successful exit that did nothing despite a request)", async () => {
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    // The `--reason "$UNSET_VAR"` shape. Treating it as unspecified would
    // leave the member-removal script believing "a new epoch was made" while
    // nothing was sent. An empty string is failed as a usage error (2) by the
    // shared argument check (a value indistinguishable from "unspecified"
    // never falls back to the default — ADR-0016 decision 2's NonBlank declaration)
    for (const empty of [["--reason", ""], ["--reason="]]) {
      expect(await runCli(["env", "rotate", ENV_ID, ...empty], env.layer)).toBe(2);
      expect(env.errors.join("\n")).toContain("Unacceptable value for flag --reason");
      expect(env.logs.join("\n")).not.toContain("Check complete");
    }
    // A whitespace-only value is also failed as empty by the shared check
    // (the unset form of `"$VAR"` can become `""` or `" "`)
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "  "], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Unacceptable value for flag --reason");
    expect(state.rotateBodies).toHaveLength(0);
    expect(server.requests.filter((request) => request.method === "POST")).toHaveLength(0);
  });

  it("the path that creates a new epoch requires --reason (also with --new-epoch given)", async () => {
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    expect(await runCli(["env", "rotate", ENV_ID, "--new-epoch"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--reason");
    expect(server.requests.filter((request) => request.method === "POST")).toHaveLength(0);
  });

  it("a rotation onto an environment absent from the chain is refused (create_environment never observed)", async () => {
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", "staging", "--reason", "test"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not exist on the chain");
    expect(state.rotateBodies).toHaveLength(0);
  });
});

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
  /** genesis + create dev(epoch 1、dek1)+ create ops(epoch 1、dekReceipts)。 */
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
            layoutVersion: 3,
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
