import type { WrappedDek } from "@maruhi/api-schema";
import type { ChainEntry } from "@maruhi/crypto";
import {
  computeChainEntryHash,
  signChainEntry,
  SUITE_ID,
  importEncryptionKeyPair,
  importSigningPublicKey,
  unwrapDek,
  verifyDekWrapSignature,
} from "@maruhi/crypto";
import { Effect } from "effect";
import { afterEach, beforeAll, expect } from "vitest";

import { makeFileFloorStore } from "../../src/floor-log.ts";
import type { ProjectFloor } from "../../src/floor.ts";
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
  manifestFor,
  manifestHashOf,
  rotateEpochOp,
  checkpointSnapshotValuesOf,
  statementFor,
  type TestUser,
  variablesDigestOf,
  type WireCheckpointSnapshot,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  type WireRecipientDek,
  type WireRotateBody,
} from "./crypto.ts";
import { testEnvironmentId, testProjectId } from "./crypto.ts";
import { testUserId } from "./crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./env.ts";
import { type MockHandler, type MockResponse, MockServer, onRequest } from "./server.ts";

export const ENV_ID = "dev";

/** One variable of a pull response (verified statement + distribution-form value). */
export interface PulledVariable {
  readonly variableId: string;
  readonly statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
}

export let owner: TestUser;
export let reader: TestUser;
export let dek1: Uint8Array;
export let dek2: Uint8Array;
export let dek3: Uint8Array;
/** genesis + create_environment (epoch 1). */
export let chainBase: BuiltChain;
/** The shape with rotate_epoch (epoch 2, DEK = dek2) stacked onto the same genesis. */
export let chainRotated: BuiltChain;
/** The shape with a further rotate_epoch (epoch 3, DEK = dek3) stacked on top. */
export let chainRotatedTwice: BuiltChain;
export let envStatement: WireDistributedEnvironmentStatement;
export let servers: MockServer[] = [];

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
export async function variableAt(input: {
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

export interface ServerOptions {
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

export interface ServerState {
  readonly handlers: readonly MockHandler[];
  readonly rotateBodies: WireRotateBody[];
  readonly pushes: {
    readonly variableId: string;
    readonly value: WireDistributedValue;
    /** The request's value-lineage declaration (AUTH_SPEC §12-5 — omitted is recorded as undefined). */
    readonly sameValueAs: number | undefined;
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
export function makeServer(options: ServerOptions): ServerState {
  const projectId = chainBase.projectId;
  const entries: ChainEntry[] = [...options.built.entries];
  const hashes: string[] = [...options.built.hashes];
  const variables = options.variables;
  const deletedVariables = options.deletedVariables ?? [];
  const deks = options.deks;
  const rotateBodies: WireRotateBody[] = [];
  const pushes: {
    variableId: string;
    value: WireDistributedValue;
    sameValueAs: number | undefined;
  }[] = [];
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
  const acceptRotate = async (body: WireRotateBody): Promise<void> => {
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
        recipientEncPubHex: wrap.recipientEncPubHex,
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
            attestations: [],
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
            schemaPolicy: "enabled" as const,
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
      const body = request.body as WireRotateBody;
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
        readonly sameValueAs?: number;
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
      pushes.push({ variableId, value: stored, sameValueAs: body.sameValueAs });
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
export async function loadFloor(env: TestEnv): Promise<ProjectFloor | null> {
  const loaded = await Effect.runPromise(
    makeFileFloorStore(env.floorDir).load(testProjectId(chainBase.projectId)),
  );
  return loaded.floor;
}

export async function startEnv(handlers: readonly MockHandler[], user: TestUser): Promise<TestEnv> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, user);
  await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });
  return env;
}

/** §5.1 signature verification of one wrap + the recipient's opening (same shape as env-create.test.ts). */
export async function verifyAndUnwrap(input: {
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
      projectId: testProjectId(chainBase.projectId),
      environmentId: testEnvironmentId(ENV_ID),
      epoch: wrap.epoch,
      recipientUserId: testUserId(wrap.recipientUserId),
      recipientEncPubHex: wrap.recipientEncPubHex,
      encHex: wrap.encHex,
      ciphertextHex: wrap.ciphertextHex,
      signerUserId: testUserId(signer.userId),
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
      projectId: testProjectId(chainBase.projectId),
      environmentId: testEnvironmentId(ENV_ID),
      epoch: wrap.epoch,
      recipientUserId: testUserId(wrap.recipientUserId),
    },
  });
  if (!dek.ok) {
    throw new Error("unwrap failed");
  }
  return dek.value;
}

/** Extracts the new-epoch DEK the runner generated, from the composite's bundled wraps. */
export async function newEpochDekOf(body: WireRotateBody): Promise<Uint8Array> {
  const wrap = body.deks.find((candidate) => candidate.recipientUserId === owner.userId);
  if (wrap === undefined) {
    throw new Error("owner wrap missing");
  }
  return verifyAndUnwrap({ wrap, recipient: owner, signer: owner });
}
