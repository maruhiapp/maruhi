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
import { afterEach, beforeAll, expect } from "vite-plus/test";

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
export let chainBase: BuiltChain;
export let chainRotated: BuiltChain;
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

export async function variableAt(input: {
  readonly built: BuiltChain;
  readonly variableId: string;
  readonly name: string;
  readonly dek: Uint8Array;
  readonly epoch: number;
  readonly version: number;
  readonly plaintext: string;
  readonly headSeq: number;
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
  readonly deletedVariables?: WireDistributedVariableStatement[];
  readonly deks: WireRecipientDek[];
  readonly currentEpoch: number;
  readonly onRotate?: (call: number) => MockResponse | undefined;
  readonly onRotateAccepted?: (chain: {
    readonly entries: readonly ChainEntry[];
    readonly hashes: readonly string[];
  }) => Promise<void> | void;
  readonly onRotateAfterAccept?: (call: number) => MockResponse | undefined;
  readonly onPush?: (call: number, variableId: string) => MockResponse | undefined;
  readonly onPull?: (call: number) => MockResponse | undefined;
  readonly onChain?: (call: number) => MockResponse | undefined;
  readonly chainAfterRotateAttempt?: BuiltChain | undefined;
  readonly appendRotateAfterAccept?: { readonly epoch: number; readonly dek: Uint8Array };
  readonly dropCheckpointFromChain?: boolean;
  readonly standaloneCheckpoint?: { readonly auditHeadHashHex: string };
}

export interface ServerState {
  readonly handlers: readonly MockHandler[];
  readonly rotateBodies: WireRotateBody[];
  readonly pushes: {
    readonly variableId: string;
    readonly value: WireDistributedValue;
    readonly sameValueAs: number | undefined;
  }[];
  readonly chainEntries: readonly ChainEntry[];
}

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
  let manifestState: {
    key: string;
    manifest: WireDistributedManifest;
    version: number;
  } | null = null;
  let checkpointSnapshot: WireCheckpointSnapshot | null = null;
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

  const acceptRotate = async (body: WireRotateBody): Promise<void> => {
    if (options.dropCheckpointFromChain === true) {
      entries.push(body.entry);
      hashes.push(await computeChainEntryHash(body.entry));
    } else {
      entries.push(body.entry, body.checkpoint);
      hashes.push(
        await computeChainEntryHash(body.entry),
        await computeChainEntryHash(body.checkpoint),
      );
      await storeCheckpointSnapshot(body.checkpoint);
    }
    currentEpoch = body.entry.payload.newEpoch;
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

export async function newEpochDekOf(body: WireRotateBody): Promise<Uint8Array> {
  const wrap = body.deks.find((candidate) => candidate.recipientUserId === owner.userId);
  if (wrap === undefined) {
    throw new Error("owner wrap missing");
  }
  return verifyAndUnwrap({ wrap, recipient: owner, signer: owner });
}
