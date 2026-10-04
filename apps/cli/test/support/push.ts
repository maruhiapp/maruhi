import { decryptVariable } from "@maruhi/crypto";
import { afterEach, beforeAll } from "vitest";

import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  hexBytes,
  makeTestUser,
  manifestFor,
  manifestHashOf,
  rotateEpochOp,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedVariableStatement,
  type WireEncryptedPayload,
  wrapDekFor,
  type WireRecipientDek,
} from "./crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./env.ts";
import { type MockHandler, MockServer, onRequest } from "./server.ts";

export const ENV_ID = "dev";

export let owner: TestUser;
export let chainV1: BuiltChain;
export let chainV2: BuiltChain;
export let dek1: Uint8Array;
export let dek2: Uint8Array;
export let wrap1: WireRecipientDek;
export let wrap2: WireRecipientDek;
export let envStatement: WireDistributedEnvironmentStatement;
export let servers: MockServer[] = [];

/** One variable of a pull response (verified statement + value). The declared head is genesis. */
export async function entryOf(
  variableId: string,
  name: string,
  value: WireEncryptedPayload,
): Promise<{
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireEncryptedPayload;
}> {
  return {
    variableId,
    statement: await statementFor({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId,
      name,
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
    }),
    value,
  };
}

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  chainV1 = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
  ]);
  // The shape where a rotation is stacked on the same genesis (same project)
  chainV2 = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
  const common = { projectId: chainV1.projectId, environmentId: ENV_ID };
  wrap1 = await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner });
  wrap2 = await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner });
  envStatement = await environmentStatementFor({
    projectId: chainV1.projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: { seq: 1, hashHex: chainV1.projectId },
  });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

export function chainHandlerOf(chains: readonly BuiltChain[]): MockHandler {
  // Advances on each call (the EpochConflict resync reveals the new chain). Stops at the last one
  let call = 0;
  return onRequest("GET", `/projects/${chainV1.projectId}/chain`, () => {
    const built = chains[Math.min(call, chains.length - 1)] as BuiltChain;
    call += 1;
    return {
      status: 200,
      json: {
        projectId: chainV1.projectId,
        entries: built.entries,
        headSeq: built.entries.length,
        headHashHex: built.hashes[built.hashes.length - 1],
        attestations: [],
      },
    };
  });
}

export function deksHandlerOf(sets: readonly (readonly WireRecipientDek[])[]): MockHandler {
  let call = 0;
  return onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/deks`, () => {
    const deks = sets[Math.min(call, sets.length - 1)] ?? [];
    call += 1;
    return { status: 200, json: { deks } };
  });
}

/**
 * The manifest computed from the distributed set itself (§12-7). Ed25519 is
 * deterministic, so recomputing the same set matches byte-exactly (no equivocation).
 */
export async function manifestOf(
  statements: readonly WireDistributedVariableStatement[],
  currentEpoch = 1,
  manifestVersion = 1,
  prevManifestSigHashHex?: string,
): Promise<unknown> {
  return manifestFor({
    projectId: chainV1.projectId,
    environmentId: ENV_ID,
    epoch: currentEpoch,
    issuer: owner,
    head: currentEpoch === 1 ? headOf(chainV1, 2) : headOf(chainV2, 3),
    envStatement,
    statements,
    manifestVersion,
    ...(prevManifestSigHashHex === undefined ? {} : { prevManifestSigHashHex }),
  });
}

/** The response JSON of a value-bearing pull (§12-7) — manifest bundled. */
export async function pullJsonOf(
  variables: readonly {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireEncryptedPayload;
  }[],
  deks: readonly WireRecipientDek[],
  currentEpoch = 1,
  /** A response whose meta set changes takes the next version (a same-version set difference is equivocation). */
  manifestVersion = 1,
  /** prev for version > 1 (the previous manifest's hash — the chain for the adjacent prev check). */
  prevManifestSigHashHex?: string,
): Promise<unknown> {
  return {
    environmentId: ENV_ID,
    currentEpoch,
    statement: envStatement,
    variables,
    deletedVariables: [],
    deks,
    manifest: await manifestOf(
      variables.map((variable) => variable.statement),
      currentEpoch,
      manifestVersion,
      prevManifestSigHashHex,
    ),
    schemaPolicy: "enabled" as const,
  };
}

/** The signed-bytes hash of the manifest for a given set · version (material for the next version's prev). */
export async function manifestHashAt(
  statements: readonly WireDistributedVariableStatement[],
  currentEpoch = 1,
  manifestVersion = 1,
  prevManifestSigHashHex?: string,
): Promise<string> {
  return manifestHashOf(
    chainV1.projectId,
    (await manifestOf(
      statements,
      currentEpoch,
      manifestVersion,
      prevManifestSigHashHex,
    )) as WireDistributedManifest,
  );
}

export function pullHandlerOf(
  variables: readonly {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireEncryptedPayload;
  }[],
  deks: readonly WireRecipientDek[],
): MockHandler {
  return onRequest(
    "GET",
    `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`,
    async () => ({
      status: 200,
      json: await pullJsonOf(variables, deks),
    }),
  );
}

/**
 * The box that records variable-creation acceptances (shared state so the
 * §12-10 (3) confirmation pull can mimic distributing the accepted statement + manifest).
 */
export interface CreateEcho {
  body: CreateBody | null;
  /** The variant that became the creation's issueBase (distributed set = variant + creation statement). */
  baseVariant: readonly WireDistributedVariableStatement[];
}

/** Issued form → distributed form (§12-2 — the server attaches the caller's attribution). */
export function distributedStatementOf(body: CreateBody): WireDistributedVariableStatement {
  return {
    ...body.statement,
    authorUserId: owner.userId,
    authorKeyFingerprintHex: owner.fingerprintHex,
  } as WireDistributedVariableStatement;
}

/**
 * The response of a metadata-only pull (§12-7). Advances through variants on
 * each call (stops at the last). Manifests between variants actually chain
 * their prev (models a legitimate "another member's meta operation" that
 * satisfies the adjacent-version prev check).
 * When `echo` holds an accepted creation, it returns that distribution
 * (variant + creation statement + accepted manifest) — material for the confirmation (§12-10 (3)).
 */
export function pullMetadataHandlerOf(
  variants: readonly (readonly WireDistributedVariableStatement[])[],
  currentEpoch = 1,
  echo?: CreateEcho,
): MockHandler {
  let call = 0;
  const manifests: WireDistributedManifest[] = [];
  const manifestAt = async (index: number): Promise<WireDistributedManifest> => {
    for (let position = manifests.length; position <= index; position += 1) {
      const previous = manifests[position - 1];
      manifests[position] = (await manifestOf(
        variants[position] ?? [],
        currentEpoch,
        position + 1,
        previous === undefined ? undefined : await manifestHashOf(chainV1.projectId, previous),
      )) as WireDistributedManifest;
    }
    return manifests[index] as WireDistributedManifest;
  };
  return onRequest(
    "GET",
    `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull/metadata`,
    async () => {
      if (echo !== undefined && echo.body !== null) {
        // Accepted: the distributed form = the issueBase set + creation
        // statement; the manifest = the accepted issued form + issuer
        // attribution (isomorphic to acceptRotate in support/env-rotate.ts)
        return {
          status: 200,
          json: {
            environmentId: ENV_ID,
            currentEpoch,
            statement: envStatement,
            variables: [...echo.baseVariant, distributedStatementOf(echo.body)],
            deletedVariables: [],
            manifest: {
              ...echo.body.manifest,
              issuerUserId: owner.userId,
              issuerKeyFingerprintHex: owner.fingerprintHex,
            },
            schemaPolicy: "enabled" as const,
          },
        };
      }
      const index = Math.min(call, variants.length - 1);
      const variables = variants[index] ?? [];
      call += 1;
      return {
        status: 200,
        json: {
          environmentId: ENV_ID,
          currentEpoch,
          statement: envStatement,
          variables,
          deletedVariables: [],
          // A variant advance = one meta operation by another member, modeled.
          // manifestVersion advances with it (consistent with the floor's monotonicity)
          manifest: await manifestAt(index),
          schemaPolicy: "enabled" as const,
        },
      };
    },
  );
}

export async function startEnv(handlers: readonly MockHandler[], stdin: string): Promise<TestEnv> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: chainV1.projectId,
    defaultEnvironment: ENV_ID,
  });
  env.setStdin(new TextEncoder().encode(stdin));
  return env;
}

export interface CreateBody {
  readonly statement: WireDistributedVariableStatement;
  readonly value: WireEncryptedPayload;
  /** The bundled manifest (§12-4 — variable creation also re-issues the manifest). */
  readonly manifest: {
    readonly environmentId: string;
    readonly epoch: number;
    readonly manifestVersion: number;
    readonly variablesDigestHex: string;
    readonly envMetaVersion: number;
    readonly envMetaSigHashHex: string;
    readonly prevManifestSigHashHex: string;
    readonly chainHeadHashHex: string;
    readonly chainHeadSeq: number;
    readonly signatureHex: string;
  };
}

export async function decryptWire(dek: Uint8Array, value: WireEncryptedPayload): Promise<string> {
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
