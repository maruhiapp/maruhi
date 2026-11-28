import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  distributedEnvironmentStatement,
  distributedManifest,
  distributedManifestHashOf,
  distributedVariableStatement,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  headOf,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedVariableStatement,
  type WireEncryptedPayload,
  type WireRecipientDek,
} from "@maruhi/test-kit";
import { afterEach, beforeAll } from "vite-plus/test";

import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./env.ts";
import { rotatedEnvironmentFor } from "./rotated-environment.ts";
import { type MockHandler, MockServer, onRequest } from "./server.ts";

export const ENV_ID = "dev";

export let owner: GeneratedIdentity;
export let chainV1: BuiltChain;
export let chainV2: BuiltChain;
export let dek1: Uint8Array;
export let dek2: Uint8Array;
export let wrap1: WireRecipientDek;
export let wrap2: WireRecipientDek;
export let envStatement: WireDistributedEnvironmentStatement;
export let servers: MockServer[] = [];

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
    statement: await distributedVariableStatement({
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
  owner = await generateIdentity("user-owner-1111");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  chainV1 = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
  ]);
  const rotated = await rotatedEnvironmentFor({ owner, environmentId: ENV_ID, dek1, dek2 });
  chainV2 = rotated.chain;
  [wrap1, wrap2] = rotated.wraps;
  envStatement = await distributedEnvironmentStatement({
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

export async function manifestOf(
  statements: readonly WireDistributedVariableStatement[],
  currentEpoch = 1,
  manifestVersion = 1,
  prevManifestSigHashHex?: string,
): Promise<unknown> {
  return distributedManifest({
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

export async function pullJsonOf(
  variables: readonly {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireEncryptedPayload;
  }[],
  deks: readonly WireRecipientDek[],
  currentEpoch = 1,
  manifestVersion = 1,
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

export async function manifestHashAt(
  statements: readonly WireDistributedVariableStatement[],
  currentEpoch = 1,
  manifestVersion = 1,
  prevManifestSigHashHex?: string,
): Promise<string> {
  return distributedManifestHashOf(
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

export interface CreateEcho {
  body: CreateBody | null;
  baseVariant: readonly WireDistributedVariableStatement[];
}

export function distributedStatementOf(body: CreateBody): WireDistributedVariableStatement {
  return {
    ...body.statement,
    authorUserId: owner.userId,
    authorKeyFingerprintHex: owner.fingerprintHex,
  } as WireDistributedVariableStatement;
}

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
        previous === undefined
          ? undefined
          : await distributedManifestHashOf(chainV1.projectId, previous),
      )) as WireDistributedManifest;
    }
    return manifests[index] as WireDistributedManifest;
  };
  return onRequest(
    "GET",
    `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull/metadata`,
    async () => {
      if (echo !== undefined && echo.body !== null) {
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
