import {
  type BuiltChain,
  distributedEnvironmentStatement,
  distributedManifest,
  distributedValue,
  distributedVariableStatement,
  type GeneratedIdentity,
  generateIdentity,
  headOf,
  type WireDistributedEnvironmentStatement,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  type WireRecipientDek,
} from "@maruhi/test-kit";
import type { ApiSuccess } from "@maruhi/test-kit/api";
import { afterEach, beforeAll } from "vite-plus/test";

import { servedChainResponse } from "./chain-handler.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./env.ts";
import { rotatedEnvironmentFor } from "./rotated-environment.ts";
import { type MockHandler, MockServer, onEndpoint } from "./server.ts";

export const ENV_ID = "prod";

export interface Fixture {
  readonly owner: GeneratedIdentity;
  readonly built: BuiltChain;
  readonly dek1: Uint8Array;
  readonly dek2: Uint8Array;
  readonly wraps: readonly [WireRecipientDek, WireRecipientDek];
  readonly valueAlpha: WireDistributedValue;
  readonly valueBeta: WireDistributedValue;
  readonly envStatement: WireDistributedEnvironmentStatement;
  readonly entryAlpha: {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  };
  readonly entryBeta: {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  };
}

export let fixture: Fixture;
export let servers: MockServer[] = [];

export function genesisHead(projectId: string): { seq: number; hashHex: string } {
  return { seq: 1, hashHex: projectId };
}

export async function pullEntry(
  projectId: string,
  variableId: string,
  name: string,
  value: WireDistributedValue,
  author?: GeneratedIdentity,
  environmentId = ENV_ID,
): Promise<{
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
}> {
  return {
    variableId,
    statement: await distributedVariableStatement({
      projectId,
      environmentId,
      variableId,
      name,
      author: author ?? fixture.owner,
      head: genesisHead(projectId),
    }),
    value,
  };
}

export async function pullEnvStatement(
  projectId: string,
  author?: GeneratedIdentity,
  environmentId = ENV_ID,
): Promise<WireDistributedEnvironmentStatement> {
  return distributedEnvironmentStatement({
    projectId,
    environmentId,
    name: environmentId,
    author: author ?? fixture.owner,
    head: genesisHead(projectId),
  });
}

beforeAll(async () => {
  const owner = await generateIdentity("user-owner-1111");
  const dek1 = crypto.getRandomValues(new Uint8Array(32));
  const dek2 = crypto.getRandomValues(new Uint8Array(32));
  const { chain: built, wraps } = await rotatedEnvironmentFor({
    owner,
    environmentId: ENV_ID,
    dek1,
    dek2,
  });
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  const valueAlpha = await distributedValue({
    dek: dek2,
    ...common,
    epoch: 2,
    variableId: "va",
    version: 3,
    plaintext: "alpha-value",
    writer: owner,
    head: headOf(built, 3),
  });
  const valueBeta = await distributedValue({
    dek: dek1,
    ...common,
    epoch: 1,
    variableId: "vb",
    version: 1,
    plaintext: "beta-value",
    writer: owner,
    head: headOf(built, 2),
  });
  const envStatement = await distributedEnvironmentStatement({
    projectId: built.projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
  });
  const entryAlpha = {
    variableId: "va",
    statement: await distributedVariableStatement({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "va",
      name: "ALPHA",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
    }),
    value: valueAlpha,
  };
  const entryBeta = {
    variableId: "vb",
    statement: await distributedVariableStatement({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "vb",
      name: "BETA",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
    }),
    value: valueBeta,
  };
  fixture = {
    owner,
    built,
    dek1,
    dek2,
    wraps,
    valueAlpha,
    valueBeta,
    envStatement,
    entryAlpha,
    entryBeta,
  };
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

export function chainHandler(): MockHandler {
  const { built } = fixture;
  return onEndpoint("membership.get", { projectId: built.projectId }, () =>
    servedChainResponse(built.projectId, built.entries, built.hashes),
  );
}

type PullBody = ApiSuccess<"variables.pull">;

function digestStatementsOf(
  variables: PullBody["variables"],
  deletedVariables: PullBody["deletedVariables"],
  declaredVariables: readonly WireDistributedVariableStatement[] = [],
): readonly WireDistributedVariableStatement[] {
  const digestInputs = new Map<string, WireDistributedVariableStatement>();
  for (const entry of variables) {
    digestInputs.set(entry.statement.variableId, entry.statement);
  }
  for (const declared of declaredVariables) {
    digestInputs.set(declared.variableId, declared);
  }
  for (const tombstone of deletedVariables) {
    digestInputs.set(tombstone.variableId, tombstone);
  }
  return [...digestInputs.values()];
}

export function pullHandler(overrides?: {
  readonly deks?: PullBody["deks"];
  readonly variables?: PullBody["variables"];
  readonly deletedVariables?: PullBody["deletedVariables"];
  readonly declaredVariables?: readonly WireDistributedVariableStatement[];
  readonly statement?: PullBody["statement"];
  readonly digestDeclared?: readonly WireDistributedVariableStatement[];
}): MockHandler {
  const { built, wraps, entryAlpha, entryBeta, envStatement } = fixture;
  const resolved: {
    readonly statement: PullBody["statement"];
    readonly variables: PullBody["variables"];
    readonly deletedVariables: PullBody["deletedVariables"];
    readonly declaredVariables: readonly WireDistributedVariableStatement[];
    readonly deks: PullBody["deks"];
    readonly digestDeclared?: readonly WireDistributedVariableStatement[];
  } = {
    statement: envStatement,
    variables: [entryAlpha, entryBeta],
    deletedVariables: [],
    declaredVariables: [],
    deks: wraps,
    ...overrides,
  };
  return onEndpoint(
    "variables.pull",
    { projectId: built.projectId, environmentId: ENV_ID },
    async () => {
      const manifest = await distributedManifest({
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 2,
        issuer: fixture.owner,
        head: headOf(built, 3),
        envStatement: resolved.statement,
        statements: digestStatementsOf(
          resolved.variables,
          resolved.deletedVariables,
          resolved.digestDeclared ?? resolved.declaredVariables,
        ),
      });
      return {
        status: 200,
        json: {
          environmentId: ENV_ID,
          currentEpoch: 2,
          statement: resolved.statement,
          variables: resolved.variables,
          deletedVariables: resolved.deletedVariables,
          ...(resolved.declaredVariables.length === 0
            ? {}
            : { declaredVariables: resolved.declaredVariables }),
          deks: resolved.deks,
          manifest,
          schemaPolicy: "enabled" as const,
        },
      };
    },
  );
}

export async function startEnv(handlers: readonly MockHandler[]): Promise<TestEnv> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, fixture.owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: fixture.built.projectId,
    defaultEnvironment: ENV_ID,
  });
  return env;
}
