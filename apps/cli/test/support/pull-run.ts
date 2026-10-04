import { afterEach, beforeAll } from "vitest";

import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  rotateEpochOp,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  type WireRecipientDek,
  wrapDekFor,
} from "./crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./env.ts";
import { type MockHandler, MockServer, onRequest } from "./server.ts";

export const ENV_ID = "prod";

export interface Fixture {
  readonly owner: TestUser;
  readonly built: BuiltChain;
  readonly dek1: Uint8Array;
  readonly dek2: Uint8Array;
  readonly wraps: readonly WireRecipientDek[];
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

/** A declaration headed by genesis (seq 1's entry hash = projectId — exists in every extension view). */
export function genesisHead(projectId: string): { seq: number; hashHex: string } {
  return { seq: 1, hashHex: projectId };
}

/**
 * One variable of a pull response (verified statement + value — the §12-7 wire shape).
 * The statement's declared head is genesis (meta carries no epoch anchor, so
 * any view verifies when author is member-or-above — §4.2).
 */
export async function pullEntry(
  projectId: string,
  variableId: string,
  name: string,
  value: WireDistributedValue,
  author?: TestUser,
  environmentId = ENV_ID,
): Promise<{
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
}> {
  return {
    variableId,
    statement: await statementFor({
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

/** The environment statement of a pull response (active · metaVersion 1 · genesis head). */
export async function pullEnvStatement(
  projectId: string,
  author?: TestUser,
  environmentId = ENV_ID,
): Promise<WireDistributedEnvironmentStatement> {
  return environmentStatementFor({
    projectId,
    environmentId,
    name: environmentId,
    author: author ?? fixture.owner,
    head: genesisHead(projectId),
  });
}

beforeAll(async () => {
  const owner = await makeTestUser("user-owner-1111");
  const dek1 = crypto.getRandomValues(new Uint8Array(32));
  const dek2 = crypto.getRandomValues(new Uint8Array(32));
  // The chain carries the real DEK's commitment (§5.2 — real data down to the pull comparison)
  const built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  const wraps = [
    await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
    await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
  ];
  // The latest version's epoch differs per variable (§12-7): ALPHA is epoch 2,
  // BETA stays at epoch 1, never re-encrypted after the rotation.
  // The value signature (§4.1) declares the head where each epoch was current (inclusive):
  // ALPHA = seq 3 (rotate), BETA = seq 2 (create)
  const valueAlpha = await encryptValueFor({
    dek: dek2,
    ...common,
    epoch: 2,
    variableId: "va",
    version: 3,
    plaintext: "alpha-value",
    writer: owner,
    head: headOf(built, 3),
  });
  const valueBeta = await encryptValueFor({
    dek: dek1,
    ...common,
    epoch: 1,
    variableId: "vb",
    version: 1,
    plaintext: "beta-value",
    writer: owner,
    head: headOf(built, 2),
  });
  const envStatement = await environmentStatementFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
  });
  const entryAlpha = {
    variableId: "va",
    statement: await statementFor({
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
    statement: await statementFor({
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
  return onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
    status: 200,
    json: {
      projectId: built.projectId,
      entries: built.entries,
      headSeq: built.entries.length,
      headHashHex: built.hashes[built.hashes.length - 1],
      attestations: [],
    },
  }));
}

/**
 * Distributed set (after overrides) → digest input. Overrides with duplicate
 * variableIds fold last-wins because the digest computation rejects them (the
 * duplicate itself is refused by the client before manifest verification).
 */
function digestStatementsOf(
  variables: readonly unknown[],
  deletedVariables: readonly unknown[],
  declaredVariables: readonly unknown[] = [],
): readonly WireDistributedVariableStatement[] {
  const digestInputs = new Map<string, WireDistributedVariableStatement>();
  for (const entry of variables as readonly {
    readonly statement: WireDistributedVariableStatement;
  }[]) {
    digestInputs.set(entry.statement.variableId, entry.statement);
  }
  for (const declared of declaredVariables as readonly WireDistributedVariableStatement[]) {
    digestInputs.set(declared.variableId, declared);
  }
  for (const tombstone of deletedVariables as readonly WireDistributedVariableStatement[]) {
    digestInputs.set(tombstone.variableId, tombstone);
  }
  return [...digestInputs.values()];
}

export function pullHandler(overrides?: {
  readonly deks?: readonly unknown[];
  readonly variables?: readonly unknown[];
  readonly deletedVariables?: readonly unknown[];
  readonly declaredVariables?: readonly unknown[];
  readonly statement?: unknown;
  /** Overrides for the manifest's digest input (for building absence negatives). */
  readonly digestDeclared?: readonly unknown[];
}): MockHandler {
  const { built, wraps, entryAlpha, entryBeta, envStatement } = fixture;
  // Default + test overrides (spread replaces only existing keys)
  const resolved = {
    statement: envStatement as unknown,
    variables: [entryAlpha, entryBeta] as readonly unknown[],
    deletedVariables: [] as readonly unknown[],
    declaredVariables: [] as readonly unknown[],
    deks: wraps as readonly unknown[],
    digestDeclared: undefined as readonly unknown[] | undefined,
    ...overrides,
    schemaPolicy: "enabled" as const,
  };
  return onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull`, async () => {
    // The manifest (§12-7) is computed from **the distributed set itself**
    // (matching even sets tampered with / swapped via override — each test's
    // negative verifies it is rejected by statement / value verification, not by the manifest)
    const manifest = await manifestFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      issuer: fixture.owner,
      head: headOf(built, 3),
      envStatement: resolved.statement as WireDistributedEnvironmentStatement,
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
  });
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
