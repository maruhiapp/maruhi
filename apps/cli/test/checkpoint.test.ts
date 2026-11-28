import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { ChainEntry, ChainOperation } from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeEnvValuesDigest,
  signChainEntry,
  SUITE_ID,
} from "@maruhi/crypto";
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
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  headOf,
  testEnvironmentId,
  testProjectId,
  testUserId,
  testVariableId,
  valueSignedBytesHashOf,
  type WireCheckpointSnapshot,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
} from "@maruhi/test-kit";
import type { ApiSuccess } from "@maruhi/test-kit/api";
import { Effect } from "effect";
import { FetchHttpClient } from "effect/http";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { makeApiClient } from "../src/api.ts";
import { verifyChainSnapshot } from "../src/chain-sync.ts";
import { checkpointProposal, issueCheckpoint } from "../src/checkpoint.package/checkpoint.ts";
import { runCli } from "../src/cli.ts";
import { makeFloorHandle } from "../src/floor-check.ts";
import { makeFileFloorStore } from "../src/floor-log.ts";
import { servedChain } from "./support/chain-handler.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import {
  type EndpointAnswer,
  type MockHandler,
  type MockResponse,
  MockServer,
  onEndpoint,
} from "./support/server.ts";

const ENV_A = "alpha";
const ENV_B = "dev";

let owner: GeneratedIdentity;
let member: GeneratedIdentity;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await generateIdentity("user-owner-1111");
  member = await generateIdentity("user-member-3333");
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

interface MockEnvironment {
  readonly environmentId: string;
  statement: WireDistributedEnvironmentStatement;
  manifest: WireDistributedManifest;
  variables: {
    readonly variableId: string;
    readonly statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  }[];
  nextValues?: WireDistributedValue[];
  checkpointSnapshot?: WireCheckpointSnapshot;
}

interface CheckpointServerOptions {
  readonly built: BuiltChain;
  readonly environments: MockEnvironment[];
  readonly me: {
    readonly userId: string;
    readonly tokenScopes?: NonNullable<ApiSuccess<"auth.me">["tokenScopes"]>;
  };
  readonly auditHeadHashHex?: string;
  readonly onAuditHead?: (call: number) => EndpointAnswer<"audit.auditHead"> | undefined;
  readonly onAppend?: (call: number, body: AppendBody) => MockResponse | undefined;
  readonly acceptWithoutAppending?: boolean;
  readonly firstFetchEntries?: number;
}

interface AppendBody {
  readonly parentHeadHashHex: string;
  readonly entry: ChainEntry & { readonly op: "checkpoint" };
}

interface CheckpointServerState {
  readonly handlers: readonly MockHandler[];
  readonly appends: AppendBody[];
  readonly auditHeadCalls: () => number;
  readonly entries: ChainEntry[];
}

function makeCheckpointServer(options: CheckpointServerOptions): CheckpointServerState {
  const projectId = options.built.projectId;
  const entries: ChainEntry[] = [...options.built.entries];
  const hashes: string[] = [...options.built.hashes];
  const appends: AppendBody[] = [];
  let appendCalls = 0;
  let auditHeadCalls = 0;
  let chainCalls = 0;
  const handlers: MockHandler[] = [
    onEndpoint("membership.get", { projectId }, () => {
      const served =
        chainCalls === 0 && options.firstFetchEntries !== undefined
          ? options.firstFetchEntries
          : entries.length;
      chainCalls += 1;
      return {
        status: 200,
        json: servedChain(projectId, entries.slice(0, served), hashes.slice(0, served)),
      };
    }),
    onEndpoint("environments.list", { projectId }, () => ({
      status: 200,
      json: {
        environments: options.environments.map((environment) => ({
          environmentId: environment.environmentId,
          currentEpoch: 1,
          statement: environment.statement,
        })),
        schemaPolicy: "enabled",
      },
    })),
    onEndpoint("auth.me", () => ({
      status: 200,
      json: {
        userId: options.me.userId,
        orgs: [],
        ...(options.me.tokenScopes === undefined ? {} : { tokenScopes: options.me.tokenScopes }),
      },
    })),
    onEndpoint("audit.auditHead", { projectId }, () => {
      const injected = options.onAuditHead?.(auditHeadCalls);
      auditHeadCalls += 1;
      if (injected !== undefined) {
        return injected;
      }
      return { status: 200, json: { auditHeadHashHex: options.auditHeadHashHex ?? "" } };
    }),
    async (request) => {
      if (request.method !== "POST" || request.path !== `/projects/${projectId}/chain/entries`) {
        return null;
      }
      const body = request.body as AppendBody;
      appends.push(body);
      const injected = options.onAppend?.(appendCalls, body);
      appendCalls += 1;
      if (injected !== undefined) {
        return injected;
      }
      if (options.acceptWithoutAppending !== true) {
        entries.push(body.entry);
        hashes.push(await computeChainEntryHash(body.entry));
      }
      return {
        status: 200,
        json: { projectId, headSeq: entries.length, headHashHex: hashes[hashes.length - 1] },
      };
    },
    ...options.environments.map((environment): MockHandler => (request) => {
      if (
        request.method !== "GET" ||
        request.path !== `/projects/${projectId}/environments/${environment.environmentId}/pull`
      ) {
        return null;
      }
      const next = environment.nextValues?.shift();
      if (next !== undefined && environment.variables[0] !== undefined) {
        environment.variables[0].value = next;
      }
      return {
        status: 200,
        json: {
          environmentId: environment.environmentId,
          currentEpoch: 1,
          statement: environment.statement,
          variables: environment.variables.map((variable) => ({
            variableId: variable.variableId,
            statement: variable.statement,
            value: variable.value,
          })),
          deletedVariables: [],
          deks: [],
          manifest: environment.manifest,
          ...(environment.checkpointSnapshot === undefined
            ? {}
            : { checkpointSnapshot: environment.checkpointSnapshot }),
          schemaPolicy: "enabled" as const,
        },
      };
    }),
  ];
  return { handlers, appends, auditHeadCalls: () => auditHeadCalls, entries };
}

async function makeEnvironment(input: {
  readonly built: BuiltChain;
  readonly environmentId: string;
  readonly dek: Uint8Array;
  readonly headSeq: number;
  readonly issuer: GeneratedIdentity;
  readonly variableId: string;
}): Promise<MockEnvironment> {
  const head = headOf(input.built, input.headSeq);
  const statement = await distributedEnvironmentStatement({
    projectId: input.built.projectId,
    environmentId: input.environmentId,
    name: input.environmentId,
    author: input.issuer,
    head,
  });
  const variableStatement = await distributedVariableStatement({
    projectId: input.built.projectId,
    environmentId: input.environmentId,
    variableId: input.variableId,
    name: `VAR_${input.environmentId.toUpperCase()}`,
    author: input.issuer,
    head,
  });
  const value = await distributedValue({
    dek: input.dek,
    projectId: input.built.projectId,
    environmentId: input.environmentId,
    epoch: 1,
    variableId: input.variableId,
    version: 1,
    plaintext: "secret-alpha",
    writer: input.issuer,
    head,
  });
  const manifest = await distributedManifest({
    projectId: input.built.projectId,
    environmentId: input.environmentId,
    epoch: 1,
    issuer: input.issuer,
    head,
    envStatement: statement,
    statements: [variableStatement],
    manifestVersion: 1,
  });
  return {
    environmentId: input.environmentId,
    statement,
    manifest,
    variables: [{ variableId: input.variableId, statement: variableStatement, value }],
  };
}

async function seededEnv(
  server: MockServer,
  projectId: string,
  user: GeneratedIdentity,
): Promise<TestEnv> {
  const env = await makeTestEnv();
  seedSession(env, server.origin, user);
  await seedConfig(env, { server: server.origin, defaultProject: projectId });
  return env;
}

async function valuesDigestOf(values: readonly WireDistributedValue[]): Promise<string> {
  const entries = await Promise.all(
    values.map(async (value) => ({
      variableId: testVariableId(value.aad.variableId),
      version: value.aad.version,
      valueSigHashHex: await valueSignedBytesHashOf(value, value.writerUserId),
    })),
  );
  const digest = await computeEnvValuesDigest(SUITE_ID, entries);
  if (!digest.ok) {
    throw new Error("digest failed");
  }
  return digest.value;
}

async function expectedValuesDigest(environment: MockEnvironment): Promise<string> {
  return valuesDigestOf(environment.variables.map((variable) => variable.value));
}

type CheckpointPayload = Extract<ChainOperation, { readonly op: "checkpoint" }>["payload"];

async function tupleOf(
  projectId: string,
  environment: MockEnvironment,
  values: readonly WireDistributedValue[] = environment.variables.map((variable) => variable.value),
): Promise<CheckpointPayload["environments"][number]> {
  return {
    environmentId: testEnvironmentId(environment.environmentId),
    epoch: 1,
    manifestVersion: environment.manifest.manifestVersion,
    manifestSigHashHex: await distributedManifestHashOf(projectId, environment.manifest),
    valuesDigestHex: await valuesDigestOf(values),
  };
}

async function appendSignedCheckpoint(
  built: BuiltChain,
  payload: CheckpointPayload,
  timestampMs: number,
): Promise<BuiltChain> {
  const signed = await signChainEntry({
    entry: {
      suite: SUITE_ID,
      seq: built.entries.length + 1,
      prevHashHex: built.hashes[built.hashes.length - 1] ?? "",
      op: "checkpoint",
      actor: { userId: owner.userId, keyFingerprintHex: owner.fingerprintHex },
      payload,
      timestampMs,
    },
    signingKey: owner.sigKeyPair.privateKey,
  });
  if (!signed.ok) throw new Error("sign failed");
  return {
    ...built,
    entries: [...built.entries, signed.value],
    hashes: [...built.hashes, await computeChainEntryHash(signed.value)],
  };
}

describe("maruhi project checkpoint (trigger (ii) — CRYPTO_SPEC §6.3 / AUTH_SPEC §16-2)", () => {
  it("builds the tuple from the verified view and issues with byte-ordered full-environment coverage + audit-head notarization", async () => {
    const dekA = crypto.getRandomValues(new Uint8Array(32));
    const dekB = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_B, dekB) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dekA) },
    ]);
    const head = "ab".repeat(32);
    const environments = [
      await makeEnvironment({
        built,
        environmentId: ENV_B,
        dek: dekB,
        headSeq: 3,
        issuer: owner,
        variableId: testVariableId("var-b"),
      }),
      await makeEnvironment({
        built,
        environmentId: ENV_A,
        dek: dekA,
        headSeq: 3,
        issuer: owner,
        variableId: "var-a",
      }),
    ];
    const state = makeCheckpointServer({
      built,
      environments,
      me: {
        userId: owner.userId,
        tokenScopes: [{ project: built.projectId, permission: "admin" }],
      },
      auditHeadHashHex: head,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId, owner);

    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    expect(state.appends.length).toBe(1);
    const entry = state.appends[0]!.entry;
    expect(entry.op).toBe("checkpoint");
    expect(entry.payload.environments.map((tuple) => tuple.environmentId)).toEqual([ENV_A, ENV_B]);
    const tupleA = entry.payload.environments[0]!;
    expect(tupleA.epoch).toBe(1);
    expect(tupleA.manifestVersion).toBe(1);
    expect(tupleA.manifestSigHashHex).toBe(
      await distributedManifestHashOf(built.projectId, environments[1]!.manifest),
    );
    expect(tupleA.valuesDigestHex).toBe(await expectedValuesDigest(environments[1]!));
    expect(entry.payload.auditHeadHashHex).toBe(head);
    expect(state.auditHeadCalls()).toBe(1);
    expect(env.logs.join("\n")).toContain("Checkpoint accepted at chain seq 4");
    expect(env.logs.join("\n")).toContain("audit head attested");
  });

  it("member role does not fetch the audit head (never steps on a 403) and issues with an empty string", async () => {
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "member") },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dek) },
    ]);
    const environment = await makeEnvironment({
      built,
      environmentId: ENV_A,
      dek,
      headSeq: 3,
      issuer: owner,
      variableId: "var-a",
    });
    const state = makeCheckpointServer({
      built,
      environments: [environment],
      me: { userId: member.userId },
      auditHeadHashHex: "ab".repeat(32),
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId, member);

    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    expect(state.appends[0]!.entry.payload.auditHeadHashHex).toBe("");
    expect(state.auditHeadCalls()).toBe(0);
  });

  it("a listed-scope issuer covers only in-scope environments and lists the rest in the SHOULD warning (ES K4 — §6.2 / §6.3 (i))", async () => {
    const dekA = crypto.getRandomValues(new Uint8Array(32));
    const dekB = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dekA) },
      { actor: owner, operation: createEnvironmentOp(ENV_B, dekB) },
      { actor: owner, operation: addMemberOp(member, "member", [ENV_A]) },
    ]);
    const environments = [
      await makeEnvironment({
        built,
        environmentId: ENV_A,
        dek: dekA,
        headSeq: 4,
        issuer: owner,
        variableId: "var-a",
      }),
      await makeEnvironment({
        built,
        environmentId: ENV_B,
        dek: dekB,
        headSeq: 4,
        issuer: owner,
        variableId: "var-b",
      }),
    ];
    const state = makeCheckpointServer({
      built,
      environments,
      me: { userId: member.userId },
      auditHeadHashHex: "ab".repeat(32),
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId, member);

    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    const entry = state.appends[0]!.entry;
    expect(entry.payload.environments.map((tuple) => tuple.environmentId)).toEqual([ENV_A]);
    expect(
      server.requests.filter((request) => request.path.includes(`/environments/${ENV_B}/pull`)),
    ).toHaveLength(0);
    expect(env.errors.join("\n")).toContain(
      `environment ${ENV_B} outside your scope cannot be covered`,
    );
  });

  it("even an admin role does not notarize with a write-scope token (effective permission is the min — §9-2)", async () => {
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dek) },
    ]);
    const environment = await makeEnvironment({
      built,
      environmentId: ENV_A,
      dek,
      headSeq: 2,
      issuer: owner,
      variableId: "var-a",
    });
    const state = makeCheckpointServer({
      built,
      environments: [environment],
      me: {
        userId: owner.userId,
        tokenScopes: [{ project: built.projectId, permission: "write" }],
      },
      auditHeadHashHex: "ab".repeat(32),
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId, owner);

    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    expect(state.appends[0]!.entry.payload.auditHeadHashHex).toBe("");
    expect(state.auditHeadCalls()).toBe(0);
  });

  it("422 (CheckpointStateMismatch) retries bounded by refetching the view and re-attesting (§16-2)", async () => {
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dek) },
    ]);
    const environment = await makeEnvironment({
      built,
      environmentId: ENV_A,
      dek,
      headSeq: 2,
      issuer: owner,
      variableId: "var-a",
    });
    const state = makeCheckpointServer({
      built,
      environments: [environment],
      me: {
        userId: owner.userId,
        tokenScopes: [{ project: built.projectId, permission: "admin" }],
      },
      auditHeadHashHex: "ab".repeat(32),
      onAppend: (call) =>
        call === 0
          ? {
              status: 422,
              json: { _tag: "CheckpointStateMismatch", reason: "values-digest-mismatch" },
            }
          : undefined,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId, owner);

    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    expect(state.appends.length).toBe(2);
    expect(state.auditHeadCalls()).toBe(2);
  });

  async function makeNotReadyFixture(input: {
    readonly onAuditHead?: (call: number) => EndpointAnswer<"audit.auditHead"> | undefined;
    readonly onAppend?: (call: number, body: AppendBody) => MockResponse | undefined;
  }): Promise<{ state: CheckpointServerState; env: TestEnv }> {
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dek) },
    ]);
    const environment = await makeEnvironment({
      built,
      environmentId: ENV_A,
      dek,
      headSeq: 2,
      issuer: owner,
      variableId: "var-a",
    });
    const state = makeCheckpointServer({
      built,
      environments: [environment],
      me: {
        userId: owner.userId,
        tokenScopes: [{ project: built.projectId, permission: "admin" }],
      },
      auditHeadHashHex: "cd".repeat(32),
      ...(input.onAuditHead === undefined ? {} : { onAuditHead: input.onAuditHead }),
      ...(input.onAppend === undefined ? {} : { onAppend: input.onAppend }),
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId, owner);
    return { state, env };
  }

  const NOT_READY = { status: 503, json: { _tag: "AuditHeadNotReady" } } as const;

  it("absorbs AuditHeadNotReady (503) on attestation fetch with bounded retries (progress is server-side)", async () => {
    const { state, env } = await makeNotReadyFixture({
      onAuditHead: (call) => (call < 2 ? NOT_READY : undefined),
    });
    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    expect(state.auditHeadCalls()).toBe(3);
    expect(state.appends.length).toBe(1);
    expect(state.appends[0]!.entry.payload).toMatchObject({ auditHeadHashHex: "cd".repeat(32) });
    expect(env.logs.join("\n")).toContain("materializing the audit-head hash column");
  });

  it("AuditHeadNotReady (503) at the acceptance stage re-fetches the attestation and resends", async () => {
    const { state, env } = await makeNotReadyFixture({
      onAppend: (call) => (call === 0 ? NOT_READY : undefined),
    });
    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    expect(state.appends.length).toBe(2);
    expect(state.auditHeadCalls()).toBe(2);
  });

  it("AuditHeadNotReady (503) at the acceptance stage backs off exponentially and exhausts the shared 10-attempt budget", async () => {
    const appendTimes: number[] = [];
    const { state, env } = await makeNotReadyFixture({
      onAppend: () => {
        appendTimes.push(Date.now());
        return NOT_READY;
      },
    });
    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(1);
    expect(state.appends.length).toBe(10);
    expect(state.auditHeadCalls()).toBe(10);
    const waits = [5, 10, 20, 40, 80, 160, 320, 640, 1280];
    for (const [index, wait] of waits.entries()) {
      expect(appendTimes[index + 1]! - appendTimes[index]!).toBeGreaterThanOrEqual(wait - 1);
    }
    expect(appendTimes[9]! - appendTimes[0]!).toBeGreaterThanOrEqual(2000);
    expect(env.logs.join("\n")).toContain(
      "refetching the attestation and retrying (attempt 10 of 10)",
    );
    const output = env.errors.join("\n");
    expect(output).toContain("still materializing the audit-head hash column");
    expect(output).toContain("re-run the command to continue where it left off");
  }, 20000);

  it("AuditHeadNotReady (503) attempts count toward one budget across a 422 (CheckpointStateMismatch) retry", async () => {
    const { state, env } = await makeNotReadyFixture({
      onAppend: (call) =>
        call === 5
          ? {
              status: 422,
              json: { _tag: "CheckpointStateMismatch", reason: "values-digest-mismatch" },
            }
          : NOT_READY,
    });
    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(1);
    expect(state.appends.length).toBe(11);
    expect(env.logs.join("\n")).toContain(
      "refetching the attestation and retrying (attempt 10 of 10)",
    );
    expect(env.errors.join("\n")).toContain("still materializing the audit-head hash column");
  });

  it("when AuditHeadNotReady is exhausted, fails with guidance on the trigger condition and the fix by re-running", async () => {
    const { state, env } = await makeNotReadyFixture({ onAuditHead: () => NOT_READY });
    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(1);
    expect(state.auditHeadCalls()).toBe(10);
    expect(state.appends.length).toBe(0);
    expect(env.errors).toEqual(
      expect.arrayContaining([
        "maruhi: The server is still materializing the audit-head hash column after 10 attempts (this happens once, on the first audit-head access of a project with a very large existing audit log). Progress is saved server-side and every attempt advances it — re-run the command to continue where it left off",
      ]),
    );
  });

  it("once retries are exhausted, issues against the subset of environments unchanged across the last 2 builds (§6.3 fallback)", async () => {
    const dekA = crypto.getRandomValues(new Uint8Array(32));
    const dekB = crypto.getRandomValues(new Uint8Array(32));
    const dekC = crypto.getRandomValues(new Uint8Array(32));
    const steps = [
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dekA) },
      { actor: owner, operation: createEnvironmentOp(ENV_B, dekB) },
      { actor: owner, operation: createEnvironmentOp("ops", dekC) },
    ];
    const base = await buildChain(steps);
    const fixtureOf = (environmentId: string, dek: Uint8Array) =>
      makeEnvironment({
        built: base,
        environmentId,
        dek,
        headSeq: 4,
        issuer: owner,
        variableId: `var-${environmentId}`,
      });
    const stable = await fixtureOf(ENV_A, dekA);
    const busy = await fixtureOf(ENV_B, dekB);
    const unchanged = await fixtureOf("ops", dekC);
    const built = await buildChain([
      ...steps,
      {
        actor: owner,
        operation: {
          op: "checkpoint",
          payload: {
            environments: [await tupleOf(base.projectId, unchanged)],
            auditHeadHashHex: "",
          },
        },
      },
    ]);
    unchanged.checkpointSnapshot = {
      chainSeq: 5,
      entryHashHex: built.hashes[4] ?? "",
      values: await checkpointSnapshotValuesOf(unchanged.variables.map((v) => v.value)),
    };
    const head = headOf(base, 4);
    const nextValues: WireDistributedValue[] = [];
    let previous = busy.variables[0]!.value;
    for (let version = 2; version <= 6; version += 1) {
      const value = await distributedValue({
        dek: dekB,
        projectId: built.projectId,
        environmentId: ENV_B,
        epoch: 1,
        variableId: `var-${ENV_B}`,
        version,
        plaintext: `secret-v${version}`,
        writer: owner,
        head,
        prevValueSigHashHex: await valueSignedBytesHashOf(previous, owner.userId),
      });
      nextValues.push(value);
      previous = value;
    }
    busy.nextValues = nextValues;
    const state = makeCheckpointServer({
      built,
      environments: [stable, busy, unchanged],
      me: {
        userId: owner.userId,
        tokenScopes: [{ project: built.projectId, permission: "admin" }],
      },
      auditHeadHashHex: "ab".repeat(32),
      onAppend: (_call, body) =>
        body.entry.payload.environments.some((tuple) => tuple.environmentId === ENV_B)
          ? {
              status: 422,
              json: { _tag: "CheckpointStateMismatch", reason: "values-digest-mismatch" },
            }
          : undefined,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId, owner);

    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    const finalAppend = state.appends[state.appends.length - 1]!;
    expect(finalAppend.entry.payload.environments.map((tuple) => tuple.environmentId)).toEqual([
      ENV_A,
    ]);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).toContain("partial checkpoint");
    expect(output).toContain(`1 environment could not be covered (${ENV_B})`);
    expect(output).toContain(
      "covering 1 changed environment (1 unchanged since the latest checkpoint)",
    );
  });

  it("the trigger-(iii) proposal (checkpointProposal): branches on baseline presence / freshness / effective permission", async () => {
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const base = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "member") },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dek) },
    ]);
    const verifiedOf = (built: BuiltChain) =>
      Effect.runPromise(
        verifyChainSnapshot({
          projectId: base.projectId as never,
          entries: built.entries,
          claimedHeadSeq: built.entries.length,
          claimedHeadHashHex: built.hashes[built.hashes.length - 1] ?? "",
        }),
      );
    const appendCheckpoint = (
      built: BuiltChain,
      input: { readonly timestampMs: number; readonly auditHeadHashHex: string },
    ): Promise<BuiltChain> =>
      appendSignedCheckpoint(
        built,
        { environments: [], auditHeadHashHex: input.auditHeadHashHex },
        input.timestampMs,
      );
    const state = makeCheckpointServer({
      built: base,
      environments: [],
      me: { userId: owner.userId, tokenScopes: [{ project: base.projectId, permission: "admin" }] },
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const client = await Effect.runPromise(
      makeApiClient({ baseUrl: server.origin }).pipe(Effect.provide(FetchHttpClient.layer)),
    );
    const propose = (built: BuiltChain, signerUserId: string) =>
      verifiedOf(built).then((verified) =>
        Effect.runPromise(
          checkpointProposal({
            client,
            verified,
            signerUserId: testUserId(signerUserId),
            nowMs: Date.now(),
            afterWrite: false,
          }),
        ),
      );

    expect(await propose(base, member.userId)).toContain("maruhi project checkpoint");
    const genesisMs = base.entries[0]?.timestampMs ?? 0;
    const proposeAt = (built: BuiltChain, signerUserId: string, nowMs: number) =>
      verifiedOf(built).then((verified) =>
        Effect.runPromise(
          checkpointProposal({
            client,
            verified,
            signerUserId: testUserId(signerUserId),
            nowMs,
            afterWrite: false,
          }),
        ),
      );
    const day = 24 * 60 * 60 * 1000;
    expect(await proposeAt(base, member.userId, genesisMs + 6 * day)).toBeNull();
    expect(await proposeAt(base, owner.userId, genesisMs + 6 * day)).toBeNull();
    expect(await proposeAt(base, member.userId, genesisMs + 8 * day)).toContain(
      "maruhi project checkpoint",
    );
    expect(await proposeAt(base, owner.userId, genesisMs + 8 * day)).toContain(
      "notarized audit prefix",
    );
    const freshPlain = await appendCheckpoint(base, {
      timestampMs: Date.now(),
      auditHeadHashHex: "",
    });
    expect(await propose(freshPlain, member.userId)).toBeNull();
    expect(await propose(freshPlain, owner.userId)).toContain("notarized audit prefix");
    const freshAttested = await appendCheckpoint(base, {
      timestampMs: Date.now(),
      auditHeadHashHex: "ab".repeat(32),
    });
    expect(await propose(freshAttested, owner.userId)).toBeNull();
  });

  it("does not report success on 2xx when the resynced chain lacks our entry (§12-10 (3))", async () => {
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dek) },
    ]);
    const environment = await makeEnvironment({
      built,
      environmentId: ENV_A,
      dek,
      headSeq: 2,
      issuer: owner,
      variableId: "var-a",
    });
    const state = makeCheckpointServer({
      built,
      environments: [environment],
      me: {
        userId: owner.userId,
        tokenScopes: [{ project: built.projectId, permission: "admin" }],
      },
      acceptWithoutAppending: true,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId, owner);

    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not contain this checkpoint entry");
  });
});

describe("the changed-only cover (CRYPTO_SPEC §6.3 — Sc-3a)", () => {
  const ENV_C = "ops";

  it("builds every environment but notarizes only those changed since their baseline or without one", async () => {
    const dekA = crypto.getRandomValues(new Uint8Array(32));
    const dekB = crypto.getRandomValues(new Uint8Array(32));
    const dekC = crypto.getRandomValues(new Uint8Array(32));
    const steps = [
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dekA) },
      { actor: owner, operation: createEnvironmentOp(ENV_B, dekB) },
      { actor: owner, operation: createEnvironmentOp(ENV_C, dekC) },
    ];
    const base = await buildChain(steps);
    const fixtureOf = (environmentId: string, dek: Uint8Array) =>
      makeEnvironment({
        built: base,
        environmentId,
        dek,
        headSeq: 4,
        issuer: owner,
        variableId: `var-${environmentId}`,
      });
    const unchanged = await fixtureOf(ENV_A, dekA);
    const unbased = await fixtureOf(ENV_B, dekB);
    const changed = await fixtureOf(ENV_C, dekC);
    const built = await buildChain([
      ...steps,
      {
        actor: owner,
        operation: {
          op: "checkpoint",
          payload: {
            environments: [
              await tupleOf(base.projectId, unchanged),
              await tupleOf(base.projectId, changed, []),
            ],
            auditHeadHashHex: "",
          },
        },
      },
    ]);
    const baseline = { chainSeq: 5, entryHashHex: built.hashes[4] ?? "" };
    unchanged.checkpointSnapshot = {
      ...baseline,
      values: await checkpointSnapshotValuesOf(unchanged.variables.map((v) => v.value)),
    };
    changed.checkpointSnapshot = { ...baseline, values: [] };
    const state = makeCheckpointServer({
      built,
      environments: [unchanged, unbased, changed],
      me: {
        userId: owner.userId,
        tokenScopes: [{ project: built.projectId, permission: "admin" }],
      },
      auditHeadHashHex: "ab".repeat(32),
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId, owner);

    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    expect(state.appends.length).toBe(1);
    const payload = state.appends[0]!.entry.payload;
    expect(payload.environments).toEqual([
      await tupleOf(built.projectId, unbased),
      await tupleOf(built.projectId, changed),
    ]);
    expect(payload.auditHeadHashHex).toBe("ab".repeat(32));
    expect(
      server.requests.filter((request) => request.path.endsWith(`/environments/${ENV_A}/pull`)),
    ).toHaveLength(1);
    expect(env.logs.join("\n")).toContain(
      "covering 2 changed environments (1 unchanged since the latest checkpoint)",
    );
  });

  async function unchangedProject(input: {
    readonly member?: "full" | "listed";
    readonly freshMs?: number;
  }) {
    const dekA = crypto.getRandomValues(new Uint8Array(32));
    const dekB = crypto.getRandomValues(new Uint8Array(32));
    const steps = [
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dekA) },
      ...(input.member === "listed"
        ? [
            { actor: owner, operation: createEnvironmentOp(ENV_B, dekB) },
            { actor: owner, operation: addMemberOp(member, "member", [ENV_A]) },
          ]
        : [{ actor: owner, operation: addMemberOp(member, "member") }]),
    ];
    const base = await buildChain(steps);
    const environment = await makeEnvironment({
      built: base,
      environmentId: ENV_A,
      dek: dekA,
      headSeq: steps.length,
      issuer: owner,
      variableId: "var-a",
    });
    const payload: CheckpointPayload = {
      environments: [await tupleOf(base.projectId, environment)],
      auditHeadHashHex: "",
    };
    const built =
      input.freshMs === undefined
        ? await buildChain([...steps, { actor: owner, operation: { op: "checkpoint", payload } }])
        : await appendSignedCheckpoint(base, payload, input.freshMs);
    environment.checkpointSnapshot = {
      chainSeq: built.entries.length,
      entryHashHex: built.hashes[built.hashes.length - 1] ?? "",
      values: await checkpointSnapshotValuesOf(environment.variables.map((v) => v.value)),
    };
    return { built, environment };
  }

  async function runCheckpoint(input: {
    readonly built: BuiltChain;
    readonly environment: MockEnvironment;
    readonly signer: GeneratedIdentity;
    readonly admin?: boolean;
  }) {
    const state = makeCheckpointServer({
      built: input.built,
      environments: [input.environment],
      me:
        input.admin === true
          ? {
              userId: input.signer.userId,
              tokenScopes: [{ project: input.built.projectId, permission: "admin" }],
            }
          : { userId: input.signer.userId },
      auditHeadHashHex: "cd".repeat(32),
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, input.built.projectId, input.signer);
    const exit = await runCli(["project", "checkpoint"], env.layer);
    return { exit, state, env };
  }

  it("nothing changed and a baseline younger than 7 days: a member issues nothing", async () => {
    const project = await unchangedProject({ freshMs: Date.now() });
    const { exit, state, env } = await runCheckpoint({ ...project, signer: member });
    expect(exit).toBe(0);
    expect(state.appends).toHaveLength(0);
    expect(env.logs.join("\n")).toContain(
      "Nothing to notarize: the environment matches its latest checkpoint",
    );
  });

  it("nothing changed and a baseline older than 7 days: a member's tuple-less entry restarts trigger (iii)'s clock", async () => {
    const project = await unchangedProject({});
    const { exit, state } = await runCheckpoint({ ...project, signer: member });
    expect(exit).toBe(0);
    expect(state.appends).toHaveLength(1);
    expect(state.appends[0]!.entry.payload).toEqual({ environments: [], auditHeadHashHex: "" });
  });

  it("nothing changed: an effective admin still notarizes the audit head in a tuple-less entry", async () => {
    const project = await unchangedProject({ freshMs: Date.now() });
    const { exit, state } = await runCheckpoint({ ...project, signer: owner, admin: true });
    expect(exit).toBe(0);
    expect(state.appends).toHaveLength(1);
    expect(state.appends[0]!.entry.payload).toEqual({
      environments: [],
      auditHeadHashHex: "cd".repeat(32),
    });
  });

  it("nothing changed under trigger (i): no tuple-less entry, since the build covers one environment, not the view", async () => {
    const project = await unchangedProject({});
    const state = makeCheckpointServer({
      built: project.built,
      environments: [project.environment],
      me: { userId: member.userId },
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, project.built.projectId, member);
    const client = await Effect.runPromise(
      makeApiClient({ baseUrl: server.origin }).pipe(Effect.provide(FetchHttpClient.layer)),
    );
    const projectId = testProjectId(project.built.projectId);
    const resync = verifyChainSnapshot({
      projectId,
      entries: state.entries,
      claimedHeadSeq: state.entries.length,
      claimedHeadHashHex: project.built.hashes[project.built.hashes.length - 1] ?? "",
    });
    const floor = makeFloorHandle({
      store: makeFileFloorStore(await mkdtemp(join(tmpdir(), "maruhi-checkpoint-i-"))),
      projectId,
      environmentId: testEnvironmentId(ENV_A),
      initial: null,
    });
    const summary = await Effect.runPromise(
      issueCheckpoint({
        client,
        verified: await Effect.runPromise(resync),
        resync,
        environmentIds: [testEnvironmentId(ENV_A)],
        signerUserId: testUserId(member.userId),
        signingKeyPair: member.sigKeyPair,
        floorFor: () => Effect.succeed(floor),
      }).pipe(Effect.provide(env.layer)),
    );
    expect(summary.headSeq).toBeNull();
    expect(summary.unchangedEnvironmentIds).toEqual([ENV_A]);
    expect(state.appends).toHaveLength(0);
  });

  it("compares against the latest view: a baseline landing after the opening view counts", async () => {
    const project = await unchangedProject({});
    const state = makeCheckpointServer({
      built: project.built,
      environments: [project.environment],
      me: {
        userId: owner.userId,
        tokenScopes: [{ project: project.built.projectId, permission: "admin" }],
      },
      auditHeadHashHex: "cd".repeat(32),
      firstFetchEntries: project.built.entries.length - 1,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, project.built.projectId, owner);
    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    expect(state.appends).toHaveLength(1);
    expect(state.appends[0]!.entry.payload.environments).toEqual([]);
  });

  it("nothing changed in a listed scope: no tuple-less entry, since the view misses an environment", async () => {
    const project = await unchangedProject({ member: "listed" });
    const { exit, state, env } = await runCheckpoint({ ...project, signer: member });
    expect(exit).toBe(0);
    expect(state.appends).toHaveLength(0);
    expect(env.errors.join("\n")).toContain(`environment ${ENV_B} outside your scope`);
    expect(env.logs.join("\n")).toContain(
      "the 7-day checkpoint suggestion is not reset; it stops once a member whose scope covers every environment",
    );
  });

  it("trigger (iii) suggests to a listed-scope member only after its own write (no repeat it cannot clear)", async () => {
    const { built } = await unchangedProject({ member: "listed" });
    const server = await MockServer.start(
      makeCheckpointServer({ built, environments: [], me: { userId: member.userId } }).handlers,
    );
    servers.push(server);
    const client = await Effect.runPromise(
      makeApiClient({ baseUrl: server.origin }).pipe(Effect.provide(FetchHttpClient.layer)),
    );
    const verified = await Effect.runPromise(
      verifyChainSnapshot({
        projectId: testProjectId(built.projectId),
        entries: built.entries,
        claimedHeadSeq: built.entries.length,
        claimedHeadHashHex: built.hashes[built.hashes.length - 1] ?? "",
      }),
    );
    const propose = (afterWrite: boolean) =>
      Effect.runPromise(
        checkpointProposal({
          client,
          verified,
          signerUserId: testUserId(member.userId),
          nowMs: Date.now(),
          afterWrite,
        }),
      );
    expect(await propose(false)).toBeNull();
    expect(await propose(true)).toContain("maruhi project checkpoint");
  });
});
