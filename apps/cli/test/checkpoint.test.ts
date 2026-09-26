// Tests for periodic checkpoint issuance (`maruhi project checkpoint` —
// CRYPTO_SPEC §6.3 / AUTH_SPEC §16-2).
//
// Pillars verified:
//  1. Construction: the tuple is assembled from the verified view (verified
//     pull) — environment IDs in byte order, manifest ref = the self-computed
//     hash of the verified manifest, values_digest = the self-computed hash
//     of the verified values (never signing the server's claimed values)
//  2. Audit-head notarization: effective-permission admin (chain role ×
//     /auth/me tokenScopes) is judged up front — below admin / write-scope
//     tokens do NOT call GET /audit-head (never step on a 403 — §16-2)
//  3. Retries: 422 (CheckpointStateMismatch) retries bounded by refetching
//     the view and re-attesting; once exhausted, issues exactly once against
//     the stable subset (§6.3 fallback). 409 (CAS) = resync + re-sign
//  4. Post-acceptance check (§12-10 (3)): even on 2xx, if the synced chain
//     doesn't show our own entry, do not report success

import type { ChainEntry } from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeEnvValuesDigest,
  signChainEntry,
  SUITE_ID,
} from "@maruhi/crypto";
import { Effect } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { makeApiClient } from "../src/api.ts";
import { checkpointProposal } from "../src/checkpoint.ts";
import { runCli } from "../src/cli.ts";
import { verifyChainSnapshot } from "../src/sync.ts";
import {
  addMemberOp,
  addScopedMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  manifestHashOf,
  statementFor,
  type TestUser,
  valueHashOf,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, type MockResponse, onRequest } from "./support/server.ts";

// Byte-order discrimination pair (alpha < dev)
const ENV_A = "alpha";
const ENV_B = "dev";

let owner: TestUser;
let member: TestUser;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  member = await makeTestUser("user-member-3333");
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
  /** Swap the value on each pull (the "busy environment" of the subset-fallback test). */
  nextValues?: WireDistributedValue[];
}

interface CheckpointServerOptions {
  readonly built: BuiltChain;
  readonly environments: MockEnvironment[];
  readonly me: { readonly userId: string; readonly tokenScopes?: readonly unknown[] };
  readonly auditHeadHashHex?: string;
  /** Per-call override for audit-head (undefined = return the attestation with 200). */
  readonly onAuditHead?: (call: number) => MockResponse | undefined;
  /** Per-call override for append (undefined = accept and append). */
  readonly onAppend?: (call: number, body: AppendBody) => MockResponse | undefined;
  /** Accept without appending to the chain (a lying 2xx server — the §12-10 (3) check). */
  readonly acceptWithoutAppending?: boolean;
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

/** Mock with every endpoint the issuance flow needs (accepted entries are reflected onto the chain). */
function makeCheckpointServer(options: CheckpointServerOptions): CheckpointServerState {
  const projectId = options.built.projectId;
  const entries: ChainEntry[] = [...options.built.entries];
  const hashes: string[] = [...options.built.hashes];
  const appends: AppendBody[] = [];
  let appendCalls = 0;
  let auditHeadCalls = 0;
  const handlers: MockHandler[] = [
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: { projectId, entries, headSeq: entries.length, headHashHex: hashes[hashes.length - 1] },
    })),
    onRequest("GET", `/projects/${projectId}/environments`, () => ({
      status: 200,
      json: {
        environments: options.environments.map((environment) => ({
          environmentId: environment.environmentId,
          currentEpoch: 1,
          statement: environment.statement,
        })),
      },
    })),
    onRequest("GET", "/auth/me", () => ({
      status: 200,
      json: {
        userId: options.me.userId,
        orgs: [],
        ...(options.me.tokenScopes === undefined ? {} : { tokenScopes: options.me.tokenScopes }),
      },
    })),
    onRequest("GET", `/projects/${projectId}/audit-head`, () => {
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
    // Per-environment pull (valued — §12-7)
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
        },
      };
    }),
  ];
  return { handlers, appends, auditHeadCalls: () => auditHeadCalls, entries };
}

/** Fixture for one environment (one variable + manifest). */
async function makeEnvironment(input: {
  readonly built: BuiltChain;
  readonly environmentId: string;
  readonly dek: Uint8Array;
  readonly headSeq: number;
  readonly issuer: TestUser;
  readonly variableId: string;
}): Promise<MockEnvironment> {
  const head = headOf(input.built, input.headSeq);
  const statement = await environmentStatementFor({
    projectId: input.built.projectId,
    environmentId: input.environmentId,
    name: input.environmentId,
    author: input.issuer,
    head,
  });
  const variableStatement = await statementFor({
    projectId: input.built.projectId,
    environmentId: input.environmentId,
    variableId: input.variableId,
    name: `VAR_${input.environmentId.toUpperCase()}`,
    author: input.issuer,
    head,
  });
  const value = await encryptValueFor({
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
  const manifest = await manifestFor({
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

async function seededEnv(server: MockServer, projectId: string, user: TestUser): Promise<TestEnv> {
  const env = await makeTestEnv();
  seedSession(env, server.origin, user);
  await seedConfig(env, { server: server.origin, defaultProject: projectId });
  return env;
}

async function expectedValuesDigest(environment: MockEnvironment): Promise<string> {
  const entries = await Promise.all(
    environment.variables.map(async (variable) => ({
      variableId: variable.variableId,
      version: variable.value.aad.version,
      valueSigHashHex: await valueHashOf(variable.value, variable.value.writerUserId),
    })),
  );
  const digest = await computeEnvValuesDigest(SUITE_ID, entries);
  if (!digest.ok) {
    throw new Error("digest failed");
  }
  return digest.value;
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
      // Deliberately listed in descending order (to discriminate the
      // issuer-side ascending normalization)
      await makeEnvironment({
        built,
        environmentId: ENV_B,
        dek: dekB,
        headSeq: 3,
        issuer: owner,
        variableId: "var-b",
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
    // Byte-ascending (alpha < dev); the tuple is self-computed from the
    // verified view
    expect(entry.payload.environments.map((tuple) => tuple.environmentId)).toEqual([ENV_A, ENV_B]);
    const tupleA = entry.payload.environments[0]!;
    expect(tupleA.epoch).toBe(1);
    expect(tupleA.manifestVersion).toBe(1);
    expect(tupleA.manifestSigHashHex).toBe(
      await manifestHashOf(built.projectId, environments[1]!.manifest),
    );
    expect(tupleA.valuesDigestHex).toBe(await expectedValuesDigest(environments[1]!));
    // Effective permission admin: notarize the attestation fetched after the
    // CAS parent was fixed
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
      { actor: owner, operation: addScopedMemberOp(member, "member", [ENV_A]) },
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
    // Out-of-scope environments get no valued pull (no var.read recorded,
    // no 403 stepped on)
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
    // The audit-head attestation is re-fetched per attempt (§16-2 retries)
    expect(state.auditHeadCalls()).toBe(2);
  });

  /** Shared fixture for the AuditHeadNotReady retry tests (a single-environment issuance by admin). */
  async function makeNotReadyFixture(input: {
    readonly onAuditHead?: (call: number) => MockResponse | undefined;
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

  const NOT_READY: MockResponse = { status: 503, json: { _tag: "AuditHeadNotReady" } };

  it("absorbs AuditHeadNotReady (503) on attestation fetch with bounded retries (progress is server-side)", async () => {
    const { state, env } = await makeNotReadyFixture({
      onAuditHead: (call) => (call < 2 ? NOT_READY : undefined),
    });
    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    // Absorbs two 503s and issues on the third attestation (issuance happens
    // once)
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
    // Resending also re-fetches the attestation (the server's extension has
    // already advanced — AUDIT_SPEC §5.1)
    expect(state.auditHeadCalls()).toBe(2);
  });

  it("when AuditHeadNotReady is exhausted, fails with guidance on the trigger condition and the fix by re-running", async () => {
    const { state, env } = await makeNotReadyFixture({ onAuditHead: () => NOT_READY });
    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(1);
    // Stops at the 10-attempt budget without reaching issuance
    expect(state.auditHeadCalls()).toBe(10);
    expect(state.appends.length).toBe(0);
    const output = env.errors.join("\n");
    expect(output).toContain("still materializing the audit-head hash column");
    expect(output).toContain("re-run the command to continue where it left off");
  });

  it("once retries are exhausted, issues against the subset of environments unchanged across the last 2 builds (§6.3 fallback)", async () => {
    const dekA = crypto.getRandomValues(new Uint8Array(32));
    const dekB = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dekA) },
      { actor: owner, operation: createEnvironmentOp(ENV_B, dekB) },
    ]);
    const stable = await makeEnvironment({
      built,
      environmentId: ENV_A,
      dek: dekA,
      headSeq: 3,
      issuer: owner,
      variableId: "var-a",
    });
    const busy = await makeEnvironment({
      built,
      environmentId: ENV_B,
      dek: dekB,
      headSeq: 3,
      issuer: owner,
      variableId: "var-b",
    });
    // ENV_B's version advances on every pull (models a concurrent push).
    // prev chains to the self-computed hash of the immediately preceding
    // version (§4.1)
    const head = headOf(built, 3);
    const nextValues: WireDistributedValue[] = [];
    let previous = busy.variables[0]!.value;
    for (let version = 2; version <= 6; version += 1) {
      const value = await encryptValueFor({
        dek: dekB,
        projectId: built.projectId,
        environmentId: ENV_B,
        epoch: 1,
        variableId: "var-b",
        version,
        plaintext: `secret-v${version}`,
        writer: owner,
        head,
        prevValueSigHashHex: await valueHashOf(previous, owner.userId),
      });
      nextValues.push(value);
      previous = value;
    }
    busy.nextValues = nextValues;
    const state = makeCheckpointServer({
      built,
      environments: [stable, busy],
      me: {
        userId: owner.userId,
        tokenScopes: [{ project: built.projectId, permission: "admin" }],
      },
      auditHeadHashHex: "ab".repeat(32),
      // Any issuance including ENV_B always 422s (a busy environment where
      // the at-acceptance match never converges)
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
    expect(output).toContain(ENV_B);
  });

  it("the trigger-(iii) proposal (checkpointProposal): branches on baseline presence / freshness / effective permission", async () => {
    const dek = crypto.getRandomValues(new Uint8Array(32));
    // buildChain's timestamps are deterministic past times — every
    // checkpoint on the chain lands on the "older than 7 days" side. A fresh
    // baseline is built by appending a hand-signed checkpoint
    // (timestampMs = now)
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
    const appendCheckpoint = async (
      built: BuiltChain,
      input: { readonly timestampMs: number; readonly auditHeadHashHex: string },
    ): Promise<BuiltChain> => {
      const signed = await signChainEntry({
        entry: {
          suite: SUITE_ID,
          seq: built.entries.length + 1,
          prevHashHex: built.hashes[built.hashes.length - 1] ?? "",
          op: "checkpoint",
          actor: { userId: owner.userId, keyFingerprintHex: owner.fingerprintHex },
          payload: { environments: [], auditHeadHashHex: input.auditHeadHashHex },
          timestampMs: input.timestampMs,
        },
        signingKey: owner.sigKeyPair.privateKey,
      });
      if (!signed.ok) throw new Error("sign failed");
      return {
        ...built,
        entries: [...built.entries, signed.value],
        hashes: [...built.hashes, await computeChainEntryHash(signed.value)],
      };
    };
    // A mock with only /auth/me (used to judge admin's effective permission)
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
          checkpointProposal({ client, verified, signerUserId, nowMs: Date.now() }),
        ),
      );

    // member: no baseline → propose / a fresh baseline (notarization not
    // required) → no proposal
    expect(await propose(base, member.userId)).toContain("maruhi project checkpoint");
    // Never-issued counts as "baseline = genesis" (DP5 ruling C): within 7
    // days of genesis, no proposal (avoids proposing on every push from day
    // one); past 7 days, propose. admin (notarized baseline) uses the same
    // threshold
    const genesisMs = base.entries[0]?.timestampMs ?? 0;
    const proposeAt = (built: BuiltChain, signerUserId: string, nowMs: number) =>
      verifiedOf(built).then((verified) =>
        Effect.runPromise(checkpointProposal({ client, verified, signerUserId, nowMs })),
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
    // Effective permission admin: a fresh un-notarized baseline doesn't
    // satisfy it (a notarized baseline — a member's issuance must not kill
    // admin's trigger)
    expect(await propose(freshPlain, owner.userId)).toContain("notarized audit prefix");
    // A fresh notarized baseline → no proposal
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
