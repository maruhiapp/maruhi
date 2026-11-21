import type { ChainEntry } from "@maruhi/crypto";
import { computeChainEntryHash, computeServerKeyFingerprint, encodeHex } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { acceptAppendedEntry, injectedAppendResponse } from "./support/chain-handler.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  checkpointSnapshotValuesOf,
  createEnvironmentOp,
  deleteEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  grantServerOp,
  headOf,
  hexBytes,
  makeTestUser,
  manifestFor,
  revokeServerOp,
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
  type WireRotateBody,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockResponse, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "env-app-1";

let owner: TestUser;
let member: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;

const SERVER_ENC_PUB_A = "5a".repeat(32);
const SERVER_ENC_PUB_B = "5b".repeat(32);
let serverFpA: string;
let serverFpB: string;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  member = await makeTestUser("user-member-2222");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  for (const [pubHex, assign] of [
    [SERVER_ENC_PUB_A, (fp: string) => (serverFpA = fp)],
    [SERVER_ENC_PUB_B, (fp: string) => (serverFpB = fp)],
  ] as const) {
    const fp = await computeServerKeyFingerprint(hexBytes(pubHex));
    if (!fp.ok) throw new Error("server fingerprint failed");
    assign(encodeHex(fp.value));
  }
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

interface PulledVariable {
  readonly variableId: string;
  readonly statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
}

interface RevokeEnvironmentFixture {
  currentEpoch: number;
  readonly deks: WireRecipientDek[];
  readonly variables?: PulledVariable[];
}

interface RevokeServerState {
  readonly handlers: readonly MockHandler[];
  readonly appendedEntries: ChainEntry[];
  readonly counters: { appendAttempts: number };
  readonly rotateBodies: WireRotateBody[];
  readonly pushes: { readonly environmentId: string; readonly variableId: string }[];
}

async function makeRevokeServer(input: {
  readonly built: BuiltChain;
  readonly environments?: Readonly<Record<string, RevokeEnvironmentFixture>>;
  readonly listedStatements?: readonly WireDistributedEnvironmentStatement[];
  readonly onAppend?: (call: number) => MockResponse | undefined;
  readonly chainAfterConflict?: BuiltChain;
  readonly onRotate?: (environmentId: string) => MockResponse | undefined;
}): Promise<RevokeServerState> {
  const projectId = input.built.projectId;
  const entries: ChainEntry[] = [...input.built.entries];
  const hashes: string[] = [...input.built.hashes];
  const appendedEntries: ChainEntry[] = [];
  const rotateBodies: WireRotateBody[] = [];
  const pushes: { environmentId: string; variableId: string }[] = [];
  const environments = input.environments ?? {};
  const listedStatements =
    input.listedStatements ??
    (await Promise.all(
      Object.keys(environments).map((environmentId) =>
        environmentStatementFor({
          projectId,
          environmentId,
          name: environmentId,
          author: owner,
          head: headOf(input.built, 1),
        }),
      ),
    ));

  const counters = { appendAttempts: 0 };
  const manifests = new Map<string, WireDistributedManifest>();
  const checkpointSnapshots = new Map<string, WireCheckpointSnapshot>();
  const snapshotFieldOf = (
    environmentId: string,
  ): { readonly checkpointSnapshot?: WireCheckpointSnapshot } => {
    const checkpointSnapshot = checkpointSnapshots.get(environmentId);
    return checkpointSnapshot === undefined ? {} : { checkpointSnapshot };
  };
  const storeSnapshot = async (
    environmentId: string,
    variables: readonly { readonly value: WireDistributedValue }[] | undefined,
  ): Promise<void> => {
    checkpointSnapshots.set(environmentId, {
      chainSeq: entries.length,
      entryHashHex: hashes[hashes.length - 1] ?? "",
      values: await checkpointSnapshotValuesOf((variables ?? []).map((variable) => variable.value)),
    });
  };
  const serveManifest = async (
    environmentId: string,
    environment: RevokeEnvironmentFixture,
    statement: WireDistributedEnvironmentStatement | undefined,
  ): Promise<WireDistributedManifest | undefined> => {
    if (statement === undefined) {
      return undefined;
    }
    let manifest = manifests.get(environmentId);
    if (manifest === undefined) {
      manifest = await manifestFor({
        projectId,
        environmentId,
        epoch: environment.currentEpoch,
        issuer: owner,
        head: { seq: entries.length, hashHex: hashes[hashes.length - 1] ?? "" },
        envStatement: statement,
        statements: (environment.variables ?? []).map((variable) => variable.statement),
      });
      manifests.set(environmentId, manifest);
    }
    return manifest;
  };
  const handlers: MockHandler[] = [
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: {
        projectId,
        entries,
        headSeq: entries.length,
        headHashHex: hashes[hashes.length - 1],
        attestations: [],
      },
    })),
    onRequest("GET", `/projects/${projectId}/environments`, () => ({
      status: 200,
      json: {
        environments: listedStatements.map((statement) => ({
          environmentId: statement.environmentId,
          currentEpoch: environments[statement.environmentId]?.currentEpoch ?? 1,
          statement,
        })),
        schemaPolicy: "enabled",
      },
    })),
    async (request) => {
      if (request.method !== "POST" || request.path !== `/projects/${projectId}/chain/entries`) {
        return null;
      }
      const injected = injectedAppendResponse(input, counters.appendAttempts, entries, hashes);
      counters.appendAttempts += 1;
      if (injected !== undefined) {
        return injected;
      }
      const body = request.body as { readonly entry: ChainEntry };
      appendedEntries.push(body.entry);
      return acceptAppendedEntry(projectId, entries, hashes, body.entry);
    },
    async (request) => {
      const match = new RegExp(`^/projects/${projectId}/environments/([^/]+)/pull$`).exec(
        request.path,
      );
      if (match === null || request.method !== "GET") {
        return null;
      }
      const environmentId = match[1] ?? "";
      const environment = environments[environmentId];
      if (environment === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId: match[1] } };
      }
      const statement = listedStatements.find((item) => item.environmentId === match[1]);
      return {
        status: 200,
        json: {
          environmentId: match[1],
          currentEpoch: environment.currentEpoch,
          statement,
          variables: environment.variables ?? [],
          deletedVariables: [],
          deks: environment.deks,
          manifest: await serveManifest(environmentId, environment, statement),
          ...snapshotFieldOf(environmentId),
          schemaPolicy: "enabled" as const,
        },
      };
    },
    async (request) => {
      const match = new RegExp(`^/projects/${projectId}/environments/([^/]+)/rotate$`).exec(
        request.path,
      );
      if (match === null || request.method !== "POST") {
        return null;
      }
      const environmentId = match[1] ?? "";
      const environment = environments[environmentId];
      if (environment === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId } };
      }
      const injected = input.onRotate?.(environmentId);
      if (injected !== undefined) {
        return injected;
      }
      const body = request.body as WireRotateBody;
      rotateBodies.push(body);
      entries.push(body.entry, body.checkpoint);
      hashes.push(
        await computeChainEntryHash(body.entry),
        await computeChainEntryHash(body.checkpoint),
      );
      await storeSnapshot(environmentId, environment.variables);
      environment.currentEpoch = body.entry.payload.newEpoch;
      manifests.set(environmentId, {
        ...body.manifest,
        issuerUserId: owner.userId,
        issuerKeyFingerprintHex: owner.fingerprintHex,
      });
      for (const wrap of body.deks) {
        if (wrap.recipientUserId !== owner.userId) {
          continue;
        }
        environment.deks.push({
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
      return {
        status: 200,
        json: {
          environmentId,
          currentEpoch: environment.currentEpoch,
          headSeq: entries.length,
          headHashHex: hashes[hashes.length - 1],
        },
      };
    },
    (request) => {
      const match = new RegExp(
        `^/projects/${projectId}/environments/([^/]+)/variables/([^/]+)/versions$`,
      ).exec(request.path);
      if (match === null || request.method !== "POST") {
        return null;
      }
      const environmentId = match[1] ?? "";
      const variableId = match[2] ?? "";
      const environment = environments[environmentId];
      if (environment === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId } };
      }
      const body = request.body as { readonly value: WireDistributedValue };
      pushes.push({ environmentId, variableId });
      const stored: WireDistributedValue = {
        ...body.value,
        writerUserId: owner.userId,
        writerKeyFingerprintHex: owner.fingerprintHex,
      };
      const target = (environment.variables ?? []).find(
        (variable) => variable.variableId === variableId,
      );
      if (target !== undefined) {
        target.value = stored;
      }
      return {
        status: 200,
        json: { variableId, version: body.value.aad.version, epoch: body.value.aad.epoch },
      };
    },
  ];
  return { handlers, appendedEntries, counters, rotateBodies, pushes };
}

async function startRevokeEnv(
  state: RevokeServerState,
  projectId: string,
  user: TestUser,
): Promise<TestEnv> {
  const server = await MockServer.start([...state.handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, user);
  await seedConfig(env, { server: server.origin, defaultProject: projectId });
  return env;
}

async function ownerWrap(
  projectId: string,
  environmentId: string,
  epoch: number,
  dek: Uint8Array,
): Promise<WireRecipientDek> {
  return wrapDekFor({ projectId, environmentId, epoch, dek, recipient: owner, signer: owner });
}

describe("maruhi server revoke", () => {
  it("appends revoke_server and force-rotates every environment with reason=server-revoked (no server-bound wrap in the compound)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp([ENV_ID], [], SERVER_ENC_PUB_A) },
    ]);
    const state = await makeRevokeServer({
      built,
      environments: {
        [ENV_ID]: {
          currentEpoch: 1,
          deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)],
        },
      },
    });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(0);

    expect(state.appendedEntries).toHaveLength(1);
    const revoke = state.appendedEntries[0];
    if (revoke?.op !== "revoke_server") throw new Error("revoke entry missing");
    expect(revoke.payload.serverKeyFingerprintHex).toBe(serverFpA);

    expect(state.rotateBodies).toHaveLength(1);
    const rotate = state.rotateBodies[0];
    if (rotate === undefined) throw new Error("rotate body missing");
    expect(rotate.entry.payload.newEpoch).toBe(2);
    expect(rotate.entry.payload.reason).toBe("server-revoked");
    expect(rotate.deks.map((wrap) => wrap.recipientUserId)).toEqual([owner.userId]);
    expect(rotate.deks.every((wrap) => wrap.recipientClass === "member")).toBe(true);

    const logs = env.logs.join("\n");
    expect(logs).toContain(`Appended revoke_server to the chain (FP=${serverFpA})`);
    expect(logs).toContain("Done: the revocation and the rotation of every environment completed");
  });

  it("mid-run recovery: when revoke is already appended but the rotation unfinished, resume only the rotation without appending", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp([ENV_ID], [], SERVER_ENC_PUB_A) },
      { actor: owner, operation: revokeServerOp(serverFpA) },
    ]);
    const state = await makeRevokeServer({
      built,
      environments: {
        [ENV_ID]: {
          currentEpoch: 1,
          deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)],
        },
      },
    });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.newEpoch).toBe(2);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("server-revoked");
    const logs = env.logs.join("\n");
    expect(logs).toContain("No active grant — resuming the post-revocation rotation");
    expect(logs).toContain("Done: the revocation and the rotation of every environment completed");
  });

  it("on a CAS conflict that detects a concurrent revoke, it doesn't append and proceeds to the rotation", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp([ENV_ID], [], SERVER_ENC_PUB_A) },
    ]);
    const concurrent = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp([ENV_ID], [], SERVER_ENC_PUB_A) },
      { actor: owner, operation: revokeServerOp(serverFpA) },
    ]);
    const state = await makeRevokeServer({
      built,
      environments: {
        [ENV_ID]: {
          currentEpoch: 1,
          deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)],
        },
      },
      onAppend: (call) =>
        call === 0
          ? {
              status: 409,
              json: {
                _tag: "ChainHeadConflict",
                currentHeadSeq: 4,
                currentHeadHashHex: concurrent.hashes[3] ?? "",
              },
            }
          : undefined,
      chainAfterConflict: concurrent,
    });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(0);
    expect(state.counters.appendAttempts).toBe(1);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("server-revoked");
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      `The targeted grant (FP=${serverFpA}) was already revoked by a concurrent run`,
    );
    expect(logs).toContain("Done: the revocation and the rotation of every environment completed");
  });

  it("mid-run recovery: when the epoch advanced but re-encryption is unfinished, resume and finish it without a new epoch", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp([ENV_ID], [], SERVER_ENC_PUB_A) },
      { actor: owner, operation: revokeServerOp(serverFpA) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    ]);
    const staleVariable: PulledVariable = {
      variableId: "var-stale-1",
      statement: await statementFor({
        projectId: built.projectId,
        environmentId: ENV_ID,
        variableId: "var-stale-1",
        name: "STALE_VALUE",
        author: owner,
        head: headOf(built, 2),
      }),
      value: await encryptValueFor({
        dek: dek1,
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        variableId: "var-stale-1",
        version: 1,
        plaintext: "dummy-stale-plaintext",
        writer: owner,
        head: headOf(built, 2),
      }),
    };
    const state = await makeRevokeServer({
      built,
      environments: {
        [ENV_ID]: {
          currentEpoch: 2,
          deks: [
            await ownerWrap(built.projectId, ENV_ID, 1, dek1),
            await ownerWrap(built.projectId, ENV_ID, 2, dek2),
          ],
          variables: [staleVariable],
        },
      },
    });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(state.pushes).toEqual([{ environmentId: ENV_ID, variableId: "var-stale-1" }]);
    const logs = env.logs.join("\n");
    expect(logs).toContain("resumed re-encryption");
    expect(logs).toContain("Done: the revocation and the rotation of every environment completed");
    expect(logs).not.toContain("Already rotated (epoch newer than the revocation");
  });

  it("mid-run recovery: when every environment is already rotated and re-encrypted after the revocation, it confirms only and changes nothing (idempotent)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp([ENV_ID], [], SERVER_ENC_PUB_A) },
      { actor: owner, operation: revokeServerOp(serverFpA) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    ]);
    const state = await makeRevokeServer({
      built,
      environments: {
        [ENV_ID]: {
          currentEpoch: 2,
          deks: [await ownerWrap(built.projectId, ENV_ID, 2, dek2)],
        },
      },
    });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(state.pushes).toHaveLength(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      `Already rotated (epoch newer than the revocation, no incomplete re-encryption confirmed): ${ENV_ID}`,
    );
    expect(logs).toContain("Done: the revocation and the rotation of every environment completed");
  });

  it("an environment deleted on the verified chain is skipped; the rest are rotated", async () => {
    const GONE_ID = "env-gone-9";
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: createEnvironmentOp(GONE_ID, dek2) },
      { actor: owner, operation: await grantServerOp([ENV_ID, GONE_ID], [], SERVER_ENC_PUB_A) },
      { actor: owner, operation: deleteEnvironmentOp(GONE_ID) },
    ]);
    const listedStatements = [
      await environmentStatementFor({
        projectId: built.projectId,
        environmentId: ENV_ID,
        name: ENV_ID,
        author: owner,
        head: headOf(built, 1),
      }),
    ];
    const state = await makeRevokeServer({
      built,
      environments: {
        [ENV_ID]: {
          currentEpoch: 1,
          deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)],
        },
      },
      listedStatements,
    });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(1);
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_ID]);
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      `Skipped deleted environments (delete_environment on the verified chain): ${GONE_ID}`,
    );
    expect(logs).toContain("Done: the revocation and the rotation of every environment completed");
  });

  it("across multiple environments, one rotation's failure doesn't stop the rest, and exit 1 reports the failure", async () => {
    const ENV_A = "env-aaa-1";
    const ENV_B = "env-bbb-2";
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_B, dek2) },
      { actor: owner, operation: await grantServerOp([ENV_A, ENV_B], [], SERVER_ENC_PUB_A) },
    ]);
    const state = await makeRevokeServer({
      built,
      environments: {
        [ENV_A]: {
          currentEpoch: 1,
          deks: [await ownerWrap(built.projectId, ENV_A, 1, dek1)],
        },
        [ENV_B]: {
          currentEpoch: 1,
          deks: [await ownerWrap(built.projectId, ENV_B, 1, dek2)],
        },
      },
      onRotate: (environmentId) =>
        environmentId === ENV_B ? { status: 500, json: {} } : undefined,
    });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(1);
    expect(state.appendedEntries).toHaveLength(1);
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_A]);
    const errors = env.errors.join("\n");
    expect(errors).toContain(`Warning: rotation of environment ${ENV_B} failed`);
    expect(env.logs.join("\n")).not.toContain(
      "Done: the revocation and the rotation of every environment completed",
    );
  });

  it("non-owners are refused (§6.2)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "member") },
      { actor: owner, operation: await grantServerOp([], [], SERVER_ENC_PUB_A) },
    ]);
    const state = await makeRevokeServer({ built });
    const env = await startRevokeEnv(state, built.projectId, member);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Only an owner can run revoke_server");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("multiple live grants require --fingerprint, and only the named target is revoked", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: await grantServerOp([], [], SERVER_ENC_PUB_A) },
      { actor: owner, operation: await grantServerOp([], [], SERVER_ENC_PUB_B) },
    ]);

    const state1 = await makeRevokeServer({ built });
    const env1 = await startRevokeEnv(state1, built.projectId, owner);
    expect(await runCli(["server", "revoke"], env1.layer)).toBe(1);
    expect(env1.errors.join("\n")).toContain("Multiple grants are active");
    expect(state1.appendedEntries).toHaveLength(0);

    const state2 = await makeRevokeServer({ built });
    const env2 = await startRevokeEnv(state2, built.projectId, owner);
    expect(await runCli(["server", "revoke", "--fingerprint", "0".repeat(32)], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain("No active grant matches --fingerprint");
    expect(state2.appendedEntries).toHaveLength(0);

    const state3 = await makeRevokeServer({ built });
    const env3 = await startRevokeEnv(state3, built.projectId, owner);
    expect(await runCli(["server", "revoke", "--fingerprint", "XYZ"], env3.layer)).toBe(2);
    expect(env3.errors.join("\n")).toContain("--fingerprint is malformed");

    const state4 = await makeRevokeServer({ built });
    const env4 = await startRevokeEnv(state4, built.projectId, owner);
    expect(await runCli(["server", "revoke", "--fingerprint", serverFpB], env4.layer)).toBe(0);
    expect(state4.appendedEntries).toHaveLength(1);
    const revoke = state4.appendedEntries[0];
    if (revoke?.op !== "revoke_server") throw new Error("revoke entry missing");
    expect(revoke.payload.serverKeyFingerprintHex).toBe(serverFpB);
    expect(env4.logs.join("\n")).toContain(
      "Done: the revocation and the rotation of every environment completed",
    );
  });

  it("with neither a live grant nor a past revoke_server it's an error (nothing to revoke)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const state = await makeRevokeServer({ built });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "There is no active grant_server and no revoke_server on the chain (nothing to revoke)",
    );
    expect(state.appendedEntries).toHaveLength(0);
  });
});
