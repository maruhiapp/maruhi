import type { ChainEntry } from "@maruhi/crypto";
import { computeChainEntryHash } from "@maruhi/crypto";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  changeRoleOp,
  createEnvironmentOp,
  deleteEnvironmentOp,
  distributedEnvironmentStatement,
  distributedManifest,
  distributedManifestHashOf,
  distributedVariableStatement,
  distributedWrap,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  headOf,
  removeMemberOp,
  rotateEpochOp,
  type WireCheckpointSnapshot,
  type WireDistributedManifest,
  type WireDistributedVariableStatement,
  type WireRecipientDek,
  type WireWrappedDek,
} from "@maruhi/test-kit";
import type { ApiReply } from "@maruhi/test-kit/api";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import {
  acceptAppendedEntry,
  type AppendAnswer,
  injectedAppendResponse,
  lastHashOf,
  servedChain,
} from "./support/chain-handler.ts";
import type { WireRotateBody } from "./support/env-rotate.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onEndpoint } from "./support/server.ts";

const ENV_ID = "env-app-1";

let owner: GeneratedIdentity;
let target: GeneratedIdentity;
let admin2: GeneratedIdentity;
let dek1: Uint8Array;
let dek2: Uint8Array;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await generateIdentity("user-owner-1111");
  target = await generateIdentity("user-target-2222");
  admin2 = await generateIdentity("user-admin2-3333");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

interface WireFlag {
  readonly environmentId: string;
  readonly variableId: string;
  readonly basis: "read" | "readable";
  readonly targetUserId: string;
  readonly recommendedAtMs: number;
  readonly triggerChainSeq: number;
  readonly trigger: "remove_member" | "change_role";
}

interface RemoveServerState {
  readonly handlers: readonly MockHandler[];
  readonly appendedEntries: ChainEntry[];
  readonly rotateBodies: WireRotateBody[];
  readonly registerBodies: { environmentId: string; deks: readonly WireWrappedDek[] }[];
  readonly counters: { appendAttempts: number };
}

async function makeRemoveServer(input: {
  readonly built: BuiltChain;
  readonly environments: Readonly<
    Record<string, { currentEpoch: number; deks: WireRecipientDek[] }>
  >;
  readonly onAppend?: (call: number) => AppendAnswer | undefined;
  readonly chainAfterConflict?: BuiltChain;
  readonly rotator?: GeneratedIdentity;
  readonly flags?: readonly WireFlag[];
  readonly variableStatements?: Readonly<
    Record<string, readonly WireDistributedVariableStatement[]>
  >;
}): Promise<RemoveServerState> {
  const rotator = input.rotator ?? owner;
  const projectId = input.built.projectId;
  const entries: ChainEntry[] = [...input.built.entries];
  const hashes: string[] = [...input.built.hashes];
  const appendedEntries: ChainEntry[] = [];
  const rotateBodies: WireRotateBody[] = [];
  const registerBodies: { environmentId: string; deks: readonly WireWrappedDek[] }[] = [];
  const counters = { appendAttempts: 0 };
  const environments = input.environments;
  const manifests = new Map<string, WireDistributedManifest>();
  const checkpointSnapshots = new Map<string, WireCheckpointSnapshot>();
  const listedStatements = await Promise.all(
    Object.keys(environments).map((environmentId) =>
      distributedEnvironmentStatement({
        projectId,
        environmentId,
        name: environmentId,
        author: owner,
        head: headOf(input.built, 1),
      }),
    ),
  );

  const metadataResponse = async (
    environmentId: string,
  ): Promise<ApiReply<"variables.pullMetadata">> => {
    const environment = environments[environmentId];
    const statement = listedStatements.find((item) => item.environmentId === environmentId);
    if (environment === undefined || statement === undefined) {
      return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId } };
    }
    const variables = input.variableStatements?.[environmentId] ?? [];
    const stored = manifests.get(environmentId);
    const epoch = stored?.epoch ?? environment.currentEpoch;
    const continuation =
      stored === undefined
        ? { manifestVersion: 1 }
        : {
            manifestVersion: stored.manifestVersion + 1,
            prevManifestSigHashHex: await distributedManifestHashOf(projectId, stored),
          };
    const manifest = await distributedManifest({
      projectId,
      environmentId,
      epoch,
      issuer: owner,
      head: { seq: entries.length, hashHex: hashes[hashes.length - 1] ?? "" },
      envStatement: statement,
      statements: variables,
      ...continuation,
    });
    return {
      status: 200,
      json: {
        environmentId,
        currentEpoch: epoch,
        statement,
        variables,
        deletedVariables: [],
        manifest,
        schemaPolicy: "enabled" as const,
      },
    };
  };

  const handlers: MockHandler[] = [
    onEndpoint("rotation.flags", { projectId }, () => ({
      status: 200,
      json: { flags: input.flags ?? [] },
    })),
    onEndpoint("variables.pullMetadata", { projectId }, async (request) => {
      return metadataResponse(request.params.environmentId);
    }),
    onEndpoint("membership.get", { projectId }, () => ({
      status: 200,
      json: servedChain(projectId, entries, hashes),
    })),
    onEndpoint("membership.append", { projectId }, async (request) => {
      const injected = injectedAppendResponse(input, counters.appendAttempts, entries, hashes);
      counters.appendAttempts += 1;
      if (injected !== undefined) {
        return injected;
      }
      const body = { entry: request.body.entry as ChainEntry };
      appendedEntries.push(body.entry);
      return acceptAppendedEntry(projectId, entries, hashes, body.entry);
    }),
    onEndpoint("environments.list", { projectId }, () => ({
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
    onEndpoint("variables.pull", { projectId }, async (request) => {
      const environmentId = request.params.environmentId;
      const environment = environments[environmentId];
      const statement = listedStatements.find((item) => item.environmentId === environmentId);
      if (environment === undefined || statement === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId } };
      }
      let manifest = manifests.get(environmentId);
      if (manifest === undefined) {
        manifest = await distributedManifest({
          projectId,
          environmentId,
          epoch: environment.currentEpoch,
          issuer: owner,
          head: { seq: entries.length, hashHex: hashes[hashes.length - 1] ?? "" },
          envStatement: statement,
          statements: [],
        });
        manifests.set(environmentId, manifest);
      }
      const checkpointSnapshot = checkpointSnapshots.get(environmentId);
      return {
        status: 200,
        json: {
          environmentId,
          currentEpoch: environment.currentEpoch,
          statement,
          variables: [],
          deletedVariables: [],
          deks: environment.deks,
          manifest,
          ...(checkpointSnapshot === undefined ? {} : { checkpointSnapshot }),
          schemaPolicy: "enabled" as const,
        },
      };
    }),
    onEndpoint("environments.rotate", { projectId }, async (request) => {
      const environmentId = request.params.environmentId;
      const environment = environments[environmentId];
      if (environment === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId } };
      }
      const body = request.body as WireRotateBody;
      rotateBodies.push(body);
      entries.push(body.entry, body.checkpoint);
      hashes.push(
        await computeChainEntryHash(body.entry),
        await computeChainEntryHash(body.checkpoint),
      );
      checkpointSnapshots.set(environmentId, {
        chainSeq: entries.length,
        entryHashHex: hashes[hashes.length - 1] ?? "",
        values: [],
      });
      environment.currentEpoch = body.entry.payload.newEpoch;
      manifests.set(environmentId, {
        ...body.manifest,
        issuerUserId: rotator.userId,
        issuerKeyFingerprintHex: rotator.fingerprintHex,
      });
      for (const wrap of body.deks) {
        if (wrap.recipientUserId !== rotator.userId) {
          continue;
        }
        environment.deks.push({
          suite: wrap.suite,
          epoch: wrap.epoch,
          recipientEncPubHex: wrap.recipientEncPubHex,
          encHex: wrap.encHex,
          ciphertextHex: wrap.ciphertextHex,
          signatureHex: wrap.signatureHex,
          signerUserId: rotator.userId,
          signerKeyFingerprintHex: rotator.fingerprintHex,
        });
      }
      return {
        status: 200,
        json: {
          environmentId,
          currentEpoch: environment.currentEpoch,
          headSeq: entries.length,
          headHashHex: lastHashOf(hashes),
        },
      };
    }),
  ];
  handlers.push(
    onEndpoint("deks.listMine", { projectId }, (request) => {
      const environmentId = request.params.environmentId;
      const environment = environments[environmentId];
      return environment === undefined
        ? { status: 404, json: { _tag: "EnvironmentNotFound", environmentId } }
        : { status: 200, json: { deks: environment.deks } };
    }),
    onEndpoint("deks.register", { projectId }, (request) => {
      const environmentId = request.params.environmentId;
      if (environments[environmentId] === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId } };
      }
      registerBodies.push({ environmentId, deks: request.body.deks });
      return { status: 204 };
    }),
  );
  return { handlers, appendedEntries, rotateBodies, registerBodies, counters };
}

async function startEnv(
  state: RemoveServerState,
  projectId: string,
  user: GeneratedIdentity,
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
  return distributedWrap({ projectId, environmentId, epoch, dek, recipient: owner, signer: owner });
}

describe("maruhi member remove", () => {
  it("appends remove_member and force-rotates every environment with reason=member-removed (no wrap to the removed target)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: addMemberOp(admin2, "member") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);

    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "remove_member") throw new Error("remove entry missing");
    expect(entry.payload.targetUserId).toBe(target.userId);

    expect(state.rotateBodies).toHaveLength(1);
    const rotate = state.rotateBodies[0];
    if (rotate === undefined) throw new Error("rotate body missing");
    expect(rotate.entry.payload.newEpoch).toBe(2);
    expect(rotate.entry.payload.reason).toBe("member-removed");
    expect(rotate.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, admin2.userId].toSorted(),
    );

    const logs = env.logs.join("\n");
    expect(logs).toContain("Appended remove_member to the chain");
    expect(logs).toContain(
      "Done: the member removal and the rotation of every environment in the target's scope completed",
    );
  });

  it("prints the rotation checklist for the removed member's flags: confirmed fetches first, each with its next action (PF6 R3)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    const head = headOf(built, 2);
    const statements = await Promise.all(
      [
        ["v-db", "DATABASE_URL"],
        ["v-stripe", "STRIPE_SECRET_KEY"],
      ].map(([variableId, name]) =>
        distributedVariableStatement({
          projectId: built.projectId,
          environmentId: ENV_ID,
          variableId: variableId ?? "",
          name: name ?? "",
          author: owner,
          head,
        }),
      ),
    );
    const flag = (variableId: string, basis: "read" | "readable"): WireFlag => ({
      environmentId: ENV_ID,
      variableId,
      basis,
      targetUserId: target.userId,
      recommendedAtMs: 1_700_000_000_000,
      triggerChainSeq: 4,
      trigger: "remove_member",
    });
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
      flags: [
        flag("v-db", "readable"),
        flag("v-stripe", "read"),
        { ...flag("v-db", "read"), targetUserId: admin2.userId },
      ],
      variableStatements: { [ENV_ID]: statements },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);

    const logs = env.logs.join("\n");
    expect(logs).toContain("Rotation checklist: 2 variables the party that lost access could read");
    const read = logs.indexOf("[read] env-app-1 STRIPE_SECRET_KEY:");
    const readable = logs.indexOf("[readable] env-app-1 DATABASE_URL:");
    expect(read).toBeGreaterThan(-1);
    expect(readable).toBeGreaterThan(read);
    expect(logs).toContain(
      "rotate at the issuer, then `maruhi push STRIPE_SECRET_KEY --env env-app-1` (runbooks: https://maruhi.app/docs/rotation)",
    );
    expect(logs).toContain("`maruhi rotation list` shows what remains");
  });

  it("on detecting a concurrent removal during the ChainHeadConflict (409) resync, doesn't append and proceeds to the sweep (§12-4)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    const concurrent = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: removeMemberOp(target) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
      onAppend: (call) =>
        call === 0
          ? {
              status: 409,
              json: {
                _tag: "ChainHeadConflict",
                currentHeadSeq: concurrent.entries.length,
                currentHeadHashHex: concurrent.hashes[concurrent.hashes.length - 1] ?? "",
              },
            }
          : undefined,
      chainAfterConflict: concurrent,
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);
    expect(state.counters.appendAttempts).toBe(1);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("member-removed");
    expect(env.logs.join("\n")).toContain("The target was already removed");
  });

  it("gives up after five head conflicts in a row, naming remove_member, and sweeps nothing", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
      onAppend: () => ({
        status: 409,
        json: {
          _tag: "ChainHeadConflict",
          currentHeadSeq: built.entries.length,
          currentHeadHashHex: built.hashes[built.hashes.length - 1] ?? "",
        },
      }),
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(1);
    expect(state.counters.appendAttempts).toBe(5);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.errors.join("\n")).toContain(
      "remove_member's chain-head conflict did not resolve (5 attempts). Wait a moment and re-run",
    );
  });

  it("interruption recovery: when the target is already a non-member (remove on record), doesn't append and resumes the sweep", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: removeMemberOp(target) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("member-removed");
    expect(env.logs.join("\n")).toContain("The target was already removed");
    expect(env.errors.join("\n")).not.toContain("unconverged rotation mandate");
  });

  it("interruption recovery: already rotated and re-encrypted after removal → confirmation only, nothing changes (idempotent)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: removeMemberOp(target) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 2, deks: [await ownerWrap(built.projectId, ENV_ID, 2, dek2)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("Already rotated (epoch newer than the mandate entry");
  });

  it("refuses removing yourself (you can't fulfil the §7 mandate yourself)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", owner.userId], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("You cannot remove yourself");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("an admin removing an admin is owner-only; an unknown target is an error (§6.2's early check)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(admin2, "admin") },
      { actor: owner, operation: addMemberOp(target, "admin") },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, admin2);
    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Only an owner can run remove_member against an admin / owner",
    );
    expect(state.appendedEntries).toHaveLength(0);

    const state2 = await makeRemoveServer({ built, environments: {} });
    const env2 = await startEnv(state2, built.projectId, owner);
    expect(await runCli(["member", "remove", "user-nobody-0000"], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain("the chain has no removal record for it");
  });
});

describe("maruhi member change-role", () => {
  it("demotion below member appends + rotates every environment (reason=role-demoted)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--role", "reader"], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    expect(entry.payload).toEqual({
      targetUserId: target.userId,
      newRole: "reader",
      scopeKind: "all",
      scopeEnvironmentIds: [],
    });
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("role-demoted");
    expect(state.rotateBodies[0]?.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, target.userId].toSorted(),
    );
    expect(env.logs.join("\n")).toContain(
      "Done: the change and the rotation of the affected environments completed",
    );
  });

  it("promotion (reader → member) carries no rotation mandate", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "reader") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--role", "member"], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(1);
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain(
      "Done: the role / scope was changed (no rotation mandate)",
    );
  });

  it("a no-op re-run on a born-reader member neither appends nor sweeps", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "reader") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--role", "reader"], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain(
      "Done: the role / scope was changed (no rotation mandate)",
    );
  });

  it("interruption recovery: demotion already appended but rotation unfinished → don't append, resume the sweep", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      {
        actor: owner,
        operation: {
          op: "change_role",
          payload: {
            targetUserId: target.userId,
            newRole: "reader",
            scopeKind: "all",
            scopeEnvironmentIds: [],
          },
        },
      },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--role", "reader"], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("role-demoted");
    expect(env.logs.join("\n")).toContain("The target already has the specified role");
  });

  it("a no-op re-run on a born-reader doesn't pick up a sweep even with someone's unconverged mandate (the target-scope criterion)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "reader") },
      { actor: owner, operation: addMemberOp(admin2, "member") },
      { actor: owner, operation: removeMemberOp(admin2) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--role", "reader"], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain(
      "Done: the role / scope was changed (no rotation mandate)",
    );
  });

  it("demoting oneself below member is refused (the person can't fulfill the §7 mandate themselves)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(admin2, "owner") },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", owner.userId, "--role", "reader"], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("You cannot demote yourself below member");
    expect(state.appendedEntries).toHaveLength(0);
  });
});

const ENV_DEV = "env-dev";
const ENV_PROD = "env-prod";

async function twoEnvironments(
  projectId: string,
): Promise<Record<string, { currentEpoch: number; deks: WireRecipientDek[] }>> {
  return {
    [ENV_DEV]: { currentEpoch: 1, deks: [await ownerWrap(projectId, ENV_DEV, 1, dek1)] },
    [ENV_PROD]: { currentEpoch: 1, deks: [await ownerWrap(projectId, ENV_PROD, 1, dek2)] },
  };
}

describe("environment scope (ES K4): the mandate's environment set and change-role --env", () => {
  it("removing a listed{dev} member rotates only dev (remove = the target's current scope — §7)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "member", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_DEV]);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("member-removed");
    expect(env.logs.join("\n")).toContain(
      "Done: the member removal and the rotation of every environment in the target's scope completed",
    );
  });

  it("narrowing via change-role --env rotates only the narrowed portion with reason=scope-narrowed, and the new DEK is not wrapped to the target (R(E))", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--env", ENV_DEV], env.layer),
    ).toBe(0);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    expect(entry.payload).toEqual({
      targetUserId: target.userId,
      newRole: "member",
      scopeKind: "listed",
      scopeEnvironmentIds: [ENV_DEV],
    });
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_PROD]);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("scope-narrowed");
    expect(state.rotateBodies[0]?.deks.map((wrap) => wrap.recipientUserId)).toEqual([owner.userId]);
    expect(state.registerBodies).toHaveLength(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(`scope=${ENV_DEV}`);
    expect(logs).toContain("Scope narrowed by 1 environment");
    expect(logs).toContain(
      "Done: the change and the rotation of the affected environments completed",
    );
  });

  it("widening via change-role --all-envs backfills the widened portion's every epoch to the target without rotating (§12-6)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "member", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "change-role", target.userId, "--all-envs"], env.layer)).toBe(0);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    expect(entry.payload).toEqual({
      targetUserId: target.userId,
      newRole: "member",
      scopeKind: "all",
      scopeEnvironmentIds: [],
    });
    expect(state.rotateBodies).toHaveLength(0);
    expect(state.registerBodies.map((body) => body.environmentId)).toEqual([ENV_PROD]);
    expect(state.registerBodies[0]?.deks.map((wrap) => [wrap.epoch, wrap.recipientUserId])).toEqual(
      [[1, target.userId]],
    );
    const logs = env.logs.join("\n");
    expect(logs).toContain("1 environment added to the member's scope");
    expect(logs).toContain("Done: the role / scope was changed (no rotation mandate)");
  });

  it("interruption recovery: the narrowing entry already appended but rotate unfinished → re-running the same flags doesn't append and rotates only the narrowed portion", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: changeRoleOp(target, "member", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--env", ENV_DEV], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_PROD]);
    expect(env.logs.join("\n")).toContain("nothing was appended");
  });

  it("a CAS retry resolves the kept side (role / scope) from the post-resync view and doesn't overwrite a concurrent change (Cursor Bugbot)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "reader") },
    ]);
    const concurrent = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "reader") },
      { actor: owner, operation: changeRoleOp(target, "member") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
      onAppend: (call) =>
        call === 0
          ? {
              status: 409,
              json: {
                _tag: "ChainHeadConflict",
                currentHeadSeq: concurrent.entries.length,
                currentHeadHashHex: concurrent.hashes[concurrent.hashes.length - 1] ?? "",
              },
            }
          : undefined,
      chainAfterConflict: concurrent,
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--env", ENV_DEV], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    expect(entry.payload).toEqual({
      targetUserId: target.userId,
      newRole: "member",
      scopeKind: "listed",
      scopeEnvironmentIds: [ENV_DEV],
    });
    expect(entry.seq).toBe(6);
  });

  it("input rules: no-change, combining --env with --all-envs, and --env on an owner are usage errors (before any traffic)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: addMemberOp(target, "admin") },
    ]);
    for (const argv of [
      ["member", "change-role", target.userId],
      ["member", "change-role", target.userId, "--env", ENV_DEV, "--all-envs"],
      ["member", "change-role", target.userId, "--role", "owner", "--env", ENV_DEV],
    ]) {
      const state = await makeRemoveServer({ built, environments: {} });
      const env = await startEnv(state, built.projectId, owner);
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(state.appendedEntries, argv.join(" ")).toHaveLength(0);
    }
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, owner);
    expect(
      await runCli(["member", "change-role", target.userId, "--env", "env-nope"], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("does not exist on this project's chain");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("a valued pull refuses out-of-scope before traffic, while a meta-only one (schema) doesn't care about scope (§6.3 / §12-7 — ruling G-2)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "member", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const server = await MockServer.start([...state.handlers]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, target);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["pull", "--env", ENV_PROD], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `Cannot operate on environment ${ENV_PROD}: it is outside your environment scope`,
    );
    expect(env.errors.join("\n")).toContain(`your scope: ${ENV_DEV}`);
    expect(server.requests.filter((request) => request.path.includes("/pull"))).toHaveLength(0);

    const schemaEnv = await makeTestEnv();
    seedSession(schemaEnv, server.origin, target);
    await seedConfig(schemaEnv, { server: server.origin, defaultProject: built.projectId });
    await runCli(["schema", "--env", ENV_PROD], schemaEnv.layer);
    expect(schemaEnv.errors.join("\n")).not.toContain("outside your environment scope");
    expect(
      server.requests.filter((request) => request.path.includes(`/${ENV_PROD}/pull/metadata`)),
    ).toHaveLength(1);
  });

  it("interruption recovery: even with a third party's change_role after a widening backfill stalls, re-derive the widened portion from the whole history and resume (pullfrog)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "member", [ENV_DEV]) },
      { actor: owner, operation: changeRoleOp(target, "member") },
      { actor: owner, operation: changeRoleOp(target, "admin") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "change-role", target.userId, "--all-envs"], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.registerBodies.map((body) => body.environmentId)).toEqual([ENV_PROD]);
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("refuses narrowing your own scope (you can't fulfil the §7 mandate yourself)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(admin2, "admin", [ENV_DEV, ENV_PROD]) },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, admin2);
    expect(
      await runCli(["member", "change-role", admin2.userId, "--env", ENV_DEV], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("You cannot narrow your own scope");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("--role owner fully replaces a listed target's scope with all and backfills the widened portion (§6.2 owner = all)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "admin", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);
    expect(
      await runCli(["member", "change-role", target.userId, "--role", "owner"], env.layer),
    ).toBe(0);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    expect(entry.payload).toMatchObject({ newRole: "owner", scopeKind: "all" });
    expect(state.registerBodies.map((body) => body.environmentId)).toEqual([ENV_PROD]);
  });

  it("--no-envs replaces the scope with listed{} (zero environments) and rotates every environment of the old scope as the narrowed portion (§6.2's empty listed)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "admin", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);
    expect(await runCli(["member", "change-role", target.userId, "--no-envs"], env.layer)).toBe(0);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    expect(entry.payload).toMatchObject({
      newRole: "admin",
      scopeKind: "listed",
      scopeEnvironmentIds: [],
    });
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_DEV]);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("scope-narrowed");
  });

  it("change-role --env drops duplicates and malformed forms as usage (2) before traffic", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    for (const argv of [
      ["member", "change-role", target.userId, "--env", ENV_DEV, "--env", ENV_DEV],
      ["member", "change-role", target.userId, "--env", "-bad id"],
      ["member", "change-role", target.userId, "--no-envs", "--all-envs"],
    ]) {
      const state = await makeRemoveServer({ built, environments: {} });
      const env = await startEnv(state, built.projectId, owner);
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(state.appendedEntries, argv.join(" ")).toHaveLength(0);
    }
  });

  it("someone-else's mandate environments outside the caller's scope aren't rotated but are noted, while one's own mandate is fulfilled (§7 — independent review S2)", async () => {
    const devAdmin = await generateIdentity("user-devadmin-4444");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(devAdmin, "admin", [ENV_DEV]) },
      { actor: owner, operation: addMemberOp(target, "member", [ENV_DEV, ENV_PROD]) },
      { actor: owner, operation: changeRoleOp(target, "member", [ENV_DEV]) },
    ]);
    const environments = {
      [ENV_DEV]: {
        currentEpoch: 1,
        deks: [
          await distributedWrap({
            projectId: built.projectId,
            environmentId: ENV_DEV,
            epoch: 1,
            dek: dek1,
            recipient: devAdmin,
            signer: owner,
          }),
        ],
      },
      [ENV_PROD]: { currentEpoch: 1, deks: [] },
    };
    const state = await makeRemoveServer({ built, environments, rotator: devAdmin });
    const env = await startEnv(state, built.projectId, devAdmin);
    expect(
      await runCli(["member", "change-role", target.userId, "--role", "reader"], env.layer),
    ).toBe(0);
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_DEV]);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("role-demoted");
    expect(env.errors.join("\n")).toContain(
      `1 environment with a pending rotation mandate is outside your scope and cannot be rotated by you (${ENV_PROD})`,
    );
  });

  it("when the unconverged portion of someone else's widening lies only outside your scope, it notes it and exits 0 with no backfill (Cursor Bugbot)", async () => {
    const devAdmin = await generateIdentity("user-devadmin-4444");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(devAdmin, "admin", [ENV_DEV]) },
      { actor: owner, operation: addMemberOp(target, "member", [ENV_DEV]) },
      { actor: owner, operation: changeRoleOp(target, "member", [ENV_DEV, ENV_PROD]) },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, devAdmin);
    expect(
      await runCli(
        ["member", "change-role", target.userId, "--env", ENV_DEV, "--env", ENV_PROD],
        env.layer,
      ),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.registerBodies).toHaveLength(0);
    expect(env.errors.join("\n")).toContain(
      `1 environment widened earlier for this member (${ENV_PROD}) is outside your scope, so you cannot backfill it`,
    );
  });

  it("a chain-deleted environment leaves the widened portion and doesn't appear in the out-of-scope note (pullfrog)", async () => {
    const devAdmin = await generateIdentity("user-devadmin-4444");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(devAdmin, "admin", [ENV_DEV]) },
      { actor: owner, operation: addMemberOp(target, "member", [ENV_DEV]) },
      { actor: owner, operation: changeRoleOp(target, "member", [ENV_DEV, ENV_PROD]) },
      { actor: owner, operation: deleteEnvironmentOp(ENV_PROD) },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, devAdmin);
    expect(
      await runCli(["member", "change-role", target.userId, "--env", ENV_DEV], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.registerBodies).toHaveLength(0);
    expect(env.errors.join("\n")).not.toContain("widened earlier for this member");
    expect(
      await runCli(
        ["member", "change-role", target.userId, "--env", ENV_DEV, "--env", ENV_PROD],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `Environment ${ENV_PROD} is deleted on this project's chain`,
    );
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("a listed admin cannot remove a target outside their scope (principle 1's pre-judgement — pullfrog)", async () => {
    const devAdmin = await generateIdentity("user-devadmin-4444");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(devAdmin, "admin", [ENV_DEV]) },
      { actor: owner, operation: addMemberOp(target, "reader", [ENV_DEV, ENV_PROD]) },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, devAdmin);
    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not contain the target's scope");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("a listed admin cannot append a change_role touching outside their scope (principle 1's pre-judgement)", async () => {
    const devAdmin = await generateIdentity("user-devadmin-4444");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(devAdmin, "admin", [ENV_DEV]) },
      { actor: owner, operation: addMemberOp(target, "reader", [ENV_DEV, ENV_PROD]) },
    ]);
    const narrow = await makeRemoveServer({ built, environments: {} });
    const narrowEnv = await startEnv(narrow, built.projectId, devAdmin);
    expect(
      await runCli(["member", "change-role", target.userId, "--env", ENV_DEV], narrowEnv.layer),
    ).toBe(1);
    expect(narrowEnv.errors.join("\n")).toContain("scope-not-contained");
    expect(narrow.appendedEntries).toHaveLength(0);
    const promote = await makeRemoveServer({ built, environments: {} });
    const promoteEnv = await startEnv(promote, built.projectId, devAdmin);
    expect(
      await runCli(["member", "change-role", target.userId, "--role", "member"], promoteEnv.layer),
    ).toBe(1);
    expect(promoteEnv.errors.join("\n")).toContain("scope-not-contained");
    expect(promote.appendedEntries).toHaveLength(0);
  });
});
