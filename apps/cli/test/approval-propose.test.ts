import { computeServerKeyFingerprint, encodeHex } from "@maruhi/crypto";
import {
  addMemberOp,
  buildChain,
  createEnvironmentOp,
  distributedWrap,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  grantServerOp,
  innerOf,
  proposeOp,
  removeMemberOp,
  setApprovalPolicyOp,
} from "@maruhi/test-kit";
import type { ApiSuccess } from "@maruhi/test-kit/api";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type FourEyesServerState, makeFourEyesServer } from "./support/four-eyes-server.ts";
import { acceptanceFixture, INVITE_ID, issueInviteFixture } from "./support/invite.ts";
import { MockServer } from "./support/server.ts";

const ENV_ID = "env-app-1";
const SERVER_ENC_PUB_HEX = "5a".repeat(32);

let owner: GeneratedIdentity;
let owner2: GeneratedIdentity;
let target: GeneratedIdentity;
let acceptor: GeneratedIdentity;
let dek1: Uint8Array;
let serverFpHex: string;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await generateIdentity("user-owner-1111");
  owner2 = await generateIdentity("user-owner-2222");
  target = await generateIdentity("user-target-4444");
  acceptor = await generateIdentity("user-acceptor-66");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  const fp = await computeServerKeyFingerprint(Uint8Array.from({ length: 32 }, () => 0x5a));
  if (!fp.ok) throw new Error("server fingerprint failed");
  serverFpHex = encodeHex(fp.value);
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function startEnv(
  state: FourEyesServerState,
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

type PolicyOp = Parameters<typeof setApprovalPolicyOp>[0][number];

async function invitationFor(
  projectId: string,
  invitee: GeneratedIdentity,
): Promise<ApiSuccess<"invites.list">["invitations"][number]> {
  const issued = await issueInviteFixture({
    inviter: owner,
    projectId,
    headHashHex: "cd".repeat(32),
    headSeq: 1,
  });
  const acceptance = await acceptanceFixture({ projectId, issued, invitee });
  return {
    id: INVITE_ID,
    projectId,
    role: "member",
    scopeKind: "all",
    scopeEnvironmentIds: [],
    status: "accepted",
    inviterUserId: owner.userId,
    issuance: issued.issuance,
    createdAtMs: 1755200000000,
    expiresAtMs: 1755993600000,
    acceptance,
  };
}

function baseSteps(ops: readonly PolicyOp[]) {
  return [
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: addMemberOp(owner2, "owner") },
    { actor: owner, operation: addMemberOp(target, "member") },
    { actor: owner, operation: setApprovalPolicyOp(ops, 2) },
  ];
}

describe("auto-proposal of existing commands (K6-A)", () => {
  it("member remove: appends propose when the policy targets it and rotate does not run; re-running reports the same proposal (idempotent)", async () => {
    const built = await buildChain(baseSteps(["remove_member"]));
    const state = await makeFourEyesServer({
      built,
      environments: {
        [ENV_ID]: {
          currentEpoch: 1,
          deks: [
            await distributedWrap({
              projectId: built.projectId,
              environmentId: ENV_ID,
              epoch: 1,
              dek: dek1,
              recipient: owner,
              signer: owner,
            }),
          ],
        },
      },
      actor: owner,
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId, "--expires", "48h"], env.layer)).toBe(
      0,
    );
    expect(state.appendedEntries.map((entry) => entry.op)).toEqual(["propose"]);
    const proposed = state.appendedEntries[0];
    if (proposed?.op !== "propose") throw new Error("propose entry missing");
    expect(proposed.payload.inner).toEqual({
      op: "remove_member",
      payload: { targetUserId: target.userId },
    });
    const lifetime = proposed.payload.expiresAtMs - proposed.timestampMs;
    expect(lifetime).toBeGreaterThan(48 * 3_600_000 - 10_000);
    expect(lifetime).toBeLessThanOrEqual(48 * 3_600_000);
    expect(state.rotateBodies).toHaveLength(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(`Proposed remove_member ${target.userId}`);
    expect(logs).toContain("nothing has been applied yet");
    expect(logs).toContain("needs 1 more owner approval (1 of 2 recounted so far)");
    expect(logs).toContain("maruhi approval approve");

    env.logs.length = 0;
    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(1);
    expect(env.logs.join("\n")).toContain("The same operation is already proposed");
  });

  it("member remove: when a CAS-conflict resync shows another owner proposed the same operation, reports that proposal and appends nothing", async () => {
    const steps = baseSteps(["remove_member"]);
    const built = await buildChain(steps);
    const concurrent = await buildChain([
      ...steps,
      { actor: owner2, operation: proposeOp(innerOf(removeMemberOp(target))) },
    ]);
    const state = await makeFourEyesServer({
      built,
      environments: {},
      actor: owner,
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
    const logs = env.logs.join("\n");
    expect(logs).toContain("The same operation is already proposed");
    expect(logs).toContain(`by ${owner2.userId}`);
  });

  it("member remove: the proposal path does not refuse a self-remove (the fulfiller is the approver — K6-N)", async () => {
    const owner3 = await generateIdentity("user-owner-3333");
    const steps = baseSteps(["remove_member"]);
    const built = await buildChain([
      ...steps.slice(0, -1),
      { actor: owner, operation: addMemberOp(owner3, "owner") },
      ...steps.slice(-1),
    ]);
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner2 });
    const env = await startEnv(state, built.projectId, owner2);
    const code = await runCli(["member", "remove", owner2.userId], env.layer);
    expect(code).toBe(0);
    expect(state.appendedEntries.map((entry) => entry.op)).toEqual(["propose"]);
    expect(env.errors.join("\n")).toContain("this proposal removes you");
  });

  it("member change-role: proposes when the op is targeted (the omitted side resolves to the current state at propose time); untargeted appends directly", async () => {
    const built = await buildChain(baseSteps(["change_role"]));
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner });
    const env = await startEnv(state, built.projectId, owner);
    expect(
      await runCli(["member", "change-role", target.userId, "--role", "reader"], env.layer),
    ).toBe(0);
    const proposed = state.appendedEntries[0];
    if (proposed?.op !== "propose") throw new Error("propose entry missing");
    expect(proposed.payload.inner).toEqual({
      op: "change_role",
      payload: {
        targetUserId: target.userId,
        newRole: "reader",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });
    expect(state.rotateBodies).toHaveLength(0);

    const other = await buildChain(baseSteps(["remove_member"]));
    const otherState = await makeFourEyesServer({ built: other, environments: {}, actor: owner });
    const otherEnv = await startEnv(otherState, other.projectId, owner);
    expect(
      await runCli(["member", "change-role", target.userId, "--role", "admin"], otherEnv.layer),
    ).toBe(0);
    expect(otherState.appendedEntries.map((entry) => entry.op)).toEqual(["change_role"]);
    otherEnv.logs.length = 0;
    expect(
      await runCli(["member", "change-role", target.userId, "--role", "owner"], otherEnv.layer),
    ).toBe(0);
    expect(otherState.appendedEntries.map((entry) => entry.op)).toEqual(["change_role", "propose"]);
    expect(otherEnv.logs.join("\n")).toContain(`Proposed change_role ${target.userId} to owner`);
  });

  it("server revoke: proposes when targeted, and rotate across all environments does not run", async () => {
    const grant = await grantServerOp([ENV_ID], [], SERVER_ENC_PUB_HEX);
    const built = await buildChain([
      ...baseSteps(["revoke_server"]),
      { actor: owner, operation: grant },
    ]);
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner });
    const env = await startEnv(state, built.projectId, owner);
    expect(await runCli(["server", "revoke"], env.layer)).toBe(0);
    const proposed = state.appendedEntries[0];
    if (proposed?.op !== "propose") throw new Error("propose entry missing");
    expect(proposed.payload.inner).toEqual({
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: serverFpHex },
    });
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain(`Proposed revoke_server key ${serverFpHex}`);
  });

  it("server grant: proposes after the ceremony (--expect-fingerprint); the server-destined backfill does not run", async () => {
    const built = await buildChain(baseSteps(["grant_server"]));
    const state = await makeFourEyesServer({
      built,
      environments: {},
      actor: owner,
      authConfig: {
        githubClientId: "dummy-client-id",
        signupPolicy: "open",
        serverKeyFingerprintHex: serverFpHex,
        serverEncPubHex: SERVER_ENC_PUB_HEX,
      },
    });
    const env = await startEnv(state, built.projectId, owner);
    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--expect-fingerprint", serverFpHex],
        env.layer,
      ),
    ).toBe(0);
    const proposed = state.appendedEntries[0];
    if (proposed?.op !== "propose") throw new Error("propose entry missing");
    expect(proposed.payload.inner).toMatchObject({
      op: "grant_server",
      payload: { serverKeyFingerprintHex: serverFpHex, scopeEnvironmentIds: [ENV_ID] },
    });
    expect(state.registerBodies).toHaveLength(0);
    const bare = await makeFourEyesServer({
      built,
      environments: {},
      actor: owner,
      authConfig: {
        githubClientId: "dummy-client-id",
        signupPolicy: "open",
        serverKeyFingerprintHex: serverFpHex,
        serverEncPubHex: SERVER_ENC_PUB_HEX,
      },
    });
    const bareEnv = await startEnv(bare, built.projectId, owner);
    bareEnv.setTerminal({ stdin: false, stdout: false });
    expect(await runCli(["server", "grant", "--environments", ENV_ID], bareEnv.layer)).toBe(1);
    expect(bare.counters.appendAttempts).toBe(0);
  });

  it("stops fail-closed when the policy changed on a CAS-conflict resync (re-run lands the new shape)", async () => {
    const grant = await grantServerOp([ENV_ID], [], SERVER_ENC_PUB_HEX);
    const cases: readonly {
      readonly op: PolicyOp;
      readonly argv: readonly string[];
      readonly granted?: boolean;
      readonly invited?: boolean;
    }[] = [
      {
        op: "add_member",
        argv: ["member", "add", "--expect-fingerprint", acceptor.fingerprintHex],
        invited: true,
      },
      { op: "remove_member", argv: ["member", "remove", target.userId] },
      { op: "change_role", argv: ["member", "change-role", target.userId, "--role", "admin"] },
      {
        op: "grant_server",
        argv: ["server", "grant", "--environments", ENV_ID, "--expect-fingerprint", serverFpHex],
      },
      { op: "revoke_server", argv: ["server", "revoke"], granted: true },
    ];
    for (const { op, argv, granted, invited } of cases) {
      const steps = [
        { actor: owner, operation: genesisOp(owner) },
        { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
        { actor: owner, operation: addMemberOp(owner2, "owner") },
        { actor: owner, operation: addMemberOp(target, "member") },
        ...(granted === true ? [{ actor: owner, operation: grant }] : []),
      ];
      const built = await buildChain(steps);
      const concurrent = await buildChain([
        ...steps,
        { actor: owner, operation: setApprovalPolicyOp([op], 2) },
      ]);
      const state = await makeFourEyesServer({
        built,
        environments: {},
        actor: owner,
        authConfig: {
          githubClientId: "dummy-client-id",
          signupPolicy: "open",
          serverKeyFingerprintHex: serverFpHex,
          serverEncPubHex: SERVER_ENC_PUB_HEX,
        },
        ...(invited === true
          ? { invitations: [await invitationFor(built.projectId, acceptor)] }
          : {}),
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
      expect(await runCli([...argv], env.layer), op).toBe(1);
      expect(env.errors.join("\n"), op).toContain(
        "The four-eyes policy changed while this command was appending",
      );
      expect(state.counters.appendAttempts, op).toBe(1);
      expect(state.appendedEntries, op).toHaveLength(0);
    }
  });

  it("a malformed --expires fails as usage (2) before any communication", async () => {
    const built = await buildChain(baseSteps(["remove_member"]));
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner });
    const env = await startEnv(state, built.projectId, owner);
    expect(await runCli(["member", "remove", target.userId, "--expires", "40d"], env.layer)).toBe(
      2,
    );
    expect(await runCli(["member", "remove", target.userId, "--expires", "soon"], env.layer)).toBe(
      2,
    );
    expect(state.counters.appendAttempts).toBe(0);
  });
});

describe("member add proposal and the key-FP re-registration warning (K6-D / K6-I)", () => {
  it("appends propose after the ceremony and does not backfill when the policy targets add_member", async () => {
    const built = await buildChain(baseSteps(["add_member"]));
    const state = await makeFourEyesServer({
      built,
      environments: {},
      actor: owner,
      invitations: [await invitationFor(built.projectId, acceptor)],
    });
    const env = await startEnv(state, built.projectId, owner);
    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);
    const proposed = state.appendedEntries[0];
    if (proposed?.op !== "propose") throw new Error("propose entry missing");
    expect(proposed.payload.inner).toEqual({
      op: "add_member",
      payload: {
        targetUserId: acceptor.userId,
        encPubHex: acceptor.encPubHex,
        sigPubHex: acceptor.sigPubHex,
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });
    expect(state.registerBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain(`Proposed add_member ${acceptor.userId} as member`);
    expect(env.errors.join("\n")).toContain(
      "the invite stays accepted until the proposal is applied",
    );
  });

  it("warns when the acceptance key appeared in a past membership interval (same user_id) — a warning, not a refusal (K5-K)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(acceptor, "member") },
      { actor: owner, operation: removeMemberOp(acceptor) },
    ]);
    const state = await makeFourEyesServer({
      built,
      environments: {
        [ENV_ID]: {
          currentEpoch: 1,
          deks: [
            await distributedWrap({
              projectId: built.projectId,
              environmentId: ENV_ID,
              epoch: 1,
              dek: dek1,
              recipient: owner,
              signer: owner,
            }),
          ],
        },
      },
      actor: owner,
      invitations: [await invitationFor(built.projectId, acceptor)],
    });
    const env = await startEnv(state, built.projectId, owner);
    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);
    expect(env.errors.join("\n")).toContain(
      "the acceptance key was registered before for this same user",
    );
    expect(env.errors.join("\n")).toContain("do not re-register it");
    expect(state.appendedEntries.map((entry) => entry.op)).toEqual(["add_member"]);
  });
});

describe("resuming an operation applied via a proposal (K6-C)", () => {
  it("re-running `member remove` on a target removed via a proposal accepts it as the removal record and resumes the sweep", async () => {
    const steps = baseSteps(["remove_member"]);
    const proposed = await buildChain([
      ...steps,
      { actor: owner, operation: proposeOp(innerOf(removeMemberOp(target))) },
    ]);
    const hash = proposed.hashes[proposed.hashes.length - 1] ?? "";
    const built = await buildChain([
      ...steps,
      { actor: owner, operation: proposeOp(innerOf(removeMemberOp(target))) },
      { actor: owner2, operation: { op: "approve", payload: { proposalHashHex: hash } } },
    ]);
    const state = await makeFourEyesServer({
      built,
      environments: {
        [ENV_ID]: {
          currentEpoch: 1,
          deks: [
            await distributedWrap({
              projectId: built.projectId,
              environmentId: ENV_ID,
              epoch: 1,
              dek: dek1,
              recipient: owner,
              signer: owner,
            }),
          ],
        },
      },
      actor: owner,
    });
    const env = await startEnv(state, built.projectId, owner);
    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("member-removed");
    expect(env.logs.join("\n")).toContain("The target was already removed");
  });
});
