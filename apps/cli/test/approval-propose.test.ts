// 既存コマンドの自動提案化(CRYPTO_SPEC §6.2 — PF1 K6。設計録 es-design.md §12 K6-A / D / I / N)。
//
// 固定する性質:
//  1. 方針が内側 op を対象にしていれば、`member remove` / `change-role` / `add`・`server grant` /
//     `revoke` は直接追記の代わりに `propose` を追記し、何も履行しない(rotate / バックフィル
//     なし — 裁定 P7)。表示は「Proposed … nothing has been applied yet」
//  2. 冪等性: 同じ内側 op の pending 提案が既にあれば新たに提案しない(K6-A)
//  3. 方針が対象にしていない op は従来どおり直接追記(既存テストが固定)。CAS 競合の再同期で
//     方針が変わっていれば fail-closed(再実行)
//  4. `member add`: 儀式(--expect-fingerprint)の後で提案し、鍵 FP の再登録には警告(K6-I)
//  5. 提案化の経路では自己 remove を拒否しない(履行者 = 承認者 — K6-N)
//  6. `--expires` の不備は usage(2)

import { computeServerKeyFingerprint, encodeHex } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  buildChain,
  createEnvironmentOp,
  genesisOp,
  grantServerOp,
  innerOf,
  makeTestUser,
  proposeOp,
  removeMemberOp,
  setApprovalPolicyOp,
  type TestUser,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type FourEyesServerState, makeFourEyesServer } from "./support/four-eyes-server.ts";
import { acceptanceFixture, INVITE_ID, issueInviteFixture } from "./support/invite.ts";
import { MockServer } from "./support/server.ts";

const ENV_ID = "env-app-1";
const SERVER_ENC_PUB_HEX = "5a".repeat(32);

let owner: TestUser;
let owner2: TestUser;
let target: TestUser;
let acceptor: TestUser;
let dek1: Uint8Array;
let serverFpHex: string;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  owner2 = await makeTestUser("user-owner-2222");
  target = await makeTestUser("user-target-4444");
  acceptor = await makeTestUser("user-acceptor-66");
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
  user: TestUser,
): Promise<TestEnv> {
  const server = await MockServer.start([...state.handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, user);
  await seedConfig(env, { server: server.origin, defaultProject: projectId });
  return env;
}

type PolicyOp = Parameters<typeof setApprovalPolicyOp>[0][number];

/** owner 2 名・member 1 名・環境 1 つ・方針(ops, required 2)。 */
function baseSteps(ops: readonly PolicyOp[]) {
  return [
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: addMemberOp(owner2, "owner") },
    { actor: owner, operation: addMemberOp(target, "member") },
    { actor: owner, operation: setApprovalPolicyOp(ops, 2) },
  ];
}

describe("既存コマンドの自動提案化(K6-A)", () => {
  it("member remove: 方針が対象なら propose を追記し、rotate は走らない。再実行は同じ提案を報告する(冪等)", async () => {
    const built = await buildChain(baseSteps(["remove_member"]));
    const state = await makeFourEyesServer({
      built,
      environments: {
        [ENV_ID]: {
          currentEpoch: 1,
          deks: [
            await wrapDekFor({
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
    // 48h ≈ 期限(署名時刻 + 48h)
    const lifetime = proposed.payload.expiresAtMs - proposed.timestampMs;
    expect(lifetime).toBeGreaterThan(48 * 3_600_000 - 10_000);
    expect(lifetime).toBeLessThanOrEqual(48 * 3_600_000);
    expect(state.rotateBodies).toHaveLength(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(`Proposed remove_member ${target.userId}`);
    expect(logs).toContain("nothing has been applied yet");
    expect(logs).toContain("needs 1 more owner approval (1 of 2 recounted so far)");
    expect(logs).toContain("maruhi approval approve");

    // 再実行: 同じ内側 op の pending があるので提案を増やさない
    env.logs.length = 0;
    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(1);
    expect(env.logs.join("\n")).toContain("The same operation is already proposed");
  });

  it("member remove: 提案化の経路では自己 remove を拒否しない(履行者は承認者 — K6-N)", async () => {
    // owner 3 名(到達可能性: owner2 を除いても required 2 に届く — 提案時の quorum 検査を通す)
    const owner3 = await makeTestUser("user-owner-3333");
    const steps = baseSteps(["remove_member"]);
    const built = await buildChain([
      ...steps.slice(0, -1),
      { actor: owner, operation: addMemberOp(owner3, "owner") },
      ...steps.slice(-1),
    ]);
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner2 });
    const env = await startEnv(state, built.projectId, owner2);
    // owner2 が自分の remove を提案: CLI は「自己 remove」だけで止めない(履行者は承認者)
    const code = await runCli(["member", "remove", owner2.userId], env.layer);
    expect(code).toBe(0);
    expect(state.appendedEntries.map((entry) => entry.op)).toEqual(["propose"]);
    // K6-N′: 適用後の帰結を本人に見せる(拒否ではない)
    expect(env.errors.join("\n")).toContain("this proposal removes you");
  });

  it("member change-role: 対象 op なら提案(省略側は提案時の現状で解決)。対象外は直接追記", async () => {
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

    // 方針が remove_member だけなら change_role は直接追記(owner の確立は常時対象)
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

  it("server revoke: 対象なら提案し、全環境の rotate は走らない", async () => {
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

  it("server grant: 儀式(--expect-fingerprint)の後で提案し、サーバー宛バックフィルは走らない", async () => {
    const built = await buildChain(baseSteps(["grant_server"]));
    const state = await makeFourEyesServer({
      built,
      environments: {},
      actor: owner,
      authConfig: {
        githubClientId: "dummy-client-id",
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
    // 儀式を飛ばした(フラグなし・非対話)実行は提案の前に止まる
    const bare = await makeFourEyesServer({
      built,
      environments: {},
      actor: owner,
      authConfig: {
        githubClientId: "dummy-client-id",
        serverKeyFingerprintHex: serverFpHex,
        serverEncPubHex: SERVER_ENC_PUB_HEX,
      },
    });
    const bareEnv = await startEnv(bare, built.projectId, owner);
    bareEnv.setTerminal({ stdin: false, stdout: false });
    expect(await runCli(["server", "grant", "--environments", ENV_ID], bareEnv.layer)).toBe(1);
    expect(bare.counters.appendAttempts).toBe(0);
  });

  it("CAS 競合の再同期で方針が変わっていたら fail-closed で止まる(再実行で新しい形へ)", async () => {
    const steps = [
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(owner2, "owner") },
      { actor: owner, operation: addMemberOp(target, "member") },
    ];
    const built = await buildChain(steps);
    // 送信と並行して方針が有効化された(remove_member が対象に)
    const concurrent = await buildChain([
      ...steps,
      { actor: owner, operation: setApprovalPolicyOp(["remove_member"], 2) },
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
    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The four-eyes policy changed while this command was appending",
    );
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("--expires の不備は usage(2)で通信前に落ちる", async () => {
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

describe("member add の提案化と鍵 FP 再登録の警告(K6-D / K6-I)", () => {
  async function invitationFor(projectId: string, invitee: TestUser) {
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

  it("方針が add_member を対象にしていれば、儀式の後に propose を追記してバックフィルしない", async () => {
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

  it("受諾鍵が過去の在籍区間(同一 user_id)に現れれば警告する(拒否ではない — K5-K)", async () => {
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
            await wrapDekFor({
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

describe("提案経由で適用された操作の再開(K6-C)", () => {
  it("提案経由で削除された対象へ `member remove` を再実行すると、削除記録として認め sweep を再開する", async () => {
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
            await wrapDekFor({
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
