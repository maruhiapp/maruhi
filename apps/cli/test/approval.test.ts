// `maruhi approval list / show / approve / withdraw` と `maruhi project policy approvals`
// (CRYPTO_SPEC §6.2 / §7 — PF1 K6。設計録 es-design.md §12)の統合テスト。
//
// 固定する性質:
//  1. list / show は検証済みチェーンの pending から出し、票数は再集計する(K5-M / K2 の
//     実装メモ)。agent-gate を掛けない(値ゼロ — K6-E)
//  2. approve: 通信前検査(duplicate-approval / proposal-expired / 自己義務)→ 追記 →
//     再同期で完成を知る(K6-B)。完成させた承認者が sweep(remove)/ バックフィル
//     (add_member)を履行する(承認項目 22)。他 owner が先に完成させていれば追記しない
//  3. withdraw: 提案者 / owner。owner が他人の提案を閉じるときは Note
//  4. policy: 有効化(owner ≥ required の予告・可用性の案内)、有効中の変更は提案

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  approveOp,
  buildChain,
  type BuiltChain,
  changeRoleOp,
  createEnvironmentOp,
  genesisOp,
  innerOf,
  makeTestUser,
  proposeOp,
  removeMemberOp,
  setApprovalPolicyOp,
  type TestUser,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type FourEyesServerState, makeFourEyesServer } from "./support/four-eyes-server.ts";
import { MockServer } from "./support/server.ts";

const ENV_ID = "env-app-1";

let owner: TestUser;
let owner2: TestUser;
let owner3: TestUser;
let target: TestUser;
let newbie: TestUser;
let dek1: Uint8Array;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  owner2 = await makeTestUser("user-owner-2222");
  owner3 = await makeTestUser("user-owner-3333");
  target = await makeTestUser("user-target-4444");
  newbie = await makeTestUser("user-newbie-5555");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
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

function wrapFor(projectId: string, user: TestUser): Promise<WireRecipientDek> {
  return wrapDekFor({
    projectId,
    environmentId: ENV_ID,
    epoch: 1,
    dek: dek1,
    recipient: user,
    signer: owner,
  });
}

/** owner 2 名(+ 任意で 3 名目)・member 1 名・方針(remove_member, required 2)+ owner の提案。 */
function prefixSteps(options?: {
  readonly thirdOwner?: boolean;
  readonly ops?: readonly ("remove_member" | "add_member" | "change_role")[];
}) {
  return [
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: addMemberOp(owner2, "owner") },
    ...(options?.thirdOwner === true
      ? [{ actor: owner, operation: addMemberOp(owner3, "owner") }]
      : []),
    { actor: owner, operation: addMemberOp(target, "member") },
    { actor: owner, operation: setApprovalPolicyOp(options?.ops ?? ["remove_member"], 2) },
  ];
}

async function proposedChain(
  options?: Parameters<typeof prefixSteps>[0] & { readonly expiresAtMs?: number },
) {
  const steps = [
    ...prefixSteps(options),
    { actor: owner, operation: proposeOp(innerOf(removeMemberOp(target)), options?.expiresAtMs) },
  ];
  const built = await buildChain(steps);
  const hash = built.hashes[built.hashes.length - 1] ?? "";
  return { steps, built, hash };
}

describe("maruhi approval list / show", () => {
  it("pending 提案を再集計した票数つきで一覧し、--json は 1 文書(agent-gate なし)", async () => {
    const { built, hash } = await proposedChain();
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner2 });
    const env = await startEnv(state, built.projectId, owner2);
    env.setAgent({ isAgent: true, name: "test-agent" });
    env.setTerminal({ stdin: false, stdout: false });

    expect(await runCli(["approval", "list"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      "Four-eyes policy: on — required approvals: 2; targeted ops: remove_member",
    );
    expect(logs).toContain("Pending proposals (1)");
    expect(logs).toContain(`${hash.slice(0, 12)}…`);
    expect(logs).toContain(`remove_member ${target.userId}`);
    expect(logs).toContain("1/2 approvals");

    env.logs.length = 0;
    expect(await runCli(["approval", "list", "--json"], env.layer)).toBe(0);
    const json = JSON.parse(env.logs.join("\n")) as {
      policy: { requiredApprovals: number; ops: string[] };
      proposals: { id: string; votes: number; needed: number; eligibleApprovers: string[] }[];
    };
    expect(json.policy).toEqual({ requiredApprovals: 2, ops: ["remove_member"] });
    expect(json.proposals[0]).toMatchObject({
      id: hash,
      votes: 1,
      needed: 0,
      eligibleApprovers: [owner2.userId],
    });
  });

  it("show は提案者・内側 op・期限・投票者と「あなたは approve できるか」を出す", async () => {
    const { built, hash } = await proposedChain();
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner2 });
    const env = await startEnv(state, built.projectId, owner2);
    expect(await runCli(["approval", "show", hash.slice(0, 8)], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(`Proposal ${hash}`);
    expect(logs).toContain(`proposer:        ${owner.userId} (as owner — counts as one approval)`);
    expect(logs).toContain("operation:       remove_member");
    expect(logs).toContain("approvals:       1 of 2 required");
    expect(logs).toContain("you:             can approve — your approval completes it");

    // 提案者本人には duplicate-approval を予告する(自己承認は重複)
    const proposerEnv = await startEnv(state, built.projectId, owner);
    expect(await runCli(["approval", "show", hash.slice(0, 8)], proposerEnv.layer)).toBe(0);
    expect(proposerEnv.logs.join("\n")).toContain("cannot approve — you proposed this as an owner");
  });

  it("未知 / 短すぎる id は型付きに拒否する", async () => {
    const { built } = await proposedChain();
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner2 });
    const env = await startEnv(state, built.projectId, owner2);
    expect(await runCli(["approval", "show", "0000000000"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("No proposal matches that id");
    expect(await runCli(["approval", "show", "abc"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("at least the first 8 digits) or #<seq>");
  });
});

describe("maruhi approval approve", () => {
  it("定足数に達する approve を追記し、完成させた承認者が remove の sweep を履行する(承認項目 22)", async () => {
    const { built, hash } = await proposedChain();
    const state = await makeFourEyesServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await wrapFor(built.projectId, owner2)] },
      },
      actor: owner2,
      author: owner,
    });
    const env = await startEnv(state, built.projectId, owner2);

    expect(await runCli(["approval", "approve", hash.slice(0, 8)], env.layer)).toBe(0);
    expect(state.appendedEntries.map((entry) => entry.op)).toEqual(["approve"]);
    const approve = state.appendedEntries[0];
    if (approve?.op !== "approve") throw new Error("approve entry missing");
    expect(approve.payload.proposalHashHex).toBe(hash);
    // §7: 削除対象を除く現メンバー全員へ新エポックのラップ(reason = member-removed)
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("member-removed");
    expect(state.rotateBodies[0]?.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, owner2.userId].toSorted(),
    );
    const logs = env.logs.join("\n");
    expect(logs).toContain("Your approval reached the quorum: applied remove_member");
    expect(logs).toContain(
      "Done: the removal and the rotation of the affected environments completed",
    );
  });

  it("定足数に届かない approve は票を記録し、何も履行しない", async () => {
    const steps = [
      ...prefixSteps({ thirdOwner: true }),
      { actor: owner, operation: proposeOp(innerOf(setApprovalPolicyOp(["remove_member"], 3))) },
    ];
    const built = await buildChain(steps);
    const policyHash = built.hashes[built.hashes.length - 1] ?? "";
    // required 3 に上げる提案(owner の 1 票)を owner2 が完成させる(現方針 required 2)→
    // その後の remove 提案は 3 票必要
    const raised = await buildChain([
      ...steps,
      { actor: owner2, operation: approveOp(policyHash) },
      { actor: owner, operation: proposeOp(innerOf(removeMemberOp(target))) },
    ]);
    const hash = raised.hashes[raised.hashes.length - 1] ?? "";
    const state = await makeFourEyesServer({ built: raised, environments: {}, actor: owner2 });
    const env = await startEnv(state, raised.projectId, owner2);
    expect(await runCli(["approval", "approve", hash.slice(0, 8)], env.layer)).toBe(0);
    expect(state.appendedEntries.map((entry) => entry.op)).toEqual(["approve"]);
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("Recorded your approval");
    expect(env.logs.join("\n")).toContain(
      "needs 1 more owner approval (2 of 3 recounted so far) — nothing has been applied yet",
    );
  });

  it("提案者(owner)の自己承認は通信前に duplicate-approval で止まる", async () => {
    const { built, hash } = await proposedChain();
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner });
    const env = await startEnv(state, built.projectId, owner);
    expect(await runCli(["approval", "approve", hash.slice(0, 8)], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("duplicate-approval");
    expect(state.counters.appendAttempts).toBe(0);
  });

  it("自分の時計で期限切れの提案は通信前に proposal-expired を予告する(K5-C の UX)", async () => {
    const { built, hash } = await proposedChain({ expiresAtMs: 1_000 });
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner2 });
    const env = await startEnv(state, built.projectId, owner2);
    expect(await runCli(["approval", "approve", hash.slice(0, 8)], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("proposal-expired");
    expect(state.counters.appendAttempts).toBe(0);
    env.logs.length = 0;
    expect(await runCli(["approval", "list"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("[EXPIRED]");
  });

  it("自分を削除する提案は承認者として完成させられない(履行者が消える — K6-N)", async () => {
    const steps = [
      ...prefixSteps({ thirdOwner: true }),
      { actor: owner, operation: proposeOp(innerOf(removeMemberOp(owner2))) },
    ];
    const built = await buildChain(steps);
    const hash = built.hashes[built.hashes.length - 1] ?? "";
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner2 });
    const env = await startEnv(state, built.projectId, owner2);
    expect(await runCli(["approval", "approve", hash.slice(0, 8)], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("This proposal removes you");
    expect(state.counters.appendAttempts).toBe(0);
  });

  it("自分の scope を縮める(owner → admin listed{})提案も承認者として完成させられない(Cursor Bugbot 指摘)", async () => {
    const steps = [
      ...prefixSteps({ thirdOwner: true, ops: ["change_role"] }),
      {
        actor: owner,
        operation: proposeOp(innerOf(changeRoleOp(owner2, "admin", []))),
      },
    ];
    const built = await buildChain(steps);
    const hash = built.hashes[built.hashes.length - 1] ?? "";
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner2 });
    const env = await startEnv(state, built.projectId, owner2);
    expect(await runCli(["approval", "approve", hash.slice(0, 8)], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("This proposal narrows your own scope");
    expect(state.counters.appendAttempts).toBe(0);
  });

  it("CAS 競合の再同期で他 owner が先に完成させていたら追記せず「履行者ではない」と案内する", async () => {
    const { steps, built, hash } = await proposedChain({ thirdOwner: true });
    const concurrent = await buildChain([...steps, { actor: owner3, operation: approveOp(hash) }]);
    const state = await makeFourEyesServer({
      built,
      environments: {},
      actor: owner2,
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
    const env = await startEnv(state, built.projectId, owner2);
    expect(await runCli(["approval", "approve", hash.slice(0, 8)], env.layer)).toBe(0);
    expect(state.counters.appendAttempts).toBe(1);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("already completed by another owner's approval");
  });

  it("add_member の提案を完成させた承認者が新メンバー宛のバックフィルを履行する(§12-6 の 5 番目の経路)", async () => {
    const steps = [
      ...prefixSteps({ ops: ["add_member"] }),
      { actor: owner, operation: proposeOp(innerOf(addMemberOp(newbie, "member"))) },
    ];
    const built = await buildChain(steps);
    const hash = built.hashes[built.hashes.length - 1] ?? "";
    const state = await makeFourEyesServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await wrapFor(built.projectId, owner2)] },
      },
      actor: owner2,
      author: owner,
    });
    const env = await startEnv(state, built.projectId, owner2);
    expect(await runCli(["approval", "approve", hash.slice(0, 8)], env.layer)).toBe(0);
    expect(state.appendedEntries.map((entry) => entry.op)).toEqual(["approve"]);
    expect(state.rotateBodies).toHaveLength(0);
    expect(state.registerBodies).toHaveLength(1);
    expect(state.registerBodies[0]?.deks.map((wrap) => [wrap.epoch, wrap.recipientUserId])).toEqual(
      [[1, newbie.userId]],
    );
    expect(env.logs.join("\n")).toContain(
      `Added member ${newbie.userId}. Backfill: 1 newly registered`,
    );
  });
});

describe("maruhi approval show — 鍵 FP 再登録の警告(K6-I′)", () => {
  it("過去の在籍と同じ鍵での add_member 提案には、承認者側にも警告を出す", async () => {
    const steps = [
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(owner2, "owner") },
      { actor: owner, operation: addMemberOp(newbie, "member") },
      { actor: owner, operation: removeMemberOp(newbie) },
      { actor: owner, operation: setApprovalPolicyOp(["add_member"], 2) },
      { actor: owner, operation: proposeOp(innerOf(addMemberOp(newbie, "member"))) },
    ];
    const built = await buildChain(steps);
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner2 });
    const env = await startEnv(state, built.projectId, owner2);
    expect(await runCli(["approval", "show", `#${steps.length}`], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain(
      "the proposed member's key was registered before for this same user",
    );
    expect(env.logs.join("\n")).toContain("you:             can approve");
  });
});

describe("maruhi approval withdraw", () => {
  it("owner は他人の提案を閉じられる(Note つき)。非 owner の非提案者は拒否", async () => {
    const { built, hash } = await proposedChain();
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner2 });
    const env = await startEnv(state, built.projectId, owner2);
    expect(await runCli(["approval", "withdraw", hash.slice(0, 8)], env.layer)).toBe(0);
    expect(state.appendedEntries.map((entry) => entry.op)).toEqual(["withdraw"]);
    expect(env.errors.join("\n")).toContain(
      `withdrawing a proposal made by ${owner.userId} (owners may close any proposal)`,
    );
    expect(env.logs.join("\n")).toContain("Withdrew proposal");

    const fresh = await makeFourEyesServer({ built, environments: {}, actor: target });
    const memberEnv = await startEnv(fresh, built.projectId, target);
    expect(await runCli(["approval", "withdraw", hash.slice(0, 8)], memberEnv.layer)).toBe(1);
    expect(memberEnv.errors.join("\n")).toContain("Only the proposer or an owner can withdraw");
    expect(fresh.counters.appendAttempts).toBe(0);
  });
});

describe("maruhi project policy approvals", () => {
  async function plainChain(): Promise<BuiltChain> {
    return buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(owner2, "owner") },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
  }

  it("フラグなしは現方針の表示、--required 2 は直接追記し、owner = required の可用性を警告する", async () => {
    const built = await plainChain();
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner });
    const env = await startEnv(state, built.projectId, owner);
    expect(await runCli(["project", "policy", "approvals"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("Four-eyes policy: off");

    expect(await runCli(["project", "policy", "approvals", "--required", "2"], env.layer)).toBe(0);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "set_approval_policy") throw new Error("policy entry missing");
    expect(entry.payload).toEqual({
      ops: ["change_role", "grant_server", "remove_member", "set_approval_policy"],
      requiredApprovals: 2,
    });
    const errors = env.errors.join("\n");
    expect(errors).toContain("the project has 2 owners and the policy requires 2 approvals");
    expect(errors).toContain("Keep at least 3 owners");
    expect(errors).toContain("make sure every owner has a recovery registered");
  });

  it("owner 数 < required は通信前に拒否し、方針が有効な間の変更 / オフは提案になる", async () => {
    const built = await plainChain();
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner });
    const env = await startEnv(state, built.projectId, owner);
    expect(await runCli(["project", "policy", "approvals", "--required", "3"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("approval-quorum-unreachable");
    expect(state.counters.appendAttempts).toBe(0);

    const active = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(owner2, "owner") },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: setApprovalPolicyOp(["remove_member"], 2) },
    ]);
    const activeState = await makeFourEyesServer({ built: active, environments: {}, actor: owner });
    const activeEnv = await startEnv(activeState, active.projectId, owner);
    expect(await runCli(["project", "policy", "approvals", "--off"], activeEnv.layer)).toBe(0);
    const proposed = activeState.appendedEntries[0];
    if (proposed?.op !== "propose") throw new Error("propose entry missing");
    expect(proposed.payload.inner).toEqual({
      op: "set_approval_policy",
      payload: { ops: [], requiredApprovals: 0 },
    });
    expect(activeEnv.logs.join("\n")).toContain("Proposed set_approval_policy off");
    expect(activeEnv.logs.join("\n")).toContain("needs 1 more owner approval");

    // 同じ設定の再指定は no-op
    activeEnv.logs.length = 0;
    expect(
      await runCli(
        ["project", "policy", "approvals", "--required", "2", "--ops", "remove_member"],
        activeEnv.layer,
      ),
    ).toBe(0);
    expect(activeEnv.logs.join("\n")).toContain("already has these settings");
    expect(activeState.appendedEntries).toHaveLength(1);
  });

  it("CAS 競合の再同期で同じ方針が既に適用されていれば、冗長な提案を追記しない(Cursor Bugbot 指摘)", async () => {
    const base = [
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(owner2, "owner") },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: setApprovalPolicyOp(["remove_member"], 2) },
    ];
    const built = await buildChain(base);
    // 送信と並行して、同じ変更(required 2 → ops を change_role に)が提案 + 承認で適用された
    const proposed = await buildChain([
      ...base,
      { actor: owner, operation: proposeOp(innerOf(setApprovalPolicyOp(["change_role"], 2))) },
    ]);
    const policyHash = proposed.hashes[proposed.hashes.length - 1] ?? "";
    const concurrent = await buildChain([
      ...base,
      { actor: owner, operation: proposeOp(innerOf(setApprovalPolicyOp(["change_role"], 2))) },
      { actor: owner2, operation: approveOp(policyHash) },
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
    expect(
      await runCli(
        ["project", "policy", "approvals", "--required", "2", "--ops", "change_role"],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "A concurrent run already set the same policy — nothing to propose",
    );
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("--ops の typo と --expires の不備は usage(2)で落ちる", async () => {
    const built = await plainChain();
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner });
    const env = await startEnv(state, built.projectId, owner);
    expect(
      await runCli(
        ["project", "policy", "approvals", "--required", "2", "--ops", "remove_membre"],
        env.layer,
      ),
    ).toBe(2);
    expect(
      await runCli(
        ["project", "policy", "approvals", "--required", "2", "--expires", "31d"],
        env.layer,
      ),
    ).toBe(2);
    expect(state.counters.appendAttempts).toBe(0);
  });
});
