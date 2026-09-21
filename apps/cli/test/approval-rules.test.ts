// 四眼の CLI 側純関数(approval-rules.ts — 設計録 es-design.md §12 K6-F / G / K)の検査。
//
// 固定する性質:
//  1. 対象判定 `isApprovalTarget` と票の再集計 `countOwnerVotes` は crypto の合意規則の
//     2 実装目(K6-G)。**差分テスト**: 同じチェーンを公開 API の verifyChain に通し、
//     直接追記の拒否(approval-required)・失効票(降格 / 鍵更新)・完成の判定が一致する
//  2. 提案 id の接頭辞解決(8 文字以上・一意・完成済み / 撤回済み / 未知の言い分け)
//  3. `--expires` の解析(既定 7 日・上限 30 日・0 不可)
//  4. 内側 op の表示と、既に足りている提案の「次の approve で完成」の判定(K5-L)

import type { ProjectId } from "@maruhi/core";
import type { ChainEntry, ChainOperation } from "@maruhi/crypto";
import { verifyChain } from "@maruhi/crypto";
import { Effect } from "effect";
import { beforeAll, describe, expect, it } from "vitest";

import {
  countOwnerVotes,
  DEFAULT_PROPOSAL_LIFETIME_MS,
  describeInnerOperation,
  isApprovalTarget,
  MAX_PROPOSAL_LIFETIME_MS,
  parseProposalExpiry,
  proposalViewOf,
  proposalViews,
  resolveProposalRef,
  signersOf,
  voteEligibility,
} from "../src/approval-rules.ts";
import { type VerifiedProject, verifyChainSnapshot } from "../src/sync.ts";
import {
  addMemberOp,
  approveOp,
  buildChain,
  type BuiltChain,
  changeRoleOp,
  genesisOp,
  innerOf,
  makeTestUser,
  proposeOp,
  removeMemberOp,
  setApprovalPolicyOp,
  type TestUser,
  withdrawOp,
} from "./support/crypto.ts";

let owner: TestUser;
let owner2: TestUser;
let owner3: TestUser;
let owner4: TestUser;
let member: TestUser;

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  owner2 = await makeTestUser("user-owner-2222");
  owner3 = await makeTestUser("user-owner-3333");
  owner4 = await makeTestUser("user-owner-4444");
  member = await makeTestUser("user-member-5555");
});

/** 組み立て済みチェーンを CLI の検証済みビューにする(sync.ts と同じ経路)。 */
function verifiedOf(built: BuiltChain): Promise<VerifiedProject> {
  return Effect.runPromise(
    verifyChainSnapshot({
      projectId: built.projectId as ProjectId,
      entries: built.entries,
      claimedHeadSeq: built.entries.length,
      claimedHeadHashHex: built.hashes[built.hashes.length - 1] ?? "",
    }),
  );
}

/** 4 owner + 1 member + 方針(remove_member / required)の前段。 */
function prefixWith(required: number, ops: readonly ("remove_member" | "change_role")[]) {
  return [
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: addMemberOp(owner2, "owner") },
    { actor: owner, operation: addMemberOp(owner3, "owner") },
    { actor: owner, operation: addMemberOp(owner4, "owner") },
    { actor: owner, operation: addMemberOp(member, "member") },
    { actor: owner, operation: setApprovalPolicyOp(ops, required) },
  ];
}

async function hashOfLast(built: BuiltChain): Promise<string> {
  const hash = built.hashes[built.hashes.length - 1];
  if (hash === undefined) throw new Error("empty chain");
  return hash;
}

/** verifyChain の結果(ok / 拒否理由)。 */
async function verifyResult(entries: readonly ChainEntry[]): Promise<string> {
  const result = await verifyChain(entries);
  if (result.ok) return "ok";
  return result.error.kind === "ChainInvalid" ? result.error.reason : result.error.kind;
}

describe("isApprovalTarget — verifyChain との差分(K6-G)", () => {
  it("方針の対象 op の直接追記は approval-required で無効になり、CLI の判定も真(対象外は両方とも通る)", async () => {
    const prefix = prefixWith(2, ["remove_member"]);
    const verified = await verifiedOf(await buildChain(prefix));
    const policy = verified.state.approvalPolicy;
    const remove: ChainOperation = removeMemberOp(member);
    const demote: ChainOperation = changeRoleOp(member, "reader", null);
    const promote: ChainOperation = changeRoleOp(member, "owner", null);
    expect(isApprovalTarget(innerOf(remove), policy)).toBe(true);
    expect(isApprovalTarget(innerOf(demote), policy)).toBe(false);
    // owner を確立する change_role は列挙に依らず常時対象(方針の単調性 (a))
    expect(isApprovalTarget(innerOf(promote), policy)).toBe(true);
    expect(isApprovalTarget(innerOf(setApprovalPolicyOp([], 0)), policy)).toBe(true);
    expect(isApprovalTarget(innerOf(remove), null)).toBe(false);

    for (const [operation, expected] of [
      [remove, "approval-required"],
      [demote, "ok"],
      [promote, "approval-required"],
      [setApprovalPolicyOp([], 0), "approval-required"],
    ] as const) {
      const chain = await buildChain([...prefix, { actor: owner, operation }]);
      expect(await verifyResult(chain.entries)).toBe(expected);
    }
  });
});

describe("countOwnerVotes / proposalViewOf — 票の再集計(原則 2)と verifyChain の一致", () => {
  it("降格された投票者の票は数えず(pending のまま)、次の未投票 owner の approve が完成させる — CLI の needed=0 と一致", async () => {
    const prefix = prefixWith(3, ["remove_member"]);
    const proposed = await buildChain([
      ...prefix,
      { actor: owner, operation: proposeOp(innerOf(removeMemberOp(member))) },
    ]);
    const hash = await hashOfLast(proposed);
    const steps = [
      ...prefix,
      { actor: owner, operation: proposeOp(innerOf(removeMemberOp(member))) },
      { actor: owner2, operation: approveOp(hash) },
      // owner2 を降格(必要な owner は owner / owner3 / owner4 の 3 名で到達可能)
      { actor: owner, operation: changeRoleOp(owner2, "admin", null) },
    ];
    const demoted = await verifiedOf(await buildChain(steps));
    const pending = demoted.state.pendingProposals.get(hash);
    if (pending === undefined) throw new Error("proposal should still be pending");
    // 記録には owner2 の票が残るが、再集計は提案者(owner)の 1 票だけ
    expect(pending.approvals.map((vote) => vote.userId)).toEqual([owner2.userId]);
    expect(countOwnerVotes(demoted.state.members, signersOf(pending))).toBe(1);
    const view = proposalViewOf(demoted, pending, 0);
    expect(view.votes).toBe(1);
    expect(view.voters).toEqual([owner.userId]);
    expect(view.needed).toBe(1);
    expect(view.eligibleApprovers.toSorted()).toEqual([owner3.userId, owner4.userId].toSorted());

    // owner3 が投票 → 2 票(pending のまま)。CLI は needed=0(次の approve で完成)
    const two = await verifiedOf(
      await buildChain([...steps, { actor: owner3, operation: approveOp(hash) }]),
    );
    const twoPending = two.state.pendingProposals.get(hash);
    if (twoPending === undefined) throw new Error("still pending after 2 votes");
    const twoView = proposalViewOf(two, twoPending, 0);
    expect(twoView.votes).toBe(2);
    expect(twoView.needed).toBe(0);
    expect(voteEligibility(two, owner4.userId, owner4.fingerprintHex, twoView)).toEqual({
      ok: true,
      completes: true,
    });
    // 既投票者(owner3)と降格済み(owner2)は approve できない
    expect(voteEligibility(two, owner3.userId, owner3.fingerprintHex, twoView)).toMatchObject({
      ok: false,
      reason: "duplicate-approval",
    });
    expect(voteEligibility(two, owner2.userId, owner2.fingerprintHex, twoView)).toMatchObject({
      ok: false,
      reason: "insufficient-role",
    });

    // owner4 の approve で verifyChain が完成させる(pending から消え、member は削除)
    const done = await verifiedOf(
      await buildChain([
        ...steps,
        { actor: owner3, operation: approveOp(hash) },
        { actor: owner4, operation: approveOp(hash) },
      ]),
    );
    expect(done.state.pendingProposals.has(hash)).toBe(false);
    expect(done.state.members.has(member.userId)).toBe(false);
    // 適用済み操作列(K6-C)に approve の seq で内側 op が載る
    const applied = done.applied.at(-1);
    expect(applied?.operation.op).toBe("remove_member");
    expect(applied?.seq).toBe(done.state.headSeq);
    expect(applied?.actorUserId).toBe(owner.userId);
    expect(applied?.viaProposalSeq).toBe(prefix.length + 1);
  });

  it("required を引き下げた後の pending は「次の approve で完成」— 既投票 owner は duplicate-approval(K5-L)", async () => {
    const prefix = prefixWith(3, ["remove_member"]);
    const proposed = await buildChain([
      ...prefix,
      { actor: owner, operation: proposeOp(innerOf(removeMemberOp(member))) },
    ]);
    const hash = await hashOfLast(proposed);
    const lowered = await verifiedOf(
      await buildChain([
        ...prefix,
        { actor: owner, operation: proposeOp(innerOf(removeMemberOp(member))) },
        { actor: owner2, operation: approveOp(hash) },
        // 方針の変更自体は四眼(required 3): 提案 → 3 owner の署名
        { actor: owner, operation: proposeOp(innerOf(setApprovalPolicyOp(["remove_member"], 2))) },
      ]),
    );
    const policyHash = lowered.history.entryHashAt(lowered.state.headSeq) ?? "";
    const chain = await buildChain([
      ...prefix,
      { actor: owner, operation: proposeOp(innerOf(removeMemberOp(member))) },
      { actor: owner2, operation: approveOp(hash) },
      { actor: owner, operation: proposeOp(innerOf(setApprovalPolicyOp(["remove_member"], 2))) },
      { actor: owner3, operation: approveOp(policyHash) },
      { actor: owner4, operation: approveOp(policyHash) },
    ]);
    const verified = await verifiedOf(chain);
    expect(verified.state.approvalPolicy?.requiredApprovals).toBe(2);
    const views = proposalViews(verified, 0);
    expect(views).toHaveLength(1);
    expect(views[0]?.votes).toBe(2);
    expect(views[0]?.needed).toBe(0);
    expect(views[0]?.eligibleApprovers.toSorted()).toEqual(
      [owner3.userId, owner4.userId].toSorted(),
    );
    expect(
      voteEligibility(verified, owner2.userId, owner2.fingerprintHex, views[0]!),
    ).toMatchObject({
      ok: false,
      reason: "duplicate-approval",
    });
  });

  it("方針が対象から外した提案は approval-not-required、期限切れは proposal-expired を予告する", async () => {
    const prefix = prefixWith(2, ["remove_member", "change_role"]);
    const proposed = await buildChain([
      ...prefix,
      { actor: owner, operation: proposeOp(innerOf(removeMemberOp(member)), 1_000) },
    ]);
    const hash = await hashOfLast(proposed);
    const verified = await verifiedOf(proposed);
    const view = proposalViewOf(verified, verified.state.pendingProposals.get(hash)!, 5_000);
    expect(view.expired).toBe(true);
    expect(voteEligibility(verified, owner2.userId, owner2.fingerprintHex, view)).toMatchObject({
      ok: false,
      reason: "proposal-expired",
    });
    // 方針を change_role だけに変える(四眼: 提案 + owner2 の approve)
    const policyChange = await buildChain([
      ...prefix,
      { actor: owner, operation: proposeOp(innerOf(removeMemberOp(member)), 1_000) },
      { actor: owner, operation: proposeOp(innerOf(setApprovalPolicyOp(["change_role"], 2))) },
    ]);
    const policyHash = await hashOfLast(policyChange);
    const narrowed = await verifiedOf(
      await buildChain([
        ...prefix,
        { actor: owner, operation: proposeOp(innerOf(removeMemberOp(member)), 1_000) },
        { actor: owner, operation: proposeOp(innerOf(setApprovalPolicyOp(["change_role"], 2))) },
        { actor: owner2, operation: approveOp(policyHash) },
      ]),
    );
    const stale = proposalViewOf(narrowed, narrowed.state.pendingProposals.get(hash)!, 0);
    expect(stale.target).toBe(false);
    expect(voteEligibility(narrowed, owner2.userId, owner2.fingerprintHex, stale)).toMatchObject({
      ok: false,
      reason: "approval-not-required",
    });
  });
});

describe("resolveProposalRef — 接頭辞解決(K6-F)", () => {
  it("8 文字以上の一意接頭辞を解決し、短い / 曖昧 / 完成済み / 撤回済み / 未知を言い分ける", async () => {
    const prefix = prefixWith(2, ["remove_member", "change_role"]);
    const first = await buildChain([
      ...prefix,
      { actor: owner, operation: proposeOp(innerOf(removeMemberOp(member))) },
    ]);
    const hashA = await hashOfLast(first);
    const second = await buildChain([
      ...prefix,
      { actor: owner, operation: proposeOp(innerOf(removeMemberOp(member))) },
      { actor: owner, operation: proposeOp(innerOf(changeRoleOp(member, "reader", null))) },
    ]);
    const hashB = await hashOfLast(second);
    const verified = await verifiedOf(second);
    expect(resolveProposalRef(verified, hashA.slice(0, 8))).toMatchObject({ kind: "pending" });
    // `#<seq>`(K6-F′): 提案エントリの seq でも指せる
    expect(resolveProposalRef(verified, `#${prefix.length + 1}`)).toMatchObject({
      kind: "pending",
      proposal: { proposalHashHex: hashA },
    });
    expect(resolveProposalRef(verified, "#999")).toEqual({ kind: "unknown" });
    expect(resolveProposalRef(verified, hashA.toUpperCase())).toMatchObject({ kind: "pending" });
    expect(resolveProposalRef(verified, hashB.slice(0, 7))).toEqual({ kind: "malformed" });
    expect(resolveProposalRef(verified, "not-hex!")).toEqual({ kind: "malformed" });
    expect(resolveProposalRef(verified, "0".repeat(64))).toEqual({ kind: "unknown" });

    // 完成 / 撤回した提案の id は pending ではなく、その旨を返す
    const closed = await verifiedOf(
      await buildChain([
        ...prefix,
        { actor: owner, operation: proposeOp(innerOf(removeMemberOp(member))) },
        { actor: owner, operation: proposeOp(innerOf(changeRoleOp(member, "reader", null))) },
        { actor: owner2, operation: approveOp(hashA) },
        { actor: owner, operation: withdrawOp(hashB) },
      ]),
    );
    expect(resolveProposalRef(closed, hashA.slice(0, 10))).toEqual({
      kind: "completed",
      proposalSeq: prefix.length + 1,
      completedAtSeq: prefix.length + 3,
    });
    expect(resolveProposalRef(closed, hashB.slice(0, 10))).toEqual({
      kind: "withdrawn",
      proposalSeq: prefix.length + 2,
    });
    expect(resolveProposalRef(closed, `#${prefix.length + 1}`)).toMatchObject({
      kind: "completed",
    });
  });
});

describe("parseProposalExpiry — --expires(K6-K)", () => {
  it("既定 7 日・単位付き期間・0 と 30 日超の拒否", () => {
    expect(parseProposalExpiry(undefined)).toEqual({
      ok: true,
      lifetimeMs: DEFAULT_PROPOSAL_LIFETIME_MS,
    });
    expect(parseProposalExpiry("48h")).toEqual({ ok: true, lifetimeMs: 48 * 3_600_000 });
    expect(parseProposalExpiry("90m")).toEqual({ ok: true, lifetimeMs: 90 * 60_000 });
    expect(parseProposalExpiry("30d")).toEqual({ ok: true, lifetimeMs: MAX_PROPOSAL_LIFETIME_MS });
    expect(parseProposalExpiry("31d").ok).toBe(false);
    expect(parseProposalExpiry("0d").ok).toBe(false);
    expect(parseProposalExpiry("7")).toMatchObject({ ok: false });
    expect(parseProposalExpiry("soon")).toMatchObject({ ok: false });
  });
});

describe("describeInnerOperation", () => {
  it("内側 op を 1 行で表す(識別子は中和)", () => {
    expect(describeInnerOperation(innerOf(removeMemberOp(member)))).toBe(
      `remove_member ${member.userId}`,
    );
    expect(describeInnerOperation(innerOf(changeRoleOp(member, "admin", ["dev"])))).toBe(
      `change_role ${member.userId} to admin (scope: dev)`,
    );
    expect(
      describeInnerOperation(innerOf(setApprovalPolicyOp(["remove_member", "change_role"], 2))),
    ).toBe("set_approval_policy required=2 ops=change_role,remove_member");
    expect(describeInnerOperation(innerOf(setApprovalPolicyOp([], 0)))).toBe(
      "set_approval_policy off",
    );
  });
});
