import type { ProjectId } from "@maruhi/core";
import type { ChainEntry, ChainOperation } from "@maruhi/crypto";
import { approvalSignersOf, isApprovalTarget, ownerVotersOf, verifyChain } from "@maruhi/crypto";
import {
  addMemberOp,
  approveOp,
  buildChain,
  type BuiltChain,
  changeRoleOp,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  innerOf,
  proposeOp,
  removeMemberOp,
  setApprovalPolicyOp,
  withdrawOp,
} from "@maruhi/test-kit";
import { Effect } from "effect";
import { beforeAll, describe, expect, it } from "vite-plus/test";

import {
  DEFAULT_PROPOSAL_LIFETIME_MS,
  describeInnerOperation,
  MAX_PROPOSAL_LIFETIME_MS,
  parseProposalExpiry,
  proposalViewOf,
  proposalViews,
  resolveProposalRef,
  voteEligibility,
} from "../src/approval-rules.ts";
import { type VerifiedProject, verifyChainSnapshot } from "../src/chain-sync.ts";

let owner: GeneratedIdentity;
let owner2: GeneratedIdentity;
let owner3: GeneratedIdentity;
let owner4: GeneratedIdentity;
let member: GeneratedIdentity;

beforeAll(async () => {
  owner = await generateIdentity("user-owner-1111");
  owner2 = await generateIdentity("user-owner-2222");
  owner3 = await generateIdentity("user-owner-3333");
  owner4 = await generateIdentity("user-owner-4444");
  member = await generateIdentity("user-member-5555");
});

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

async function verifyResult(entries: readonly ChainEntry[]): Promise<string> {
  const result = await verifyChain(entries);
  if (result.ok) return "ok";
  return result.error.kind === "ChainInvalid" ? result.error.reason : result.error.kind;
}

describe("isApprovalTarget (crypto public API) — agrees with verifyChain (K6-G)", () => {
  it("a direct append of a policy-targeted op is invalid as approval-required, and the CLI's verdict is also true (untargeted ops pass both)", async () => {
    const prefix = prefixWith(2, ["remove_member"]);
    const verified = await verifiedOf(await buildChain(prefix));
    const policy = verified.state.approvalPolicy;
    const remove: ChainOperation = removeMemberOp(member);
    const demote: ChainOperation = changeRoleOp(member, "reader");
    const promote: ChainOperation = changeRoleOp(member, "owner");
    expect(isApprovalTarget(innerOf(remove), policy)).toBe(true);
    expect(isApprovalTarget(innerOf(demote), policy)).toBe(false);
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

describe("ownerVotersOf / proposalViewOf — vote recount (principle 2) agrees with verifyChain", () => {
  it("a demoted voter's vote is not counted (stays pending), and the next non-voting owner's approve completes it — matching the CLI's needed=0", async () => {
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
      { actor: owner, operation: changeRoleOp(owner2, "admin") },
    ];
    const demoted = await verifiedOf(await buildChain(steps));
    const pending = demoted.state.pendingProposals.get(hash);
    if (pending === undefined) throw new Error("proposal should still be pending");
    expect(pending.approvals.map((vote) => vote.userId)).toEqual([owner2.userId]);
    expect(ownerVotersOf(demoted.state.members, approvalSignersOf(pending)).size).toBe(1);
    const view = proposalViewOf(demoted, pending, 0);
    expect(view.votes).toBe(1);
    expect(view.voters).toEqual([owner.userId]);
    expect(view.needed).toBe(1);
    expect(view.eligibleApprovers.toSorted()).toEqual([owner3.userId, owner4.userId].toSorted());

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
    expect(voteEligibility(two, owner3.userId, owner3.fingerprintHex, twoView)).toMatchObject({
      ok: false,
      reason: "duplicate-approval",
    });
    expect(voteEligibility(two, owner2.userId, owner2.fingerprintHex, twoView)).toMatchObject({
      ok: false,
      reason: "insufficient-role",
    });

    const done = await verifiedOf(
      await buildChain([
        ...steps,
        { actor: owner3, operation: approveOp(hash) },
        { actor: owner4, operation: approveOp(hash) },
      ]),
    );
    expect(done.state.pendingProposals.has(hash)).toBe(false);
    expect(done.state.members.has(member.userId)).toBe(false);
    const applied = done.applied.at(-1);
    expect(applied?.operation.op).toBe("remove_member");
    expect(applied?.seq).toBe(done.state.headSeq);
    expect(applied?.actorUserId).toBe(owner.userId);
    expect(applied?.viaProposalSeq).toBe(prefix.length + 1);
  });

  it("after required is lowered, a pending entry is 'completes on the next approve' — an already-voted owner is duplicate-approval (K5-L)", async () => {
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

  it("a proposal whose op the policy dropped is approval-not-required, and an expired one previews proposal-expired", async () => {
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

describe("resolveProposalRef — prefix resolution (K6-F)", () => {
  it("resolves a unique prefix of 8+ chars and distinguishes too-short / ambiguous / completed / withdrawn / unknown", async () => {
    const prefix = prefixWith(2, ["remove_member", "change_role"]);
    const first = await buildChain([
      ...prefix,
      { actor: owner, operation: proposeOp(innerOf(removeMemberOp(member))) },
    ]);
    const hashA = await hashOfLast(first);
    const second = await buildChain([
      ...prefix,
      { actor: owner, operation: proposeOp(innerOf(removeMemberOp(member))) },
      { actor: owner, operation: proposeOp(innerOf(changeRoleOp(member, "reader"))) },
    ]);
    const hashB = await hashOfLast(second);
    const verified = await verifiedOf(second);
    expect(resolveProposalRef(verified, hashA.slice(0, 8))).toMatchObject({ kind: "pending" });
    expect(resolveProposalRef(verified, `#${prefix.length + 1}`)).toMatchObject({
      kind: "pending",
      proposal: { proposalHashHex: hashA },
    });
    expect(resolveProposalRef(verified, "#999")).toEqual({ kind: "unknown" });
    expect(resolveProposalRef(verified, hashA.toUpperCase())).toMatchObject({ kind: "pending" });
    expect(resolveProposalRef(verified, hashB.slice(0, 7))).toEqual({ kind: "malformed" });
    expect(resolveProposalRef(verified, "not-hex!")).toEqual({ kind: "malformed" });
    expect(resolveProposalRef(verified, "0".repeat(64))).toEqual({ kind: "unknown" });

    const closed = await verifiedOf(
      await buildChain([
        ...prefix,
        { actor: owner, operation: proposeOp(innerOf(removeMemberOp(member))) },
        { actor: owner, operation: proposeOp(innerOf(changeRoleOp(member, "reader"))) },
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

describe("parseProposalExpiry — --expires (K6-K)", () => {
  it("defaults to 7 days, accepts unit-suffixed durations, rejects 0 and >30 days", () => {
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
  it("renders an inner op on one line (identifiers neutralized)", () => {
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
