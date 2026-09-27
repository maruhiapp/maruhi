// Checks for the four-eyes CLI-side pure functions (approval-rules.ts —
// design note es-design.md §12 K6-F / G / K).
//
// Properties pinned down:
//  1. The target check `isApprovalTarget` and the vote recount
//     `countOwnerVotes` are the second implementation of crypto's consensus
//     rules (K6-G). **Differential test**: run the same chains through the
//     public API's verifyChain and require the direct-append rejection
//     (approval-required), stale votes (demotion / key rotation), and
//     completion verdicts to agree
//  2. Proposal-id prefix resolution (8+ chars, unique; distinguishing
//     completed / withdrawn / unknown)
//  3. `--expires` parsing (default 7 days, cap 30 days, 0 not allowed)
//  4. Displaying the inner op and judging an already-satisfied proposal as
//     "completes on the next approve" (K5-L)

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

/** Turns a built chain into the CLI's verified view (same path as sync.ts). */
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

/** Prefix of 4 owners + 1 member + policy (remove_member / required). */
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

/** verifyChain's result (ok / rejection reason). */
async function verifyResult(entries: readonly ChainEntry[]): Promise<string> {
  const result = await verifyChain(entries);
  if (result.ok) return "ok";
  return result.error.kind === "ChainInvalid" ? result.error.reason : result.error.kind;
}

describe("isApprovalTarget — differential vs verifyChain (K6-G)", () => {
  it("a direct append of a policy-targeted op is invalid as approval-required, and the CLI's verdict is also true (untargeted ops pass both)", async () => {
    const prefix = prefixWith(2, ["remove_member"]);
    const verified = await verifiedOf(await buildChain(prefix));
    const policy = verified.state.approvalPolicy;
    const remove: ChainOperation = removeMemberOp(member);
    const demote: ChainOperation = changeRoleOp(member, "reader", null);
    const promote: ChainOperation = changeRoleOp(member, "owner", null);
    expect(isApprovalTarget(innerOf(remove), policy)).toBe(true);
    expect(isApprovalTarget(innerOf(demote), policy)).toBe(false);
    // A change_role that establishes an owner is always targeted regardless
    // of the listing (policy monotonicity (a))
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

describe("countOwnerVotes / proposalViewOf — vote recount (principle 2) agrees with verifyChain", () => {
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
      // Demote owner2 (the required owners are still reachable via the 3:
      // owner / owner3 / owner4)
      { actor: owner, operation: changeRoleOp(owner2, "admin", null) },
    ];
    const demoted = await verifiedOf(await buildChain(steps));
    const pending = demoted.state.pendingProposals.get(hash);
    if (pending === undefined) throw new Error("proposal should still be pending");
    // owner2's vote remains in the record, but the recount counts only the
    // proposer's (owner's) single vote
    expect(pending.approvals.map((vote) => vote.userId)).toEqual([owner2.userId]);
    expect(countOwnerVotes(demoted.state.members, signersOf(pending))).toBe(1);
    const view = proposalViewOf(demoted, pending, 0);
    expect(view.votes).toBe(1);
    expect(view.voters).toEqual([owner.userId]);
    expect(view.needed).toBe(1);
    expect(view.eligibleApprovers.toSorted()).toEqual([owner3.userId, owner4.userId].toSorted());

    // owner3 votes → 2 votes (still pending). The CLI reports needed=0
    // (completes on the next approve)
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
    // An already-voted owner (owner3) and the demoted one (owner2) cannot
    // approve
    expect(voteEligibility(two, owner3.userId, owner3.fingerprintHex, twoView)).toMatchObject({
      ok: false,
      reason: "duplicate-approval",
    });
    expect(voteEligibility(two, owner2.userId, owner2.fingerprintHex, twoView)).toMatchObject({
      ok: false,
      reason: "insufficient-role",
    });

    // owner4's approve lets verifyChain complete it (gone from pending,
    // member removed)
    const done = await verifiedOf(
      await buildChain([
        ...steps,
        { actor: owner3, operation: approveOp(hash) },
        { actor: owner4, operation: approveOp(hash) },
      ]),
    );
    expect(done.state.pendingProposals.has(hash)).toBe(false);
    expect(done.state.members.has(member.userId)).toBe(false);
    // The applied-operations list (K6-C) carries the inner op at the
    // approve's seq
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
        // Changing the policy itself is four-eyes (required 3): propose →
        // signatures from the 3 owners
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
    // Change the policy to change_role only (four-eyes: propose + owner2's
    // approve)
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
      { actor: owner, operation: proposeOp(innerOf(changeRoleOp(member, "reader", null))) },
    ]);
    const hashB = await hashOfLast(second);
    const verified = await verifiedOf(second);
    expect(resolveProposalRef(verified, hashA.slice(0, 8))).toMatchObject({ kind: "pending" });
    // `#<seq>` (K6-F'): the proposal entry can also be pointed at by its seq
    expect(resolveProposalRef(verified, `#${prefix.length + 1}`)).toMatchObject({
      kind: "pending",
      proposal: { proposalHashHex: hashA },
    });
    expect(resolveProposalRef(verified, "#999")).toEqual({ kind: "unknown" });
    expect(resolveProposalRef(verified, hashA.toUpperCase())).toMatchObject({ kind: "pending" });
    expect(resolveProposalRef(verified, hashB.slice(0, 7))).toEqual({ kind: "malformed" });
    expect(resolveProposalRef(verified, "not-hex!")).toEqual({ kind: "malformed" });
    expect(resolveProposalRef(verified, "0".repeat(64))).toEqual({ kind: "unknown" });

    // Ids of completed / withdrawn proposals are not pending — says so
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
