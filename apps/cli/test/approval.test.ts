// Integration tests for `maruhi approval list / show / approve / withdraw` and
// `maruhi project policy approvals` (CRYPTO_SPEC §6.2 / §7 — PF1 K6. Design
// note es-design.md §12).
//
// Properties pinned down:
//  1. list / show read from the verified chain's pending and recount the vote
//     counts (K5-M / K2 implementation memo). No agent-gate (zero values —
//     K6-E)
//  2. approve: pre-flight checks (duplicate-approval / proposal-expired /
//     self-obligation) → append → learn completion on resync (K6-B). The
//     approver who completes it fulfills the sweep (remove) / backfill
//     (add_member) (approval item 22). If another owner completed it first,
//     do not append
//  3. withdraw: proposer / owner. A Note is required when an owner closes
//     someone else's proposal
//  4. policy: activation (pre-announce owner ≥ required, availability
//     guidance); changes while active go through a proposal

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

/** 2 owners (+ optional third), 1 member, policy (remove_member, required 2), plus owner's proposal. */
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
  it("lists pending proposals with recounted vote tallies; --json emits one document (no agent-gate)", async () => {
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

  it("show prints proposer, inner op, expiry, voters, and 'can you approve'", async () => {
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

    // The proposer themself is shown a duplicate-approval preview (self-
    // approval counts as a duplicate)
    const proposerEnv = await startEnv(state, built.projectId, owner);
    expect(await runCli(["approval", "show", hash.slice(0, 8)], proposerEnv.layer)).toBe(0);
    expect(proposerEnv.logs.join("\n")).toContain("cannot approve — you proposed this as an owner");
  });

  it("rejects unknown / too-short ids with typed errors", async () => {
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
  it("appends the quorum-reaching approve, and the completing approver fulfills the remove sweep (approval item 22)", async () => {
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
    // §7: wrap the new epoch to every current member except the removal
    // target (reason = member-removed)
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

  it("an approve short of quorum only records the vote and fulfills nothing", async () => {
    const steps = [
      ...prefixSteps({ thirdOwner: true }),
      { actor: owner, operation: proposeOp(innerOf(setApprovalPolicyOp(["remove_member"], 3))) },
    ];
    const built = await buildChain(steps);
    const policyHash = built.hashes[built.hashes.length - 1] ?? "";
    // owner2 completes the proposal to raise to required 3 (owner's single
    // vote, under the current required-2 policy) → subsequent remove
    // proposals need 3 votes
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

  it("the proposer's (owner's) self-approval stops pre-flight with duplicate-approval", async () => {
    const { built, hash } = await proposedChain();
    const state = await makeFourEyesServer({ built, environments: {}, actor: owner });
    const env = await startEnv(state, built.projectId, owner);
    expect(await runCli(["approval", "approve", hash.slice(0, 8)], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("duplicate-approval");
    expect(state.counters.appendAttempts).toBe(0);
  });

  it("a proposal expired on your own clock previews proposal-expired pre-flight (K5-C UX)", async () => {
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

  it("a proposal that removes you cannot be completed by you as approver (the fulfiller would vanish — K6-N)", async () => {
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

  it("a proposal narrowing your own scope (owner → admin listed{}) likewise cannot be completed by you as approver (Cursor Bugbot flag)", async () => {
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

  it("when a CAS-conflict resync finds another owner completed it first, does not append and says 'you are not the fulfiller'", async () => {
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

  it("the approver who completes an add_member proposal fulfills the backfill for the new member (the fifth path in §12-6)", async () => {
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

describe("maruhi approval show — key-FP re-registration warning (K6-I')", () => {
  it("warns the approver side too on an add_member proposal reusing a key from a past membership", async () => {
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
  it("an owner can close someone else's proposal (with a Note); a non-owner non-proposer is refused", async () => {
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

  it("no flags shows the current policy; --required 2 appends directly and warns about owner = required availability", async () => {
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

  it("refuses owner count < required pre-flight, and changes / disabling while the policy is active become proposals", async () => {
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

    // Re-specifying the same setting is a no-op
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

  it("does not append a redundant proposal when a CAS-conflict resync finds the same policy already applied (Cursor Bugbot flag)", async () => {
    const base = [
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(owner2, "owner") },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: setApprovalPolicyOp(["remove_member"], 2) },
    ];
    const built = await buildChain(base);
    // Concurrently with the submission, the same change (required 2 → ops
    // change_role) was applied via proposal + approval
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

  it("a typo in --ops and a malformed --expires fail as usage (2)", async () => {
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
