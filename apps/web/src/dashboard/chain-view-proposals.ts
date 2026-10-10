// See chain-view.ts for the display-only contract.

import { applyOperation, type OperationOf } from "./chain-view-operations.ts";
import {
  hasStrings,
  ownProp,
  unboundDevicesOf,
  type EntryOf,
  type FoldState,
  type InnerSummarizer,
  type MutableMember,
  type PendingFold,
  type ProposableEntry,
  type Vote,
} from "./chain-view-state.ts";
import { isRecord } from "./json-record.ts";

/** Principle 2's S = {the proposer who proposed as an owner} ∪ approvals. */
export function signersOf(pending: PendingFold): Vote[] {
  const proposer: Vote[] =
    pending.proposerRoleAtProposal === "owner"
      ? [{ userId: pending.proposerUserId, keyFingerprintHex: pending.proposerKeyFingerprintHex }]
      : [];
  return [...proposer, ...pending.approvals];
}

/** If the vote's FP is one of that person's bound devices, whether that device's roleCap is owner (undefined if unbound). */
function ownerVoteByDevice(member: MutableMember, fp: string): boolean | undefined {
  const device = member.devices.find((d) => d.keyFingerprintHex === fp);
  return device === undefined ? undefined : device.roleCap === "owner";
}

/** An unbindable signing FP: counted only when **all** of that person's unbound devices are roleCap owner. */
function ownerVoteByUnbound(member: MutableMember, fp: string): boolean {
  if (!member.unboundSignerFps.has(fp)) return false;
  const unbound = unboundDevicesOf(member);
  return unbound.length > 0 && unbound.every((d) => d.roleCap === "owner");
}

/**
 * Whether one vote counts (§6.2's device vocabulary — K5-2): the
 * voter is a current owner, the vote's FP matches one of that person's
 * bound devices, and the device's roleCap is owner (effective role =
 * owner). A signing FP that could not be bound counts only when **all**
 * of that person's unbound devices are roleCap owner (the conclusion
 * is the same whichever device it was). Anything else is not counted
 * (fail-closed — an unidentifiable vote is not counted).
 */
function countsAsOwnerVote(state: FoldState, signer: Vote): boolean {
  const member = state.members.get(signer.userId);
  if (member === undefined || member.role !== "owner") return false;
  return (
    ownerVoteByDevice(member, signer.keyFingerprintHex) ??
    ownerVoteByUnbound(member, signer.keyFingerprintHex)
  );
}

/** The vote count = the distinct user_ids in S that are "current owner and the key FP matches (known)" (recounted). */
export function countedVoters(state: FoldState, signers: ReadonlyArray<Vote>): string[] {
  const counted = signers.filter((signer) => countsAsOwnerVote(state, signer));
  return [...new Set(counted.map((signer) => signer.userId))];
}

/** The proposer's current role ("unknown" if not a member). */
function proposerRoleOf(state: FoldState, userId: string): string {
  return state.members.get(userId)?.role ?? "unknown";
}

/** Whether the proposal's inner op is in a readable shape (a record whose op name is a string). */
function readableInner(inner: unknown): inner is ProposableEntry {
  return hasStrings(inner, ["op"]);
}

export function applyPropose(
  state: FoldState,
  entry: EntryOf<"propose">,
  hash: string | undefined,
): void {
  if (hash === undefined) return;
  const inner = entry.payload.inner;
  if (!readableInner(inner) || typeof entry.payload.expiresAtMs !== "number") {
    state.unreadableEntries += 1;
    return;
  }
  state.pending.set(hash, {
    seq: entry.seq,
    proposerUserId: entry.actor.userId,
    proposerKeyFingerprintHex: entry.actor.keyFingerprintHex,
    proposerRoleAtProposal: proposerRoleOf(state, entry.actor.userId),
    inner,
    expiresAtMs: entry.payload.expiresAtMs,
    approvals: [],
  });
}

/**
 * approve: records the vote and, once the recount reaches the current
 * policy's required, applies the inner op and removes it from pending
 * (§6.2 — applied at the approve entry's seq). An approve on the chain
 * already passed the consensus rule at the acceptance surface (an
 * invalid one is never on the chain), so only the arithmetic of votes
 * is transcribed here.
 */
export function applyApprove(state: FoldState, entry: EntryOf<"approve">): void {
  if (typeof entry.payload.proposalHashHex !== "string") {
    state.unreadableEntries += 1;
    return;
  }
  const pending = state.pending.get(entry.payload.proposalHashHex);
  if (pending === undefined) return;
  const vote: Vote = {
    userId: entry.actor.userId,
    keyFingerprintHex: entry.actor.keyFingerprintHex,
  };
  if (!quorumReached(state, [...signersOf(pending), vote])) {
    pending.approvals.push(vote);
    return;
  }
  state.pending.delete(entry.payload.proposalHashHex);
  applyOperation(state, entry.seq, pending.inner);
}

/** Whether the recounted vote count reached the current policy's required (never reached when the policy is off). */
function quorumReached(state: FoldState, signers: ReadonlyArray<Vote>): boolean {
  const required = state.policy?.requiredApprovals;
  return required !== undefined && countedVoters(state, signers).length >= required;
}

// One-line summaries of inner ops (identifiers stay raw — the render
// side neutralizes them)
const INNER_SUMMARIES: {
  readonly [Op in ProposableEntry["op"]]?: (operation: OperationOf<Op>) => string;
} = {
  add_member: (o) => `add ${o.payload.targetUserId} as ${o.payload.role}`,
  remove_member: (o) => `remove ${o.payload.targetUserId}`,
  change_role: (o) => `change ${o.payload.targetUserId} to ${o.payload.newRole}`,
  grant_server: (o) => `grant server key ${o.payload.serverKeyFingerprintHex}`,
  revoke_server: (o) => `revoke server key ${o.payload.serverKeyFingerprintHex}`,
  set_approval_policy: (o) =>
    o.payload.requiredApprovals === 0
      ? "turn the approval policy off"
      : `set the approval policy to ${o.payload.requiredApprovals} approvals`,
};

export function summarizeInner(operation: ProposableEntry): string {
  // The summary reads the inner payload's fields — a non-record falls
  // back to the op name
  if (!isRecord(operation.payload)) return operation.op;
  return (
    (ownProp(INNER_SUMMARIES, operation.op) as InnerSummarizer | undefined)?.(operation) ??
    operation.op
  );
}
