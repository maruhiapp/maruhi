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

export function signersOf(pending: PendingFold): Vote[] {
  const proposer: Vote[] = pending.proposerSignedAsOwner
    ? [{ userId: pending.proposerUserId, keyFingerprintHex: pending.proposerKeyFingerprintHex }]
    : [];
  return [...proposer, ...pending.approvals];
}

function ownerVoteByDevice(member: MutableMember, fp: string): boolean | undefined {
  const device = member.devices.find((d) => d.keyFingerprintHex === fp);
  return device === undefined ? undefined : device.roleCap === "owner";
}

function ownerVoteByUnbound(member: MutableMember, fp: string): boolean {
  if (!member.unboundSignerFps.has(fp)) return false;
  const unbound = unboundDevicesOf(member);
  return unbound.length > 0 && unbound.every((d) => d.roleCap === "owner");
}

function countsAsOwnerVote(state: FoldState, signer: Vote): boolean {
  const member = state.members.get(signer.userId);
  if (member === undefined || member.role !== "owner") return false;
  return (
    ownerVoteByDevice(member, signer.keyFingerprintHex) ??
    ownerVoteByUnbound(member, signer.keyFingerprintHex)
  );
}

export function countedVoters(state: FoldState, signers: ReadonlyArray<Vote>): string[] {
  const counted = signers.filter((signer) => countsAsOwnerVote(state, signer));
  return [...new Set(counted.map((signer) => signer.userId))];
}

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
    proposerSignedAsOwner: countsAsOwnerVote(state, {
      userId: entry.actor.userId,
      keyFingerprintHex: entry.actor.keyFingerprintHex,
    }),
    inner,
    expiresAtMs: entry.payload.expiresAtMs,
    approvals: [],
  });
}

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

function quorumReached(state: FoldState, signers: ReadonlyArray<Vote>): boolean {
  const required = state.policy?.requiredApprovals;
  return required !== undefined && countedVoters(state, signers).length >= required;
}

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
  if (!isRecord(operation.payload)) return operation.op;
  return (
    (ownProp(INNER_SUMMARIES, operation.op) as InnerSummarizer | undefined)?.(operation) ??
    operation.op
  );
}
