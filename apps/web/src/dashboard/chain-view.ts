import { applyAddDevice, applyRevokeDevice } from "./chain-view-devices.ts";
import { applyOperation } from "./chain-view-operations.ts";
import {
  applyApprove,
  applyPropose,
  countedVoters,
  signersOf,
  summarizeInner,
} from "./chain-view-proposals.ts";
import type { ReportedChainView, ReportedMember } from "./chain-view-reported.ts";
import {
  ALL_SCOPE,
  bindActor,
  bindFingerprint,
  FingerprintTable,
  hasStrings,
  ownProp,
  scopeIdsWithout,
  startTenure,
  type EntryFolder,
  type EntryOf,
  type FoldState,
  type MutableMember,
  type ProposableEntry,
} from "./chain-view-state.ts";
import { isRecord } from "./json-record.ts";
import type { ChainEntry } from "./types.ts";

function applyGenesis(state: FoldState, entry: EntryOf<"genesis">): void {
  if (!hasStrings(entry.payload, ["encPubHex", "sigPubHex"])) {
    state.unreadableEntries += 1;
    return;
  }
  const member = startTenure(
    state,
    entry.actor.userId,
    "owner",
    ALL_SCOPE,
    entry.payload,
    entry.seq,
  );
  const first = member.devices[0];
  if (first !== undefined)
    bindFingerprint(state, member.userId, first, entry.actor.keyFingerprintHex);
}

function applyDeleteEnvironment(state: FoldState, entry: EntryOf<"delete_environment">): void {
  const environmentId = entry.payload.environmentId;
  if (typeof environmentId !== "string") {
    state.unreadableEntries += 1;
    return;
  }
  for (const member of state.members.values()) pruneMember(member, environmentId, entry.seq);
  for (const [fingerprint, server] of state.servers) {
    state.servers.set(fingerprint, {
      ...server,
      scopeEnvironmentIds: server.scopeEnvironmentIds.filter((id) => id !== environmentId),
    });
  }
}

function pruneMember(member: MutableMember, environmentId: string, seq: number): void {
  const memberIds = scopeIdsWithout(member, environmentId);
  if (memberIds !== null) {
    member.scopeEnvironmentIds = memberIds;
    member.sinceSeq = seq;
  }
  for (const device of member.devices) {
    device.scopeEnvironmentIds =
      scopeIdsWithout(device, environmentId) ?? device.scopeEnvironmentIds;
  }
}

const ENTRY_FOLDERS: {
  readonly [Op in ChainEntry["op"]]?: (
    state: FoldState,
    entry: EntryOf<Op>,
    hash: string | undefined,
  ) => void;
} = {
  genesis: applyGenesis,
  propose: applyPropose,
  approve: (state, entry) => applyApprove(state, entry),
  withdraw: (state, entry) => {
    if (typeof entry.payload.proposalHashHex === "string") {
      state.pending.delete(entry.payload.proposalHashHex);
    } else {
      state.unreadableEntries += 1;
    }
  },
  add_device: applyAddDevice,
  revoke_device: applyRevokeDevice,
  delete_environment: applyDeleteEnvironment,
};

function foldEntry(state: FoldState, entry: ChainEntry, hash: string | undefined): void {
  if (!Object.hasOwn(ENTRY_KINDS, entry.op)) return;
  if (!isRecord(entry.payload)) {
    state.unreadableEntries += 1;
    return;
  }
  const fold = ownProp(ENTRY_FOLDERS, entry.op) as EntryFolder | undefined;
  if (fold === undefined) {
    applyOperation(state, entry.seq, entry as ProposableEntry);
    return;
  }
  fold(state, entry, hash);
}

const ENTRY_KINDS: { readonly [Op in ChainEntry["op"]]?: true } = {
  genesis: true,
  add_member: true,
  remove_member: true,
  change_role: true,
  grant_server: true,
  revoke_server: true,
  set_approval_policy: true,
  propose: true,
  approve: true,
  withdraw: true,
  add_device: true,
  revoke_device: true,
  delete_environment: true,
};

function reportedMemberOf(member: MutableMember): ReportedMember {
  return {
    userId: member.userId,
    role: member.role,
    scopeKind: member.scopeKind,
    scopeEnvironmentIds: member.scopeEnvironmentIds,
    sinceSeq: member.sinceSeq,
    devices: member.devices.map((d) => ({ ...d })),
    unresolvedRevocations: member.unresolvedRevocations,
  };
}

function readableEnvelope(entry: unknown): entry is ChainEntry {
  return (
    isRecord(entry) &&
    typeof entry.seq === "number" &&
    hasStrings(entry.actor, ["userId", "keyFingerprintHex"])
  );
}

export function deriveReportedView(
  entries: ReadonlyArray<ChainEntry>,
  headHashHex?: string,
): ReportedChainView {
  const state: FoldState = {
    members: new Map(),
    servers: new Map(),
    policy: null,
    pending: new Map(),
    fingerprints: new FingerprintTable(),
    unreadableEntries: 0,
  };
  entries.forEach((entry, index) => {
    if (!readableEnvelope(entry)) {
      state.unreadableEntries += 1;
      return;
    }
    bindActor(state, entry.actor.userId, entry.actor.keyFingerprintHex);
    foldEntry(state, entry, entries[index + 1]?.prevHashHex ?? headHashHex);
  });
  const proposals = [...state.pending]
    .map(([hash, pending]) => {
      const voters = countedVoters(state, signersOf(pending));
      return {
        proposalHashHex: hash,
        proposalSeq: pending.seq,
        proposerUserId: pending.proposerUserId,
        innerOp: pending.inner.op,
        innerSummary: summarizeInner(pending.inner),
        expiresAtMs: pending.expiresAtMs,
        votes: voters.length,
        voterUserIds: voters,
      };
    })
    .toSorted((a, b) => a.proposalSeq - b.proposalSeq);
  return {
    members: [...state.members.values()].map(reportedMemberOf),
    servers: [...state.servers.values()],
    policy: state.policy,
    proposals,
    unreadableEntries: state.unreadableEntries,
  };
}
