// Deriving the display view from the chain fetch response (S5 —
// design document §3).
//
// This is **not verification** (ADR-0018 amendments 2 and 4 — no
// chain/signature verification code in the web bundle): it is a
// display transform that mechanically folds the returned entry list in
// the order it came back, performing no checks of signatures, hash
// linkage, or consensus rules. Every result is "as reported by the
// server" and the UI says so. When a verified member set is needed,
// that is `maruhi project verify`'s (the CLI's) job.
//
// Four-eyes (CRYPTO_SPEC §6.2 — PF1. Design record es-design.md §12
// K6-J): the policy and pending proposals are derived by the same
// mechanical fold. approve / withdraw point at a proposal by
// entry_hash, but the response carries no per-entry hash, so they are
// drawn from **the next entry's prevHashHex** (headHashHex at the
// tail) — no hashes computed, no crypto brought in. The vote count is
// not the raw record: at each approve the "current owner whose key FP
// matches" voters are recounted (K2's implementation note). The key FP
// is tracked from the genesis actor and from the actor of each entry
// the member signed, and an add_member carrying the same key as the
// previous membership interval inherits it (if different it stays
// "unknown" until it signs = never counted — a different key means a
// different FP, so the consensus rule does not count it either). An
// approve that reaches quorum folds in the inner op (needed so an
// applied remove disappears from Members).
//
// Device keys (CRYPTO_SPEC §3 / §6.2 — DK. Design record dk-design.md
// §10 K5-1 / K5-2 / K5-4): a member holds a set of devices; the
// `genesis` / `add_member` key is the first device (cap is
// structurally owner/all), and `add_device` / `revoke_device` grow
// and shrink it. The `add_device` wire carries two public keys and a
// cap and **carries no FP** (an FP is a SHA-256 derived value), so a
// device is identified by the key pair and FPs are bound only within
// "what can be mechanically transcribed from the reported bytes": a
// genesis actor FP binds to the first key, and an actor FP of an entry
// a member signed binds to that device only when "exactly one device
// is FP-unbound" (no hashes computed — K6-J). Bindings are recorded in
// the learned key ↔ FP correspondence table (`FingerprintTable` —
// injective, set-once. K5-16), and an FP that once belonged to a key
// is never tied to another (a revoked device's FP, re-binding across
// membership intervals, and another person's FP are excluded
// structurally). A `revoke_device` FP matching a bound device removes
// that device; a matching-less, undeclared FP is removed arithmetically
// by the count of unbound devices (the device count is always exact;
// which ones is honestly shown as "unresolved"). Four-eyes votes are
// counted in device vocabulary (§6.2).
//
// Environment deletion (CRYPTO_SPEC §6.2 `delete_environment` —
// 2026-10-07): the deleted id leaves every listed scope — each member's,
// each of their devices' caps, each granted server's — by the same
// pruning rule as crypto's `scopeWithout` (`all` is never pruned; a
// listed scope stays listed, possibly empty). Like the device ops it
// is never a four-eyes target (a propose carrying it is
// `approval-not-required`), so it folds only as a direct entry (K5-4's
// line).

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

/**
 * delete_environment: prunes the deleted id from every member's listed
 * scope (a pruned member's sinceSeq moves to the deletion — it set the
 * scope, the same change point as crypto's history index), from every
 * device's listed cap, and from every granted server's scope. The
 * environment set itself is not folded (the dashboard lists live
 * environments from the server's listing — AUTH_SPEC §12-7).
 */
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

/** One member's share of a deletion: its own listed scope (a change point at `seq`) and its devices' listed caps. */
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

// The fold of the entries themselves (genesis, the 4 four-eyes ops,
// the 2 device ops, delete_environment). The 2 device ops and
// delete_environment cannot be proposed (§6.2 `approval-not-required`),
// so they fold only as direct entries (ignored as inner ops — K5-4).
// Any other state-changing op goes to applyOperation (the applied-op
// table — shared with a completed approve's inner op)
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

/** The fold of one entry. */
function foldEntry(state: FoldState, entry: ChainEntry, hash: string | undefined): void {
  // Object.hasOwn: self-defense so a hostile server's op (e.g.
  // "__proto__") cannot hit a prototype-chain value and drop the
  // render with a throw
  if (!Object.hasOwn(ENTRY_KINDS, entry.op)) return;
  // Each folder reads the payload's fields, so a non-record payload
  // cannot be folded
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

// The closed set of ops the fold admits (for the own-property check).
// create_environment / rotate_epoch / checkpoint do not affect the
// member/server sets, so they are not here. scope (the trailing 2
// fields of add_member / change_role) was added by K4 (2026-09-15 ES —
// design record K4-D), the 4 four-eyes ops by K6 (design record K6-J),
// the 2 device ops by DK K5 (design record dk-design.md §10), and
// delete_environment (which prunes member / device / server scopes) at
// 2026-10-07
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

/** A mutable record → the public row (the vote material is not emitted). */
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

/** Whether an entry's envelope is readable (type is never trusted — only the shape is read): a record, seq a number, actor with a string id / FP. */
function readableEnvelope(entry: unknown): entry is ChainEntry {
  return (
    isRecord(entry) &&
    typeof entry.seq === "number" &&
    hasStrings(entry.actor, ["userId", "keyFingerprintHex"])
  );
}

/**
 * Folds the entry list in the order it came back into the display
 * member / server sets, the policy, and the pending proposals.
 * `headHashHex` is the tail entry's hash (the response's headHashHex —
 * server-reported).
 */
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
    // A row whose envelope is unreadable (non-record, missing actor,
    // missing seq) cannot be folded
    // — counted as an unreadable row (a shape a hostile server sends —
    // same discipline as K5-17)
    if (!readableEnvelope(entry)) {
      state.unreadableEntries += 1;
      return;
    }
    // The signing actor's own actor FP is one of that member's
    // devices (the acceptance surface already verified it — as
    // reported)
    bindActor(state, entry.actor.userId, entry.actor.keyFingerprintHex);
    // entry i's hash = entry i + 1's prevHashHex; the tail is
    // headHashHex
    foldEntry(state, entry, entries[index + 1]?.prevHashHex ?? headHashHex);
  });
  const proposals = [...state.pending]
    .map(([hash, pending]) => {
      const voters = countedVoters(state, signersOf(pending));
      return {
        proposalHashHex: hash,
        proposalSeq: pending.seq,
        proposerUserId: pending.proposerUserId,
        proposerRoleAtProposal: pending.proposerRoleAtProposal,
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
