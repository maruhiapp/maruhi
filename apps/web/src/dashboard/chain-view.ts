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
import type { ChainEntry } from "./types.ts";

/**
 * One device key of a member, derived from the reported entries (server-reported,
 * unverified). `keyFingerprintHex` is null while the fingerprint could not be
 * bound from the reported bytes (the `add_device` wire carries public keys, not
 * the fingerprint — K5-1); the cap and the adding seq are always reported.
 */
export interface ReportedDevice {
  keyFingerprintHex: string | null;
  encPubHex: string;
  sigPubHex: string;
  /** Role cap as reported (`owner` = no bound — CRYPTO_SPEC §6.2). */
  roleCap: string;
  scopeKind: "all" | "listed";
  scopeEnvironmentIds: ReadonlyArray<string>;
  /** The reported chain seq that put this key on the chain (genesis / add_member / add_device). */
  addedSeq: number;
}

/** One member row derived from the reported entries (server-reported, unverified). */
export interface ReportedMember {
  userId: string;
  role: string;
  /** Environment scope as reported (CRYPTO_SPEC §6.2 — `all`, or the listed environment ids). */
  scopeKind: "all" | "listed";
  scopeEnvironmentIds: ReadonlyArray<string>;
  /** The reported chain seq that last set this member's role / scope. */
  sinceSeq: number;
  /** The member's device keys as reported (may include revoked-but-unresolved ones — see below). */
  devices: ReadonlyArray<ReportedDevice>;
  /**
   * Devices revoked among the fingerprint-less ones whose identity the reported
   * bytes cannot resolve (K5-1). The active device count is
   * `devices.length - unresolvedRevocations` (`reportedDeviceCount`).
   */
  unresolvedRevocations: number;
}

/** Active device count as reported (row count minus the unresolved revocations). */
export function reportedDeviceCount(
  member: Pick<ReportedMember, "devices" | "unresolvedRevocations">,
): number {
  return member.devices.length - member.unresolvedRevocations;
}

/** One granted server key derived from the reported entries (server-reported). */
export interface ReportedServer {
  keyFingerprintHex: string;
  scopeEnvironmentIds: ReadonlyArray<string>;
  sinceSeq: number;
}

/** The four-eyes policy as reported (null = off). */
export interface ReportedPolicy {
  requiredApprovals: number;
  ops: ReadonlyArray<string>;
}

/** One pending proposal as reported (votes recounted under the policy current at the head). */
export interface ReportedProposal {
  proposalHashHex: string;
  proposalSeq: number;
  proposerUserId: string;
  /** `owner` puts the proposal signature into the signer set (one vote — §6.2). */
  proposerRoleAtProposal: string;
  innerOp: string;
  /** One-line summary of the inner operation (ids are shown raw — the UI neutralizes on render). */
  innerSummary: string;
  expiresAtMs: number;
  /** Distinct current owners whose signature counts (recounted — never the raw record). */
  votes: number;
  voterUserIds: ReadonlyArray<string>;
}

export interface ReportedChainView {
  members: ReportedMember[];
  servers: ReportedServer[];
  policy: ReportedPolicy | null;
  proposals: ReportedProposal[];
  /**
   * Entries the fold could not read and left out (the K5-17 generalization): unknown actor / target,
   * a key already held, a fingerprint that is not the target's, a revocation that would
   * leave no device, a malformed payload, or a malformed envelope (non-record entry,
   * actor without a string id/fingerprint, non-record payload). A dropped `add_device`
   * leaves a device out; a dropped `revoke_device` leaves one in — so the displayed sets
   * may be smaller or larger than what those rows would have produced. Shown, never
   * silently absorbed. Ops the fold does not model at all are not counted.
   */
  unreadableEntries: number;
}

/** The record of a vote (the user_id and the signing key's FP — an element of principle 2's S). */
interface Vote {
  userId: string;
  keyFingerprintHex: string;
}

type EntryOf<Op extends ChainEntry["op"]> = Extract<ChainEntry, { op: Op }>;

/** The inner op of a proposal (wire shape — folded when the approve applies). */
type ProposableEntry = EntryOf<"propose">["payload"]["inner"];

interface PendingFold {
  seq: number;
  proposerUserId: string;
  proposerKeyFingerprintHex: string;
  proposerRoleAtProposal: string;
  inner: ProposableEntry;
  expiresAtMs: number;
  approvals: Vote[];
}

/** The mutable record of one device (the FP enters only once it could be bound). */
interface MutableDevice {
  keyFingerprintHex: string | null;
  encPubHex: string;
  sigPubHex: string;
  roleCap: string;
  scopeKind: "all" | "listed";
  scopeEnvironmentIds: ReadonlyArray<string>;
  addedSeq: number;
}

/** The mutable record of one member (a membership interval = one record. Deleted on remove, rebuilt on add_member). */
interface MutableMember {
  userId: string;
  role: string;
  scopeKind: "all" | "listed";
  scopeEnvironmentIds: ReadonlyArray<string>;
  sinceSeq: number;
  devices: MutableDevice[];
  unresolvedRevocations: number;
  /**
   * FPs this person signed with but that could not be bound to a
   * device (when there are two or more unbound devices). Used only for
   * the vote judgment (K5-2) and discarded every time a revocation
   * shrinks the unbound devices (fail-closed).
   */
  unboundSignerFps: Set<string>;
}

/**
 * The learned key ↔ FP correspondence table (K5-16 — an invariant kept
 * by structure). A key is (user_id, public key pair); an FP is a
 * reported actor FP. The correspondence is **injective and set-once**:
 * once (key, FP) is learned, neither that key nor that FP is ever tied
 * to another party. Consequences: (1) the same key inherits the same
 * FP on re-addition after revocation or on re-membership (same key ⇒
 * same FP — the K6-J generalization). (2) A revoked device's FP or
 * another person's device's FP is "already someone's key's", so it is
 * never tied to a different device (a stale actor, re-binding across
 * membership intervals, and reusing someone else's FP are excluded by
 * a property of the table, not by bookkeeping). (3) Two rows with the
 * same FP cannot be created in one person's device set (a different
 * key means a different FP).
 */
class FingerprintTable {
  private readonly fingerprintByKey = new Map<string, string>();
  private readonly ownerByFingerprint = new Map<string, { userId: string; keyId: string }>();

  /** The key's learned FP (null if none). */
  fingerprintOf(keyId: string): string | null {
    return this.fingerprintByKey.get(keyId) ?? null;
  }

  /** The key that already holds an FP (undefined if none). */
  ownerOf(fp: string): { userId: string; keyId: string } | undefined {
    return this.ownerByFingerprint.get(fp);
  }

  /** Binds only when both sides are unlearned (set-once). True when the bind succeeded. */
  claim(userId: string, keyId: string, fp: string): boolean {
    if (this.fingerprintByKey.has(keyId) || this.ownerByFingerprint.has(fp)) return false;
    this.fingerprintByKey.set(keyId, fp);
    this.ownerByFingerprint.set(fp, { userId, keyId });
    return true;
  }
}

interface FoldState {
  members: Map<string, MutableMember>;
  servers: Map<string, ReportedServer>;
  policy: ReportedPolicy | null;
  pending: Map<string, PendingFold>;
  fingerprints: FingerprintTable;
  /** The number of entry rows dropped as unreadable (K5-17 — never silently absorbed). */
  unreadableEntries: number;
}

type Scope = { scopeKind: "all" | "listed"; scopeEnvironmentIds: ReadonlyArray<string> };

/** Whether a value is a record (null and arrays excluded). A report is never trusted by type — only its shape is read. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Whether all the named fields are strings. */
function hasStrings(value: unknown, fields: ReadonlyArray<string>): boolean {
  return isRecord(value) && fields.every((f) => typeof value[f] === "string");
}

/** The own-property value (never hits a prototype-chain value — defends against a hostile server's "__proto__"). */
function ownProp<K extends string, V>(obj: { readonly [P in K]?: V }, key: string): V | undefined {
  return Object.hasOwn(obj, key) ? obj[key as K] : undefined;
}

function keyIdOf(userId: string, encPubHex: string, sigPubHex: string): string {
  return `${userId}:${encPubHex}:${sigPubHex}`;
}

function keyIdOfDevice(userId: string, device: MutableDevice): string {
  return keyIdOf(userId, device.encPubHex, device.sigPubHex);
}

/** A new device record (inherits the FP if already learned). */
function newDevice(
  state: FoldState,
  userId: string,
  keys: { encPubHex: string; sigPubHex: string },
  cap: { roleCap: string } & Scope,
  addedSeq: number,
): MutableDevice {
  return {
    keyFingerprintHex: state.fingerprints.fingerprintOf(
      keyIdOf(userId, keys.encPubHex, keys.sigPubHex),
    ),
    encPubHex: keys.encPubHex,
    sigPubHex: keys.sigPubHex,
    roleCap: cap.roleCap,
    scopeKind: cap.scopeKind,
    scopeEnvironmentIds: cap.scopeEnvironmentIds,
    addedSeq,
  };
}

/** The genesis creator's scope is structurally all (CRYPTO_SPEC §6.2). The first key's cap is also (owner, all). */
const ALL_SCOPE = { scopeKind: "all", scopeEnvironmentIds: [] } as const;
const FIRST_DEVICE_CAP = { roleCap: "owner", ...ALL_SCOPE } as const;

/** The start of a membership interval (genesis / add_member): rebuilds the record and puts the first device on it. */
function startTenure(
  state: FoldState,
  userId: string,
  role: string,
  scope: Scope,
  keys: { encPubHex: string; sigPubHex: string },
  seq: number,
): MutableMember {
  const member: MutableMember = {
    userId,
    role,
    scopeKind: scope.scopeKind,
    scopeEnvironmentIds: scope.scopeEnvironmentIds,
    sinceSeq: seq,
    devices: [newDevice(state, userId, keys, FIRST_DEVICE_CAP, seq)],
    unresolvedRevocations: 0,
    unboundSignerFps: new Set(),
  };
  state.members.set(userId, member);
  return member;
}

/** Binds and learns an FP to a device (only when the table accepts it — set-once). */
function bindFingerprint(
  state: FoldState,
  userId: string,
  device: MutableDevice,
  fp: string,
): void {
  if (state.fingerprints.claim(userId, keyIdOfDevice(userId, device), fp)) {
    device.keyFingerprintHex = fp;
  }
}

/** FP-unbound devices. */
function unboundDevicesOf(member: MutableMember): MutableDevice[] {
  return member.devices.filter((d) => d.keyFingerprintHex === null);
}

/**
 * The signer's record (undefined = nothing to bind when absent, or when
 * the FP already belongs to some key). An FP on the table belongs to
 * this person's current devices, to a revoked device, to a previous
 * membership interval, or to someone else's key — in every case it is
 * not a candidate for an unbound device (K5-16).
 */
function signerNeedingBinding(
  state: FoldState,
  userId: string,
  fp: string,
): MutableMember | undefined {
  const member = state.members.get(userId);
  if (member === undefined || state.fingerprints.ownerOf(fp) !== undefined) return undefined;
  return member;
}

/**
 * Ties the signer's own actor FP to that person's device (K5-1): if it
 * already belongs to someone's key, does nothing. If exactly one device
 * is unbound, binds to it; if two or more, does not identify it and
 * puts it into "unbound signer FPs" (used only for the vote judgment —
 * K5-2). If zero, the report is unreadable (ignored).
 */
function bindActor(state: FoldState, userId: string, fp: string): void {
  const member = signerNeedingBinding(state, userId, fp);
  if (member === undefined) return;
  const unbound = unboundDevicesOf(member);
  if (unbound.length >= 2) {
    member.unboundSignerFps.add(fp);
    return;
  }
  const sole = unbound[0];
  if (sole !== undefined) bindFingerprint(state, userId, sole, fp);
}

function applyChangeRole(
  state: FoldState,
  seq: number,
  payload: EntryOf<"change_role">["payload"],
): void {
  if (!hasStrings(payload, ["targetUserId", "newRole"])) {
    state.unreadableEntries += 1;
    return;
  }
  const existing = state.members.get(payload.targetUserId);
  if (existing !== undefined) {
    // Full replacement by the new (role, scope) (§6.2 — scope is also
    // copied per 2026-09-15 ES K4). The device set is unchanged
    const scope = reportedScope(payload);
    existing.role = payload.newRole;
    existing.scopeKind = scope.scopeKind;
    existing.scopeEnvironmentIds = scope.scopeEnvironmentIds;
    existing.sinceSeq = seq;
  }
}

function applyGrantServer(
  state: FoldState,
  seq: number,
  payload: EntryOf<"grant_server">["payload"],
): void {
  if (typeof payload.serverKeyFingerprintHex !== "string") {
    state.unreadableEntries += 1;
    return;
  }
  state.servers.set(payload.serverKeyFingerprintHex, {
    keyFingerprintHex: payload.serverKeyFingerprintHex,
    scopeEnvironmentIds: isStringArray(payload.scopeEnvironmentIds)
      ? payload.scopeEnvironmentIds
      : [],
    sinceSeq: seq,
  });
}

/** add_member: starts a membership interval (the first device = the payload's key. Same key as the previous interval inherits the FP). */
function applyAddMember(
  state: FoldState,
  seq: number,
  payload: EntryOf<"add_member">["payload"],
): void {
  if (!hasStrings(payload, ["targetUserId", "role", "encPubHex", "sigPubHex"])) {
    state.unreadableEntries += 1;
    return;
  }
  startTenure(state, payload.targetUserId, payload.role, reportedScope(payload), payload, seq);
}

type OperationOf<Op extends ProposableEntry["op"]> = Extract<ProposableEntry, { op: Op }>;

// The fold of applied ops (shared between a direct append and an
// approve's inner op that reached quorum).
// `seq` = the application seq (the approve's seq when it came via a
// proposal — the inclusive convention). create_environment /
// rotate_epoch / checkpoint / genesis are not here (they do not affect
// the member/server sets; genesis is folded by deriveReportedView with
// key-FP tracking)
const OPERATION_FOLDERS: {
  readonly [Op in ProposableEntry["op"]]?: (
    state: FoldState,
    seq: number,
    operation: OperationOf<Op>,
  ) => void;
} = {
  add_member: (state, seq, operation) => applyAddMember(state, seq, operation.payload),
  remove_member: (state, _seq, operation) => {
    if (typeof operation.payload.targetUserId === "string") {
      state.members.delete(operation.payload.targetUserId);
    } else {
      state.unreadableEntries += 1;
    }
  },
  change_role: (state, seq, operation) => applyChangeRole(state, seq, operation.payload),
  grant_server: (state, seq, operation) => applyGrantServer(state, seq, operation.payload),
  revoke_server: (state, _seq, operation) => {
    if (typeof operation.payload.serverKeyFingerprintHex === "string") {
      state.servers.delete(operation.payload.serverKeyFingerprintHex);
    } else {
      state.unreadableEntries += 1;
    }
  },
  set_approval_policy: (state, _seq, operation) => {
    const { requiredApprovals, ops } = operation.payload;
    if (typeof requiredApprovals !== "number" || !isStringArray(ops)) {
      state.unreadableEntries += 1;
      return;
    }
    state.policy = requiredApprovals === 0 ? null : { requiredApprovals, ops: [...new Set(ops)] };
  },
};

function applyOperation(state: FoldState, seq: number, operation: ProposableEntry): void {
  const fold = ownProp(OPERATION_FOLDERS, operation.op) as OperationFolder | undefined;
  // An unmodeled inner op is ignored (K5-4). Because the folders read
  // the payload's fields, a non-record payload is counted here as an
  // unreadable row (same discipline as K5-17)
  if (fold === undefined) return;
  if (!isRecord(operation.payload)) {
    state.unreadableEntries += 1;
    return;
  }
  fold(state, seq, operation);
}

/** Principle 2's S = {the proposer who proposed as an owner} ∪ approvals. */
function signersOf(pending: PendingFold): Vote[] {
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
function countedVoters(state: FoldState, signers: ReadonlyArray<Vote>): string[] {
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

function applyPropose(state: FoldState, entry: EntryOf<"propose">, hash: string | undefined): void {
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
function applyApprove(state: FoldState, entry: EntryOf<"approve">): void {
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

function summarizeInner(operation: ProposableEntry): string {
  // The summary reads the inner payload's fields — a non-record falls
  // back to the op name
  if (!isRecord(operation.payload)) return operation.op;
  return (
    (ownProp(INNER_SUMMARIES, operation.op) as InnerSummarizer | undefined)?.(operation) ??
    operation.op
  );
}

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

// ---------------------------------------------------------------------------
// The 2 device ops (K5-1 / K5-4): transcribe only the structural rules
// the fold's consistency needs; unreadable rows are ignored
// ---------------------------------------------------------------------------

function isStringArray(value: unknown): value is ReadonlyArray<string> {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

/** Whether scope's 2 fields are in a readable shape (type is never trusted — only the shape is read). */
function readableScope(payload: Scope): boolean {
  return (
    (payload.scopeKind === "all" || payload.scopeKind === "listed") &&
    isStringArray(payload.scopeEnvironmentIds)
  );
}

/**
 * Folds the reported scope into a readable shape (defense against a
 * hostile server): an unreadable shape folds to "listed" + empty and
 * is emitted as "not reported". The member record itself is not
 * dropped (even when add_member's scope is unreadable, a membership
 * interval is a membership interval)
 */
function reportedScope(payload: Scope): Scope {
  return readableScope(payload) ? payload : { scopeKind: "listed", scopeEnvironmentIds: [] };
}

/** Whether an add_device payload is in a readable shape (public keys, cap, scope). */
function readableAddDevice(payload: EntryOf<"add_device">["payload"]): boolean {
  const keysReadable = [payload.encPubHex, payload.sigPubHex, payload.roleCap].every(
    (field) => typeof field === "string",
  );
  return keysReadable && readableScope(payload);
}

/** Among the current members' devices, the one holding the same public key (the holder and the device). */
function currentKeyHolder(
  state: FoldState,
  encPubHex: string,
  sigPubHex: string,
): { member: MutableMember; device: MutableDevice } | undefined {
  for (const member of state.members.values()) {
    const device = member.devices.find(
      (d) => d.encPubHex === encPubHex || d.sigPubHex === sigPubHex,
    );
    if (device !== undefined) return { member, device };
  }
  return undefined;
}

/**
 * When the same key is visible on a current member's device, resolves
 * whether it is the residue of an ambiguously revoked unbound device
 * (K5-12): an accepted `add_device` means "that key is not currently
 * valid" (`duplicate-member-key`), so if the holder has unresolved
 * entries and that device is unbound, that device is confirmed revoked
 * and removed. If it cannot be resolved, it is a duplicate (an
 * unreadable row).
 */
function resolveStaleHolder(holder: { member: MutableMember; device: MutableDevice }): boolean {
  const { member, device } = holder;
  if (device.keyFingerprintHex !== null || member.unresolvedRevocations === 0) return false;
  member.devices = member.devices.filter((d) => d !== device);
  member.unresolvedRevocations -= 1;
  return true;
}

/** Whether a new device's key is usable: it does not duplicate a current member's device, or the duplicate resolves as revocation residue. */
function keyAvailable(state: FoldState, encPubHex: string, sigPubHex: string): boolean {
  const holder = currentKeyHolder(state, encPubHex, sigPubHex);
  return holder === undefined || resolveStaleHolder(holder);
}

/**
 * Adds to the device set. Re-adding the same key restores the learned
 * FP (revocation is not monotonic — §6.2).
 * Two rows with the same FP are not checked here: a different key
 * means a different FP (the table's injectivity), and two rows with
 * the same key are already rejected by `keyAvailable` — the invariant
 * follows from the table and key uniqueness (K5-16).
 */
function pushDevice(member: MutableMember, device: MutableDevice): void {
  member.devices.push(device);
}

/** add_device: adds a new device to the actor's own device set (the target = the actor — §6.2). Counts it if unreadable. */
function applyAddDevice(state: FoldState, entry: EntryOf<"add_device">): void {
  const member = state.members.get(entry.actor.userId);
  const payload = entry.payload;
  if (
    member === undefined ||
    !readableAddDevice(payload) ||
    !keyAvailable(state, payload.encPubHex, payload.sigPubHex)
  ) {
    state.unreadableEntries += 1;
    return;
  }
  pushDevice(member, newDevice(state, member.userId, payload, payload, entry.seq));
}

/** Whether a revoke_device payload is in a readable shape (the FP list: 1+ elements, no duplicates). */
function readableRevokeDevice(payload: EntryOf<"revoke_device">["payload"]): boolean {
  const fps = payload.deviceFingerprintsHex;
  return (
    typeof payload.targetUserId === "string" &&
    isStringArray(fps) &&
    fps.length > 0 &&
    new Set(fps).size === fps.length
  );
}

/** The revocation arithmetic (K5-1): the matched devices, the unmatched FP count, the unbound remainder, and whether it is readable. */
interface RevocationPlan {
  matched: Set<MutableDevice>;
  unmatched: number;
  unboundRemaining: number;
  /** The unmatched FPs do not exceed the unbound remainder, and at least one device remains after revocation (§6.2 `unknown-device` / `last-device-protected`). */
  readable: boolean;
}

function planRevocation(
  state: FoldState,
  member: MutableMember,
  fps: ReadonlySet<string>,
): RevocationPlan {
  const matched = new Set(
    member.devices.filter((d) => d.keyFingerprintHex !== null && fps.has(d.keyFingerprintHex)),
  );
  const unmatchedFps = [...fps].filter(
    (fp) => !member.devices.some((d) => d.keyFingerprintHex === fp),
  );
  // If an unmatched FP is "already someone's key's" (a revoked device
  // or someone else's device), it cannot be a revocation of this
  // person's unbound device (§6.2 `unknown-device`) — the row is
  // unreadable (K5-16)
  const foreign = unmatchedFps.some((fp) => state.fingerprints.ownerOf(fp) !== undefined);
  const unmatched = unmatchedFps.length;
  const unboundRemaining = unboundDevicesOf(member).length - member.unresolvedRevocations;
  const countAfter =
    member.devices.length - member.unresolvedRevocations - matched.size - unmatched;
  return {
    matched,
    unmatched,
    unboundRemaining,
    readable: !foreign && unmatched <= unboundRemaining && countAfter > 0,
  };
}

/**
 * A readable revocation plan (the target member + the arithmetic).
 * A row whose payload is unreadable, whose target is not a current
 * member, or whose arithmetic does not hold is undefined (= an
 * unreadable row).
 */
function readableRevocation(
  state: FoldState,
  payload: EntryOf<"revoke_device">["payload"],
): { member: MutableMember; plan: RevocationPlan } | undefined {
  const member = readableRevokeDevice(payload)
    ? state.members.get(payload.targetUserId)
    : undefined;
  if (member === undefined) return undefined;
  const plan = planRevocation(state, member, new Set(payload.deviceFingerprintsHex));
  return plan.readable ? { member, plan } : undefined;
}

/** Removes the matched bound devices (their FPs stay on the table = henceforth never tied to another device — K5-16). */
function revokeMatched(member: MutableMember, plan: RevocationPlan): void {
  member.devices = member.devices.filter((d) => !plan.matched.has(d));
}

/** Removes the unmatched FPs arithmetically from the unbound devices (clears them when it is the whole remainder, otherwise counts into unresolved). */
function revokeUnbound(member: MutableMember, plan: RevocationPlan): void {
  // Fewer unbound devices = a device of the unbound signer FPs may have
  // been revoked → discard the vote material
  member.unboundSignerFps.clear();
  if (plan.unmatched === plan.unboundRemaining) {
    member.devices = member.devices.filter((d) => d.keyFingerprintHex !== null);
    member.unresolvedRevocations = 0;
  } else {
    member.unresolvedRevocations += plan.unmatched;
  }
}

/**
 * revoke_device: an FP matching a bound device removes that device;
 * an unmatched FP is removed arithmetically by the count of unbound
 * devices (K5-1). When it equals the unbound remainder (row count −
 * unresolved) all are removed; when fewer, the difference is counted
 * into unresolved (the device count is exact; which ones is unknown).
 * More than that / 0 devices after revocation / unknown target are
 * ignored.
 */
function applyRevokeDevice(state: FoldState, entry: EntryOf<"revoke_device">): void {
  const readable = readableRevocation(state, entry.payload);
  if (readable === undefined) {
    state.unreadableEntries += 1;
    return;
  }
  const { member, plan } = readable;
  revokeMatched(member, plan);
  if (plan.unmatched > 0) revokeUnbound(member, plan);
}

// The fold of the entries themselves (genesis, the 4 four-eyes ops,
// the 2 device ops). The 2 device ops cannot be proposed
// (§6.2 `approval-not-required`), so they fold only as direct entries
// (ignored as inner ops — K5-4). Any other state-changing op goes to
// applyOperation (the applied-op table — shared with a completed
// approve's inner op)
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
// and the 2 device ops by DK K5 (design record dk-design.md §10)
// One branch of the dispatch table takes arguments narrower to its
// op's entry, so the lookup side calls it after widening back to the
// generic (each folder assumes only rows that passed the structural
// check arrive — the table's type is for recording the call)
type EntryFolder = (state: FoldState, entry: ChainEntry, hash: string | undefined) => void;
type OperationFolder = (state: FoldState, seq: number, op: ProposableEntry) => void;
type InnerSummarizer = (op: ProposableEntry) => string;

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
