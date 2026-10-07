// See chain-view.ts for the display-only contract.

import type { ReportedPolicy, ReportedServer } from "./chain-view-reported.ts";
import type { ChainEntry } from "./types.ts";

/** The record of a vote (the user_id and the signing key's FP — an element of principle 2's S). */
export interface Vote {
  userId: string;
  keyFingerprintHex: string;
}

export type EntryOf<Op extends ChainEntry["op"]> = Extract<ChainEntry, { op: Op }>;

/** The inner op of a proposal (wire shape — folded when the approve applies). */
export type ProposableEntry = EntryOf<"propose">["payload"]["inner"];

export interface PendingFold {
  seq: number;
  proposerUserId: string;
  proposerKeyFingerprintHex: string;
  proposerRoleAtProposal: string;
  inner: ProposableEntry;
  expiresAtMs: number;
  approvals: Vote[];
}

/** The mutable record of one device (the FP enters only once it could be bound). */
export interface MutableDevice {
  keyFingerprintHex: string | null;
  encPubHex: string;
  sigPubHex: string;
  roleCap: string;
  scopeKind: "all" | "listed";
  scopeEnvironmentIds: ReadonlyArray<string>;
  addedSeq: number;
}

/** The mutable record of one member (a membership interval = one record. Deleted on remove, rebuilt on add_member). */
export interface MutableMember {
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
export class FingerprintTable {
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

export interface FoldState {
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
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Whether all the named fields are strings. */
export function hasStrings(value: unknown, fields: ReadonlyArray<string>): boolean {
  return isRecord(value) && fields.every((f) => typeof value[f] === "string");
}

/** The own-property value (never hits a prototype-chain value — defends against a hostile server's "__proto__"). */
export function ownProp<K extends string, V>(
  obj: { readonly [P in K]?: V },
  key: string,
): V | undefined {
  return Object.hasOwn(obj, key) ? obj[key as K] : undefined;
}

export function isStringArray(value: unknown): value is ReadonlyArray<string> {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function keyIdOf(userId: string, encPubHex: string, sigPubHex: string): string {
  return `${userId}:${encPubHex}:${sigPubHex}`;
}

function keyIdOfDevice(userId: string, device: MutableDevice): string {
  return keyIdOf(userId, device.encPubHex, device.sigPubHex);
}

/** A new device record (inherits the FP if already learned). */
export function newDevice(
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
export const ALL_SCOPE = { scopeKind: "all", scopeEnvironmentIds: [] } as const;
const FIRST_DEVICE_CAP = { roleCap: "owner", ...ALL_SCOPE } as const;

/** The start of a membership interval (genesis / add_member): rebuilds the record and puts the first device on it. */
export function startTenure(
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
export function bindFingerprint(
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
export function unboundDevicesOf(member: MutableMember): MutableDevice[] {
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
export function bindActor(state: FoldState, userId: string, fp: string): void {
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

/** Whether scope's 2 fields are in a readable shape (type is never trusted — only the shape is read). */
export function readableScope(payload: Scope): boolean {
  return (
    (payload.scopeKind === "all" || payload.scopeKind === "listed") &&
    isStringArray(payload.scopeEnvironmentIds)
  );
}

/**
 * The listed ids left after a deleted environment leaves a scope (the
 * display mirror of crypto's `scopeWithout` — §6.2 `delete_environment`):
 * `all` is never pruned, and a `listed` scope that names the environment
 * stays `listed`, possibly empty. Null when the scope is not pruned
 * (`all`, or a listed scope that does not name the environment).
 */
export function scopeIdsWithout(scope: Scope, environmentId: string): ReadonlyArray<string> | null {
  if (scope.scopeKind === "all" || !scope.scopeEnvironmentIds.includes(environmentId)) return null;
  return scope.scopeEnvironmentIds.filter((id) => id !== environmentId);
}

/**
 * Folds the reported scope into a readable shape (defense against a
 * hostile server): an unreadable shape folds to "listed" + empty and
 * is emitted as "not reported". The member record itself is not
 * dropped (even when add_member's scope is unreadable, a membership
 * interval is a membership interval)
 */
export function reportedScope(payload: Scope): Scope {
  return readableScope(payload) ? payload : { scopeKind: "listed", scopeEnvironmentIds: [] };
}

// One branch of the dispatch table takes arguments narrower to its
// op's entry, so the lookup side calls it after widening back to the
// generic (each folder assumes only rows that passed the structural
// check arrive — the table's type is for recording the call)
export type EntryFolder = (state: FoldState, entry: ChainEntry, hash: string | undefined) => void;
export type OperationFolder = (state: FoldState, seq: number, op: ProposableEntry) => void;
export type InnerSummarizer = (op: ProposableEntry) => string;
