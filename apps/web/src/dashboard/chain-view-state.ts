import type { ReportedPolicy, ReportedServer } from "./chain-view-reported.ts";
import { isRecord } from "./json-record.ts";
import type { ChainEntry } from "./types.ts";

export interface Vote {
  userId: string;
  keyFingerprintHex: string;
}

export type EntryOf<Op extends ChainEntry["op"]> = Extract<ChainEntry, { op: Op }>;

export type ProposableEntry = EntryOf<"propose">["payload"]["inner"];

export interface PendingFold {
  seq: number;
  proposerUserId: string;
  proposerKeyFingerprintHex: string;
  proposerSignedAsOwner: boolean;
  inner: ProposableEntry;
  expiresAtMs: number;
  approvals: Vote[];
}

export interface MutableDevice {
  keyFingerprintHex: string | null;
  encPubHex: string;
  sigPubHex: string;
  roleCap: string;
  scopeKind: "all" | "listed";
  scopeEnvironmentIds: ReadonlyArray<string>;
  addedSeq: number;
}

export interface MutableMember {
  userId: string;
  role: string;
  scopeKind: "all" | "listed";
  scopeEnvironmentIds: ReadonlyArray<string>;
  sinceSeq: number;
  devices: MutableDevice[];
  unresolvedRevocations: number;
  unboundSignerFps: Set<string>;
}

export class FingerprintTable {
  private readonly fingerprintByKey = new Map<string, string>();
  private readonly ownerByFingerprint = new Map<string, { userId: string; keyId: string }>();

  fingerprintOf(keyId: string): string | null {
    return this.fingerprintByKey.get(keyId) ?? null;
  }

  ownerOf(fp: string): { userId: string; keyId: string } | undefined {
    return this.ownerByFingerprint.get(fp);
  }

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
  unreadableEntries: number;
}

type Scope = { scopeKind: "all" | "listed"; scopeEnvironmentIds: ReadonlyArray<string> };

export function hasStrings(value: unknown, fields: ReadonlyArray<string>): boolean {
  return isRecord(value) && fields.every((f) => typeof value[f] === "string");
}

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

export const ALL_SCOPE = { scopeKind: "all", scopeEnvironmentIds: [] } as const;
const FIRST_DEVICE_CAP = { roleCap: "owner", ...ALL_SCOPE } as const;

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

export function unboundDevicesOf(member: MutableMember): MutableDevice[] {
  return member.devices.filter((d) => d.keyFingerprintHex === null);
}

function signerNeedingBinding(
  state: FoldState,
  userId: string,
  fp: string,
): MutableMember | undefined {
  const member = state.members.get(userId);
  if (member === undefined || state.fingerprints.ownerOf(fp) !== undefined) return undefined;
  return member;
}

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

export function readableScope(payload: Scope): boolean {
  return (
    (payload.scopeKind === "all" || payload.scopeKind === "listed") &&
    isStringArray(payload.scopeEnvironmentIds)
  );
}

export function scopeIdsWithout(scope: Scope, environmentId: string): ReadonlyArray<string> | null {
  if (scope.scopeKind === "all" || !scope.scopeEnvironmentIds.includes(environmentId)) return null;
  return scope.scopeEnvironmentIds.filter((id) => id !== environmentId);
}

export function reportedScope(payload: Scope): Scope {
  return readableScope(payload) ? payload : { scopeKind: "listed", scopeEnvironmentIds: [] };
}

export type EntryFolder = (state: FoldState, entry: ChainEntry, hash: string | undefined) => void;
export type OperationFolder = (state: FoldState, seq: number, op: ProposableEntry) => void;
export type InnerSummarizer = (op: ProposableEntry) => string;
