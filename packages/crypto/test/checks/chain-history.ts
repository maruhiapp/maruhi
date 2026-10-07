// Checks for ChainHistoryIndex (CRYPTO_SPEC §6.3 / session-14 ruling A).
// Against the canonical chain (chain-entries.json) and the tenure extension
// chain (tenure_extension in value-signature.json), pins seq → entry hash,
// member/environment state as of the declared head (inclusive), and tenure
// separation.

import type {
  ChainEntry,
  ChainHistoryIndex,
  ChainState,
  MemberScope,
  MemberStateAtSeq,
} from "../../src/index.ts";
import { soleDeviceOf, verifyChainWithHistory } from "../../src/index.ts";
import valueVectors from "../../test-vectors/value-signature.json" with { type: "json" };
import {
  toTypedEntry,
  typedEntries,
  vectorEntries,
  vectorExtendedChains,
  vectorKeys,
  vectorValidAppends,
} from "./chain-vector.ts";
import { type CheckResult, Checks } from "./support.ts";

const OWNER = "user-owner-0001";
const MEMBER = "user-member-0002";
const ADMIN = "user-admin-0003";
const DEV_MEMBER = "user-devmember-0010";
/** Head seq of the canonical chain (chain-entries.json — 24 as of 2026-09-14 ES + PF1). */
const HEAD_SEQ = 24;
/** seq of the re-add entry in tenure_extension (value-signature.json) (= head + 1). */
const EXTENSION_SEQ = HEAD_SEQ + 1;

/** Returns the tenure_extension entry (the new-key re-add at seq 25), typed. */
function tenureExtensionEntry(): ChainEntry {
  const raw = valueVectors.tenure_extension.entry;
  return toTypedEntry({
    seq: raw.seq,
    suite: raw.suite,
    prev_hash_hex: raw.prev_hash_hex,
    op: raw.op,
    actor: raw.actor,
    payload: raw.payload,
    timestamp_ms: raw.timestamp_ms,
    payload_bytes_hex: raw.payload_bytes_hex,
    signed_bytes_hex: raw.signed_bytes_hex,
    signature_hex: raw.signature_hex,
    entry_bytes_hex: raw.entry_bytes_hex,
    entry_hash_hex: raw.entry_hash_hex,
  });
}

/** Verified history index of the canonical 24-entry chain. */
export async function canonicalHistory(): Promise<ChainHistoryIndex> {
  const result = await verifyChainWithHistory(typedEntries);
  if (!result.ok) {
    throw new Error("canonical chain failed verification");
  }
  return result.value.history;
}

/**
 * Verified history index of a chain-entries.json derived chain
 * (extended_chains). Checkpoint-bound manifest verification (§4.3 (2) —
 * env-manifest.ts) uses the checkpoint-boundary-* chains as comparison
 * chains.
 */
export async function extendedVectorChainHistory(name: string): Promise<ChainHistoryIndex> {
  const extended = vectorExtendedChains[name];
  if (extended === undefined) {
    throw new Error(`extended chain ${name} missing`);
  }
  const result = await verifyChainWithHistory([
    ...typedEntries.slice(0, extended.base_seq),
    ...extended.entries.map((entry) => toTypedEntry(entry)),
  ]);
  if (!result.ok) {
    throw new Error(`extended chain ${name} failed verification`);
  }
  return result.value.history;
}

/** Verified history index of the canonical 24 entries + the seq-25 re-add derived chain. */
export async function extendedHistory(): Promise<ChainHistoryIndex> {
  const result = await verifyChainWithHistory([...typedEntries, tenureExtensionEntry()]);
  if (!result.ok) {
    throw new Error("tenure-extension chain failed verification");
  }
  return result.value.history;
}

function entryHashChecks(c: Checks, history: ChainHistoryIndex): void {
  c.push("history: head seq", history.headSeq === HEAD_SEQ);
  c.push(
    "history: head hash",
    history.headHashHex === vectorEntries[vectorEntries.length - 1]?.entry_hash_hex,
  );
  for (const vector of vectorEntries) {
    c.push(
      `history: entry hash at seq ${vector.seq}`,
      history.entryHashAt(vector.seq) === vector.entry_hash_hex,
    );
  }
  c.push("history: entry hash at seq 0 is undefined", history.entryHashAt(0) === undefined);
  c.push(
    "history: entry hash beyond head is undefined",
    history.entryHashAt(HEAD_SEQ + 1) === undefined,
  );
  c.push(
    "history: entry hash at non-integer seq is undefined",
    history.entryHashAt(3.5) === undefined,
  );
}

function memberBoundaryChecks(c: Checks, history: ChainHistoryIndex): void {
  // The owner is valid at genesis's own seq (inclusive)
  c.push("history: owner valid at genesis seq", history.memberStateAt(OWNER, 1)?.role === "owner");
  // The target is valid at add_member's own seq (inclusive). Not yet a
  // member at seq 1
  c.push("history: member absent before add", history.memberStateAt(MEMBER, 1) === undefined);
  const memberAt2 = history.memberStateAt(MEMBER, 2);
  c.push(
    "history: member valid at its own add seq",
    memberAt2?.role === "member" && memberAt2.tenureStartSeq === 2,
  );
  // The target is invalid at remove_member's own seq (inclusive). Valid up
  // to the preceding seq
  c.push(
    "history: member valid just before removal",
    history.memberStateAt(MEMBER, 4) !== undefined,
  );
  c.push(
    "history: member invalid at its removal seq",
    history.memberStateAt(MEMBER, 5) === undefined,
  );
  c.push(
    "history: member invalid after removal",
    history.memberStateAt(MEMBER, HEAD_SEQ) === undefined,
  );
}

/** The device at membership start = the single first key (cap is structurally (owner, all) — §6.2), plus point-in-time device lookups. */
function memberDeviceChecks(c: Checks, history: ChainHistoryIndex): void {
  const memberDevice = soleDeviceAt(history, MEMBER, 2);
  const expected = vectorKeys[MEMBER];
  if (memberDevice === undefined || expected === undefined) {
    c.push("history: member key binding matches chain keys", false, "device or keys missing");
    return;
  }
  c.push(
    "history: member key binding matches chain keys",
    memberDevice.keyFingerprintHex === expected.key_fingerprint_hex &&
      memberDevice.sigPubHex === expected.sig_pub_hex,
  );
  c.push(
    "history: first key has the structural cap (owner, all) from its add seq",
    memberDevice.roleCap === "owner" &&
      memberDevice.scope.kind === "all" &&
      memberDevice.addedSeq === 2,
  );
  // Point-in-time device lookup (§6.3-1): the same key is valid only inside
  // its membership interval
  const deviceAt2 = history.deviceStateAt(MEMBER, expected.key_fingerprint_hex, 2);
  c.push(
    "history: member device state at its add seq carries the person's permission",
    deviceAt2?.permission.role === "member" && deviceAt2.tenureStartSeq === 2,
  );
  c.push(
    "history: member device state is undefined at the removal seq",
    history.deviceStateAt(MEMBER, expected.key_fingerprint_hex, 5) === undefined,
  );
}

/** The member's sole device as of `seq` (undefined when absent or multiple). */
function soleDeviceAt(history: ChainHistoryIndex, userId: string, seq: number) {
  const member = history.memberStateAt(userId, seq);
  return member === undefined ? undefined : soleDeviceOf(member);
}

function roleChangeBoundaryChecks(c: Checks, history: ChainHistoryIndex): void {
  // The new role is valid at change_role's own seq (inclusive). The role at
  // add time is reader
  c.push("history: admin absent before add", history.memberStateAt(ADMIN, 5) === undefined);
  c.push(
    "history: admin is reader at its add seq",
    history.memberStateAt(ADMIN, 6)?.role === "reader",
  );
  c.push(
    "history: admin has new role at its change_role seq",
    history.memberStateAt(ADMIN, 7)?.role === "admin",
  );
  c.push(
    "history: admin keeps role at head",
    history.memberStateAt(ADMIN, HEAD_SEQ)?.role === "admin",
  );
}

/** Change points of (role, scope) (§6.2 — 2026-09-14 ES / PF1 application via proposal). */
/** The environment id list of a listed scope (all / absent → undefined). */
function listed(state: MemberStateAtSeq | undefined): readonly string[] | undefined {
  return state?.scope.kind === "listed" ? state.scope.environmentIds : undefined;
}

function scopeBoundaryChecks(c: Checks, history: ChainHistoryIndex): void {
  // A genesis-derived owner / an old-format-equivalent add_member has scope
  // = all
  c.push("history: owner scope is all", history.memberStateAt(OWNER, 1)?.scope.kind === "all");
  c.push("history: admin scope is all", history.memberStateAt(ADMIN, 6)?.scope.kind === "all");
  // seq 13: joins as member of listed{dev} (inclusive)
  c.push(
    "history: dev member absent before add",
    history.memberStateAt(DEV_MEMBER, 12) === undefined,
  );
  const at13 = history.memberStateAt(DEV_MEMBER, 13);
  c.push(
    "history: dev member listed{dev} at its add seq",
    at13?.role === "member" && listed(at13)?.join(",") === "env-dev-0002",
  );
  // seq 17: change_role (widens only the scope — {dev} → {dev, stage}) is
  // valid at its own seq
  c.push(
    "history: dev member scope unchanged just before change_role",
    listed(history.memberStateAt(DEV_MEMBER, 16))?.join(",") === "env-dev-0002",
  );
  const at17 = history.memberStateAt(DEV_MEMBER, 17);
  c.push(
    "history: dev member widened scope at its change_role seq",
    at17?.role === "member" && listed(at17)?.join(",") === "env-dev-0002,env-stage-0003",
  );
}

/** Application via proposal (PF1): the change point is the seq of the approve entry that reaches quorum (inclusive). */
function proposalApplyBoundaryChecks(c: Checks, history: ChainHistoryIndex): void {
  // The propose at seq 21 changes no state; the approve at seq 22 (quorum
  // reached) applies the inner change_role (reader / listed{dev})
  const at21 = history.memberStateAt(DEV_MEMBER, 21);
  c.push(
    "history: propose does not change the target",
    at21?.role === "member" && listed(at21)?.join(",") === "env-dev-0002,env-stage-0003",
  );
  const at22 = history.memberStateAt(DEV_MEMBER, 22);
  c.push(
    "history: quorum approve applies the inner change_role at its own seq",
    at22?.role === "reader" && listed(at22)?.join(",") === "env-dev-0002",
  );
  c.push(
    "history: applied change persists at head",
    history.memberStateAt(DEV_MEMBER, HEAD_SEQ)?.role === "reader",
  );
}

function environmentCreateRotateChecks(c: Checks, history: ChainHistoryIndex): void {
  // Epoch 1 is valid at create_environment's own seq (inclusive). At the
  // preceding seq the environment does not exist
  c.push(
    "history: environment absent before create",
    history.environmentStateAt("env-prod-0001", 2) === undefined,
  );
  const prodAt3 = history.environmentStateAt("env-prod-0001", 3);
  c.push(
    "history: environment epoch 1 at its create seq",
    prodAt3?.createdAtSeq === 3 && prodAt3?.currentEpoch === 1,
  );
  // The new epoch is valid at rotate_epoch's own seq (inclusive)
  c.push(
    "history: new epoch at its rotate seq",
    history.environmentStateAt("env-prod-0001", 4)?.currentEpoch === 2,
  );
  c.push(
    "history: epoch stays current at head",
    history.environmentStateAt("env-prod-0001", HEAD_SEQ)?.currentEpoch === 2,
  );
}

function environmentCoverageChecks(c: Checks, history: ChainHistoryIndex): void {
  c.push(
    "history: dev environment created at seq 8",
    history.environmentStateAt("env-dev-0002", 8)?.currentEpoch === 1 &&
      history.environmentStateAt("env-dev-0002", 7) === undefined,
  );
  c.push(
    "history: dev epoch 2 from seq 10",
    history.environmentStateAt("env-dev-0002", 9)?.currentEpoch === 1 &&
      history.environmentStateAt("env-dev-0002", 10)?.currentEpoch === 2,
  );
  c.push(
    "history: stage stays epoch 1",
    history.environmentStateAt("env-stage-0003", HEAD_SEQ)?.currentEpoch === 1,
  );
  c.push(
    "history: unknown environment is undefined",
    history.environmentStateAt("env-ghost-9999", HEAD_SEQ) === undefined,
  );
}

function keyLookupChecks(c: Checks, history: ChainHistoryIndex): void {
  c.push(
    "history: sig key by fingerprint",
    history.sigKeyByFingerprint(OWNER, vectorKeys[OWNER]?.key_fingerprint_hex ?? "") ===
      vectorKeys[OWNER]?.sig_pub_hex,
  );
  c.push(
    "history: removed member's key stays resolvable",
    history.sigKeyByFingerprint(MEMBER, vectorKeys[MEMBER]?.key_fingerprint_hex ?? "") ===
      vectorKeys[MEMBER]?.sig_pub_hex,
  );
  c.push(
    "history: unknown fingerprint is undefined",
    history.sigKeyByFingerprint(OWNER, "00".repeat(16)) === undefined,
  );
  c.push(
    "history: unknown user is undefined",
    history.sigKeyByFingerprint("user-ghost-0042", vectorKeys[OWNER]?.key_fingerprint_hex ?? "") ===
      undefined,
  );
}

function tenureBoundaryChecks(c: Checks, extended: ChainHistoryIndex): void {
  const rejoined = valueVectors.tenure_extension.rejoined_member;
  const oldKeys = vectorKeys[MEMBER];
  // remove → re-add is a separate tenure: the old interval (seq 2-4) keeps
  // the old key, the new interval (seq 25-) binds the new key
  c.push(
    "history: tenure 1 keeps the original key",
    soleDeviceAt(extended, MEMBER, 4)?.keyFingerprintHex === oldKeys?.key_fingerprint_hex &&
      extended.memberStateAt(MEMBER, 4)?.tenureStartSeq === 2,
  );
  c.push(
    "history: tenure 2 binds the re-add key",
    soleDeviceAt(extended, MEMBER, EXTENSION_SEQ)?.keyFingerprintHex ===
      rejoined.key_fingerprint_hex &&
      extended.memberStateAt(MEMBER, EXTENSION_SEQ)?.tenureStartSeq === EXTENSION_SEQ,
  );
  c.push(
    "history: removal gap stays invalid between tenures",
    extended.memberStateAt(MEMBER, HEAD_SEQ) === undefined,
  );
}

/** An old-interval key x a new-interval head is not a valid device (crossing tenures — §6.3-1). */
function tenureDeviceChecks(c: Checks, extended: ChainHistoryIndex): void {
  const rejoined = valueVectors.tenure_extension.rejoined_member;
  const oldFp = vectorKeys[MEMBER]?.key_fingerprint_hex ?? "";
  c.push(
    "history: tenure 1 key is not a device in tenure 2",
    extended.deviceStateAt(MEMBER, oldFp, EXTENSION_SEQ) === undefined,
  );
  c.push(
    "history: tenure 2 key is a device at the re-add seq",
    extended.deviceStateAt(MEMBER, rejoined.key_fingerprint_hex, EXTENSION_SEQ) !== undefined,
  );
}

function tenureKeyLookupChecks(c: Checks, extended: ChainHistoryIndex): void {
  const rejoined = valueVectors.tenure_extension.rejoined_member;
  const oldKeys = vectorKeys[MEMBER];
  // The keys of both tenures of the same user_id resolve individually by FP
  // (dedupe must not erase tenure)
  c.push(
    "history: both tenures' keys resolvable by fingerprint",
    extended.sigKeyByFingerprint(MEMBER, oldKeys?.key_fingerprint_hex ?? "") ===
      oldKeys?.sig_pub_hex &&
      extended.sigKeyByFingerprint(MEMBER, rejoined.key_fingerprint_hex) === rejoined.sig_pub_hex,
  );
}

// ---------------------------------------------------------------------------
// Device keys (2026-09-19 DK — §6.2 "device validity interval" / §6.3
// "device-key selection and effective permission").
// Pinned against the derived chain device-ops (base 24, seq 25-37 —
// convention 28)

const ALL_MEMBER = "user-allmember-0013";
const OWNER_3 = "user-owner-0015";
const OWNER_2 = "user-owner-0014";

function deviceKey(label: string): { readonly fp: string; readonly sig: string } {
  const key = vectorKeys[label];
  if (key === undefined) {
    throw new Error(`device key ${label} missing`);
  }
  return { fp: key.key_fingerprint_hex, sig: key.sig_pub_hex };
}

function deviceIntervalChecks(c: Checks, history: ChainHistoryIndex): void {
  const cibox = deviceKey("user-allmember-0013@ci-box"); // added seq 27, revoked seq 37
  const first = deviceKey(ALL_MEMBER); // the first key (seq 16)
  c.push("history: device-ops head seq", history.headSeq === 37);
  // Valid at add_device's own seq (inclusive). Invalid just before
  c.push(
    "history: second device absent before its add_device seq",
    history.deviceStateAt(ALL_MEMBER, cibox.fp, 26) === undefined &&
      history.memberStateAt(ALL_MEMBER, 26)?.devices.size === 1,
  );
  const at27 = history.deviceStateAt(ALL_MEMBER, cibox.fp, 27);
  c.push(
    "history: second device valid at its add_device seq with its cap",
    at27?.device.roleCap === "member" &&
      at27.device.scope.kind === "listed" &&
      at27.device.addedSeq === 27 &&
      at27.tenureStartSeq === 16 &&
      history.memberStateAt(ALL_MEMBER, 27)?.devices.size === 2,
  );
  // Invalid at revoke_device's own seq (inclusive). The person stays a
  // member; the first key remains
  c.push(
    "history: second device valid just before its revoke seq",
    history.deviceStateAt(ALL_MEMBER, cibox.fp, 36) !== undefined,
  );
  c.push(
    "history: second device invalid at its revoke seq while the person stays",
    history.deviceStateAt(ALL_MEMBER, cibox.fp, 37) === undefined &&
      history.deviceStateAt(ALL_MEMBER, first.fp, 37) !== undefined &&
      history.memberStateAt(ALL_MEMBER, 37)?.devices.size === 1,
  );
  // A revoked device's key also resolves by FP (§6.3-1 key selection spans
  // all intervals — validity is deviceStateAt's job)
  c.push(
    "history: revoked device key stays resolvable by fingerprint",
    history.sigKeyByFingerprint(ALL_MEMBER, cibox.fp) === cibox.sig,
  );
  c.push(
    "history: device key is bound to its own user only",
    history.sigKeyByFingerprint(OWNER, cibox.fp) === undefined &&
      history.deviceStateAt(OWNER, cibox.fp, 30) === undefined,
  );
}

function effectivePermissionChecks(c: Checks, history: ChainHistoryIndex): void {
  const cibox = deviceKey("user-allmember-0013@ci-box");
  const readerCap = deviceKey("user-owner-0015@reader-cap"); // cap (reader, all) — seq 29
  const phone = deviceKey("user-owner-0001@phone"); // cap (owner, listed{}) — seq 26-34
  // (min(person role, role_cap), person scope ∩ device scope)
  const ciAt28 = history.deviceStateAt(ALL_MEMBER, cibox.fp, 28);
  c.push(
    "history: effective scope is the intersection with the device scope",
    ciAt28?.permission.role === "member" &&
      ciAt28.permission.scope.kind === "listed" &&
      ciAt28.permission.scope.environmentIds.join(",") === "env-dev-0002,env-stage-0003" &&
      history.memberStateAt(ALL_MEMBER, 28)?.scope.kind === "all",
  );
  const readerAt29 = history.deviceStateAt(OWNER_3, readerCap.fp, 29);
  c.push(
    "history: effective role is min(person role, role cap)",
    readerAt29?.permission.role === "reader" &&
      readerAt29.permission.scope.kind === "all" &&
      history.memberStateAt(OWNER_3, 29)?.role === "owner",
  );
  const phoneAt30 = history.deviceStateAt(OWNER, phone.fp, 30);
  c.push(
    "history: empty listed device scope yields an empty effective scope",
    phoneAt30?.permission.role === "owner" &&
      phoneAt30.permission.scope.kind === "listed" &&
      phoneAt30.permission.scope.environmentIds.length === 0,
  );
  // The first key's effective permission = the person's permission (cap
  // (owner, all) means uncapped)
  const firstOwner2 = deviceKey(OWNER_2);
  c.push(
    "history: first key carries the person's full permission",
    history.deviceStateAt(OWNER_2, firstOwner2.fp, 37)?.permission.role === "owner",
  );
}

const STAGE = "env-stage-0003";

function sameScope(a: MemberScope | undefined, b: MemberScope): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * The index agrees with the verified state at the head: every current
 * member's (role, scope), every active device's cap, each environment's
 * deletion seq, and the latest-checkpoint baselines (the invariant a
 * delete_environment's pruning must keep — §6.2).
 */
function agreesWithState(history: ChainHistoryIndex, state: ChainState): boolean {
  const head = history.headSeq;
  const members = [...state.members.values()].every((member) => {
    const atHead = history.memberStateAt(member.userId, head);
    return (
      atHead !== undefined &&
      atHead.role === member.role &&
      sameScope(atHead.scope, member.scope) &&
      [...member.devices.values()].every((device) =>
        sameScope(atHead.devices.get(device.keyFingerprintHex)?.scope, device.scope),
      )
    );
  });
  const environments = [...state.environments].every(
    ([environmentId, environment]) =>
      history.environmentStateAt(environmentId, head)?.deletedAtSeq === environment.deletedAtSeq &&
      (history.latestCheckpointFor(environmentId) === undefined) ===
        !state.checkpoints.has(environmentId),
  );
  return members && environments;
}

/** The listed ids of a scope (null for `all` or an absent scope). */
function listedIds(scope: MemberScope | undefined): readonly string[] | null {
  return scope?.kind === "listed" ? scope.environmentIds : null;
}

/** Verifies an extended chain (plus optional appended entries) with its history; throws on failure. */
async function verifiedExtended(
  name: string,
  appended: readonly ChainEntry[] = [],
): Promise<{ readonly history: ChainHistoryIndex; readonly state: ChainState }> {
  const extended = vectorExtendedChains[name];
  if (extended === undefined) {
    throw new Error(`extended chain ${name} missing`);
  }
  const result = await verifyChainWithHistory([
    ...typedEntries.slice(0, extended.base_seq),
    ...extended.entries.map((entry) => toTypedEntry(entry)),
    ...appended,
  ]);
  if (!result.ok) {
    throw new Error(`extended chain ${name} failed verification`);
  }
  return result.value;
}

/**
 * delete_environment as a change point (§6.2 — 2026-10-07) on a member
 * scope: on environment-deleted (canonical prefix up to 19, then
 * user-devadmin-0011 deletes env-stage-0003 at seq 20) the listed scope is
 * pruned from the deletion's own seq (inclusive), the earlier interval is
 * unchanged, and an `all` scope gets no new interval.
 */
async function memberPruneChecks(c: Checks): Promise<void> {
  const { history, state } = await verifiedExtended("environment-deleted");
  const before = listedIds(history.memberStateAt(DEV_MEMBER, 19)?.scope);
  const at = listedIds(history.memberStateAt(DEV_MEMBER, 20)?.scope);
  c.push(
    "history deletion: a listed scope holds the environment before the deletion seq",
    before?.includes(STAGE) === true,
  );
  c.push(
    "history deletion: a listed scope is pruned from the deletion seq (inclusive)",
    JSON.stringify(at) === JSON.stringify(before?.filter((id) => id !== STAGE)),
  );
  c.push(
    "history deletion: the role is kept across the pruning",
    history.memberStateAt(DEV_MEMBER, 20)?.role === history.memberStateAt(DEV_MEMBER, 19)?.role,
  );
  c.push(
    "history deletion: an `all` scope is not pruned",
    history.memberStateAt(OWNER, 20)?.scope.kind === "all",
  );
  c.push(
    "history deletion: the environment is deleted from the deletion seq on",
    history.environmentStateAt(STAGE, 19)?.deletedAtSeq === null &&
      history.environmentStateAt(STAGE, 20)?.deletedAtSeq === 20,
  );
  c.push(
    "history deletion: the index agrees with the state at the head",
    agreesWithState(history, state),
  );
}

/**
 * The same on a device cap: delete-environment-prunes-device-scope appends
 * admin-0003's deletion of env-stage-0003 (seq 30) onto device-added
 * (canonical 24 + seq 25-29), pruning CI box C's cap (member, listed{dev,
 * stage} — added at 27).
 */
async function devicePruneChecks(c: Checks): Promise<void> {
  const append = vectorValidAppends.find(
    (candidate) => candidate.name === "delete-environment-prunes-device-scope",
  );
  if (append === undefined) {
    c.push("history deletion: device-pruning vector present", false);
    return;
  }
  const { history, state } = await verifiedExtended("device-added", [toTypedEntry(append.entry)]);
  const cibox = deviceKey("user-allmember-0013@ci-box");
  const before = history.deviceStateAt(ALL_MEMBER, cibox.fp, 29);
  const at = history.deviceStateAt(ALL_MEMBER, cibox.fp, 30);
  c.push(
    "history deletion: a device cap holds the environment before the deletion seq",
    listedIds(before?.device.scope)?.includes(STAGE) === true,
  );
  c.push(
    "history deletion: a device cap and its effective scope are pruned from the deletion seq",
    listedIds(at?.device.scope)?.includes(STAGE) === false &&
      listedIds(at?.permission.scope)?.includes(STAGE) === false,
  );
  c.push(
    "history deletion: the device-pruning index agrees with the state at the head",
    agreesWithState(history, state),
  );
}

export async function chainHistoryChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  const history = await canonicalHistory();
  entryHashChecks(c, history);
  memberBoundaryChecks(c, history);
  memberDeviceChecks(c, history);
  roleChangeBoundaryChecks(c, history);
  scopeBoundaryChecks(c, history);
  proposalApplyBoundaryChecks(c, history);
  environmentCreateRotateChecks(c, history);
  environmentCoverageChecks(c, history);
  keyLookupChecks(c, history);
  const extended = await extendedHistory();
  c.push("history: extension head seq", extended.headSeq === EXTENSION_SEQ);
  c.push(
    "history: extension entry hash at the re-add seq",
    extended.entryHashAt(EXTENSION_SEQ) === valueVectors.tenure_extension.entry.entry_hash_hex,
  );
  tenureBoundaryChecks(c, extended);
  tenureDeviceChecks(c, extended);
  tenureKeyLookupChecks(c, extended);
  const deviceOps = await extendedVectorChainHistory("device-ops");
  deviceIntervalChecks(c, deviceOps);
  effectivePermissionChecks(c, deviceOps);
  await memberPruneChecks(c);
  await devicePruneChecks(c);
  return c.results;
}
