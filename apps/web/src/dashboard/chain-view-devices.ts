// See chain-view.ts for the display-only contract.

import {
  isStringArray,
  newDevice,
  readableScope,
  unboundDevicesOf,
  type EntryOf,
  type FoldState,
  type MutableDevice,
  type MutableMember,
} from "./chain-view-state.ts";

// ---------------------------------------------------------------------------
// The 2 device ops (K5-1 / K5-4): transcribe only the structural rules
// the fold's consistency needs; unreadable rows are ignored
// ---------------------------------------------------------------------------

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
export function applyAddDevice(state: FoldState, entry: EntryOf<"add_device">): void {
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
export function applyRevokeDevice(state: FoldState, entry: EntryOf<"revoke_device">): void {
  const readable = readableRevocation(state, entry.payload);
  if (readable === undefined) {
    state.unreadableEntries += 1;
    return;
  }
  const { member, plan } = readable;
  revokeMatched(member, plan);
  if (plan.unmatched > 0) revokeUnbound(member, plan);
}
