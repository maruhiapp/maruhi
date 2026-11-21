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

function readableAddDevice(payload: EntryOf<"add_device">["payload"]): boolean {
  const keysReadable = [payload.encPubHex, payload.sigPubHex, payload.roleCap].every(
    (field) => typeof field === "string",
  );
  return keysReadable && readableScope(payload);
}

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

function resolveStaleHolder(holder: { member: MutableMember; device: MutableDevice }): boolean {
  const { member, device } = holder;
  if (device.keyFingerprintHex !== null || member.unresolvedRevocations === 0) return false;
  member.devices = member.devices.filter((d) => d !== device);
  member.unresolvedRevocations -= 1;
  return true;
}

function keyAvailable(state: FoldState, encPubHex: string, sigPubHex: string): boolean {
  const holder = currentKeyHolder(state, encPubHex, sigPubHex);
  return holder === undefined || resolveStaleHolder(holder);
}

function pushDevice(member: MutableMember, device: MutableDevice): void {
  member.devices.push(device);
}

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

function readableRevokeDevice(payload: EntryOf<"revoke_device">["payload"]): boolean {
  const fps = payload.deviceFingerprintsHex;
  return (
    typeof payload.targetUserId === "string" &&
    isStringArray(fps) &&
    fps.length > 0 &&
    new Set(fps).size === fps.length
  );
}

interface RevocationPlan {
  matched: Set<MutableDevice>;
  unmatched: number;
  unboundRemaining: number;
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

function revokeMatched(member: MutableMember, plan: RevocationPlan): void {
  member.devices = member.devices.filter((d) => !plan.matched.has(d));
}

function revokeUnbound(member: MutableMember, plan: RevocationPlan): void {
  member.unboundSignerFps.clear();
  if (plan.unmatched === plan.unboundRemaining) {
    member.devices = member.devices.filter((d) => d.keyFingerprintHex !== null);
    member.unresolvedRevocations = 0;
  } else {
    member.unresolvedRevocations += plan.unmatched;
  }
}

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
