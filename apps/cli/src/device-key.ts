import { cryptoPromise, type KeyFingerprintHex, type UserId } from "@maruhi/core";
import type {
  ChainDevice,
  ChainMember,
  ChainState,
  DeviceCap,
  SigningKeyPair,
} from "@maruhi/crypto";
import { encodeHex, exportSigningPublicKey } from "@maruhi/crypto";
import { Effect } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { describeScope, scopeContains } from "./scope.ts";

const ROLE_RANK = { reader: 0, member: 1, admin: 2, owner: 3 } as const;

export type OwnKeyRef =
  | { readonly keyFingerprintHex: string }
  | { readonly encPubHex: string }
  | { readonly sigPubHex: string };

export function findOwnDevice(member: ChainMember, ref: OwnKeyRef): ChainDevice | undefined {
  if ("keyFingerprintHex" in ref) {
    return member.devices.get(ref.keyFingerprintHex);
  }
  for (const device of member.devices.values()) {
    if (
      "encPubHex" in ref ? device.encPubHex === ref.encPubHex : device.sigPubHex === ref.sigPubHex
    ) {
      return device;
    }
  }
  return undefined;
}

function deviceNotOnChainMessage(userId: UserId): string {
  return `The key on this machine is not one of your active device keys on this project's chain (member ${displayText(userId)}). This device has not been registered here yet. If \`maruhi device add\` is still waiting on this machine, approve it from a registered device with \`maruhi device approve\`. If this device is registered on other projects of yours, a device of yours that is registered here adds it when it runs a keyed command on this project at a terminal, if its cap covers this device's and it has synced a project that has it (\`maruhi device list\` shows where each device is registered)`;
}

function deviceRevokedMessage(userId: UserId, fingerprintHex: string): string {
  return `The key on this machine (${fingerprintHex}) was revoked on this project's chain (member ${displayText(userId)}), and a revoked key is never registered again. To use this machine here again, ${reAddDeviceRoute("this machine")}. If this key is still registered on other projects of yours, revoke it there once the new key is approved (\`maruhi device list\` shows where it is still registered)`;
}

export function ownDeviceOrFail(
  verified: VerifiedProject,
  member: ChainMember,
  ref: OwnKeyRef,
): Effect.Effect<ChainDevice, CliError> {
  const device = findOwnDevice(member, ref);
  if (device !== undefined) {
    return Effect.succeed(device);
  }
  const fingerprintHex = historicalFingerprintOf(verified, member.userId, ref);
  return Effect.fail(
    cliError(
      fingerprintHex !== undefined &&
        revokedFingerprintsOf(verified, member.userId).has(fingerprintHex)
        ? deviceRevokedMessage(member.userId, fingerprintHex)
        : deviceNotOnChainMessage(member.userId),
    ),
  );
}

function historicalFingerprintOf(
  verified: VerifiedProject,
  userId: UserId,
  ref: OwnKeyRef,
): string | undefined {
  if ("keyFingerprintHex" in ref) {
    return ref.keyFingerprintHex;
  }
  return (verified.keyHistory.get(userId) ?? []).find((binding) =>
    "encPubHex" in ref ? binding.encPubHex === ref.encPubHex : binding.sigPubHex === ref.sigPubHex,
  )?.keyFingerprintHex;
}

export const ownDeviceBySigningKey = Effect.fn("device-key.ownDeviceBySigningKey")(function* (
  verified: VerifiedProject,
  member: ChainMember,
  signingKeyPair: SigningKeyPair,
): Effect.fn.Return<ChainDevice, CliError> {
  const sigPub = yield* cryptoPromise("exportSigningPublicKey", () =>
    exportSigningPublicKey(signingKeyPair.publicKey),
  ).pipe(Effect.mapError(() => cliError("Failed to export the signing public key (crypto error)")));
  return yield* ownDeviceOrFail(verified, member, { sigPubHex: encodeHex(sigPub) });
});

export function memberHasKeys(member: ChainMember, encPubHex: string, sigPubHex: string): boolean {
  return [...member.devices.values()].some(
    (device) => device.encPubHex === encPubHex && device.sigPubHex === sigPubHex,
  );
}

export function ownDeviceByKeys(
  member: ChainMember,
  encPubHex: string,
  sigPubHex: string,
): ChainDevice | undefined {
  return [...member.devices.values()].find(
    (device) => device.encPubHex === encPubHex && device.sigPubHex === sigPubHex,
  );
}

export type RegisteredKeyHolder =
  | { readonly kind: "device"; readonly userId: UserId }
  | { readonly kind: "grant"; readonly serverKeyFingerprintHex: KeyFingerprintHex };

export function registeredKeyHolderOf(
  state: Pick<ChainState, "members" | "namedServerKeys">,
  keys: { readonly encPubHex: string; readonly sigPubHex: string },
): RegisteredKeyHolder | null {
  for (const member of state.members.values()) {
    for (const device of member.devices.values()) {
      if (device.encPubHex === keys.encPubHex || device.sigPubHex === keys.sigPubHex) {
        return { kind: "device", userId: member.userId };
      }
    }
  }
  const serverKeyFingerprintHex = state.namedServerKeys.get(keys.encPubHex);
  return serverKeyFingerprintHex === undefined ? null : { kind: "grant", serverKeyFingerprintHex };
}

export function devicesOf(member: ChainMember): readonly ChainDevice[] {
  return [...member.devices.values()].toSorted((a, b) =>
    a.keyFingerprintHex < b.keyFingerprintHex
      ? -1
      : a.keyFingerprintHex > b.keyFingerprintHex
        ? 1
        : 0,
  );
}

export function capWithinSignerCap(candidate: DeviceCap, signer: DeviceCap): boolean {
  return (
    ROLE_RANK[candidate.roleCap] <= ROLE_RANK[signer.roleCap] &&
    scopeContains(signer.scope, candidate.scope)
  );
}

export function describeCap(cap: DeviceCap): string {
  return `${cap.roleCap}/${cap.scope.kind === "all" ? "all" : describeScope(cap.scope)}`;
}

export function describeDevice(device: ChainDevice): string {
  const bounded = device.roleCap !== "owner" || device.scope.kind !== "all";
  return bounded ? `${device.keyFingerprintHex}(${describeCap(device)})` : device.keyFingerprintHex;
}

export interface DeviceProvenance {
  readonly seq: number;
  readonly addedByFingerprintHex: string | null;
  readonly addedByUserId: UserId;
  readonly adderStillActive: boolean;
}

export function deviceProvenanceOf(
  verified: VerifiedProject,
  userId: UserId,
  device: ChainDevice,
): DeviceProvenance {
  const entry = verified.entries.find((candidate) => candidate.seq === device.addedSeq);
  if (entry !== undefined && entry.op === "add_device") {
    const adder = entry.actor;
    const adderMember = verified.state.members.get(adder.userId);
    return {
      seq: device.addedSeq,
      addedByFingerprintHex: adder.keyFingerprintHex,
      addedByUserId: adder.userId,
      adderStillActive: adderMember?.devices.has(adder.keyFingerprintHex) === true,
    };
  }
  return {
    seq: device.addedSeq,
    addedByFingerprintHex: null,
    addedByUserId: entry?.actor.userId ?? userId,
    adderStillActive: true,
  };
}

export function revokedFingerprintsOf(
  verified: VerifiedProject,
  userId: UserId,
): ReadonlySet<string> {
  const revoked = new Set<string>();
  for (const applied of verified.applied) {
    if (
      applied.operation.op === "revoke_device" &&
      applied.operation.payload.targetUserId === userId
    ) {
      for (const fp of applied.operation.payload.deviceFingerprintsHex) {
        revoked.add(fp);
      }
    }
  }
  return revoked;
}

export function reAddDeviceRoute(machine: string): string {
  return `run \`maruhi device add --replace\` on ${machine} (a revoked key is never registered again, so it generates a new key) and approve the fingerprint it prints from a registered device`;
}
