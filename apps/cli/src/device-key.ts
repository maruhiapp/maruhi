// CLI-side resolution of device keys (CRYPTO_SPEC §3 / §6.2 —
// 2026-09-19 DK) (K4).
//
// A member holds a **set** of device keys (`ChainMember.devices`). The
// key this device uses for signing and unwrapping is "that person's
// currently valid device matching the key at hand" (design record
// dk-design.md §9 K4-16) — it does not silently pick "the first
// device". If the key at hand is not on the chain it is a typed
// failure: if revoked on this chain, re-add with a new key (DK K13-5);
// otherwise guide the registration path (approve a pending request, or
// sync from a device listed here — DK K10-5).
//
// Paths that need the other side's key (backfill targets, guardian
// segments, verifying issuance signatures) iterate **all** of the
// device set (the callers). The pre-flight judgment of monotonicity
// (principle D2) is derived from crypto's public API (role order via
// `ROLE_RANK`, scope inclusion via `scopeContains`) without copying
// the internal implementation (`capWithinCap`) (the same discipline as
// ES K4-I).

import { cryptoPromise } from "@maruhi/core";
import type { ChainDevice, ChainMember, DeviceCap, SigningKeyPair } from "@maruhi/crypto";
import { encodeHex, exportSigningPublicKey } from "@maruhi/crypto";
import { Effect } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { describeScope, scopeContains } from "./scope.ts";

/** Order of roles (CRYPTO_SPEC §6.2). `satisfies` exposes changes to Role to the type checker. */
const ROLE_RANK = { reader: 0, member: 1, admin: 2, owner: 3 } as const;

/** How the caller names its own key: by fingerprint, enc public key, or sig public key. */
export type OwnKeyRef =
  | { readonly keyFingerprintHex: string }
  | { readonly encPubHex: string }
  | { readonly sigPubHex: string };

/** The member's active device that matches the caller's key, or undefined. */
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

/**
 * Wording for when the key at hand is not on this project's chain and
 * not revoked (unregistered). `device approve` works only when a
 * pending request exists (a registered key cannot recreate the
 * request). A device listed on another project is added by syncing my
 * device listed here (DK K10-5).
 */
function deviceNotOnChainMessage(userId: string): string {
  return `The key on this machine is not one of your active device keys on this project's chain (member ${displayText(userId)}). This device has not been registered here yet. If \`maruhi device add\` is still waiting on this machine, approve it from a registered device with \`maruhi device approve\`. If this device is registered on other projects of yours, a device of yours that is registered here adds it when it runs a keyed command on this project at a terminal, if its cap covers this device's and it has synced a project that has it (\`maruhi device list\` shows where each device is registered)`;
}

/**
 * Wording for when the key at hand is revoked on this project (DK
 * K13-5). A revoked key never comes back, so re-adding uses a new key
 * (`reAddDeviceRoute`). The body can only see this project's chain, so
 * cleanup when the key remains on other projects is stated
 * conditionally and checking is left to `device list` (`device list`
 * also shows revocation in each project — K13-6).
 */
function deviceRevokedMessage(userId: string, fingerprintHex: string): string {
  return `The key on this machine (${fingerprintHex}) was revoked on this project's chain (member ${displayText(userId)}), and a revoked key is never registered again. To use this machine here again, ${reAddDeviceRoute("this machine")}. If this key is still registered on other projects of yours, revoke it there once the new key is approved (\`maruhi device list\` shows where it is still registered)`;
}

/**
 * The member's active device holding the caller's key, or a typed failure:
 * revoked on this chain → the re-add route (a new key); otherwise the
 * registration routes (K4-16 — never "the first device"; DK K13-5). The
 * verified chain resolves the caller's key to a fingerprint through the key
 * history, so a revoked key (no longer in `member.devices`) is recognised.
 */
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

/** Resolves a key reference to the FP of a key ever bound to that person (`keyHistory` — revoked keys also remain). */
function historicalFingerprintOf(
  verified: VerifiedProject,
  userId: string,
  ref: OwnKeyRef,
): string | undefined {
  if ("keyFingerprintHex" in ref) {
    return ref.keyFingerprintHex;
  }
  return (verified.keyHistory.get(userId) ?? []).find((binding) =>
    "encPubHex" in ref ? binding.encPubHex === ref.encPubHex : binding.sigPubHex === ref.sigPubHex,
  )?.keyFingerprintHex;
}

/**
 * Resolves the signing device from the signing keypair itself (the device whose
 * sig public key is the keypair's public key), so chain-signing paths need no
 * extra fingerprint parameter.
 */
export function ownDeviceBySigningKey(
  verified: VerifiedProject,
  member: ChainMember,
  signingKeyPair: SigningKeyPair,
): Effect.Effect<ChainDevice, CliError> {
  return Effect.gen(function* () {
    const sigPub = yield* cryptoPromise("exportSigningPublicKey", () =>
      exportSigningPublicKey(signingKeyPair.publicKey),
    ).pipe(
      Effect.mapError(() => cliError("Failed to export the signing public key (crypto error)")),
    );
    return yield* ownDeviceOrFail(verified, member, { sigPubHex: encodeHex(sigPub) });
  });
}

/** Whether one of the member's current device keys is exactly (enc, sig). */
export function memberHasKeys(member: ChainMember, encPubHex: string, sigPubHex: string): boolean {
  return [...member.devices.values()].some(
    (device) => device.encPubHex === encPubHex && device.sigPubHex === sigPubHex,
  );
}

/** The device version of memberHasKeys: the enrolled device whose (enc, sig) match (for deriving effective permission). */
export function ownDeviceByKeys(
  member: ChainMember,
  encPubHex: string,
  sigPubHex: string,
): ChainDevice | undefined {
  return [...member.devices.values()].find(
    (device) => device.encPubHex === encPubHex && device.sigPubHex === sigPubHex,
  );
}

/** The member's devices in fingerprint order (deterministic recipient / display order). */
export function devicesOf(member: ChainMember): readonly ChainDevice[] {
  return [...member.devices.values()].toSorted((a, b) =>
    a.keyFingerprintHex < b.keyFingerprintHex
      ? -1
      : a.keyFingerprintHex > b.keyFingerprintHex
        ? 1
        : 0,
  );
}

/**
 * Monotonicity (principle D2 — CRYPTO_SPEC §6.2 `add_device`): the candidate's cap must
 * not exceed the signing device's **own** cap — compared cap to cap, never
 * against the person's effective permission. Derived from the public API
 * (`scopeContains` mirrors the §6.2 containment algebra).
 */
export function capWithinSignerCap(candidate: DeviceCap, signer: DeviceCap): boolean {
  return (
    ROLE_RANK[candidate.roleCap] <= ROLE_RANK[signer.roleCap] &&
    scopeContains(signer.scope, candidate.scope)
  );
}

/** Human form of a device cap: `owner/all` is the unbounded cap. */
export function describeCap(cap: DeviceCap): string {
  return `${cap.roleCap}/${cap.scope.kind === "all" ? "all" : describeScope(cap.scope)}`;
}

/** `fp` or `fp(cap)` — the cap is shown only when it bounds the device. */
export function describeDevice(device: ChainDevice): string {
  const bounded = device.roleCap !== "owner" || device.scope.kind !== "all";
  return bounded ? `${device.keyFingerprintHex}(${describeCap(device)})` : device.keyFingerprintHex;
}

/** Where a device key came from on a verified chain (the `add_device` actor and seq — the provenance of K4-4). */
export interface DeviceProvenance {
  readonly seq: number;
  /** The device that signed the `add_device` (null = the member's first key: genesis / add_member). */
  readonly addedByFingerprintHex: string | null;
  readonly addedByUserId: string;
  /** Whether the adding device is still active for that user at the head (K4-4 counterexample 2). */
  readonly adderStillActive: boolean;
}

/**
 * The provenance of one of `userId`'s devices from the verified entry list (the
 * `add_device` that put the key on the chain, or the tenure-starting entry).
 */
export function deviceProvenanceOf(
  verified: VerifiedProject,
  userId: string,
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

/**
 * The fingerprints revoked for `userId` on this verified chain (the union of
 * applied `revoke_device` entries). One predicate shared by the
 * candidates-exclusion of registration from the record
 * (`device-sync.ts`) and by `device add` saying "revoked on this
 * project" (DK K12-6).
 */
export function revokedFingerprintsOf(
  verified: VerifiedProject,
  userId: string,
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

/**
 * The procedure for re-adding a revoked device (DK K12-7 — the wording
 * of the CLI's copy is produced only here). A revoked key never comes
 * back as the same key (registration from the record excludes revoked
 * keys, and `device add` cannot make a request with that key), so
 * re-adding always uses a new key.
 */
export function reAddDeviceRoute(machine: string): string {
  return `run \`maruhi device add --replace\` on ${machine} (a revoked key is never registered again, so it generates a new key) and approve the fingerprint it prints from a registered device`;
}
