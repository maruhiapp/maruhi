// 端末鍵(CRYPTO_SPEC §3 / §6.2 — 2026-09-19 DK)の CLI 側の解決(K4)。
//
// メンバーは端末鍵の**集合**を持つ(`ChainMember.devices`)。この端末が署名・開封に
// 使う鍵は「手元の鍵と一致する、その人の現在有効な端末」であり(設計録 dk-design.md
// §9 K4-16)、黙って「最初の端末」を選ばない。手元の鍵がチェーンに無い(未登録・
// 失効済み)なら型付きの失敗で `device approve` の再実行を案内する。
//
// 相手の鍵が要る経路(バックフィル先・保護者の分片・発行署名の検証)は端末集合を
// **すべて**回す(呼び出し側)。単調性(原則 D2)の通信前判定は crypto の公開 API
// (role の順序は `ROLE_RANK`、scope の包含は `scopeContains`)から導出し、内部実装
// (`capWithinCap`)をコピーしない(ES K4-I と同じ規律)。

import type { ChainDevice, ChainMember, DeviceCap, SigningKeyPair } from "@maruhi/crypto";
import { encodeHex, exportSigningPublicKey } from "@maruhi/crypto";
import { Effect } from "effect";

import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { describeScope, scopeContains } from "./scope.ts";
import type { VerifiedProject } from "./sync.ts";

/** role の順序(CRYPTO_SPEC §6.2)。`satisfies` で Role の増減を型検査に見せる。 */
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

/** 手元の鍵がこのプロジェクトのチェーンに無いときの文言(未登録 / 失効済みの両方)。 */
function deviceNotOnChainMessage(userId: string): string {
  return `The key on this machine is not one of your active device keys on this project's chain (member ${displayText(userId)}). Either this device has not been registered here yet, or it was revoked. From a device that is registered, run \`maruhi device approve\` for this machine (or \`maruhi device list\` to see the registered devices)`;
}

/**
 * The member's active device holding the caller's key, or a typed failure
 * pointing at `maruhi device approve` (K4-16 — never "the first device").
 */
export function ownDeviceOrFail(
  member: ChainMember,
  ref: OwnKeyRef,
): Effect.Effect<ChainDevice, CliError> {
  const device = findOwnDevice(member, ref);
  return device === undefined
    ? Effect.fail(cliError(deviceNotOnChainMessage(member.userId)))
    : Effect.succeed(device);
}

/**
 * Resolves the signing device from the signing keypair itself (the device whose
 * sig public key is the keypair's public key), so chain-signing paths need no
 * extra fingerprint parameter.
 */
export function ownDeviceBySigningKey(
  member: ChainMember,
  signingKeyPair: SigningKeyPair,
): Effect.Effect<ChainDevice, CliError> {
  return Effect.gen(function* () {
    const sigPub = yield* Effect.tryPromise({
      try: () => exportSigningPublicKey(signingKeyPair.publicKey),
      catch: () => cliError("Failed to export the signing public key (crypto error)"),
    });
    return yield* ownDeviceOrFail(member, { sigPubHex: encodeHex(sigPub) });
  });
}

/** Whether one of the member's current device keys is exactly (enc, sig). */
export function memberHasKeys(member: ChainMember, encPubHex: string, sigPubHex: string): boolean {
  return [...member.devices.values()].some(
    (device) => device.encPubHex === encPubHex && device.sigPubHex === sigPubHex,
  );
}

/** memberHasKeys の端末版: (enc, sig) が一致する在籍端末(実効権限の導出用)。 */
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
 * Monotonicity (原則 D2 — CRYPTO_SPEC §6.2 `add_device`): the candidate's cap must
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

/** Where a device key came from on a verified chain (`add_device` の actor と seq — K4-4 の出所)。 */
export interface DeviceProvenance {
  readonly seq: number;
  /** The device that signed the `add_device` (null = the member's first key: genesis / add_member). */
  readonly addedByFingerprintHex: string | null;
  readonly addedByUserId: string;
  /** Whether the adding device is still active for that user at the head (K4-4 反例 2). */
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
