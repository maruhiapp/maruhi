// 端末鍵(CRYPTO_SPEC §6.2 — 2026-09-19 DK)の CLI 側の橋渡し(K2)。
//
// メンバーは端末鍵の集合を持つ(`ChainMember.devices`)が、この段の CLI は端末を
// 1 つとして扱う(`add_device` / `revoke_device` を生成しない — 設計録 dk-design.md §3
// K2 → K4)。「メンバーの鍵」が要る箇所は本モジュールの fail-closed な補助関数を通し、
// 端末が 0 / 2 つ以上のメンバー(K3 以降のサーバーから届きうる)を黙って「最初の端末」に
// 倒さない。K4(`device` グループ・R(E) の端末展開)で置き換える。

import { type ChainDevice, type ChainMember, soleDeviceOf } from "@maruhi/crypto";
import { Effect } from "effect";

import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";

/**
 * The member's only device key, or a typed failure when the chain lists zero or
 * several devices for them (this release wraps / signs for one device per member).
 */
export function soleDeviceOrFail(member: ChainMember): Effect.Effect<ChainDevice, CliError> {
  const device = soleDeviceOf(member);
  return device === undefined
    ? Effect.fail(
        cliError(
          `Member ${displayText(member.userId)} holds ${member.devices.size} device keys on the chain, and this maruhi release handles exactly one device per member. Update maruhi to a release with device support`,
        ),
      )
    : Effect.succeed(device);
}

/** Whether one of the member's current device keys is exactly (enc, sig). */
export function memberHasKeys(member: ChainMember, encPubHex: string, sigPubHex: string): boolean {
  return [...member.devices.values()].some(
    (device) => device.encPubHex === encPubHex && device.sigPubHex === sigPubHex,
  );
}

/** The member's device fingerprints (lowercase hex, ascending). */
export function deviceFingerprintsOf(member: ChainMember): readonly string[] {
  return [...member.devices.keys()].toSorted();
}
