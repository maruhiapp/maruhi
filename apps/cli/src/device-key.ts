// 端末鍵(CRYPTO_SPEC §3 / §6.2 — 2026-09-19 DK)の CLI 側の解決(K4)。
//
// メンバーは端末鍵の**集合**を持つ(`ChainMember.devices`)。この端末が署名・開封に
// 使う鍵は「手元の鍵と一致する、その人の現在有効な端末」であり(設計録 dk-design.md
// §9 K4-16)、黙って「最初の端末」を選ばない。手元の鍵がチェーンに無ければ型付きの失敗で、
// このチェーンで失効していれば新しい鍵での足し直し(DK K13-5)、そうでなければ登録の経路
// (待機中の要求の承認か、ここに載っている端末の同期 — DK K10-5)を案内する。
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

/**
 * 手元の鍵がこのプロジェクトのチェーンに無く、失効もしていないときの文言(未登録)。
 * `device approve` が効くのは待機中の要求があるときだけ(登録済みの鍵は要求を作り直せない)。
 * 他のプロジェクトに載っている端末は、ここに載っている自分の端末の同期が足す(DK K10-5)。
 */
function deviceNotOnChainMessage(userId: string): string {
  return `The key on this machine is not one of your active device keys on this project's chain (member ${displayText(userId)}). This device has not been registered here yet. If \`maruhi device add\` is still waiting on this machine, approve it from a registered device with \`maruhi device approve\`. If this device is registered on other projects of yours, a device of yours that is registered here adds it when it runs a keyed command on this project at a terminal, if its cap covers this device's and it has synced a project that has it (\`maruhi device list\` shows where each device is registered)`;
}

/**
 * 手元の鍵がこのプロジェクトで失効しているときの文言(DK K13-5)。失効した鍵は戻らないので
 * 足し直しは新しい鍵(`reAddDeviceRoute`)。本体はこのプロジェクトのチェーンしか見えない
 * ので、他のプロジェクトに残っている場合の後始末は条件つきで言い、確認は `device list` に
 * 委ねる(`device list` は各プロジェクトの失効も示す — K13-6)。
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

/** 鍵の参照を、その人に束縛されたことのある鍵(`keyHistory` — 失効した鍵も残る)の FP に解決する。 */
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
    const sigPub = yield* Effect.tryPromise({
      try: () => exportSigningPublicKey(signingKeyPair.publicKey),
      catch: () => cliError("Failed to export the signing public key (crypto error)"),
    });
    return yield* ownDeviceOrFail(verified, member, { sigPubHex: encodeHex(sigPub) });
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

/**
 * The device's keys were the first key of `userId` in some tenure on this chain
 * (an applied genesis or `add_member` carrying them). Applied operations outlive
 * the tenure, so a key re-added with `add_device` after a re-invite still counts.
 * 台帳の鍵の判定(device-standing.ts — DK K14-1 1-f / K14-18)と、観測の記録の証人
 * (device-sync.ts — DK K15-12)が共有する 1 つの述語。
 */
export function wasFirstKeyOf(
  verified: VerifiedProject,
  userId: string,
  device: { readonly encPubHex: string; readonly sigPubHex: string },
): boolean {
  const carries = (keys: { readonly encPubHex: string; readonly sigPubHex: string }) =>
    keys.encPubHex === device.encPubHex && keys.sigPubHex === device.sigPubHex;
  return verified.applied.some(({ operation, actorUserId }) => {
    if (operation.op === "genesis") {
      return actorUserId === userId && carries(operation.payload);
    }
    return (
      operation.op === "add_member" &&
      operation.payload.targetUserId === userId &&
      carries(operation.payload)
    );
  });
}

/**
 * The fingerprints revoked for `userId` on this verified chain (the union of
 * applied `revoke_device` entries). 記録からの登録の候補を除く述語(`device-sync.ts`)と、
 * `device add` が「このプロジェクトでは失効した」と言う述語(DK K12-6)が共有する。
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
 * 失効した端末を足し直す手順(DK K12-7 — CLI の写しの字面はここだけで作る)。失効した鍵は
 * 同じ鍵のまま戻らない(記録からの登録は失効を除き、`device add` はその鍵で要求を作れない)
 * ので、足し直しは常に新しい鍵になる。
 */
export function reAddDeviceRoute(machine: string): string {
  return `run \`maruhi device add --replace\` on ${machine} (a revoked key is never registered again, so it generates a new key) and approve the fingerprint it prints from a registered device`;
}
