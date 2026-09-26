// 端末 op(`add_device` / `revoke_device` — CRYPTO_SPEC §6.2、2026-09-19 DK)の署名・追記
// (親ヘッド CAS)と、端末追加のバックフィル(§7)・端末失効の sweep(§7)の共有核(K4)。
// 使い手: device.ts(`device approve` / `revoke`)、device-sync.ts(初回同期の登録)、
// key-recover.ts(復元後の新端末鍵の登録・予備鍵の rotate)。
//
// 通信前検査は合意規則(§6.2)の写しで、サーバーの 422 を待たない: actor は署名鍵と
// 一致する現端末(device-key.ts)、鍵の一意性は現メンバーの全端末、`listed` の環境の
// 存在、単調性(cap 同士 — 原則 D2)、失効は対象の現端末・最後の端末の保護・他人なら
// role 規則(`remove_member` と同じ 2 段)と原則 1 の包含(**人**の scope)。
//
// バックフィル(§7「端末追加のバックフィル」): 新端末の**実効 scope**(人 ∩ 端末)の各
// 環境について全エポックの DEK を、自分宛ラップから開いて新端末の enc 公開鍵へ包み
// 直す(backfill.ts の共有核 — 409 は登録済み扱い)。

import { ChainHeadConflictError } from "@maruhi/api-schema";
import type {
  ChainDevice,
  ChainEntry,
  ChainMember,
  DeviceCap,
  MemberScope,
  SigningKeyPair,
} from "@maruhi/crypto";
import {
  effectivePermissionOf,
  scopeIncludesEnvironment,
  scopePayloadFieldsOf,
  signChainEntry,
  SUITE_ID,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { backfillEachEnvironment, backfillEnvironmentFor } from "./backfill.ts";
import { appendEntry } from "./chain-append.ts";
import { ROLE_RANK } from "./dek-wrap.ts";
import type { DekRecipient } from "./deks.ts";
import { capWithinSignerCap, describeCap, ownDeviceBySigningKey } from "./device-key.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { retryOnConflict } from "./retry.ts";
import {
  baselinesOf,
  partitionSweepBaselines,
  type RotationMandate,
  rotationMandates,
  type SweepOutcome,
  type SweepRotate,
  sweepRotations,
  verifiedDeletedEnvironmentSet,
} from "./rotation-sweep.ts";
import { compareCodePoints, requireScopeEnvironmentsExist, scopeContains } from "./scope.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";

const MAX_ATTEMPTS = 5;

/** A device key to register (public side + declared cap). */
export interface DeviceCandidate {
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly cap: DeviceCap;
}

/** The signer of a device op: the person and the signing keypair of one of their devices. */
export interface DeviceOpSigner {
  readonly userId: string;
  readonly signingKeyPair: SigningKeyPair;
}

/** CAS 追記の共有足場(member.ts の appendWithCas と同型 — 端末 op 用)。 */
function appendWithCas(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly opLabel: string;
  readonly signEntry: (verified: VerifiedProject) => Effect.Effect<ChainEntry | null, CliError>;
}): Effect.Effect<{ readonly verified: VerifiedProject; readonly appended: boolean }, CliError> {
  return retryOnConflict<
    VerifiedProject,
    { readonly verified: VerifiedProject; readonly appended: boolean },
    "head-conflict"
  >(input.verified, {
    maxAttempts: MAX_ATTEMPTS,
    attempt: (view) =>
      Effect.gen(function* () {
        // null = 既に目的の状態(並行実行が先に積んだ)— 追記せず継続
        const entry = yield* input.signEntry(view);
        if (entry === null) {
          return { verified: view, appended: false };
        }
        yield* appendEntry(input.client, view, entry);
        return { verified: view, appended: true };
      }),
    classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
    recover: (view) => resyncExtended(input.resync, view),
    exhaustedMessage: `${input.opLabel}'s chain-head conflict did not resolve (${MAX_ATTEMPTS} attempts). Wait a moment and re-run`,
  });
}

/** 鍵の一意性(§6.2 — 現メンバーの全端末の同種公開鍵と重複しない)の通信前判定。 */
function duplicateKeyRejection(
  verified: VerifiedProject,
  candidate: DeviceCandidate,
): string | null {
  for (const member of verified.state.members.values()) {
    for (const device of member.devices.values()) {
      if (device.encPubHex === candidate.encPubHex || device.sigPubHex === candidate.sigPubHex) {
        return `The key is already registered as a device of ${displayText(member.userId)} (consensus rule duplicate-member-key — CRYPTO_SPEC §6.2)`;
      }
    }
  }
  return null;
}

/** `add_device` の通信前検査 → 署名(既に登録済みなら null)。 */
function signAddDevice(input: {
  readonly verified: VerifiedProject;
  readonly signer: DeviceOpSigner;
  readonly candidate: DeviceCandidate;
}): Effect.Effect<ChainEntry | null, CliError> {
  return Effect.gen(function* () {
    const member = input.verified.state.members.get(input.signer.userId);
    if (member === undefined) {
      return yield* Effect.fail(cliError("You are not a chain-derived member of this project"));
    }
    const already = [...member.devices.values()].some(
      (device) =>
        device.encPubHex === input.candidate.encPubHex &&
        device.sigPubHex === input.candidate.sigPubHex,
    );
    if (already) {
      return null;
    }
    const actorDevice = yield* ownDeviceBySigningKey(
      input.verified,
      member,
      input.signer.signingKeyPair,
    );
    const duplicate = duplicateKeyRejection(input.verified, input.candidate);
    if (duplicate !== null) {
      return yield* Effect.fail(cliError(duplicate));
    }
    yield* requireScopeEnvironmentsExist(input.verified, input.candidate.cap.scope);
    if (!capWithinSignerCap(input.candidate.cap, actorDevice)) {
      return yield* Effect.fail(
        cliError(
          `The device's cap (${describeCap(input.candidate.cap)}) exceeds the cap of the device signing this registration (${describeCap(actorDevice)}) — consensus rule device-cap-exceeded (CRYPTO_SPEC §6.2 principle D2). Register it from a device with a wider cap`,
        ),
      );
    }
    const signed = yield* Effect.tryPromise({
      try: () =>
        signChainEntry({
          entry: {
            suite: SUITE_ID,
            seq: input.verified.state.headSeq + 1,
            prevHashHex: input.verified.state.headHashHex,
            op: "add_device",
            actor: { userId: member.userId, keyFingerprintHex: actorDevice.keyFingerprintHex },
            payload: {
              encPubHex: input.candidate.encPubHex,
              sigPubHex: input.candidate.sigPubHex,
              roleCap: input.candidate.cap.roleCap,
              ...scopePayloadFieldsOf(input.candidate.cap.scope),
            },
            timestampMs: Date.now(),
          },
          signingKey: input.signer.signingKeyPair.privateKey,
        }),
      catch: () => cliError("Failed to sign the add_device entry"),
    });
    if (!signed.ok) {
      return yield* Effect.fail(cliError("Failed to sign the add_device entry"));
    }
    return signed.value;
  });
}

/**
 * Appends `add_device` for `candidate` (signed by `signer`'s device that holds
 * `signingKeyPair`), with CAS retries. Idempotent: an already-registered key
 * appends nothing.
 */
export function appendAddDevice(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly signer: DeviceOpSigner;
  readonly candidate: DeviceCandidate;
}): Effect.Effect<{ readonly verified: VerifiedProject; readonly appended: boolean }, CliError> {
  return appendWithCas({
    client: input.client,
    verified: input.verified,
    resync: input.resync,
    opLabel: "add_device",
    signEntry: (view) =>
      signAddDevice({ verified: view, signer: input.signer, candidate: input.candidate }),
  });
}

/** 他人の端末の失効の role 規則(`remove_member` と同じ 2 段 — K2 申し送り 4 の厳しい読み)。 */
function revokeRoleRejection(
  actorRole: ChainMember["role"],
  actorScope: MemberScope,
  target: ChainMember,
): string | null {
  if (ROLE_RANK[actorRole] < ROLE_RANK.admin) {
    return `Only an admin or owner can revoke another member's device (your effective role on this device: ${actorRole} — CRYPTO_SPEC §6.2)`;
  }
  if (ROLE_RANK[target.role] >= ROLE_RANK.admin && actorRole !== "owner") {
    return `Only an owner can revoke a device of an ${target.role} (CRYPTO_SPEC §6.2)`;
  }
  if (!scopeContains(actorScope, target.scope)) {
    return `The target's environment scope is not contained in this device's effective scope, so you could not fulfil the rotation mandate (consensus rule scope-not-contained — CRYPTO_SPEC §6.2 principle 1)`;
  }
  return null;
}

/** 通信前検査(他人なら role 規則、誰でも last-device-protected)。ok なら null。 */
function revokeRejection(input: {
  readonly actor: ChainMember;
  readonly actorDevice: ChainDevice;
  readonly target: ChainMember;
  readonly revoking: readonly string[];
}): string | null {
  const { actor, target, revoking } = input;
  if (target.userId !== actor.userId) {
    const permission = effectivePermissionOf(actor, input.actorDevice);
    const rejection = revokeRoleRejection(permission.role, permission.scope, target);
    if (rejection !== null) {
      return rejection;
    }
  }
  if (target.devices.size - revoking.length <= 0) {
    return `Revoking ${revoking.length === 1 ? "this device" : "these devices"} would leave ${target.userId === actor.userId ? "you" : displayText(target.userId)} with no device on this project (consensus rule last-device-protected — CRYPTO_SPEC §6.2). Register another device first, or remove the member with \`maruhi member remove\``;
  }
  return null;
}

/** `revoke_device` の通信前検査 → 署名(失効対象が残っていなければ null)。 */
function signRevokeDevice(input: {
  readonly verified: VerifiedProject;
  readonly signer: DeviceOpSigner;
  readonly targetUserId: string;
  readonly fingerprintsHex: readonly string[];
}): Effect.Effect<
  { readonly entry: ChainEntry; readonly revoking: readonly string[] } | null,
  CliError
> {
  return Effect.gen(function* () {
    const actor = input.verified.state.members.get(input.signer.userId);
    if (actor === undefined) {
      return yield* Effect.fail(cliError("You are not a chain-derived member of this project"));
    }
    const target = input.verified.state.members.get(input.targetUserId);
    if (target === undefined) {
      return yield* Effect.fail(
        cliError(`${displayText(input.targetUserId)} is not a current member of this project`),
      );
    }
    const revoking = input.fingerprintsHex
      .filter((fingerprintHex) => target.devices.has(fingerprintHex))
      .toSorted(compareCodePoints);
    if (revoking.length === 0) {
      return null;
    }
    const actorDevice = yield* ownDeviceBySigningKey(
      input.verified,
      actor,
      input.signer.signingKeyPair,
    );
    const rejection = revokeRejection({ actor, actorDevice, target, revoking });
    if (rejection !== null) {
      return yield* Effect.fail(cliError(rejection));
    }
    const signed = yield* Effect.tryPromise({
      try: () =>
        signChainEntry({
          entry: {
            suite: SUITE_ID,
            seq: input.verified.state.headSeq + 1,
            prevHashHex: input.verified.state.headHashHex,
            op: "revoke_device",
            actor: { userId: actor.userId, keyFingerprintHex: actorDevice.keyFingerprintHex },
            payload: { targetUserId: target.userId, deviceFingerprintsHex: revoking },
            timestampMs: Date.now(),
          },
          signingKey: input.signer.signingKeyPair.privateKey,
        }),
      catch: () => cliError("Failed to sign the revoke_device entry"),
    });
    if (!signed.ok) {
      return yield* Effect.fail(cliError("Failed to sign the revoke_device entry"));
    }
    return { entry: signed.value, revoking };
  });
}

/**
 * Appends `revoke_device` for the target's devices among `fingerprintsHex`
 * that are still active (CAS retries; idempotent). Returns the fingerprints
 * actually revoked by this call.
 */
export function appendRevokeDevice(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly signer: DeviceOpSigner;
  readonly targetUserId: string;
  readonly fingerprintsHex: readonly string[];
}): Effect.Effect<
  { readonly verified: VerifiedProject; readonly revoked: readonly string[] },
  CliError
> {
  return Effect.gen(function* () {
    let revoked: readonly string[] = [];
    const outcome = yield* appendWithCas({
      client: input.client,
      verified: input.verified,
      resync: input.resync,
      opLabel: "revoke_device",
      signEntry: (view) =>
        Effect.map(
          signRevokeDevice({
            verified: view,
            signer: input.signer,
            targetUserId: input.targetUserId,
            fingerprintsHex: input.fingerprintsHex,
          }),
          (signed) => {
            revoked = signed === null ? [] : signed.revoking;
            return signed === null ? null : signed.entry;
          },
        ),
    });
    return { verified: outcome.verified, revoked: outcome.appended ? revoked : [] };
  });
}

/** 端末追加のバックフィルの結果(環境ごとに集計。1 環境の失敗で残りを止めない)。 */
export interface DeviceBackfillOutcome {
  readonly environments: number;
  readonly registered: number;
  readonly alreadyRegistered: number;
  readonly failed: readonly { readonly environmentId: string; readonly message: string }[];
}

/**
 * 端末が受け取るべき環境: 検証済みで削除されていない環境のうち、その端末の実効 scope に
 * 含まれるもの(コード点順)。バックフィルの対象と、新端末の `device add` が鍵の到達を
 * 確かめる対象(DK K12-1)が同じ関数で決まる — 配ったはずの集合と確かめる集合を構造で一致させる。
 */
export function deviceEnvironmentsOf(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetMember: ChainMember;
  readonly targetDevice: ChainDevice;
}): Effect.Effect<readonly string[], CliError> {
  return Effect.gen(function* () {
    const deletedVerified = yield* verifiedDeletedEnvironmentSet(input.client, input.verified);
    const scope = effectivePermissionOf(input.targetMember, input.targetDevice).scope;
    return [...input.verified.state.environments.keys()]
      .filter(
        (environmentId) =>
          !deletedVerified.has(environmentId) && scopeIncludesEnvironment(scope, environmentId),
      )
      .toSorted(compareCodePoints);
  });
}

/**
 * Backfills every epoch of every environment in the target device's effective
 * scope to that device (CRYPTO_SPEC §7「端末追加のバックフィル」). `recipient`
 * is the caller's own key that opens the DEKs (this device, or the reserve key
 * during recovery).
 */
export function backfillToDevice(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly recipient: DekRecipient;
  readonly targetMember: ChainMember;
  readonly targetDevice: ChainDevice;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<DeviceBackfillOutcome, CliError> {
  return Effect.gen(function* () {
    const environments = yield* deviceEnvironmentsOf(input);
    const aggregate = yield* backfillEachEnvironment(environments, (environmentId) =>
      backfillEnvironmentFor({
        client: input.client,
        verified: input.verified,
        environmentId,
        recipient: input.recipient,
        wrapRecipient: { kind: "member", member: input.targetMember, device: input.targetDevice },
        recipientLabel: "device-addressed",
        signerUserId: input.signerUserId,
        signingKeyPair: input.signingKeyPair,
      }),
    );
    return {
      environments: environments.length,
      registered: aggregate.registered,
      alreadyRegistered: aggregate.alreadyRegistered,
      failed: aggregate.failed,
    };
  });
}

/** 端末失効の sweep の結果(member 系と同じ形 — 報告を共有する)。 */
export type DeviceSweepOutcome = SweepOutcome & {
  readonly skippedDeleted: readonly string[];
  /** 署名端末の実効 scope 外(または role 不足)で rotate できない義務環境(K4-8 — 持ち越し)。 */
  readonly outOfScope: readonly string[];
};

/** Rotation reason recorded on the `rotate_epoch` entries of a device-revocation sweep. */
export const DEVICE_REVOKED_ROTATION_REASON = "device-revoked";

/**
 * §7 の端末失効の義務環境の走査(設計録 K4-8): 対象者の `device-revoked` 義務のうち
 * 署名端末の実効 scope 内(かつ実効 role が member 以上)の環境を rotate し、外は
 * `outOfScope` として「同じ人の別端末か次の同期に持ち越す」。
 */
export function sweepAfterDeviceRevoke<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetUserId: string;
  readonly actorUserId: string;
  readonly actorDevice: ChainDevice;
  readonly rotate: SweepRotate<R>;
}): Effect.Effect<DeviceSweepOutcome | null, CliError, R> {
  return Effect.gen(function* () {
    const mandates: readonly RotationMandate[] = rotationMandates(input.verified).filter(
      (mandate) => mandate.kind === "device-revoked" && mandate.target === input.targetUserId,
    );
    if (mandates.length === 0) {
      return null;
    }
    const actor = input.verified.state.members.get(input.actorUserId);
    const permission = actor === undefined ? null : effectivePermissionOf(actor, input.actorDevice);
    const canRotate = permission !== null && ROLE_RANK[permission.role] >= ROLE_RANK.member;
    const actorScope: MemberScope =
      canRotate && permission !== null ? permission.scope : { kind: "listed", environmentIds: [] };
    const deletedVerified = yield* verifiedDeletedEnvironmentSet(input.client, input.verified);
    const { baselines, outOfScope, skippedDeleted } = partitionSweepBaselines({
      verified: input.verified,
      all: baselinesOf(mandates),
      actorScope,
      deletedVerified,
    });
    const sweep = yield* sweepRotations({
      rotate: input.rotate,
      verified: input.verified,
      baselines,
      deletedVerified,
    });
    return { ...sweep, skippedDeleted, outOfScope };
  });
}
