// Signing and appending (parent-head CAS) of device ops (`add_device` /
// `revoke_device` — CRYPTO_SPEC §6.2, 2026-09-19 DK), plus the shared
// core of the device-addition backfill (§7) and the device-revocation
// sweep (§7) (K4). Users: device-add.ts (`device add`'s key-arrival
// check), device-approve.ts (`device approve`), device-revoke.ts
// (`device revoke`), device-sync.ts (registration on first sync),
// key-recover.ts (registering the new device key after recovery,
// rotating the reserve key).
//
// The pre-flight checks are a copy of the consensus rules (§6.2) and do
// not wait for the server's 422: actor = the current device matching
// the signing key (device-key.ts), key uniqueness across all devices of
// current members, existence of the `listed` environments, monotonicity
// (cap vs cap — principle D2), revocation = the target being a current
// device, last-device protection, and for others the role rule (the
// same two stages as `remove_member`) plus the principle-1 inclusion
// (the **person's** scope).
//
// Backfill (§7 "device-addition backfill"): for each environment in the
// new device's **effective scope** (person ∩ device), unwrap every
// epoch's DEK from the my-addressed wraps and re-wrap it to the new
// device's enc public key (the shared core in backfill.ts — 409 counts
// as already registered).

import { ChainHeadConflictError } from "@maruhi/api-schema";
import { cryptoEffect } from "@maruhi/core";
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
import { Clock, Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { backfillEachEnvironment, backfillEnvironmentFor } from "./backfill.ts";
import { appendEntry } from "./chain-append.ts";
import { resyncExtended, type VerifiedProject } from "./chain-sync.ts";
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

/** Shared scaffolding for a CAS append (same shape as member.ts's appendWithCas — for device ops). */
function appendWithCas(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly opLabel: string;
  readonly signEntry: (verified: VerifiedProject) => Effect.Effect<ChainEntry | null, CliError>;
}): Effect.Effect<{ readonly verified: VerifiedProject; readonly appended: boolean }, CliError> {
  return retryOnConflict(input.verified, {
    maxAttempts: MAX_ATTEMPTS,
    attempt: (view) =>
      Effect.gen(function* () {
        // null = already in the desired state (a concurrent run appended first) — continue without appending
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

/** Pre-flight judgment of key uniqueness (§6.2 — no duplicate same-kind public key across all devices of current members). */
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

/** `add_device` pre-flight checks → sign (null if already registered). */
const signAddDevice = Effect.fn("device-ops.signAddDevice")(function* (input: {
  readonly verified: VerifiedProject;
  readonly signer: DeviceOpSigner;
  readonly candidate: DeviceCandidate;
}): Effect.fn.Return<ChainEntry | null, CliError> {
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
  const timestampMs = yield* Clock.currentTimeMillis;
  return yield* cryptoEffect(() =>
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
        timestampMs,
      },
      signingKey: input.signer.signingKeyPair.privateKey,
    }),
  ).pipe(Effect.mapError(() => cliError("Failed to sign the add_device entry")));
});

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

/** The role rule for revoking another person's device (the same two stages as `remove_member` — the strict reading of K2 handoff 4). */
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

/** Pre-flight checks (role rule for others; last-device-protected for anyone). null when ok. */
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

/** `revoke_device` pre-flight checks → sign (null if no revocation target remains). */
const signRevokeDevice = Effect.fn("device-ops.signRevokeDevice")(function* (input: {
  readonly verified: VerifiedProject;
  readonly signer: DeviceOpSigner;
  readonly targetUserId: string;
  readonly fingerprintsHex: readonly string[];
}): Effect.fn.Return<
  { readonly entry: ChainEntry; readonly revoking: readonly string[] } | null,
  CliError
> {
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
  const timestampMs = yield* Clock.currentTimeMillis;
  const entry = yield* cryptoEffect(() =>
    signChainEntry({
      entry: {
        suite: SUITE_ID,
        seq: input.verified.state.headSeq + 1,
        prevHashHex: input.verified.state.headHashHex,
        op: "revoke_device",
        actor: { userId: actor.userId, keyFingerprintHex: actorDevice.keyFingerprintHex },
        payload: { targetUserId: target.userId, deviceFingerprintsHex: revoking },
        timestampMs,
      },
      signingKey: input.signer.signingKeyPair.privateKey,
    }),
  ).pipe(Effect.mapError(() => cliError("Failed to sign the revoke_device entry")));
  return { entry, revoking };
});

/**
 * Appends `revoke_device` for the target's devices among `fingerprintsHex`
 * that are still active (CAS retries; idempotent). Returns the fingerprints
 * actually revoked by this call.
 */
export const appendRevokeDevice = Effect.fn("device-ops.appendRevokeDevice")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly signer: DeviceOpSigner;
  readonly targetUserId: string;
  readonly fingerprintsHex: readonly string[];
}): Effect.fn.Return<
  { readonly verified: VerifiedProject; readonly revoked: readonly string[] },
  CliError
> {
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

/** Result of the device-addition backfill (aggregated per environment; one environment's failure does not stop the rest). */
export interface DeviceBackfillOutcome {
  readonly environments: number;
  readonly registered: number;
  readonly alreadyRegistered: number;
  readonly failed: readonly { readonly environmentId: string; readonly message: string }[];
}

/**
 * The environments a device should receive: among the verified,
 * non-deleted environments, those included in the device's effective
 * scope (code-point order). The backfill targets and the set `device
 * add` of the new device checks key reachability against (DK K12-1) are
 * decided by the same function — the structure keeps "the set we should
 * have delivered" and "the set we check" identical.
 */
export const deviceEnvironmentsOf = Effect.fn("device-ops.deviceEnvironmentsOf")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetMember: ChainMember;
  readonly targetDevice: ChainDevice;
}): Effect.fn.Return<readonly string[], CliError> {
  const deletedVerified = yield* verifiedDeletedEnvironmentSet(input.client, input.verified);
  const scope = effectivePermissionOf(input.targetMember, input.targetDevice).scope;
  return [...input.verified.state.environments.keys()]
    .filter(
      (environmentId) =>
        !deletedVerified.has(environmentId) && scopeIncludesEnvironment(scope, environmentId),
    )
    .toSorted(compareCodePoints);
});

/**
 * Backfills every epoch of every environment in the target device's effective
 * scope to that device (CRYPTO_SPEC §7 "device-addition backfill"). `recipient`
 * is the caller's own key that opens the DEKs (this device, or the reserve key
 * during recovery).
 */
export const backfillToDevice = Effect.fn("device-ops.backfillToDevice")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly recipient: DekRecipient;
  readonly targetMember: ChainMember;
  readonly targetDevice: ChainDevice;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.fn.Return<DeviceBackfillOutcome, CliError> {
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

/** Result of the device-revocation sweep (same shape as the member one — shares the report). */
export type DeviceSweepOutcome = SweepOutcome & {
  readonly skippedDeleted: readonly string[];
  /** Obligation environments that cannot be rotated because they are outside the signing device's effective scope (or role is insufficient) (K4-8 — carried over). */
  readonly outOfScope: readonly string[];
};

/** Rotation reason recorded on the `rotate_epoch` entries of a device-revocation sweep. */
export const DEVICE_REVOKED_ROTATION_REASON = "device-revoked";

/**
 * Scanning the obligation environments of §7's device revocation
 * (design record K4-8): among the target's `device-revoked`
 * obligations, rotate those inside the signing device's effective
 * scope (and where the effective role is member or above); the rest go
 * to `outOfScope` as "carried over to another device of the same person
 * or the next sync".
 */
export const sweepAfterDeviceRevoke = Effect.fn("device-ops.sweepAfterDeviceRevoke")(function* <
  R,
>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetUserId: string;
  readonly actorUserId: string;
  readonly actorDevice: ChainDevice;
  readonly rotate: SweepRotate<R>;
}): Effect.fn.Return<DeviceSweepOutcome | null, CliError, R> {
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
