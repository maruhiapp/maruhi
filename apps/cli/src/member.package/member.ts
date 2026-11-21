import { type EnvironmentId, type UserId } from "@maruhi/core";
import {
  type ChainDevice,
  type ChainEntry,
  type ChainMember,
  type EffectivePermission,
  effectivePermissionOf,
  type MemberScope,
  type ProposableOperation,
  type Role,
  type SigningKeyPair,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import { ensureStillTarget, type ProposedSummary } from "../approval.package/index.ts";
import { appendWithRetry } from "../chain-append.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import { ROLE_RANK } from "../dek-wrap.ts";
import { chainDeletedEnvironments } from "../deks.ts";
import { ownDeviceBySigningKey } from "../device-key.ts";
import { cliError, type CliError } from "../errors.ts";
import {
  baselinesOf,
  partitionSweepBaselines,
  type RotationMandate,
  rotationMandates,
  type SweepOutcome,
  type SweepRotate,
  sweepRotations,
} from "../rotation-sweep.ts";

export type MemberOpOutcome<S> =
  | { readonly kind: "proposed"; readonly proposal: ProposedSummary }
  | { readonly kind: "applied"; readonly summary: S };

const MEMBER_REMOVED_ROTATION_REASON = "member-removed";
const ROLE_DEMOTED_ROTATION_REASON = "role-demoted";
const SCOPE_NARROWED_ROTATION_REASON = "scope-narrowed";

export function memberMandatesFor(
  verified: VerifiedProject,
  targetUserId: UserId,
): readonly RotationMandate[] {
  return rotationMandates(verified).filter(
    (mandate) =>
      mandate.kind !== "server-revoked" &&
      mandate.kind !== "device-revoked" &&
      mandate.target === targetUserId,
  );
}

export const sweepAfterMandate = Effect.fn("member.sweepAfterMandate")(function* <R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly mandates: readonly RotationMandate[];
  readonly actorUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
  readonly rotateWith: (reason: string) => SweepRotate<R>;
}): Effect.fn.Return<MemberSweepOutcome, CliError, R> {
  const actorScope = yield* actorEffectiveScope(
    input.verified,
    input.actorUserId,
    input.signingKeyPair,
  );
  const deletedVerified = chainDeletedEnvironments(input.verified);
  const { baselines, outOfScope, skippedDeleted } = partitionSweepBaselines({
    verified: input.verified,
    all: baselinesOf(input.mandates),
    actorScope,
    deletedVerified,
  });
  const reasons = reasonsByEnvironment(input.mandates);
  const sweep = yield* sweepRotations({
    rotate: (environmentId, mode) =>
      input.rotateWith(reasons.get(environmentId) ?? MEMBER_REMOVED_ROTATION_REASON)(
        environmentId,
        mode,
      ),
    verified: input.verified,
    baselines,
    deletedVerified,
  });
  return { ...sweep, skippedDeleted, outOfScope };
});

const actorEffectiveScope = Effect.fn("member.actorEffectiveScope")(function* (
  verified: VerifiedProject,
  actorUserId: UserId,
  signingKeyPair: SigningKeyPair,
): Effect.fn.Return<MemberScope, CliError> {
  const actor = verified.state.members.get(actorUserId);
  if (actor === undefined) {
    return { kind: "listed", environmentIds: [] };
  }
  const device = yield* ownDeviceBySigningKey(verified, actor, signingKeyPair).pipe(
    Effect.orElseSucceed((): ChainDevice | null => null),
  );
  if (device === null) {
    return { kind: "listed", environmentIds: [] };
  }
  const permission = effectivePermissionOf(actor, device);
  return ROLE_RANK[permission.role] >= ROLE_RANK.member
    ? permission.scope
    : { kind: "listed", environmentIds: [] };
});

export function sweepMemberMandates<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetUserId: UserId;
  readonly actorUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
  readonly rotateWith: (reason: string) => SweepRotate<R>;
}): Effect.Effect<MemberSweepOutcome | null, CliError, R> {
  const mandates = memberMandatesFor(input.verified, input.targetUserId);
  return mandates.length === 0 ? Effect.succeed(null) : sweepAfterMandate({ ...input, mandates });
}

export type MemberSweepOutcome = SweepOutcome & {
  readonly skippedDeleted: readonly EnvironmentId[];
  readonly outOfScope: readonly EnvironmentId[];
};

const MANDATE_REASONS = {
  "member-removed": MEMBER_REMOVED_ROTATION_REASON,
  "role-demoted": ROLE_DEMOTED_ROTATION_REASON,
  "scope-narrowed": SCOPE_NARROWED_ROTATION_REASON,
  "server-revoked": "server-revoked",
  "device-revoked": "device-revoked",
} satisfies Record<RotationMandate["kind"], string>;

function reasonsByEnvironment(mandates: readonly RotationMandate[]): ReadonlyMap<string, string> {
  const chosen = new Map<string, RotationMandate>();
  for (const mandate of mandates) {
    for (const environmentId of mandate.environmentIds) {
      const current = chosen.get(environmentId);
      if (
        current === undefined ||
        current.seq < mandate.seq ||
        (current.seq === mandate.seq && mandate.kind === "role-demoted")
      ) {
        chosen.set(environmentId, mandate);
      }
    }
  }
  return new Map(
    [...chosen].map(([environmentId, mandate]) => [environmentId, MANDATE_REASONS[mandate.kind]]),
  );
}

export function appendWithCas(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly inner: ProposableOperation;
  readonly signEntry: (verified: VerifiedProject) => Effect.Effect<ChainEntry, CliError>;
  readonly recheck: (
    verified: VerifiedProject,
  ) => Effect.Effect<{ readonly already: boolean }, CliError>;
}): Effect.Effect<{ readonly verified: VerifiedProject; readonly appended: boolean }, CliError> {
  return appendWithRetry(input, {
    op: input.inner.op,
    initial: { verified: input.verified, already: false },
    sign: (state) => (state.already ? Effect.succeed(null) : input.signEntry(state.verified)),
    recheck: (resynced) =>
      ensureStillTarget(resynced, input.inner, false).pipe(
        Effect.flatMap(() => input.recheck(resynced)),
        Effect.map((rechecked) => ({ verified: resynced, already: rechecked.already })),
      ),
  }).pipe(
    Effect.map(({ state, entry }) => ({ verified: state.verified, appended: entry !== null })),
  );
}

export function resolveActorAndTarget(
  verified: VerifiedProject,
  signerUserId: UserId,
  targetUserId: UserId,
): Effect.Effect<
  { readonly actor: ChainMember; readonly target: ChainMember | undefined },
  CliError
> {
  const actor = verified.state.members.get(signerUserId);
  if (actor === undefined) {
    return Effect.fail(cliError("You are not a chain-derived member of this project"));
  }
  return Effect.succeed({ actor, target: verified.state.members.get(targetUserId) });
}

export type ActorAuthority = { readonly role: Role; readonly scope: MemberScope };

export function actorAuthority(
  verified: VerifiedProject,
  actor: ChainMember,
  signingKeyPair: SigningKeyPair,
): Effect.Effect<EffectivePermission, CliError> {
  return Effect.map(ownDeviceBySigningKey(verified, actor, signingKeyPair), (device) =>
    effectivePermissionOf(actor, device),
  );
}

export function targetedOpRejection(input: {
  readonly actor: ActorAuthority;
  readonly target: ChainMember;
  readonly operation: string;
}): string | null {
  if (ROLE_RANK[input.actor.role] < ROLE_RANK.admin) {
    return `Only admins and above can run ${input.operation} (CRYPTO_SPEC §6.2)`;
  }
  if (ROLE_RANK[input.target.role] >= ROLE_RANK.admin && input.actor.role !== "owner") {
    return `Only an owner can run ${input.operation} against an admin / owner (CRYPTO_SPEC §6.2)`;
  }
  return null;
}

export function ownersCount(verified: VerifiedProject): number {
  let count = 0;
  for (const member of verified.state.members.values()) {
    if (member.role === "owner") {
      count += 1;
    }
  }
  return count;
}
