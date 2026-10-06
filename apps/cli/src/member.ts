// `maruhi member add|remove|change-role` (CRYPTO_SPEC §6.2 / §6.5 / §7,
// AUTH_SPEC §12-6 / §15).
//
// - add: §6.5 independent verification of the list's acceptance block +
//   issuance-pin cross-check + the FP-confirmation ceremony → add_member
//   append (CAS retry) → backfill of every environment × every epoch
//   (409 = an idempotent resume of already-registered. **A 409 from a
//   re-addition (a past membership under a different key) suggests a
//   stale-key wrap**, so it auto-repairs via delete → re-register behind a
//   key-history gate — §12-6's repair path. Left alone, a re-added member
//   cannot decrypt historical epochs)
// - remove / change-role (demotion below member): append the entry →
//   **forced rotation of every environment** (§7). Interruption recovery
//   uses the same chain-derived scheme as server revoke
//   (rotation-sweep.ts — baseline = the seq of the last rotation-duty
//   entry)
//
// Removing yourself or demoting yourself below member is refused: after
// the operation the actor loses rotate_epoch authority and cannot fulfill
// the §7 duty themselves (the consensus rules don't forbid it, but the CLI
// never creates a shape where the duty is structurally orphaned).

import { ChainHeadConflictError } from "@maruhi/api-schema";
import {
  type ChainDevice,
  type ChainEntry,
  type ChainMember,
  type EffectivePermission,
  effectivePermissionOf,
  type MemberScope,
  type Role,
  type SigningKeyPair,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { ProposedSummary } from "./approval.ts";
import { appendEntry } from "./chain-append.ts";
import { resyncExtended, type VerifiedProject } from "./chain-sync.ts";
import { ROLE_RANK } from "./dek-wrap.ts";
import { ownDeviceBySigningKey } from "./device-key.ts";
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

const MAX_ATTEMPTS = 5;

/**
 * Each op's result under four-eyes (K6): if the policy targets the inner
 * op, append a `propose` and finish (`proposed` — nothing is applied).
 * Otherwise the usual application result (`applied`).
 */
export type MemberOpOutcome<S> =
  | { readonly kind: "proposed"; readonly proposal: ProposedSummary }
  | { readonly kind: "applied"; readonly summary: S };

/** The rotation reason after a remove / demotion / narrowing (the fixed string of the §6.2 payload). */
const MEMBER_REMOVED_ROTATION_REASON = "member-removed";
const ROLE_DEMOTED_ROTATION_REASON = "role-demoted";
const SCOPE_NARROWED_ROTATION_REASON = "scope-narrowed";

// ---------------------------------------------------------------------------
// Shared: the rotation-duty environment set and the baseline seq (the interruption-recovery baseline — chain-derived only)
// ---------------------------------------------------------------------------

/**
 * **The target user_id's** rotation-duty entries (`remove_member` /
 * demotion / narrowing — §7). The derivation's core is rotation-sweep.ts's
 * rotationMandates (the same single derivation as the always-on
 * unconverged warning — prevents judgment drift structurally). The duty's
 * environment set is concretized per entry (remove = the current scope,
 * demotion = the new scope, narrowing = old \ new — design record K4-J).
 *
 * Target-scoping exists to limit the duty each command converges to **its
 * own operation's share**: keyed on the global duty, a no-op re-run
 * against a born-reader would pick up **someone else's** unconverged duty
 * and start a rotation. Rotations after the target's duty entry close the
 * target's forgeable coordinates (§7), so a target scope never
 * under-fulfills its own duty (others' unconverged duties are the
 * always-on warning — rotation-sweep.ts — and that operation's re-run's
 * responsibility).
 */
export function memberMandatesFor(
  verified: VerifiedProject,
  targetUserId: string,
): readonly RotationMandate[] {
  // The device-revocation duty (`device-revoked`) is fulfilled by `device
  // revoke`'s own sweep (device-ops.ts) — member commands' re-runs never
  // pick up another operation's duty (same line)
  return rotationMandates(verified).filter(
    (mandate) =>
      mandate.kind !== "server-revoked" &&
      mandate.kind !== "device-revoked" &&
      mandate.target === targetUserId,
  );
}

/** The §7 duty-environment sweep (the shared aftermath of remove / demotion / narrowing. Baseline = environment → the max duty seq). */
export function sweepAfterMandate<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly mandates: readonly RotationMandate[];
  /** The actor. A duty environment outside scope cannot be rotated (§7), so it is dropped from the targets and noted. */
  readonly actorUserId: string;
  /** The key of the device the actor signs with (the fulfillable range = the device's effective scope — DK K4-17). */
  readonly signingKeyPair: SigningKeyPair;
  /** The per-duty-kind rotation injection (the rotate entry's reason matches the duty). */
  readonly rotateWith: (reason: string) => SweepRotate<R>;
}): Effect.Effect<MemberSweepOutcome, CliError, R> {
  return Effect.gen(function* () {
    const actorScope = yield* actorEffectiveScope(
      input.verified,
      input.actorUserId,
      input.signingKeyPair,
    );
    // Duty environments outside my (the device's effective) scope (when a
    // duty from a narrowing / remove someone made in the past remains on
    // the target's history, when run on a capped device) are excluded from
    // the rotate targets (CRYPTO_SPEC §7 — even the actor cannot rotate
    // outside scope. Independent review S2). The always-on warning keeps
    // displaying them
    const deletedVerified = yield* verifiedDeletedEnvironmentSet(input.client, input.verified);
    const { baselines, outOfScope, skippedDeleted } = partitionSweepBaselines({
      verified: input.verified,
      all: baselinesOf(input.mandates),
      actorScope,
      deletedVerified,
    });
    // Each environment's reason = the kind of the duty that became that environment's baseline (max seq) (independent review N3)
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
}

/**
 * The range of environments where the actor can fulfill rotate = the
 * signing device's effective scope (person ∩ device — DK K4-17). An
 * effective role below member (reader, or a member-cap device) is empty
 * (rotate needs member or above — §6.2). Non-members and unregistered
 * devices are empty too (fail-closed — they stay on the always-on
 * warning).
 */
function actorEffectiveScope(
  verified: VerifiedProject,
  actorUserId: string,
  signingKeyPair: SigningKeyPair,
): Effect.Effect<MemberScope, CliError> {
  return Effect.gen(function* () {
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
}

/**
 * The sweep of the target's duties (remove / demotion / narrowing —
 * including application via a proposal). Shared between the direct
 * append's aftermath and the approver's fulfillment that completes the
 * application under four-eyes (approval-approve.ts — approval item 22).
 */
export function sweepMemberMandates<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetUserId: string;
  readonly actorUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly rotateWith: (reason: string) => SweepRotate<R>;
}): Effect.Effect<MemberSweepOutcome | null, CliError, R> {
  const mandates = memberMandatesFor(input.verified, input.targetUserId);
  return mandates.length === 0 ? Effect.succeed(null) : sweepAfterMandate({ ...input, mandates });
}

/** The member-family sweep result (includes deleted environments and ones that could not be rotated because they are outside the actor's scope). */
export type MemberSweepOutcome = SweepOutcome & {
  readonly skippedDeleted: readonly string[];
  /** Duty environments outside the actor's scope that cannot be rotated (§7 — left to another member's fulfillment). */
  readonly outOfScope: readonly string[];
};

const MANDATE_REASONS = {
  "member-removed": MEMBER_REMOVED_ROTATION_REASON,
  "role-demoted": ROLE_DEMOTED_ROTATION_REASON,
  "scope-narrowed": SCOPE_NARROWED_ROTATION_REASON,
  "server-revoked": "server-revoked",
  "device-revoked": "device-revoked",
} satisfies Record<RotationMandate["kind"], string>;

/** Environment → the reason of the baseline (max seq) duty (on a seq tie, demotion wins). */
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

/**
 * The CAS append of a membership op (the shared scaffolding of
 * retryOnConflict — same shape across add / remove / change_role). On each
 * head conflict: resync with the extension check → redo the pre-check via
 * `recheck`; if a concurrent run already committed the same change
 * (already), continue without appending.
 */
export function appendWithCas(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The op name used in the exhausted wording (e.g. "remove_member"). */
  readonly opLabel: string;
  readonly signEntry: (verified: VerifiedProject) => Effect.Effect<ChainEntry, CliError>;
  readonly recheck: (
    verified: VerifiedProject,
  ) => Effect.Effect<{ readonly already: boolean }, CliError>;
}): Effect.Effect<{ readonly verified: VerifiedProject; readonly appended: boolean }, CliError> {
  return retryOnConflict(
    { verified: input.verified, already: false },
    {
      maxAttempts: MAX_ATTEMPTS,
      attempt: (
        state,
      ): Effect.Effect<
        { readonly verified: VerifiedProject; readonly appended: boolean },
        CliError | ChainHeadConflictError
      > =>
        state.already
          ? Effect.succeed({ verified: state.verified, appended: false })
          : Effect.gen(function* () {
              const entry = yield* input.signEntry(state.verified);
              yield* appendEntry(input.client, state.verified, entry);
              return { verified: state.verified, appended: true };
            }),
      classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
      recover: (state) =>
        Effect.gen(function* () {
          const resynced = yield* resyncExtended(input.resync, state.verified);
          const rechecked = yield* input.recheck(resynced);
          return { verified: resynced, already: rechecked.already };
        }),
      exhaustedMessage: `${input.opLabel}'s chain-head conflict did not resolve (${MAX_ATTEMPTS} attempts). Wait a moment and re-run`,
    },
  );
}

/** Resolving the actor and the target (the shared prologue of remove / change_role). */
export function resolveActorAndTarget(
  verified: VerifiedProject,
  signerUserId: string,
  targetUserId: string,
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

/**
 * The actor's authority material the pre-flight sees. Since the consensus
 * judges by effective authority (person ∩ device cap — §6.2
 * `effectivePermissionOf`), the early judgment follows it (if the signing
 * device's cap is narrower than the person's, skipping the effective-side
 * check means advancing to the append-time refusal).
 */
export type ActorAuthority = { readonly role: Role; readonly scope: MemberScope };

/**
 * Pulls the signing device and returns its effective authority. For a key
 * absent from the chain (unregistered / revoked), a typed failure precedes
 * the person's-authority wording (same order as device-ops.ts).
 */
export function actorAuthority(
  verified: VerifiedProject,
  actor: ChainMember,
  signingKeyPair: SigningKeyPair,
): Effect.Effect<EffectivePermission, CliError> {
  return Effect.map(ownDeviceBySigningKey(verified, actor, signingKeyPair), (device) =>
    effectivePermissionOf(actor, device),
  );
}

/** The CLI's early check of the target rules (§6.2) for remove / change_role (a pre-judgment for the wording). */
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
