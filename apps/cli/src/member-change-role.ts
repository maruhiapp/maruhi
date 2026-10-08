// `maruhi member change-role`: the full (role, scope) replacement append ->
// widening backfill + demotion / narrowing sweep (§7 — the group's overview
// lives in member.ts).

import { type EnvironmentId, type UserId } from "@maruhi/core";
import {
  ALL_SCOPE,
  type ChainEntry,
  type ChainMember,
  isApprovalTarget,
  type MemberScope,
  memberScopeOf,
  type ProposableOperation,
  type Role,
  scopeIncludesEnvironment,
  scopePayloadFieldsOf,
  type SigningKeyPair,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import {
  ensureStillTarget,
  type ProposalInput,
  type ProposeContext,
  type ProposedSummary,
  proposeOperation,
  proposeRecheck,
} from "./approval.ts";
import { signEntryAtHead } from "./chain-append.ts";
import { resyncExtended, type VerifiedProject } from "./chain-sync.ts";
import { ROLE_RANK } from "./dek-wrap.ts";
import type { DekRecipient } from "./deks.ts";
import { chainDeletedEnvironments } from "./deks.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { backfillAllEnvironments, type MemberAddSummary } from "./member-add.ts";
import {
  actorAuthority,
  type ActorAuthority,
  appendWithCas,
  memberMandatesFor,
  type MemberOpOutcome,
  type MemberSweepOutcome,
  ownersCount,
  resolveActorAndTarget,
  sweepAfterMandate,
  targetedOpRejection,
} from "./member.ts";
import type { SweepRotate } from "./rotation-sweep.ts";
import {
  compareCodePoints,
  describeScope,
  environmentsOfScopeAt,
  requireScopeEnvironmentsExist,
  sameScope,
  scopeChangeAt,
  scopeContains,
} from "./scope.ts";

// ---------------------------------------------------------------------------
// member change-role
// ---------------------------------------------------------------------------

export interface MemberChangeRoleSummary {
  /** Whether it was appended to the chain (false = already at the target (role, scope) — only the duty resumes). */
  readonly appended: boolean;
  readonly targetUserId: UserId;
  readonly newRole: Role;
  readonly newScope: MemberScope;
  /** Of the widened environments (new \ old — the actor's backfill duty. §12-6), those inside the actor's scope. */
  readonly widenedEnvironmentIds: readonly EnvironmentId[];
  /** Of the historical widenings, those outside the actor's scope (not my duty — left to a member whose scope has that environment). */
  readonly widenedOutOfScopeEnvironmentIds: readonly EnvironmentId[];
  /** The narrowed environments (old \ new — the rotate duty. §7). */
  readonly narrowedEnvironmentIds: readonly string[];
  /** The widened part's backfill result (no widening = null). */
  readonly backfill: Pick<
    MemberAddSummary,
    "registered" | "alreadyRegistered" | "repaired" | "failed"
  > | null;
  /** Whether the target has a demotion duty (role-demoted) (report-wording material — not re-derived from the new role). */
  readonly demoted: boolean;
  /** The result of rotating the duty environments for the demotion / narrowing (no duty = null). */
  readonly sweep: MemberSweepOutcome | null;
}

/** The change_role input (omitting role or scope means kept as-is — design record K4-A). */
export interface ChangeRoleRequest {
  readonly newRole: Role | null;
  readonly newScope: MemberScope | null;
}

/** From the target's current (role, scope) and the request, decides the new (role, scope) to append (a full replacement — §6.2). */
function resolveRoleChange(
  target: ChainMember,
  request: ChangeRoleRequest,
): Effect.Effect<{ readonly role: Role; readonly scope: MemberScope }, CliError> {
  const role = request.newRole ?? target.role;
  if (role === "owner") {
    // An owner's scope is always all (§6.2 scope-role-mismatch) — combining `--env` is a contradiction
    if (request.newScope !== null && request.newScope.kind !== "all") {
      return Effect.fail(
        usageError(
          "An owner's scope is always all environments (CRYPTO_SPEC §6.2 scope-role-mismatch) — drop --env / --no-envs, or use --all-envs",
        ),
      );
    }
    return Effect.succeed({ role, scope: ALL_SCOPE });
  }
  return Effect.succeed({ role, scope: request.newScope ?? target.scope });
}

/** Early check of change_role's role rules (§6.2) (a reason string when unmet). */
function changeRoleRuleRejection(input: {
  readonly verified: VerifiedProject;
  readonly actor: ActorAuthority;
  readonly target: ChainMember;
  readonly newRole: Role;
}): string | null {
  const base = targetedOpRejection({
    actor: input.actor,
    target: input.target,
    operation: "change_role",
  });
  if (base !== null) {
    return base;
  }
  if (ROLE_RANK[input.newRole] >= ROLE_RANK.admin && input.actor.role !== "owner") {
    return "Only an owner can change a role to admin / owner (CRYPTO_SPEC §6.2)";
  }
  if (
    input.target.role === "owner" &&
    input.newRole !== "owner" &&
    ownersCount(input.verified) === 1
  ) {
    return "The last owner cannot be demoted (CRYPTO_SPEC §6.2 last-owner-protected)";
  }
  return null;
}

/**
 * The pre-judgment of principle 1 (§6.2 scope-not-contained): when the
 * role changes, old ∪ new; when only the scope changes, the symmetric
 * difference must be contained in the actor's scope. If old or new is all,
 * the difference becomes U \ X, so only an all-scoped actor can do it
 * (set algebra — the derivation of design record K4-I).
 */
function scopeContainmentRejection(input: {
  readonly actor: ActorAuthority;
  readonly target: ChainMember;
  readonly newRole: Role;
  readonly newScope: MemberScope;
}): string | null {
  const contained =
    input.newRole !== input.target.role
      ? scopeContains(input.actor.scope, input.target.scope) &&
        scopeContains(input.actor.scope, input.newScope)
      : actorMayReplaceScope(input);
  if (contained) {
    return null;
  }
  return `Your environment scope (${describeScope(input.actor.scope)}) does not contain the environments whose permissions this change affects (target: ${describeScope(input.target.scope)} → ${describeScope(input.newScope)}) — CRYPTO_SPEC §6.2 scope-not-contained. Ask an owner or an admin whose scope covers them`;
}

/** For a scope-only replacement, whether the actor contains the symmetric difference (old △ new). */
function actorMayReplaceScope(input: {
  readonly actor: ActorAuthority;
  readonly target: ChainMember;
  readonly newScope: MemberScope;
}): boolean {
  if (input.actor.scope.kind === "all") {
    return true;
  }
  const before = input.target.scope;
  const after = input.newScope;
  if (before.kind === "all" || after.kind === "all") {
    // all △ all = ∅ (no change), all △ listed = U \ X (a listed actor cannot contain it)
    return before.kind === after.kind;
  }
  const beforeIds = new Set(before.environmentIds);
  const afterIds = new Set(after.environmentIds);
  const changed = [
    ...before.environmentIds.filter((id) => !afterIds.has(id)),
    ...after.environmentIds.filter((id) => !beforeIds.has(id)),
  ];
  return scopeContains(input.actor.scope, { kind: "listed", environmentIds: changed });
}

/**
 * Refusing a demotion / narrowing onto oneself: the person would become
 * unable to fulfill the §7 duty (rotate) (below member after a demotion,
 * the environment outside scope after a narrowing).
 */
function rejectSelfObligation(
  verified: VerifiedProject,
  target: ChainMember,
  next: { readonly role: Role; readonly scope: MemberScope },
): Effect.Effect<void, CliError> {
  switch (selfObligationReason(verified, target, next)) {
    case "demotion":
      return Effect.fail(
        cliError(
          "You cannot demote yourself below member. You would be unable to run the post-demotion rotation of every environment (CRYPTO_SPEC §7) — ask another admin / owner to demote you",
        ),
      );
    case "scope-narrowing":
      return Effect.fail(
        cliError(
          "You cannot narrow your own scope. You would be unable to run the rotation of the environments you leave (CRYPTO_SPEC §7) — ask another admin / owner to narrow it",
        ),
      );
    case null:
      return Effect.void;
  }
}

/**
 * Whether the change makes the target itself unable to fulfill its §7
 * duty: a demotion below member, or a scope narrowing (a direct append
 * where the fulfiller = the target itself, and an approve where the
 * approver = the target — design record K6-N / Cursor Bugbot's catch).
 */
export function selfObligationReason(
  verified: VerifiedProject,
  target: ChainMember,
  next: { readonly role: Role; readonly scope: MemberScope },
): "demotion" | "scope-narrowing" | null {
  if (ROLE_RANK[target.role] >= ROLE_RANK.member && ROLE_RANK[next.role] < ROLE_RANK.member) {
    return "demotion";
  }
  return scopeChangeAt(verified, target.scope, next.scope, verified.state.headSeq).narrowed.length >
    0
    ? "scope-narrowing"
    : null;
}

/**
 * change_role's pre-append checks (re-run after a CAS retry's resync as
 * well). `proposing` = the proposal path (the self-demotion /
 * self-narrowing refusal is dropped because the fulfiller moves to the
 * approver — design record K6-N).
 */
const ensureRoleChangeable = Effect.fn("member-change-role.ensureRoleChangeable")(
  function* (input: {
    readonly verified: VerifiedProject;
    readonly signerUserId: UserId;
    readonly targetUserId: UserId;
    readonly request: ChangeRoleRequest;
    readonly proposing: boolean;
    readonly signingKeyPair: SigningKeyPair;
  }): Effect.fn.Return<
    { readonly alreadyChanged: boolean; readonly role: Role; readonly scope: MemberScope },
    CliError
  > {
    const { actor, target } = yield* resolveActorAndTarget(
      input.verified,
      input.signerUserId,
      input.targetUserId,
    );
    const permission = yield* actorAuthority(input.verified, actor, input.signingKeyPair);
    if (target === undefined) {
      return yield* Effect.fail(cliError("The target is not a member (check the user ID)"));
    }
    const next = yield* resolveRoleChange(target, input.request);
    if (input.targetUserId === input.signerUserId && !input.proposing) {
      yield* rejectSelfObligation(input.verified, target, next);
    }
    if (target.role === next.role && sameScope(target.scope, next.scope)) {
      // Already appended (a previous run's interruption / a concurrent
      // run) or a no-op. Shapes so an interrupted demotion / narrowing
      // recovery (the entry landed but the duty is unfinished) can resume
      // from here. The resume (rotate / backfill) requires member or above
      // (same guard as a remove resume — independent review N11)
      if (ROLE_RANK[permission.role] < ROLE_RANK.member) {
        return yield* Effect.fail(
          cliError(
            "Resuming the rotation / backfill requires the member role or above (CRYPTO_SPEC §6.2)",
          ),
        );
      }
      return { alreadyChanged: true, ...next };
    }
    // The check order follows §6.2's consensus rules: role rules →
    // last-owner → unknown-environment → scope-not-contained (independent
    // review N2)
    const rejection = changeRoleRuleRejection({
      verified: input.verified,
      actor: permission,
      target,
      newRole: next.role,
    });
    if (rejection !== null) {
      return yield* Effect.fail(cliError(rejection));
    }
    yield* requireScopeEnvironmentsExist(input.verified, next.scope);
    const containment = scopeContainmentRejection({
      actor: permission,
      target,
      newRole: next.role,
      newScope: next.scope,
    });
    if (containment !== null) {
      return yield* Effect.fail(cliError(containment));
    }
    return { alreadyChanged: false, ...next };
  },
);

/**
 * Signs a change_role entry right after the current head (the shared core
 * = chain-append.ts). The payload is the full replacement of (role,
 * scope) (CRYPTO_SPEC §6.2) — 2026-09-15 ES K4: omitting `--role` /
 * `--env` / `--all-envs` keeps each as-is (design record K4-A), and an
 * owner is pinned to all.
 */
function signChangeRoleEntry(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: UserId;
  readonly targetUserId: UserId;
  readonly newRole: Role;
  readonly newScope: MemberScope;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry, CliError> {
  const scope = scopePayloadFieldsOf(input.newScope);
  return signEntryAtHead({
    verified: input.verified,
    signerUserId: input.signerUserId,
    operation: {
      op: "change_role",
      payload: {
        targetUserId: input.targetUserId,
        newRole: input.newRole,
        scopeKind: scope.scopeKind,
        scopeEnvironmentIds: scope.scopeEnvironmentIds,
      },
    },
    signingKeyPair: input.signingKeyPair,
    failureText: "Failed to sign the change_role entry",
  });
}

/**
 * Resolves the new (role, scope) from the target's current state **on the
 * signing view** and signs (the kept-as-is side comes from that view's
 * state). Even when a concurrent change_role changed the kept-as-is side
 * across a CAS retry, it is not overwritten (design record K4-A's
 * "omitted = unchanged" — Cursor Bugbot's catch).
 */
const signChangeRoleAtView = Effect.fn("member-change-role.signChangeRoleAtView")(
  function* (input: {
    readonly verified: VerifiedProject;
    readonly signerUserId: UserId;
    readonly targetUserId: UserId;
    readonly request: ChangeRoleRequest;
    readonly signingKeyPair: SigningKeyPair;
  }): Effect.fn.Return<ChainEntry, CliError> {
    const current = input.verified.state.members.get(input.targetUserId);
    if (current === undefined) {
      return yield* Effect.fail(cliError("The target is not a member (check the user ID)"));
    }
    const next = yield* resolveRoleChange(current, input.request);
    return yield* signChangeRoleEntry({
      verified: input.verified,
      signerUserId: input.signerUserId,
      targetUserId: input.targetUserId,
      newRole: next.role,
      newScope: next.scope,
      signingKeyPair: input.signingKeyPair,
    });
  },
);

/**
 * The widened part = of the union of the widened parts of **all**
 * `change_role` entries in the target's history (each entry's diff against
 * its immediately preceding state), the environments still in the current
 * scope (pullfrog's catch: looking at only the last entry, a third party's
 * change_role committed mid-interruption of a widening backfill would make
 * the widened part empty and never resumed. Like the sweep side folding
 * every duty of the target, it is derived from the whole history. A 409 is
 * idempotent, so excess converges to "already registered"). The narrowed
 * part is for reporting — the last entry's diff.
 */
export function scopeChangesOf(
  verified: VerifiedProject,
  target: ChainMember,
): { readonly widened: readonly EnvironmentId[]; readonly narrowed: readonly EnvironmentId[] } {
  const current = new Set(environmentsOfScopeAt(verified, target.scope, verified.state.headSeq));
  const widened = new Set<EnvironmentId>();
  let narrowed: readonly EnvironmentId[] = [];
  // A change_role applied via a proposal lands on the same list (design record K6-C)
  for (const { seq, operation } of verified.applied) {
    if (operation.op !== "change_role" || operation.payload.targetUserId !== target.userId) {
      continue;
    }
    const before = verified.history.memberStateAt(target.userId, seq - 1);
    if (before === undefined) {
      continue;
    }
    const change = scopeChangeAt(verified, before.scope, memberScopeOf(operation.payload), seq);
    for (const environmentId of change.widened) {
      if (current.has(environmentId)) {
        widened.add(environmentId);
      }
    }
    narrowed = change.narrowed;
  }
  return { widened: [...widened].toSorted(compareCodePoints), narrowed };
}

/**
 * Of the historical widenings, environments outside the actor's scope are
 * not my duty (a §6.2 corollary — duty environment set ⊆ permission-change
 * environment set ⊆ actor scope. Independent review S6). Like the sweep,
 * they go to the note and are left to a re-run by a member whose scope
 * carries that environment.
 */
function splitWidenedByActorScope(input: {
  readonly verified: VerifiedProject;
  readonly actorUserId: UserId;
  readonly widened: readonly EnvironmentId[];
}): {
  readonly widened: readonly EnvironmentId[];
  readonly widenedOutOfScope: readonly EnvironmentId[];
} {
  // A chain-deleted environment is dropped from the widened part (never
  // keep emitting an out-of-scope note for "an environment nobody can
  // fill" — pullfrog's catch. Same set as backfillAllEnvironments; a
  // deletion also prunes the id from every scope — CRYPTO_SPEC §6.2)
  const deletedVerified = chainDeletedEnvironments(input.verified);
  const live = input.widened.filter((environmentId) => !deletedVerified.has(environmentId));
  const actor = input.verified.state.members.get(input.actorUserId);
  const actorScope: MemberScope = actor?.scope ?? { kind: "listed", environmentIds: [] };
  return {
    widened: live.filter((environmentId) => scopeIncludesEnvironment(actorScope, environmentId)),
    widenedOutOfScope: live.filter(
      (environmentId) => !scopeIncludesEnvironment(actorScope, environmentId),
    ),
  };
}

/** change_role's inner op (proposal-ization — the omitted side is already resolved against the target's state on the proposal-time view). */
function changeRoleOperation(input: {
  readonly targetUserId: UserId;
  readonly newRole: Role;
  readonly newScope: MemberScope;
}): Extract<ProposableOperation, { readonly op: "change_role" }> {
  const scope = scopePayloadFieldsOf(input.newScope);
  return {
    op: "change_role",
    payload: {
      targetUserId: input.targetUserId,
      newRole: input.newRole,
      scopeKind: scope.scopeKind,
      scopeEnvironmentIds: scope.scopeEnvironmentIds,
    },
  };
}

/** change_role's proposal (K6-A): after the resync it also confirms that the omitted side's re-resolution matches the proposal-time one. */
function proposeRoleChange(
  input: ProposeContext,
  inner: ProposableOperation,
  resolved: { readonly role: Role; readonly scope: MemberScope },
  recheck: (
    view: VerifiedProject,
  ) => Effect.Effect<
    { readonly alreadyChanged: boolean; readonly role: Role; readonly scope: MemberScope },
    CliError
  >,
): Effect.Effect<ProposedSummary, CliError> {
  const notApplied = proposeRecheck(
    recheck,
    (rechecked) => rechecked.alreadyChanged,
    "The target already has the requested role / scope (a concurrent run applied it) — nothing to propose. Re-run `maruhi member change-role` to resume any pending backfill / rotation",
  );
  return proposeOperation(input, inner, (view) =>
    notApplied(view).pipe(
      Effect.flatMap((rechecked) =>
        rechecked.role === resolved.role && sameScope(rechecked.scope, resolved.scope)
          ? Effect.void
          : Effect.fail(
              cliError(
                "The target's role / scope changed concurrently, so the omitted side of this request no longer resolves to the same (role, scope) — re-run to propose against the current state",
              ),
            ),
      ),
    ),
  );
}

/**
 * change_role's direct append (CAS) and the listing confirmation on the
 * post-acceptance resync (the server's claim is never the source of
 * truth). Must match the request's fixpoint (the omitted side stays
 * as-is) — even if a concurrent change_role changed the kept side, it
 * holds when the requested side is on the chain.
 */
const appendRoleChange = Effect.fn("member-change-role.appendRoleChange")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetUserId: UserId;
  readonly request: ChangeRoleRequest;
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly inner: ProposableOperation;
  readonly alreadyChanged: boolean;
  readonly recheck: (
    view: VerifiedProject,
  ) => Effect.Effect<{ readonly alreadyChanged: boolean }, CliError>;
}): Effect.fn.Return<
  { readonly verified: VerifiedProject; readonly appended: boolean; readonly target: ChainMember },
  CliError
> {
  let verified = input.verified;
  let appended = false;
  if (!input.alreadyChanged) {
    const outcome = yield* appendWithCas({
      client: input.client,
      verified,
      resync: input.resync,
      opLabel: "change_role",
      // The omitted side (role / scope) is resolved from the target's
      // state on **the signing view** (signChangeRoleAtView — Cursor
      // Bugbot's catch)
      signEntry: (view) =>
        signChangeRoleAtView({
          verified: view,
          signerUserId: input.signerUserId,
          targetUserId: input.targetUserId,
          request: input.request,
          signingKeyPair: input.signingKeyPair,
        }),
      recheck: (view) =>
        ensureStillTarget(view, input.inner, false).pipe(
          Effect.flatMap(() => input.recheck(view)),
          Effect.map((rechecked) => ({ already: rechecked.alreadyChanged })),
        ),
    });
    verified = outcome.verified;
    appended = outcome.appended;
  }
  verified = yield* resyncExtended(input.resync, verified);
  const target = verified.state.members.get(input.targetUserId);
  const expected =
    target === undefined ? undefined : yield* resolveRoleChange(target, input.request);
  if (
    target === undefined ||
    expected === undefined ||
    target.role !== expected.role ||
    !sameScope(target.scope, expected.scope)
  ) {
    return yield* Effect.fail(
      cliError(
        "The resync after change_role was accepted does not show the target's new role / scope (the server's response contradicts the chain). Investigate the served chain",
      ),
    );
  }
  return { verified, appended, target };
});

/** The result of change_role's post-application fulfillment (widening backfill + demotion / narrowing sweep). */
export type RoleChangeFulfilment = Pick<
  MemberChangeRoleSummary,
  | "widenedEnvironmentIds"
  | "widenedOutOfScopeEnvironmentIds"
  | "narrowedEnvironmentIds"
  | "backfill"
  | "demoted"
  | "sweep"
>;

/**
 * change_role's post-application stage (design record K4-B's order:
 * widening backfill → rotate of the demotion / narrowing part). Shared
 * between a direct-append change-role and the fulfillment of the approver
 * who completes the application under four-eyes (approval-approve.ts —
 * approval item 22). The target is the current member after resync.
 */
export const fulfilRoleChange = Effect.fn("member-change-role.fulfilRoleChange")(function* <
  R,
>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly target: ChainMember;
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
  readonly recipient: DekRecipient;
  readonly rotateWith: (reason: string) => SweepRotate<R>;
}): Effect.fn.Return<RoleChangeFulfilment, CliError, R> {
  const change = scopeChangesOf(input.verified, input.target);
  const { widened, widenedOutOfScope } = splitWidenedByActorScope({
    verified: input.verified,
    actorUserId: input.signerUserId,
    widened: change.widened,
  });

  // (1) The widening backfill — the actor holds the DEK by the containment rule (§12-6). Idempotent via 409
  const backfill =
    widened.length === 0
      ? null
      : yield* backfillAllEnvironments({
          client: input.client,
          verified: input.verified,
          recipient: input.recipient,
          target: input.target,
          environments: widened,
          signerUserId: input.signerUserId,
          signingKeyPair: input.signingKeyPair,
        });

  // (2) Rotate the demotion / narrowing duty environments (§7). With no
  // duty entry on the target, no duty ever arose (promotion, widening, a
  // born-reader no-op) — others' unconverged duties are not picked up
  const mandates = memberMandatesFor(input.verified, input.target.userId);
  const demoted = mandates.some((mandate) => mandate.kind === "role-demoted");
  const sweep =
    mandates.length === 0
      ? null
      : yield* sweepAfterMandate({
          client: input.client,
          verified: input.verified,
          mandates,
          actorUserId: input.signerUserId,
          signingKeyPair: input.signingKeyPair,
          rotateWith: input.rotateWith,
        });
  return {
    widenedEnvironmentIds: widened,
    widenedOutOfScopeEnvironmentIds: widenedOutOfScope,
    narrowedEnvironmentIds: change.narrowed,
    backfill,
    demoted,
    sweep,
  };
});

/**
 * `maruhi member change-role`: appends the full replacement of (role,
 * scope), the actor backfills the widened part (§12-6's append path), then
 * rotates the duty environments of the demotion / narrowing (§7) (the
 * order is design record K4-B: the 3 environment sets are pairwise
 * disjoint, and each can resume idempotently).
 */
export const memberChangeRoleOp = Effect.fn("member-change-role.memberChangeRoleOp")(function* <
  R,
>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetUserId: UserId;
  readonly request: ChangeRoleRequest;
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The per-duty-reason rotation injection (demotion = role-demoted / narrowing only = scope-narrowed). */
  readonly rotateWith: (reason: string) => SweepRotate<R>;
  readonly proposal: ProposalInput;
}): Effect.fn.Return<MemberOpOutcome<MemberChangeRoleSummary>, CliError, R> {
  // The proposal-ization judgment runs on the new (role, scope) resolved
  // from the request on the current view (establishing an owner is always
  // targeted). The check order (the order of §6.2's consensus rules — own
  // duty → role rules → …) belongs to ensureRoleChangeable
  const { target: current } = yield* resolveActorAndTarget(
    input.verified,
    input.signerUserId,
    input.targetUserId,
  );
  if (current === undefined) {
    return yield* Effect.fail(cliError("The target is not a member (check the user ID)"));
  }
  const resolved = yield* resolveRoleChange(current, input.request);
  const inner = changeRoleOperation({
    targetUserId: input.targetUserId,
    newRole: resolved.role,
    newScope: resolved.scope,
  });
  const proposing = isApprovalTarget(inner, input.verified.state.approvalPolicy);
  const recheck = (view: VerifiedProject) =>
    ensureRoleChangeable({
      verified: view,
      signerUserId: input.signerUserId,
      targetUserId: input.targetUserId,
      request: input.request,
      proposing,
      signingKeyPair: input.signingKeyPair,
    });
  const first = yield* recheck(input.verified);

  // Four-eyes (K6-A): if the policy targets it, propose and finish (the
  // widening backfill and the narrowing sweep are fulfilled by the
  // approver after the application — approval item 22). The omitted side
  // is fixed to the proposal-time view's state
  if (!first.alreadyChanged && proposing) {
    const proposal = yield* proposeRoleChange(input, inner, resolved, recheck);
    return { kind: "proposed", proposal };
  }

  const { verified, appended, target } = yield* appendRoleChange({
    ...input,
    inner,
    alreadyChanged: first.alreadyChanged,
    recheck,
  });
  const fulfilment = yield* fulfilRoleChange({
    client: input.client,
    verified,
    target,
    signerUserId: input.signerUserId,
    signingKeyPair: input.signingKeyPair,
    recipient: input.recipient,
    rotateWith: input.rotateWith,
  });
  return {
    kind: "applied",
    summary: {
      appended,
      targetUserId: input.targetUserId,
      newRole: target.role,
      newScope: target.scope,
      ...fulfilment,
    },
  };
});
