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

import type { MaruhiClient } from "../api.ts";
import {
  type ProposalInput,
  type ProposeContext,
  type ProposedSummary,
  proposeOperation,
  proposeRecheck,
} from "../approval.package/index.ts";
import { signEntryAtHead } from "../chain-append.ts";
import { resyncExtended, type VerifiedProject } from "../chain-sync.ts";
import { ROLE_RANK } from "../dek-wrap.ts";
import type { DekRecipient } from "../deks.ts";
import { chainDeletedEnvironments } from "../deks.ts";
import { cliError, type CliError, usageError } from "../errors.ts";
import type { SweepRotate } from "../rotation-sweep.ts";
import {
  compareCodePoints,
  describeScope,
  environmentsOfScopeAt,
  requireScopeEnvironmentsExist,
  sameScope,
  scopeChangeAt,
  scopeContains,
} from "../scope.ts";
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

export interface MemberChangeRoleSummary {
  readonly appended: boolean;
  readonly targetUserId: UserId;
  readonly newRole: Role;
  readonly newScope: MemberScope;
  readonly widenedEnvironmentIds: readonly EnvironmentId[];
  readonly widenedOutOfScopeEnvironmentIds: readonly EnvironmentId[];
  readonly narrowedEnvironmentIds: readonly string[];
  readonly backfill: Pick<
    MemberAddSummary,
    "registered" | "alreadyRegistered" | "repaired" | "failed"
  > | null;
  readonly demoted: boolean;
  readonly sweep: MemberSweepOutcome | null;
}

export interface ChangeRoleRequest {
  readonly newRole: Role | null;
  readonly newScope: MemberScope | null;
}

function resolveRoleChange(
  target: ChainMember,
  request: ChangeRoleRequest,
): Effect.Effect<{ readonly role: Role; readonly scope: MemberScope }, CliError> {
  const role = request.newRole ?? target.role;
  if (role === "owner") {
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
      if (ROLE_RANK[permission.role] < ROLE_RANK.member) {
        return yield* Effect.fail(
          cliError(
            "Resuming the rotation / backfill requires the member role or above (CRYPTO_SPEC §6.2)",
          ),
        );
      }
      return { alreadyChanged: true, ...next };
    }
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
  });
}

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

export function scopeChangesOf(
  verified: VerifiedProject,
  target: ChainMember,
): { readonly widened: readonly EnvironmentId[]; readonly narrowed: readonly EnvironmentId[] } {
  const current = new Set(environmentsOfScopeAt(verified, target.scope, verified.state.headSeq));
  const widened = new Set<EnvironmentId>();
  let narrowed: readonly EnvironmentId[] = [];
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

function splitWidenedByActorScope(input: {
  readonly verified: VerifiedProject;
  readonly actorUserId: UserId;
  readonly widened: readonly EnvironmentId[];
}): {
  readonly widened: readonly EnvironmentId[];
  readonly widenedOutOfScope: readonly EnvironmentId[];
} {
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
      inner: input.inner,
      signEntry: (view) =>
        signChangeRoleAtView({
          verified: view,
          signerUserId: input.signerUserId,
          targetUserId: input.targetUserId,
          request: input.request,
          signingKeyPair: input.signingKeyPair,
        }),
      recheck: (view) =>
        Effect.map(input.recheck(view), (rechecked) => ({ already: rechecked.alreadyChanged })),
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

export type RoleChangeFulfilment = Pick<
  MemberChangeRoleSummary,
  | "widenedEnvironmentIds"
  | "widenedOutOfScopeEnvironmentIds"
  | "narrowedEnvironmentIds"
  | "backfill"
  | "demoted"
  | "sweep"
>;

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
  readonly rotateWith: (reason: string) => SweepRotate<R>;
  readonly proposal: ProposalInput;
}): Effect.fn.Return<MemberOpOutcome<MemberChangeRoleSummary>, CliError, R> {
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
