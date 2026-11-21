import type { UserId } from "@maruhi/core";
import {
  type ChainEntry,
  type ChainMember,
  isApprovalTarget,
  type ProposableOperation,
  type SigningKeyPair,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import { type ProposalInput, proposeOperation, proposeRecheck } from "../approval.package/index.ts";
import { signEntryAtHead } from "../chain-append.ts";
import { resyncExtended, type VerifiedProject } from "../chain-sync.ts";
import { ROLE_RANK } from "../dek-wrap.ts";
import { cliError, type CliError } from "../errors.ts";
import type { SweepRotate } from "../rotation-sweep.ts";
import { describeScope, scopeContains } from "../scope.ts";
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

interface MemberRemoveSummary extends MemberSweepOutcome {
  readonly appended: boolean;
  readonly targetUserId: UserId;
}

const ensureRemovable = Effect.fn("member-remove.ensureRemovable")(function* (input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: UserId;
  readonly targetUserId: UserId;
  readonly proposing: boolean;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.fn.Return<{ readonly alreadyRemoved: boolean }, CliError> {
  if (input.targetUserId === input.signerUserId && !input.proposing) {
    return yield* Effect.fail(
      cliError(
        "You cannot remove yourself. You would be unable to run the post-removal rotation of every environment (CRYPTO_SPEC §7) — ask another admin / owner to remove you",
      ),
    );
  }
  const { actor, target } = yield* resolveActorAndTarget(
    input.verified,
    input.signerUserId,
    input.targetUserId,
  );
  const permission = yield* actorAuthority(input.verified, actor, input.signingKeyPair);
  if (target === undefined) {
    const resumable = removalResumeRejection(input.verified, permission, input.targetUserId);
    return resumable === null ? { alreadyRemoved: true } : yield* Effect.fail(cliError(resumable));
  }
  const rejection = removeRuleRejection(input.verified, permission, target);
  return rejection === null ? { alreadyRemoved: false } : yield* Effect.fail(cliError(rejection));
});

function removalResumeRejection(
  verified: VerifiedProject,
  actor: ActorAuthority,
  targetUserId: UserId,
): string | null {
  const removedBefore = verified.applied.some(
    ({ operation }) =>
      operation.op === "remove_member" && operation.payload.targetUserId === targetUserId,
  );
  if (!removedBefore) {
    return "The target is not a member and the chain has no removal record for it (check the user ID)";
  }
  return ROLE_RANK[actor.role] < ROLE_RANK.member
    ? "Resuming the rotation requires the member role or above (CRYPTO_SPEC §6.2)"
    : null;
}

function removeRuleRejection(
  verified: VerifiedProject,
  actor: ActorAuthority,
  target: ChainMember,
): string | null {
  const rejection = targetedOpRejection({ actor, target, operation: "remove_member" });
  if (rejection !== null) {
    return rejection;
  }
  if (!scopeContains(actor.scope, target.scope)) {
    return `Your environment scope (${describeScope(actor.scope)}) does not contain the target's scope (${describeScope(target.scope)}), so you could not run the post-removal rotation — CRYPTO_SPEC §6.2 scope-not-contained. Ask an owner or an admin whose scope covers them`;
  }
  return target.role === "owner" && ownersCount(verified) === 1
    ? "The last owner cannot be removed (CRYPTO_SPEC §6.2 last-owner-protected)"
    : null;
}

function signRemoveEntry(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: UserId;
  readonly targetUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry, CliError> {
  return signEntryAtHead({
    verified: input.verified,
    signerUserId: input.signerUserId,
    operation: { op: "remove_member", payload: { targetUserId: input.targetUserId } },
    signingKeyPair: input.signingKeyPair,
  });
}

export const memberRemoveOp = Effect.fn("member-remove.memberRemoveOp")(function* <R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetUserId: UserId;
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly rotateWith: (reason: string) => SweepRotate<R>;
  readonly proposal: ProposalInput;
}): Effect.fn.Return<MemberOpOutcome<MemberRemoveSummary>, CliError, R> {
  const inner: ProposableOperation = {
    op: "remove_member",
    payload: { targetUserId: input.targetUserId },
  };
  const proposing = isApprovalTarget(inner, input.verified.state.approvalPolicy);
  const recheck = (view: VerifiedProject) =>
    ensureRemovable({
      verified: view,
      signerUserId: input.signerUserId,
      targetUserId: input.targetUserId,
      proposing,
      signingKeyPair: input.signingKeyPair,
    });
  const first = yield* recheck(input.verified);

  if (!first.alreadyRemoved && proposing) {
    const proposal = yield* proposeOperation(
      input,
      inner,
      proposeRecheck(
        recheck,
        (rechecked) => rechecked.alreadyRemoved,
        "The target was removed by a concurrent run while this proposal was being appended — nothing to propose. Re-run `maruhi member remove` to resume the rotation",
      ),
    );
    return { kind: "proposed", proposal };
  }

  let verified = input.verified;
  let appended = false;
  if (!first.alreadyRemoved) {
    const outcome = yield* appendWithCas({
      client: input.client,
      verified,
      resync: input.resync,
      inner,
      signEntry: (view) =>
        signRemoveEntry({
          verified: view,
          signerUserId: input.signerUserId,
          targetUserId: input.targetUserId,
          signingKeyPair: input.signingKeyPair,
        }),
      recheck: (view) =>
        Effect.map(recheck(view), (rechecked) => ({ already: rechecked.alreadyRemoved })),
    });
    verified = outcome.verified;
    appended = outcome.appended;
  }

  verified = yield* resyncExtended(input.resync, verified);
  if (verified.state.members.has(input.targetUserId)) {
    return yield* Effect.fail(
      cliError(
        "The resync after remove_member was accepted still shows the target as a member (the server's response contradicts the chain). Investigate the served chain",
      ),
    );
  }

  const mandates = memberMandatesFor(verified, input.targetUserId);
  if (!mandates.some((mandate) => mandate.kind === "member-removed")) {
    return yield* Effect.fail(
      cliError(
        "Cannot find the rotation-mandate entry on the chain (internal contradiction in the derivation)",
      ),
    );
  }
  const sweep = yield* sweepAfterMandate({
    client: input.client,
    verified,
    mandates,
    actorUserId: input.signerUserId,
    signingKeyPair: input.signingKeyPair,
    rotateWith: input.rotateWith,
  });
  return { kind: "applied", summary: { appended, targetUserId: input.targetUserId, ...sweep } };
});
