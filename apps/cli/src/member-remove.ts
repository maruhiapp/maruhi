// `maruhi member remove`: the pre-append checks -> remove_member append ->
// forced rotation of every environment (§7 — the group's overview lives in
// member.ts).

import type { ChainEntry, ChainMember, ProposableOperation, SigningKeyPair } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { isApprovalTarget } from "./approval-rules.ts";
import {
  ensureStillTarget,
  type ProposalInput,
  proposeOperation,
  proposeRecheck,
} from "./approval.ts";
import { signEntryAtHead } from "./chain-append.ts";
import { resyncExtended, type VerifiedProject } from "./chain-sync.ts";
import { ROLE_RANK } from "./dek-wrap.ts";
import { cliError, type CliError } from "./errors.ts";
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
import { describeScope, scopeContains } from "./scope.ts";
// ---------------------------------------------------------------------------
// member remove
// ---------------------------------------------------------------------------

export interface MemberRemoveSummary extends MemberSweepOutcome {
  /** Whether it was appended to the chain (false = already deleted — resumes from mid-rotation). */
  readonly appended: boolean;
  readonly targetUserId: string;
}

/**
 * remove's pre-append checks (re-run after a CAS retry's resync as well).
 * `proposing` = the proposal path (the self-remove refusal is dropped
 * because the fulfiller moves to the approver — design record K6-N).
 */
function ensureRemovable(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly targetUserId: string;
  readonly proposing: boolean;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<{ readonly alreadyRemoved: boolean }, CliError> {
  return Effect.gen(function* () {
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
      return resumable === null
        ? { alreadyRemoved: true }
        : yield* Effect.fail(cliError(resumable));
    }
    const rejection = removeRuleRejection(input.verified, permission, target);
    return rejection === null ? { alreadyRemoved: false } : yield* Effect.fail(cliError(rejection));
  });
}

/**
 * The conditions for resuming from deleted (interruption recovery): a
 * remove of that user_id exists on the chain (never create a shape where
 * the sweep runs on a mistyped user_id. A remove applied via a proposal —
 * four-eyes K6 — also lands on the same list: design record K6-C), and the
 * resuming actor is member or above.
 */
function removalResumeRejection(
  verified: VerifiedProject,
  actor: ActorAuthority,
  targetUserId: string,
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

/** The pre-judgment of remove_member's §6.2 rules (role → scope-not-contained → last-owner). */
function removeRuleRejection(
  verified: VerifiedProject,
  actor: ActorAuthority,
  target: ChainMember,
): string | null {
  const rejection = targetedOpRejection({ actor, target, operation: "remove_member" });
  if (rejection !== null) {
    return rejection;
  }
  // Principle 1 (§6.2 scope-not-contained): remove's permission-change
  // environment set = the target's current scope ("can remove = can
  // fulfill rotate" — ruling D). The same pre-judgment as change-role
  if (!scopeContains(actor.scope, target.scope)) {
    return `Your environment scope (${describeScope(actor.scope)}) does not contain the target's scope (${describeScope(target.scope)}), so you could not run the post-removal rotation — CRYPTO_SPEC §6.2 scope-not-contained. Ask an owner or an admin whose scope covers them`;
  }
  return target.role === "owner" && ownersCount(verified) === 1
    ? "The last owner cannot be removed (CRYPTO_SPEC §6.2 last-owner-protected)"
    : null;
}

/** Signs a remove_member entry right after the current head (the shared core = chain-append.ts). */
function signRemoveEntry(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly targetUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry, CliError> {
  return signEntryAtHead({
    verified: input.verified,
    signerUserId: input.signerUserId,
    operation: { op: "remove_member", payload: { targetUserId: input.targetUserId } },
    signingKeyPair: input.signingKeyPair,
    failureText: "Failed to sign the remove_member entry",
  });
}

export function memberRemoveOp<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetUserId: string;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly rotateWith: (reason: string) => SweepRotate<R>;
  readonly proposal: ProposalInput;
}): Effect.Effect<MemberOpOutcome<MemberRemoveSummary>, CliError, R> {
  return Effect.gen(function* () {
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

    // Four-eyes (K6-A): if the policy targets remove_member, propose and
    // finish (the rotate duty is fulfilled by the approver's sweep after
    // the application — rulings P7 / P8). A resume (already deleted) is
    // never proposed
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
        opLabel: "remove_member",
        signEntry: (view) =>
          signRemoveEntry({
            verified: view,
            signerUserId: input.signerUserId,
            targetUserId: input.targetUserId,
            signingKeyPair: input.signingKeyPair,
          }),
        recheck: (view) =>
          ensureStillTarget(view, inner, false).pipe(
            Effect.flatMap(() => recheck(view)),
            Effect.map((rechecked) => ({ already: rechecked.alreadyRemoved })),
          ),
      });
      verified = outcome.verified;
      appended = outcome.appended;
    }

    // The post-acceptance resync confirms the deletion's listing (the server's claim is never the source of truth)
    verified = yield* resyncExtended(input.resync, verified);
    if (verified.state.members.has(input.targetUserId)) {
      return yield* Effect.fail(
        cliError(
          "The resync after remove_member was accepted still shows the target as a member (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }

    // The target's duty entry (this remove's append or a historical one —
    // past narrowings / demotions included) becomes the baseline. No remove
    // at all means "a deletion was confirmed yet no duty entry exists" = an
    // internal contradiction of the derivation. The duty's environment set
    // is the target's current scope (§7 — listed{} means empty)
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
}
