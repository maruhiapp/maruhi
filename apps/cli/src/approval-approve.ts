// `maruhi approval approve <id>` (CRYPTO_SPEC §6.2 / §7 — PF1; design
// record es-design.md §12 K6-B / N).
//
// Appends an approve and learns the result from the re-synced verified chain
// (the server response does not carry whether it applied — K5-S (1)):
// (i) the proposal stays pending = the vote was recorded; (ii) it leaves
// pending and the completion seq in core's `indexProposals` equals my approve
// seq = I completed it = **fulfiller** (approval item 22 / CRYPTO_SPEC §7).
// Fulfilment calls, per inner op kind, the same functions as the post-stage
// of a direct append: remove / demotion / narrowing = sweep (rotation
// obligation), add_member / scope widening = member-directed backfill,
// grant_server = server-directed backfill, revoke_server = sweep of all
// environments. set_approval_policy = none. An approve that does not
// complete fulfils nothing.
//
// Pre-flight checks (K5-S / K5-L): foretell duplicate-approval (my
// (user_id, current key FP) is in S), approval-not-required (excluded by a
// policy change), proposal-expired (my clock). A proposal targeting the
// approver themself (own remove / demotion below member) is refused because
// completing it removes the fulfiller; the user is guided to ask another
// owner to approve (K6-N).

import { ChainHeadConflictError } from "@maruhi/api-schema";
import type { PendingProposal, ProposableOperation, SigningKeyPair } from "@maruhi/crypto";
import { memberScopeOf } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import {
  describeUnresolvedRef,
  type ProposalView,
  proposalViewOf,
  resolveProposalRef,
  voteEligibility,
} from "./approval-rules.ts";
import { proposalStatusOf } from "./approval.ts";
import { appendEntry, signEntryAtHead } from "./chain-append.ts";
import { resyncExtended, type VerifiedProject } from "./chain-sync.ts";
import type { DekRecipient } from "./deks.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { backfillNewMember, type MemberAddSummary } from "./member-add.ts";
import {
  fulfilRoleChange,
  type RoleChangeFulfilment,
  selfObligationReason,
} from "./member-change-role.ts";
import { type MemberSweepOutcome, sweepMemberMandates } from "./member.ts";
import { retryOnConflict } from "./retry.ts";
import type { SweepOutcome, SweepRotate } from "./rotation-sweep.ts";
import { backfillServerGrant } from "./server-grant.ts";
import { sweepAfterRevoke } from "./server-revoke.ts";

const MAX_ATTEMPTS = 5;

/** What the completing approver's client did after the inner op was applied (approval item 22). */
export type Fulfilment =
  | { readonly kind: "none" }
  | {
      readonly kind: "member-rotation";
      readonly targetUserId: string;
      readonly sweep: MemberSweepOutcome | null;
    }
  | {
      readonly kind: "member-backfill";
      readonly targetUserId: string;
      readonly backfill: Pick<
        MemberAddSummary,
        "registered" | "alreadyRegistered" | "repaired" | "failed"
      >;
    }
  | {
      readonly kind: "role-change";
      readonly targetUserId: string;
      readonly change: RoleChangeFulfilment;
    }
  | {
      readonly kind: "server-backfill";
      readonly serverKeyFingerprintHex: string;
      readonly scopeEnvironmentIds: readonly string[];
      readonly registered: number;
      readonly alreadyRegistered: number;
    }
  | {
      readonly kind: "server-rotation";
      readonly serverKeyFingerprintHex: string;
      readonly sweep: SweepOutcome & { readonly skippedDeleted: readonly string[] };
    };

export type ApproveOutcome =
  | { readonly kind: "recorded"; readonly view: ProposalView }
  | {
      readonly kind: "applied";
      readonly seq: number;
      readonly proposal: PendingProposal;
      readonly fulfilment: Fulfilment;
    }
  | {
      readonly kind: "completed-by-other";
      readonly proposal: PendingProposal;
      readonly completedAtSeq: number;
    }
  | { readonly kind: "withdrawn-concurrently"; readonly proposal: PendingProposal };

/** The shape where a proposal targets the approver themself and applying it leaves the approver unable to fulfil the §7 obligations (K6-N). */
function selfObligationRejection(
  verified: VerifiedProject,
  inner: ProposableOperation,
  signerUserId: string,
): string | null {
  if (inner.op === "remove_member" && inner.payload.targetUserId === signerUserId) {
    return "This proposal removes you. Completing it would leave the post-removal rotation (CRYPTO_SPEC §7) to a member who no longer exists — ask another owner to approve it";
  }
  const self = verified.state.members.get(signerUserId);
  if (
    inner.op !== "change_role" ||
    inner.payload.targetUserId !== signerUserId ||
    self === undefined
  ) {
    return null;
  }
  // Demotion / scope narrowing is judged by the same single predicate as the self-obligation check of a direct append (member.ts)
  switch (
    selfObligationReason(verified, self, {
      role: inner.payload.newRole,
      scope: memberScopeOf(inner.payload),
    })
  ) {
    case "demotion":
      return "This proposal demotes you below member. Completing it would leave the post-demotion rotation (CRYPTO_SPEC §7) to you without the role to run it — ask another owner to approve it";
    case "scope-narrowing":
      return "This proposal narrows your own scope. Completing it would leave the rotation of the environments you leave (CRYPTO_SPEC §7) to you without access to them — ask another owner to approve it";
    case null:
      return null;
  }
}

/** The pre-check for approve (run again after a resync). */
function ensureApprovable(
  verified: VerifiedProject,
  proposalHashHex: string,
  signerUserId: string,
  signerFingerprintHex: string,
  nowMs: number,
): Effect.Effect<ProposalView, CliError> {
  const resolution = resolveProposalRef(verified, proposalHashHex);
  if (resolution.kind !== "pending") {
    return Effect.fail(cliError(describeUnresolvedRef(resolution)));
  }
  const view = proposalViewOf(verified, resolution.proposal, nowMs);
  const eligibility = voteEligibility(verified, signerUserId, signerFingerprintHex, view);
  if (!eligibility.ok) {
    return Effect.fail(cliError(`You cannot approve this proposal: ${eligibility.message}`));
  }
  const self = selfObligationRejection(verified, view.proposal.inner, signerUserId);
  return self === null ? Effect.succeed(view) : Effect.fail(cliError(self));
}

/** Fulfils the applied inner op (approval item 22 — the approver regardless of the inner op kind). */
function fulfil<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly seq: number;
  readonly inner: ProposableOperation;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly recipient: DekRecipient;
  readonly rotateWith: (reason: string) => SweepRotate<R>;
}): Effect.Effect<Fulfilment, CliError, R | CliIo> {
  return Effect.gen(function* () {
    const { inner, verified } = input;
    switch (inner.op) {
      case "remove_member": {
        const sweep = yield* sweepMemberMandates({
          client: input.client,
          verified,
          targetUserId: inner.payload.targetUserId,
          actorUserId: input.signerUserId,
          signingKeyPair: input.signingKeyPair,
          rotateWith: input.rotateWith,
        });
        return { kind: "member-rotation", targetUserId: inner.payload.targetUserId, sweep };
      }
      case "add_member": {
        const target = verified.state.members.get(inner.payload.targetUserId);
        if (target === undefined) {
          return yield* Effect.fail(
            cliError(
              "The resync after the completing approve does not show the added member on the chain (the server's response contradicts the chain). Investigate the served chain",
            ),
          );
        }
        const backfill = yield* backfillNewMember({
          client: input.client,
          verified,
          target,
          recipient: input.recipient,
          signerUserId: input.signerUserId,
          signingKeyPair: input.signingKeyPair,
        });
        return { kind: "member-backfill", targetUserId: target.userId, backfill };
      }
      case "change_role": {
        const target = verified.state.members.get(inner.payload.targetUserId);
        if (target === undefined) {
          return yield* Effect.fail(
            cliError(
              "The resync after the completing approve does not show the target as a member (the server's response contradicts the chain). Investigate the served chain",
            ),
          );
        }
        const change = yield* fulfilRoleChange({
          client: input.client,
          verified,
          target,
          signerUserId: input.signerUserId,
          signingKeyPair: input.signingKeyPair,
          recipient: input.recipient,
          rotateWith: input.rotateWith,
        });
        return { kind: "role-change", targetUserId: target.userId, change };
      }
      case "grant_server": {
        const grant = verified.state.serverGrants.get(inner.payload.serverKeyFingerprintHex);
        if (grant === undefined) {
          return yield* Effect.fail(
            cliError(
              "The resync after the completing approve does not show the grant (the server's response contradicts the chain). Investigate the served chain",
            ),
          );
        }
        const result = yield* backfillServerGrant({
          client: input.client,
          verified,
          grant,
          recipient: input.recipient,
          signerUserId: input.signerUserId,
          signingKeyPair: input.signingKeyPair,
        });
        return {
          kind: "server-backfill",
          serverKeyFingerprintHex: grant.serverKeyFingerprintHex,
          scopeEnvironmentIds: grant.scopeEnvironmentIds,
          ...result,
        };
      }
      case "revoke_server": {
        const sweep = yield* sweepAfterRevoke({
          client: input.client,
          verified,
          revokeSeq: input.seq,
          rotate: input.rotateWith("server-revoked"),
        });
        return {
          kind: "server-rotation",
          serverKeyFingerprintHex: inner.payload.serverKeyFingerprintHex,
          sweep,
        };
      }
      default:
        return { kind: "none" };
    }
  });
}

interface ApproveState {
  readonly verified: VerifiedProject;
  /** Set when the resync after a conflict shows the proposal no longer pending. */
  readonly closed:
    | { readonly kind: "completed"; readonly completedAtSeq: number }
    | { readonly kind: "withdrawn" }
    | null;
}

export function approveProposalOp<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly ref: string;
  readonly signerUserId: string;
  /** FP of the signing device (a vote's eligibility is the device's effective role — approval-rules.ts). */
  readonly signerFingerprintHex: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly rotateWith: (reason: string) => SweepRotate<R>;
  readonly nowMs: number;
}): Effect.Effect<ApproveOutcome, CliError, R | CliIo> {
  return Effect.gen(function* () {
    const first = yield* ensureApprovable(
      input.verified,
      input.ref,
      input.signerUserId,
      input.signerFingerprintHex,
      input.nowMs,
    );
    const proposal = first.proposal;
    let mySeq: number | null = null;
    const outcome = yield* retryOnConflict<ApproveState, ApproveState, "head-conflict">(
      { verified: input.verified, closed: null },
      {
        maxAttempts: MAX_ATTEMPTS,
        attempt: (state) =>
          state.closed !== null
            ? Effect.succeed(state)
            : Effect.gen(function* () {
                const entry = yield* signEntryAtHead({
                  verified: state.verified,
                  signerUserId: input.signerUserId,
                  operation: {
                    op: "approve",
                    payload: { proposalHashHex: proposal.proposalHashHex },
                  },
                  signingKeyPair: input.signingKeyPair,
                  failureText: "Failed to sign the approve entry",
                });
                mySeq = entry.seq;
                yield* appendEntry(input.client, state.verified, entry);
                return state;
              }),
        classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
        recover: (state) =>
          Effect.gen(function* () {
            const resynced = yield* resyncExtended(input.resync, state.verified);
            const status = proposalStatusOf(resynced, proposal.proposalHashHex);
            // Another owner completed / withdrew it first: re-signing and
            // sending anyway would only be rejected as unknown-proposal, so
            // stop here with a typed outcome (K6-B)
            if (status.kind === "completed" || status.kind === "withdrawn") {
              return { verified: resynced, closed: status };
            }
            yield* ensureApprovable(
              resynced,
              proposal.proposalHashHex,
              input.signerUserId,
              input.signerFingerprintHex,
              input.nowMs,
            );
            return { verified: resynced, closed: null };
          }),
        exhaustedMessage: `approve's chain-head conflict did not resolve (${MAX_ATTEMPTS} attempts). Wait a moment and re-run`,
      },
    );
    if (outcome.closed !== null) {
      return outcome.closed.kind === "completed"
        ? { kind: "completed-by-other", proposal, completedAtSeq: outcome.closed.completedAtSeq }
        : { kind: "withdrawn-concurrently", proposal };
    }

    // Learn the result from the post-acceptance resync (the server response does not carry whether it applied — K5-S)
    const verified = yield* resyncExtended(input.resync, outcome.verified);
    const status = proposalStatusOf(verified, proposal.proposalHashHex);
    if (status.kind === "pending") {
      const pending = verified.state.pendingProposals.get(proposal.proposalHashHex);
      if (pending === undefined) {
        return yield* Effect.fail(
          cliError("Pending proposal vanished between two reads (internal contradiction)"),
        );
      }
      return { kind: "recorded", view: proposalViewOf(verified, pending, input.nowMs) };
    }
    if (status.kind === "withdrawn") {
      return { kind: "withdrawn-concurrently", proposal };
    }
    if (status.kind === "unknown") {
      return yield* Effect.fail(
        cliError(
          "The resync after the approve entry was accepted no longer knows the proposal (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }
    const seq: number | null = mySeq;
    if (seq === null || status.completedAtSeq !== seq) {
      // Another owner's approve completed it after mine (my vote counted,
      // but that owner is the fulfiller)
      return { kind: "completed-by-other", proposal, completedAtSeq: status.completedAtSeq };
    }
    const io = yield* CliIo;
    yield* io.log(
      `Your approval reached the quorum: applied ${proposal.inner.op} at seq=${seq} (proposed by ${displayText(proposal.proposerUserId)}). You are the fulfiller of its obligations (CRYPTO_SPEC §7)`,
    );
    const fulfilment = yield* fulfil({
      client: input.client,
      verified,
      seq,
      inner: proposal.inner,
      signerUserId: input.signerUserId,
      signingKeyPair: input.signingKeyPair,
      recipient: input.recipient,
      rotateWith: input.rotateWith,
    });
    return { kind: "applied", seq, proposal, fulfilment };
  });
}
