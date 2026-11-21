import { type EnvironmentId, type UserId } from "@maruhi/core";
import type { PendingProposal, ProposableOperation, SigningKeyPair } from "@maruhi/crypto";
import { memberScopeOf } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import {
  describeUnresolvedRef,
  type ProposalView,
  proposalViewOf,
  resolveProposalRef,
  voteEligibility,
} from "../approval-rules.ts";
import { appendOperationWithRetry } from "../chain-append.ts";
import { resyncExtended, type VerifiedProject } from "../chain-sync.ts";
import type { DekRecipient } from "../deks.ts";
import { displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { CliIo } from "../io.ts";
import {
  backfillNewMember,
  fulfilRoleChange,
  type MemberAddSummary,
  type MemberSweepOutcome,
  type RoleChangeFulfilment,
  selfObligationReason,
  sweepMemberMandates,
} from "../member.package/index.ts";
import type { SweepOutcome, SweepRotate } from "../rotation-sweep.ts";
import { backfillServerGrant, sweepAfterRevoke } from "../server.package/index.ts";
import { proposalStatusOf } from "./approval.ts";

export type Fulfilment =
  | { readonly kind: "none" }
  | {
      readonly kind: "member-rotation";
      readonly targetUserId: UserId;
      readonly sweep: MemberSweepOutcome | null;
    }
  | {
      readonly kind: "member-backfill";
      readonly targetUserId: UserId;
      readonly backfill: Pick<
        MemberAddSummary,
        "registered" | "alreadyRegistered" | "repaired" | "failed"
      >;
    }
  | {
      readonly kind: "role-change";
      readonly targetUserId: UserId;
      readonly change: RoleChangeFulfilment;
    }
  | {
      readonly kind: "server-backfill";
      readonly serverKeyFingerprintHex: string;
      readonly scopeEnvironmentIds: readonly EnvironmentId[];
      readonly registered: number;
      readonly alreadyRegistered: number;
    }
  | {
      readonly kind: "server-rotation";
      readonly serverKeyFingerprintHex: string;
      readonly sweep: SweepOutcome & { readonly skippedDeleted: readonly string[] };
    };

type ApproveOutcome =
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

function selfObligationRejection(
  verified: VerifiedProject,
  inner: ProposableOperation,
  signerUserId: UserId,
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

function ensureApprovable(
  verified: VerifiedProject,
  proposalHashHex: string,
  signerUserId: UserId,
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

const fulfil = Effect.fn("approval-approve.fulfil")(function* <R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly seq: number;
  readonly inner: ProposableOperation;
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
  readonly recipient: DekRecipient;
  readonly rotateWith: (reason: string) => SweepRotate<R>;
}): Effect.fn.Return<Fulfilment, CliError, R | CliIo> {
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

interface ApproveState {
  readonly verified: VerifiedProject;
  readonly closed:
    | { readonly kind: "completed"; readonly completedAtSeq: number }
    | { readonly kind: "withdrawn" }
    | null;
}

export const approveProposalOp = Effect.fn("approval-approve.approveProposalOp")(function* <
  R,
>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly ref: string;
  readonly signerUserId: UserId;
  readonly signerFingerprintHex: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly rotateWith: (reason: string) => SweepRotate<R>;
  readonly nowMs: number;
}): Effect.fn.Return<ApproveOutcome, CliError, R | CliIo> {
  const first = yield* ensureApprovable(
    input.verified,
    input.ref,
    input.signerUserId,
    input.signerFingerprintHex,
    input.nowMs,
  );
  const proposal = first.proposal;
  const initial: ApproveState = { verified: input.verified, closed: null };
  const outcome = yield* appendOperationWithRetry(input, {
    operation: { op: "approve", payload: { proposalHashHex: proposal.proposalHashHex } },
    initial,
    settled: (state) => state.closed !== null,
    recheck: (resynced) =>
      Effect.gen(function* () {
        const status = proposalStatusOf(resynced, proposal.proposalHashHex);
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
  });
  const { closed } = outcome.state;
  if (closed !== null) {
    return closed.kind === "completed"
      ? { kind: "completed-by-other", proposal, completedAtSeq: closed.completedAtSeq }
      : { kind: "withdrawn-concurrently", proposal };
  }

  const verified = yield* resyncExtended(input.resync, outcome.state.verified);
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
  const seq = outcome.entry?.seq ?? null;
  if (seq === null || status.completedAtSeq !== seq) {
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
