// `maruhi approval approve <id>`(CRYPTO_SPEC §6.2 / §7 — PF1。設計録 es-design.md §12 K6-B / N)。
//
// approve を追記し、再同期した検証済みチェーンで結果を知る(サーバー応答は適用の有無を
// 運ばない — K5-S (1)): (i) 提案が pending に残る = 票を記録した、(ii) pending から消え、
// core の `indexProposals` の完成 seq が自分の approve の seq = 自分が完成させた =
// **履行者**(承認項目 22 / CRYPTO_SPEC §7)。履行は内側 op の種類ごとに、直接追記の
// 後段と同じ関数を呼ぶ: remove / 降格 / 縮小 = sweep(rotate 義務)、add_member /
// scope 拡大 = メンバー宛バックフィル、grant_server = サーバー宛バックフィル、
// revoke_server = 全環境の sweep。set_approval_policy = なし。未完成の approve では
// 何も履行しない。
//
// 通信前検査(K5-S / K5-L): duplicate-approval(自分の (user_id, 現鍵 FP) が S にある)・
// approval-not-required(方針変更で対象外)・proposal-expired(自分の時計)を予告する。
// 承認者自身を対象にする提案(自分の remove / member 未満への降格)は、完成させると
// 履行者が消えるため拒否し、別の owner に承認を頼むよう案内する(K6-N)。

import { ChainHeadConflictError } from "@maruhi/api-schema";
import type { PendingProposal, ProposableOperation, SigningKeyPair } from "@maruhi/crypto";
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
import { ROLE_RANK } from "./dek-wrap.ts";
import type { DekRecipient } from "./deks.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import {
  backfillNewMember,
  fulfilRoleChange,
  type MemberAddSummary,
  type MemberSweepOutcome,
  type RoleChangeFulfilment,
  sweepMemberMandates,
} from "./member.ts";
import { retryOnConflict } from "./retry.ts";
import type { SweepOutcome, SweepRotate } from "./rotation-sweep.ts";
import { backfillServerGrant } from "./server-grant.ts";
import { sweepAfterRevoke } from "./server-revoke.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";

const MAX_ATTEMPTS = 5;

/** What the completing approver's client did after the inner op was applied (承認項目 22). */
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

/** 承認者自身を対象にする提案で、適用後に承認者が §7 の義務を履行できなくなる形(K6-N)。 */
function selfObligationRejection(
  verified: VerifiedProject,
  inner: ProposableOperation,
  signerUserId: string,
): string | null {
  if (inner.op === "remove_member" && inner.payload.targetUserId === signerUserId) {
    return "This proposal removes you. Completing it would leave the post-removal rotation (CRYPTO_SPEC §7) to a member who no longer exists — ask another owner to approve it";
  }
  if (
    inner.op === "change_role" &&
    inner.payload.targetUserId === signerUserId &&
    ROLE_RANK[inner.payload.newRole] < ROLE_RANK.member &&
    (verified.state.members.get(signerUserId)?.role ?? "reader") !== "reader"
  ) {
    return "This proposal demotes you below member. Completing it would leave the post-demotion rotation (CRYPTO_SPEC §7) to you without the role to run it — ask another owner to approve it";
  }
  return null;
}

/** approve の前検査(再同期後にも通す)。 */
function ensureApprovable(
  verified: VerifiedProject,
  proposalHashHex: string,
  signerUserId: string,
  nowMs: number,
): Effect.Effect<ProposalView, CliError> {
  const resolution = resolveProposalRef(verified, proposalHashHex);
  if (resolution.kind !== "pending") {
    return Effect.fail(cliError(describeUnresolvedRef(resolution)));
  }
  const view = proposalViewOf(verified, resolution.proposal, nowMs);
  const eligibility = voteEligibility(verified, signerUserId, view);
  if (!eligibility.ok) {
    return Effect.fail(cliError(`You cannot approve this proposal: ${eligibility.message}`));
  }
  const self = selfObligationRejection(verified, view.proposal.inner, signerUserId);
  return self === null ? Effect.succeed(view) : Effect.fail(cliError(self));
}

/** 適用済みの内側 op の履行(承認項目 22 — 内側 op の種類を問わず承認者)。 */
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
            // 他の owner が先に完成させた / 撤回した: そのまま再署名して送っても
            // unknown-proposal で拒否されるだけなので、ここで型付きに止まる(K6-B)
            if (status.kind === "completed" || status.kind === "withdrawn") {
              return { verified: resynced, closed: status };
            }
            yield* ensureApprovable(
              resynced,
              proposal.proposalHashHex,
              input.signerUserId,
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

    // 受理後の再同期で結果を知る(サーバー応答は適用の有無を運ばない — K5-S)
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
      // 自分の approve の後に別 owner の approve が完成させた(自分の票は数えられたが、
      // 履行者はその owner)
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
