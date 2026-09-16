// 四眼の提案・撤回・方針の追記(CRYPTO_SPEC §6.2 — PF1。設計録 es-design.md §12 K6-A / H / L)。
//
// - `proposeOperation`: 既存コマンド(member remove / change-role / add・server grant /
//   revoke・project policy approvals)が、検証済みチェーンの現方針が内側 op を対象に
//   していれば直接追記の代わりに呼ぶ共有核。**冪等**: 同じ内側 op の pending 提案が既に
//   あれば新たに提案せず、その提案の状態を返す(再実行が提案を増やさない)。CAS 競合の
//   再同期後も同じ判定を通す
// - 提案時には sweep / バックフィルを走らせない(適用前 — 裁定 P7 / 承認項目 21)。
//   履行は適用を完成させた承認者(approval-approve.ts)
// - 承認者側の履行(approve)は approval-approve.ts(member / server-grant / server-revoke
//   の後段を呼ぶため、ここから切り離して循環 import を避ける)

import { ChainHeadConflictError } from "@maruhi/api-schema";
import type {
  ApprovalTargetOp,
  ChainEntry,
  ProposableOperation,
  SigningKeyPair,
} from "@maruhi/crypto";
import { computeChainEntryHash } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import {
  describeUnresolvedRef,
  isApprovalTarget,
  type ProposalView,
  proposalViewOf,
  resolveProposalRef,
  sameOperation,
} from "./approval-rules.ts";
import { appendEntry, signEntryAtHead } from "./chain-append.ts";
import { proposalIndexOf } from "./chain-applied.ts";
import { cliError, type CliError } from "./errors.ts";
import { retryOnConflict } from "./retry.ts";
import { sameScope } from "./scope.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";

const MAX_ATTEMPTS = 5;

/** The outcome of proposing: a new proposal, or the one already pending for the same operation. */
export interface ProposedSummary {
  readonly kind: "proposed" | "already-pending";
  readonly view: ProposalView;
  readonly headSeq: number;
}

/** 同じ内側 op の pending 提案(冪等性 — K6-A)。複数あれば最初(seq 最小)。 */
export function findPendingSame(
  verified: VerifiedProject,
  inner: ProposableOperation,
): ProposalView["proposal"] | null {
  const same = [...verified.state.pendingProposals.values()]
    .filter((pending) => sameOperation(pending.inner, inner))
    .toSorted((a, b) => a.proposalSeq - b.proposalSeq);
  return same[0] ?? null;
}

/** 方針が有効化 / 無効化されて追記の形(直接 / 提案)が変わったときの fail-closed(K6-A)。 */
export function ensureStillTarget(
  verified: VerifiedProject,
  inner: ProposableOperation,
  expected: boolean,
): Effect.Effect<void, CliError> {
  return isApprovalTarget(inner, verified.state.approvalPolicy) === expected
    ? Effect.void
    : Effect.fail(
        cliError(
          "The four-eyes policy changed while this command was appending (the operation switched between a direct append and a proposal) — re-run to apply the new policy",
        ),
      );
}

interface ProposeState {
  readonly verified: VerifiedProject;
  readonly existing: ProposalView["proposal"] | null;
}

/**
 * `propose` エントリの追記(親ヘッド CAS リトライ)。`recheck` は呼び出し側の追記前検査
 * (再同期後にも同じ検査を通す — 中断復旧の既存規律)。受理後は再同期して pending に
 * 載ったことを確認する(サーバー申告を真実源にしない)。
 */
export function proposeOperation(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly inner: ProposableOperation;
  readonly expiresAtMs: number;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly recheck: (verified: VerifiedProject) => Effect.Effect<void, CliError>;
  readonly nowMs: number;
}): Effect.Effect<ProposedSummary, CliError> {
  return Effect.gen(function* () {
    const existing = findPendingSame(input.verified, input.inner);
    if (existing !== null) {
      return {
        kind: "already-pending",
        view: proposalViewOf(input.verified, existing, input.nowMs),
        headSeq: input.verified.state.headSeq,
      };
    }
    let signed: ChainEntry | null = null;
    const outcome = yield* retryOnConflict<ProposeState, ProposeState, "head-conflict">(
      { verified: input.verified, existing: null },
      {
        maxAttempts: MAX_ATTEMPTS,
        attempt: (state) =>
          state.existing !== null
            ? Effect.succeed(state)
            : Effect.gen(function* () {
                const entry = yield* signEntryAtHead({
                  verified: state.verified,
                  signerUserId: input.signerUserId,
                  operation: {
                    op: "propose",
                    payload: { inner: input.inner, expiresAtMs: input.expiresAtMs },
                  },
                  signingKeyPair: input.signingKeyPair,
                  failureText: "Failed to sign the propose entry",
                });
                signed = entry;
                yield* appendEntry(input.client, state.verified, entry);
                return state;
              }),
        classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
        recover: (state) =>
          Effect.gen(function* () {
            const resynced = yield* resyncExtended(input.resync, state.verified);
            yield* ensureStillTarget(resynced, input.inner, true);
            yield* input.recheck(resynced);
            return { verified: resynced, existing: findPendingSame(resynced, input.inner) };
          }),
        exhaustedMessage: `propose's chain-head conflict did not resolve (${MAX_ATTEMPTS} attempts). Wait a moment and re-run`,
      },
    );
    const verified = yield* resyncExtended(input.resync, outcome.verified);
    if (outcome.existing !== null) {
      const pending = verified.state.pendingProposals.get(outcome.existing.proposalHashHex);
      if (pending === undefined) {
        return yield* Effect.fail(
          cliError(
            "A concurrent run proposed the same operation, but the resync no longer shows it as pending — re-run to see the current state (`maruhi approval list`)",
          ),
        );
      }
      return {
        kind: "already-pending",
        view: proposalViewOf(verified, pending, input.nowMs),
        headSeq: verified.state.headSeq,
      };
    }
    const entry: ChainEntry | null = signed;
    if (entry === null) {
      return yield* Effect.fail(
        cliError("The propose entry was not signed (internal contradiction)"),
      );
    }
    const hash = yield* Effect.tryPromise({
      try: () => computeChainEntryHash(entry),
      catch: () => cliError("Failed to compute the proposal hash (crypto error)"),
    });
    const pending = verified.state.pendingProposals.get(hash);
    if (pending === undefined) {
      return yield* Effect.fail(
        cliError(
          "The resync after the propose entry was accepted does not show the proposal as pending (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }
    return {
      kind: "proposed",
      view: proposalViewOf(verified, pending, input.nowMs),
      headSeq: verified.state.headSeq,
    };
  });
}

// ---------------------------------------------------------------------------
// withdraw
// ---------------------------------------------------------------------------

export interface WithdrawSummary {
  readonly proposalHashHex: string;
  readonly proposalSeq: number;
  readonly proposerUserId: string;
  /** Closed by an owner who is not the proposer (K6-L の Note). */
  readonly closedByOtherOwner: boolean;
}

/** withdraw の前検査(§6.2 — 提案者または owner)。再同期後にも通す。 */
function ensureWithdrawable(
  verified: VerifiedProject,
  ref: string,
  signerUserId: string,
): Effect.Effect<ProposalView["proposal"], CliError> {
  const resolution = resolveProposalRef(verified, ref);
  if (resolution.kind !== "pending") {
    return Effect.fail(cliError(describeUnresolvedRef(resolution)));
  }
  const actor = verified.state.members.get(signerUserId);
  if (actor === undefined) {
    return Effect.fail(cliError("You are not a chain-derived member of this project"));
  }
  if (actor.role !== "owner" && resolution.proposal.proposerUserId !== signerUserId) {
    return Effect.fail(
      cliError(
        "Only the proposer or an owner can withdraw a proposal (CRYPTO_SPEC §6.2). Ask the proposer or an owner to withdraw it",
      ),
    );
  }
  return Effect.succeed(resolution.proposal);
}

export function withdrawProposalOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly ref: string;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}): Effect.Effect<WithdrawSummary, CliError> {
  return Effect.gen(function* () {
    const first = yield* ensureWithdrawable(input.verified, input.ref, input.signerUserId);
    const outcome = yield* retryOnConflict<VerifiedProject, VerifiedProject, "head-conflict">(
      input.verified,
      {
        maxAttempts: MAX_ATTEMPTS,
        attempt: (view) =>
          Effect.gen(function* () {
            const entry = yield* signEntryAtHead({
              verified: view,
              signerUserId: input.signerUserId,
              operation: { op: "withdraw", payload: { proposalHashHex: first.proposalHashHex } },
              signingKeyPair: input.signingKeyPair,
              failureText: "Failed to sign the withdraw entry",
            });
            yield* appendEntry(input.client, view, entry);
            return view;
          }),
        classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
        recover: (view) =>
          Effect.gen(function* () {
            const resynced = yield* resyncExtended(input.resync, view);
            // 並行して完成 / 撤回されていればここで型付きに止まる(unknown-proposal を送らない)
            yield* ensureWithdrawable(resynced, first.proposalHashHex, input.signerUserId);
            return resynced;
          }),
        exhaustedMessage: `withdraw's chain-head conflict did not resolve (${MAX_ATTEMPTS} attempts). Wait a moment and re-run`,
      },
    );
    const verified = yield* resyncExtended(input.resync, outcome);
    if (verified.state.pendingProposals.has(first.proposalHashHex)) {
      return yield* Effect.fail(
        cliError(
          "The resync after the withdraw entry was accepted still shows the proposal as pending (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }
    return {
      proposalHashHex: first.proposalHashHex,
      proposalSeq: first.proposalSeq,
      proposerUserId: first.proposerUserId,
      closedByOtherOwner: first.proposerUserId !== input.signerUserId,
    };
  });
}

// ---------------------------------------------------------------------------
// set_approval_policy(`maruhi project policy approvals` — K6-H)
// ---------------------------------------------------------------------------

/** The requested policy: `off`, or `on` with the required count and the targeted ops (sorted, deduplicated). */
export type PolicyRequest =
  | { readonly kind: "off" }
  | {
      readonly kind: "on";
      readonly requiredApprovals: number;
      readonly ops: readonly ApprovalTargetOp[];
    };

export type PolicyOutcome =
  | { readonly kind: "unchanged" }
  | { readonly kind: "applied"; readonly headSeq: number }
  | { readonly kind: "proposed"; readonly proposal: ProposedSummary };

function policyOperation(request: PolicyRequest): ProposableOperation {
  return request.kind === "off"
    ? { op: "set_approval_policy", payload: { ops: [], requiredApprovals: 0 } }
    : {
        op: "set_approval_policy",
        payload: { ops: request.ops, requiredApprovals: request.requiredApprovals },
      };
}

function ownersOf(verified: VerifiedProject): readonly string[] {
  return [...verified.state.members.values()]
    .filter((member) => member.role === "owner")
    .map((member) => member.userId);
}

/** 方針の追記前検査(owner・到達可能性の予告・no-op の検出)。再同期後にも通す。 */
function ensurePolicySettable(
  verified: VerifiedProject,
  request: PolicyRequest,
  signerUserId: string,
): Effect.Effect<{ readonly unchanged: boolean }, CliError> {
  const actor = verified.state.members.get(signerUserId);
  if (actor === undefined || actor.role !== "owner") {
    return Effect.fail(
      cliError("Only an owner can change the four-eyes approval policy (CRYPTO_SPEC §6.2)"),
    );
  }
  const current = verified.state.approvalPolicy;
  if (request.kind === "off") {
    return Effect.succeed({ unchanged: current === null });
  }
  const owners = ownersOf(verified);
  if (owners.length < request.requiredApprovals) {
    return Effect.fail(
      cliError(
        `The project has ${owners.length} owner${owners.length === 1 ? "" : "s"}, fewer than the ${request.requiredApprovals} required approvals — the chain would reject this policy (CRYPTO_SPEC §6.2 approval-quorum-unreachable). Add owners first (or lower --required)`,
      ),
    );
  }
  const unchanged =
    current !== null &&
    current.requiredApprovals === request.requiredApprovals &&
    sameScope(
      { kind: "listed", environmentIds: [...current.ops] },
      { kind: "listed", environmentIds: [...request.ops] },
    );
  return Effect.succeed({ unchanged });
}

export function setApprovalPolicyOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly request: PolicyRequest;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly expiresAtMs: number;
  readonly nowMs: number;
}): Effect.Effect<PolicyOutcome, CliError> {
  return Effect.gen(function* () {
    const first = yield* ensurePolicySettable(input.verified, input.request, input.signerUserId);
    if (first.unchanged) {
      return { kind: "unchanged" };
    }
    const operation = policyOperation(input.request);
    // 方針が有効な間は set_approval_policy 自身が常時対象(§6.2「方針」)
    if (isApprovalTarget(operation, input.verified.state.approvalPolicy)) {
      const proposal = yield* proposeOperation({
        client: input.client,
        verified: input.verified,
        signerUserId: input.signerUserId,
        signingKeyPair: input.signingKeyPair,
        inner: operation,
        expiresAtMs: input.expiresAtMs,
        resync: input.resync,
        recheck: (view) =>
          ensurePolicySettable(view, input.request, input.signerUserId).pipe(Effect.asVoid),
        nowMs: input.nowMs,
      });
      return { kind: "proposed", proposal };
    }
    const appended = yield* retryOnConflict<VerifiedProject, VerifiedProject, "head-conflict">(
      input.verified,
      {
        maxAttempts: MAX_ATTEMPTS,
        attempt: (view) =>
          Effect.gen(function* () {
            const entry = yield* signEntryAtHead({
              verified: view,
              signerUserId: input.signerUserId,
              operation,
              signingKeyPair: input.signingKeyPair,
              failureText: "Failed to sign the set_approval_policy entry",
            });
            yield* appendEntry(input.client, view, entry);
            return view;
          }),
        classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
        recover: (view) =>
          Effect.gen(function* () {
            const resynced = yield* resyncExtended(input.resync, view);
            yield* ensureStillTarget(resynced, operation, false);
            const rechecked = yield* ensurePolicySettable(
              resynced,
              input.request,
              input.signerUserId,
            );
            if (rechecked.unchanged) {
              return yield* Effect.fail(
                cliError(
                  "A concurrent run already set the same policy — nothing to do (check with `maruhi project policy approvals`)",
                ),
              );
            }
            return resynced;
          }),
        exhaustedMessage: `set_approval_policy's chain-head conflict did not resolve (${MAX_ATTEMPTS} attempts). Wait a moment and re-run`,
      },
    );
    const verified = yield* resyncExtended(input.resync, appended);
    const rechecked = yield* ensurePolicySettable(verified, input.request, input.signerUserId);
    if (!rechecked.unchanged) {
      return yield* Effect.fail(
        cliError(
          "The resync after set_approval_policy was accepted does not show the new policy (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }
    return { kind: "applied", headSeq: verified.state.headSeq };
  });
}

/** 完成済み / 撤回済み / pending の判別(approve の競合処理が使う — K6-B)。 */
export function proposalStatusOf(
  verified: VerifiedProject,
  proposalHashHex: string,
):
  | { readonly kind: "pending" }
  | { readonly kind: "completed"; readonly completedAtSeq: number }
  | { readonly kind: "withdrawn" }
  | { readonly kind: "unknown" } {
  if (verified.state.pendingProposals.has(proposalHashHex)) {
    return { kind: "pending" };
  }
  const indexed = proposalIndexOf(verified).get(proposalHashHex);
  if (indexed === undefined) {
    return { kind: "unknown" };
  }
  return indexed.completedAtSeq === null
    ? { kind: "withdrawn" }
    : { kind: "completed", completedAtSeq: indexed.completedAtSeq };
}
