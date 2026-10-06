// Appends for four-eyes propose / withdraw / policy (CRYPTO_SPEC §6.2 —
// PF1; design record es-design.md §12 K6-A / H / L).
//
// - `proposeOperation`: the shared core the existing commands (member
//   remove / change-role / add, server grant / revoke, project policy
//   approvals) call instead of a direct append when the verified chain's
//   current policy targets the inner op. **Idempotent**: when a pending
//   proposal for the same inner op already exists, it does not propose anew
//   and returns that proposal's state (a re-run does not add proposals).
//   The same check runs after the resync of a CAS conflict
// - No sweep / backfill runs at proposal time (before apply — ruling P7 /
//   approval item 21). Fulfilment belongs to the approver who completes the
//   apply (approval-approve.ts)
// - The approver-side fulfilment (approve) lives in approval-approve.ts (it
//   calls the post-stages of member / server-grant / server-revoke, so it
//   is split off here to avoid circular imports)

import { ChainHeadConflictError } from "@maruhi/api-schema";
import { cryptoPromise } from "@maruhi/core";
import type {
  ApprovalTargetOp,
  ChainEntry,
  ProposableOperation,
  Role,
  SigningKeyPair,
} from "@maruhi/crypto";
import { computeChainEntryHash, effectivePermissionOf } from "@maruhi/crypto";
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
import { resyncExtended, type VerifiedProject } from "./chain-sync.ts";
import { ownDeviceBySigningKey } from "./device-key.ts";
import { cliError, type CliError } from "./errors.ts";
import { retryOnConflict } from "./retry.ts";
import { sameScope } from "./scope.ts";

const MAX_ATTEMPTS = 5;

/** The outcome of proposing: a new proposal, or the one already pending for the same operation. */
export interface ProposedSummary {
  readonly kind: "proposed" | "already-pending";
  readonly view: ProposalView;
  readonly headSeq: number;
}

/** The inputs proposing requires (expiry and clock — design record K6-K). */
export interface ProposalInput {
  readonly expiresAtMs: number;
  readonly nowMs: number;
}

/** The context held by the side appending a proposal (a subtype of each op's input — callers can pass theirs as-is). */
export interface ProposeContext {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly proposal: ProposalInput;
}

/** A pending proposal for the same inner op (idempotency — K6-A). If several, the first (smallest seq). */
function findPendingSame(
  verified: VerifiedProject,
  inner: ProposableOperation,
): ProposalView["proposal"] | null {
  const same = [...verified.state.pendingProposals.values()]
    .filter((pending) => sameOperation(pending.inner, inner))
    .toSorted((a, b) => a.proposalSeq - b.proposalSeq);
  return same[0] ?? null;
}

/** fail-closed when a policy was enabled / disabled and the append shape (direct / proposal) changed (K6-A). */
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
 * Appends a `propose` entry (parent-head CAS retry). `recheck` is the
 * caller's pre-append check (the same check runs after a resync — the
 * existing interrupted-recovery discipline). After acceptance it resyncs
 * and confirms the proposal is on pending (does not make the server's
 * claim the source of truth).
 */
export function proposeOperation(
  input: ProposeContext,
  inner: ProposableOperation,
  recheck: (verified: VerifiedProject) => Effect.Effect<void, CliError>,
): Effect.Effect<ProposedSummary, CliError> {
  return Effect.gen(function* () {
    const { expiresAtMs, nowMs } = input.proposal;
    const existing = findPendingSame(input.verified, inner);
    if (existing !== null) {
      return {
        kind: "already-pending",
        view: proposalViewOf(input.verified, existing, nowMs),
        headSeq: input.verified.state.headSeq,
      };
    }
    let signed: ChainEntry | null = null;
    const initial: ProposeState = { verified: input.verified, existing: null };
    const outcome = yield* retryOnConflict(initial, {
      maxAttempts: MAX_ATTEMPTS,
      attempt: (state) =>
        state.existing !== null
          ? Effect.succeed(state)
          : Effect.gen(function* () {
              const entry = yield* signEntryAtHead({
                verified: state.verified,
                signerUserId: input.signerUserId,
                operation: { op: "propose", payload: { inner, expiresAtMs } },
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
          yield* ensureStillTarget(resynced, inner, true);
          yield* recheck(resynced);
          return { verified: resynced, existing: findPendingSame(resynced, inner) };
        }),
      exhaustedMessage: `propose's chain-head conflict did not resolve (${MAX_ATTEMPTS} attempts). Wait a moment and re-run`,
    });
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
        view: proposalViewOf(verified, pending, nowMs),
        headSeq: verified.state.headSeq,
      };
    }
    const entry: ChainEntry | null = signed;
    if (entry === null) {
      return yield* Effect.fail(
        cliError("The propose entry was not signed (internal contradiction)"),
      );
    }
    const hash = yield* cryptoPromise("computeChainEntryHash", () =>
      computeChainEntryHash(entry),
    ).pipe(Effect.mapError(() => cliError("Failed to compute the proposal hash (crypto error)")));
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
      view: proposalViewOf(verified, pending, nowMs),
      headSeq: verified.state.headSeq,
    };
  });
}

/**
 * Re-checks the proposing path (after the resync of a CAS conflict): runs
 * the caller's pre-append check and, when a concurrent run already applied
 * the same change (`already`), stops without proposing (K6-A).
 */
export function proposeRecheck<A>(
  check: (verified: VerifiedProject) => Effect.Effect<A, CliError>,
  already: (checked: A) => boolean,
  appliedMessage: string,
): (verified: VerifiedProject) => Effect.Effect<A, CliError> {
  return (verified) =>
    check(verified).pipe(
      Effect.flatMap((checked) =>
        already(checked) ? Effect.fail(cliError(appliedMessage)) : Effect.succeed(checked),
      ),
    );
}

// ---------------------------------------------------------------------------
// withdraw
// ---------------------------------------------------------------------------

export interface WithdrawSummary {
  readonly proposalHashHex: string;
  readonly proposalSeq: number;
  readonly proposerUserId: string;
  /** Closed by an owner who is not the proposer (the K6-L Note). */
  readonly closedByOtherOwner: boolean;
}

/** The pre-check for withdraw (§6.2 — the proposer or an owner). Run again after a resync. */
function ensureWithdrawable(
  verified: VerifiedProject,
  ref: string,
  signerUserId: string,
  signingKeyPair: SigningKeyPair,
): Effect.Effect<ProposalView["proposal"], CliError> {
  const resolution = resolveProposalRef(verified, ref);
  if (resolution.kind !== "pending") {
    return Effect.fail(cliError(describeUnresolvedRef(resolution)));
  }
  const actor = verified.state.members.get(signerUserId);
  if (actor === undefined) {
    return Effect.fail(cliError("You are not a chain-derived member of this project"));
  }
  // Consensus is judged by effective permission (person ∩ device cap — §6.2 effectivePermissionOf)
  return Effect.flatMap(ownDeviceBySigningKey(verified, actor, signingKeyPair), (device) =>
    effectivePermissionOf(actor, device).role !== "owner" &&
    resolution.proposal.proposerUserId !== signerUserId
      ? Effect.fail(
          cliError(
            "Only the proposer or an owner can withdraw a proposal (CRYPTO_SPEC §6.2). Ask the proposer or an owner to withdraw it",
          ),
        )
      : Effect.succeed(resolution.proposal),
  );
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
    const first = yield* ensureWithdrawable(
      input.verified,
      input.ref,
      input.signerUserId,
      input.signingKeyPair,
    );
    const outcome = yield* retryOnConflict(input.verified, {
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
          // If it was concurrently completed / withdrawn, stop here with a typed outcome (do not send an unknown-proposal)
          yield* ensureWithdrawable(
            resynced,
            first.proposalHashHex,
            input.signerUserId,
            input.signingKeyPair,
          );
          return resynced;
        }),
      exhaustedMessage: `withdraw's chain-head conflict did not resolve (${MAX_ATTEMPTS} attempts). Wait a moment and re-run`,
    });
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

/** The pre-append check for policy (owner, reachability foretell, no-op detection). Run again after a resync. */
function ensurePolicySettable(
  verified: VerifiedProject,
  request: PolicyRequest,
  signerUserId: string,
  signingKeyPair: SigningKeyPair,
): Effect.Effect<{ readonly unchanged: boolean }, CliError> {
  const actor = verified.state.members.get(signerUserId);
  if (actor === undefined) {
    return Effect.fail(
      cliError("Only an owner can change the four-eyes approval policy (CRYPTO_SPEC §6.2)"),
    );
  }
  return Effect.flatMap(ownDeviceBySigningKey(verified, actor, signingKeyPair), (device) =>
    ensurePolicySettableWith(verified, request, effectivePermissionOf(actor, device)),
  );
}

/** The inside of the policy check at effective permission (the rules other than owner do not change). */
function ensurePolicySettableWith(
  verified: VerifiedProject,
  request: PolicyRequest,
  permission: { readonly role: Role },
): Effect.Effect<{ readonly unchanged: boolean }, CliError> {
  if (permission.role !== "owner") {
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
  readonly proposal: ProposalInput;
}): Effect.Effect<PolicyOutcome, CliError> {
  return Effect.gen(function* () {
    const first = yield* ensurePolicySettable(
      input.verified,
      input.request,
      input.signerUserId,
      input.signingKeyPair,
    );
    if (first.unchanged) {
      return { kind: "unchanged" };
    }
    const operation = policyOperation(input.request);
    // While a policy is enabled, set_approval_policy itself is an always-target (§6.2 "policy")
    if (isApprovalTarget(operation, input.verified.state.approvalPolicy)) {
      // Do not propose when the same policy was already applied after the resync (Cursor Bugbot finding — a redundant proposal)
      const proposal = yield* proposeOperation(
        input,
        operation,
        proposeRecheck(
          (view) =>
            ensurePolicySettable(view, input.request, input.signerUserId, input.signingKeyPair),
          (checked) => checked.unchanged,
          "A concurrent run already set the same policy — nothing to propose (check with `maruhi project policy approvals`)",
        ),
      );
      return { kind: "proposed", proposal };
    }
    const appended = yield* retryOnConflict(input.verified, {
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
            input.signingKeyPair,
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
    });
    const verified = yield* resyncExtended(input.resync, appended);
    const rechecked = yield* ensurePolicySettable(
      verified,
      input.request,
      input.signerUserId,
      input.signingKeyPair,
    );
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

/** Distinguishes completed / withdrawn / pending (used by approve's conflict handling — K6-B). */
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
