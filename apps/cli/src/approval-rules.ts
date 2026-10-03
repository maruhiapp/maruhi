// CLI-side pure functions for four-eyes (CRYPTO_SPEC §6.2 — PF1; design
// record es-design.md §12 K6-F / G / K / O).
//
// - The target check `isApprovalTarget` and the vote re-tally
//   `countOwnerVotes` are the CLI's second implementation of crypto's
//   consensus rules (private functions in chain-verify.ts). They are derived
//   from the public API (`APPROVAL_TARGET_OPS` / `ApprovalPolicy` /
//   `PendingProposal` / `ApprovalVote` / `ChainMember`) without copying the
//   internals (the same shape as K4-I's inclusion predicate). A divergence
//   is caught by the consensus rule's 422 as the final arbiter, and the
//   differential test against `verifyChain` (approval-rules.test.ts) catches
//   regressions. Consider making them public API the next time crypto is
//   touched (K6-Q handoff)
// - The vote count does not echo the record (`PendingProposal.approvals`)
//   verbatim — **it is re-tallied under the current policy and current
//   members** (the record keeps revoked votes — design record §8 K2
//   implementation memo)
// - A proposal's identifier is only the proposal entry's entry_hash (hex
//   64); the CLI invents no alias. It accepts a unique prefix of at least
//   the first 8 characters (approval item 23)

import {
  APPROVAL_TARGET_OPS,
  type ApprovalPolicy,
  type ApprovalTargetOp,
  type ApprovalVote,
  canonicalChainPayloadBytes,
  type ChainMember,
  effectivePermissionOf,
  type PendingProposal,
  type ProposableOperation,
} from "@maruhi/crypto";

import { proposalIndexOf } from "./chain-applied.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { displayText, formatUtcMinutes } from "./display.ts";
import { describeScope } from "./scope.ts";

const MS_PER_MINUTE = 60_000;
const MS_PER_HOUR = 60 * MS_PER_MINUTE;
const MS_PER_DAY = 24 * MS_PER_HOUR;

/** Default proposal lifetime (ruling P6 — 7 days). */
export const DEFAULT_PROPOSAL_LIFETIME_MS = 7 * MS_PER_DAY;
/** Server acceptance-policy upper bound of `expires_at_ms` (CRYPTO_SPEC §6.4 — 30 days). */
export const MAX_PROPOSAL_LIFETIME_MS = 30 * MS_PER_DAY;

/** Default `--ops` set when a policy is enabled (approval item 17 — the recommended default set). */
export const DEFAULT_POLICY_OPS: readonly ApprovalTargetOp[] = [
  "change_role",
  "grant_server",
  "remove_member",
  "set_approval_policy",
];

/** Shortest proposal-id prefix accepted on the command line (approval item 23). */
const MIN_PROPOSAL_REF_LENGTH = 8;

// ---------------------------------------------------------------------------
// Target check and vote re-tally (the CLI-side copy of the §6.2 principle 2)
// ---------------------------------------------------------------------------

/** Whether `value` names an operation a policy may list in `ops` (closed set — CRYPTO_SPEC §6.2). */
export function isApprovalTargetOp(value: string): value is ApprovalTargetOp {
  return APPROVAL_TARGET_OPS.some((op) => op === value);
}

/** add_member / change_role that establish an owner role (always-targets, per policy monotonicity (a)). */
function establishesOwner(operation: ProposableOperation): boolean {
  return (
    (operation.op === "add_member" && operation.payload.role === "owner") ||
    (operation.op === "change_role" && operation.payload.newRole === "owner")
  );
}

/**
 * The four-eyes target check (§6.2): a policy is enabled and the op is
 * either listed in `ops` or an always-target (`set_approval_policy` itself
 * and add_member / change_role that establish an owner). The CLI-side copy
 * of the single predicate shared by `propose` / `approve` / direct-append
 * refusal.
 */
export function isApprovalTarget(
  operation: ProposableOperation,
  policy: ApprovalPolicy | null,
): boolean {
  if (policy === null) {
    return false;
  }
  if (operation.op === "set_approval_policy" || establishesOwner(operation)) {
    return true;
  }
  return isApprovalTargetOp(operation.op) && policy.ops.includes(operation.op);
}

/**
 * Principle 2 (§6.2) signer set S = {proposers who proposed as owner} ∪
 * {actors of accepted approves}. Elements are (user_id, key FP at signing).
 * A proposer who proposed as admin does not enter S (they can append an
 * approve after being promoted — 2026-09-15 ruling ②).
 */
export function signersOf(pending: PendingProposal): readonly ApprovalVote[] {
  const proposer: readonly ApprovalVote[] =
    pending.proposerRoleAtProposal === "owner"
      ? [{ userId: pending.proposerUserId, keyFingerprintHex: pending.proposerKeyFingerprintHex }]
      : [];
  return [...proposer, ...pending.approvals];
}

/** Whether the vote's device is currently a valid device of that person (§6.2 "the device vocabulary of an approve vote" — 2026-09-19 DK). */
function voteIsLive(members: ReadonlyMap<string, ChainMember>, signer: ApprovalVote): boolean {
  return members.get(signer.userId)?.devices.has(signer.keyFingerprintHex) === true;
}

/**
 * Whether the device's effective role is owner (§6.2 "the device vocabulary
 * of an approve vote"). Foretelling (eligibleApprovers / voteEligibility)
 * and tallying (countedVoters) read the same predicate — so the foretell
 * layer and the tally layer cannot disagree on a capped device (PR #186
 * pullfrog finding). The K2 CLI has one device, so "any device" = that
 * device. K4 narrows it to the signing device (the key at hand)
 */
function ownerOnAnyDevice(member: ChainMember): boolean {
  return [...member.devices.values()].some(
    (device) => effectivePermissionOf(member, device).role === "owner",
  );
}

/**
 * Among S's elements, the distinct user_id whose FP is currently a valid
 * device of a current owner and whose device's effective role is owner
 * (another device of the same person is one vote — §6.2).
 */
function countedVoters(
  members: ReadonlyMap<string, ChainMember>,
  signers: readonly ApprovalVote[],
): readonly string[] {
  const voters = new Set<string>();
  for (const signer of signers) {
    const member = members.get(signer.userId);
    const device = member?.devices.get(signer.keyFingerprintHex);
    if (
      member !== undefined &&
      device !== undefined &&
      effectivePermissionOf(member, device).role === "owner"
    ) {
      voters.add(signer.userId);
    }
  }
  return [...voters].toSorted();
}

/** Vote count = |S ∩ owners at apply time| (principle 2 — votes by voters who left, were demoted, or rotated keys are not counted). */
export function countOwnerVotes(
  members: ReadonlyMap<string, ChainMember>,
  signers: readonly ApprovalVote[],
): number {
  return countedVoters(members, signers).length;
}

/** Whether the actor's user_id holds a live vote in S (a signature by a currently valid device) (the `duplicate-approval` foretell). */
function hasVoted(
  members: ReadonlyMap<string, ChainMember>,
  pending: PendingProposal,
  member: ChainMember,
): boolean {
  return signersOf(pending).some(
    (signer) => signer.userId === member.userId && voteIsLive(members, signer),
  );
}

/** Whether two operations are the same (match on op and normalized payload_bytes — used to judge proposal idempotency. K6-A). */
export function sameOperation(a: ProposableOperation, b: ProposableOperation): boolean {
  if (a.op !== b.op) {
    return false;
  }
  const left = canonicalChainPayloadBytes(a);
  const right = canonicalChainPayloadBytes(b);
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

// ---------------------------------------------------------------------------
// Display views of pending proposals (with re-tally)
// ---------------------------------------------------------------------------

/** One pending proposal with the votes recounted under the current policy and member set. */
export interface ProposalView {
  readonly proposal: PendingProposal;
  /** Whether the inner op is still a target of the current policy (`approval-not-required` otherwise). */
  readonly target: boolean;
  /** `required_approvals` of the current policy (null while the policy is off). */
  readonly required: number | null;
  /** Distinct current owners whose signature counts (recounted — never the raw record). */
  readonly voters: readonly string[];
  readonly votes: number;
  /** Votes still needed for the next `approve` to apply (0 = the next approve completes it). */
  readonly needed: number | null;
  /** Current owners who have not voted with their current key (the ones who can complete it). */
  readonly eligibleApprovers: readonly string[];
  /** Expired by the given clock (the chain keeps it pending until withdrawn — CRYPTO_SPEC §6.2). */
  readonly expired: boolean;
}

/** The view of one proposal (re-tallied under the current policy and members). */
export function proposalViewOf(
  verified: VerifiedProject,
  proposal: PendingProposal,
  nowMs: number,
): ProposalView {
  const policy = verified.state.approvalPolicy;
  const members = verified.state.members;
  const target = isApprovalTarget(proposal.inner, policy);
  const required = policy === null ? null : policy.requiredApprovals;
  const signers = signersOf(proposal);
  const voters = countedVoters(members, signers);
  const eligibleApprovers = [...members.values()]
    .filter((member) => ownerOnAnyDevice(member) && !hasVoted(members, proposal, member))
    .map((member) => member.userId)
    .toSorted();
  return {
    proposal,
    target,
    required,
    voters,
    votes: voters.length,
    // The next approve's actor themself is one vote, so remaining = required − current votes − 1 (floor 0)
    needed: required === null ? null : Math.max(0, required - voters.length - 1),
    eligibleApprovers,
    expired: nowMs > proposal.expiresAtMs,
  };
}

/** The list of pending proposals (ascending by proposal seq — K6-F). */
export function proposalViews(verified: VerifiedProject, nowMs: number): readonly ProposalView[] {
  return [...verified.state.pendingProposals.values()]
    .toSorted((a, b) => a.proposalSeq - b.proposalSeq)
    .map((proposal) => proposalViewOf(verified, proposal, nowMs));
}

/** Whether I can approve (pre-flight check — follows the §6.2 approve check order). */
export type VoteEligibility =
  | {
      readonly ok: true;
      /** Whether this approve reaches the quorum (recounted). */
      readonly completes: boolean;
    }
  | {
      readonly ok: false;
      readonly reason:
        | "not-a-member"
        | "device-not-registered"
        | "insufficient-role"
        | "duplicate-approval"
        | "approval-not-required"
        | "proposal-expired";
      readonly message: string;
    };

/**
 * My vote is judged by the effective role of **the signing device** (the FP
 * of the key at hand) (DK K4 — the foretell `eligibleApprovers` stays
 * "people holding at least one owner-effective device" because it cannot
 * know which device others will vote from). If the key at hand is not a
 * valid device of that person, the vote is not counted (the same predicate
 * as the tally `countedVoters`).
 */
export function voteEligibility(
  verified: VerifiedProject,
  userId: string,
  signingDeviceFingerprintHex: string,
  view: ProposalView,
): VoteEligibility {
  const member = verified.state.members.get(userId);
  if (member === undefined) {
    return {
      ok: false,
      reason: "not-a-member",
      message: "you are not a chain-derived member of this project",
    };
  }
  const device = member.devices.get(signingDeviceFingerprintHex);
  if (device === undefined) {
    return {
      ok: false,
      reason: "device-not-registered",
      message:
        "the key on this machine is not one of your active device keys on this project's chain (register it with `maruhi device add` and approve it from a registered device with `maruhi device approve`)",
    };
  }
  if (effectivePermissionOf(member, device).role !== "owner") {
    return {
      ok: false,
      reason: "insufficient-role",
      message: `only an owner can approve (your role: ${member.role}${member.role === "owner" ? `, but this device's key is capped at ${device.roleCap}` : ""} — CRYPTO_SPEC §6.2)`,
    };
  }
  if (hasVoted(verified.state.members, view.proposal, member)) {
    const asProposer = view.proposal.proposerUserId === userId;
    return {
      ok: false,
      reason: "duplicate-approval",
      message: asProposer
        ? "you proposed this as an owner, so your proposal signature already counts as your vote (duplicate-approval); another owner has to approve"
        : "you already approved this with your current key (duplicate-approval); another owner has to approve",
    };
  }
  if (!view.target) {
    return {
      ok: false,
      reason: "approval-not-required",
      message:
        view.required === null
          ? "the four-eyes policy is off, so this proposal can no longer be approved (approval-not-required); withdraw it — the operation can be run directly"
          : "the current policy no longer targets this operation, so this proposal can no longer be approved (approval-not-required); withdraw it — the operation can be run directly",
    };
  }
  if (view.expired) {
    return {
      ok: false,
      reason: "proposal-expired",
      message: `it expired on ${formatUtcMinutes(view.proposal.expiresAtMs)} by this machine's clock (proposal-expired); ask the proposer to withdraw and re-propose (if this machine's clock is wrong, fix it first)`,
    };
  }
  return { ok: true, completes: view.needed === 0 };
}

// ---------------------------------------------------------------------------
// Prefix resolution of id (entry_hash)
// ---------------------------------------------------------------------------

export type ProposalRefResolution =
  | { readonly kind: "pending"; readonly proposal: PendingProposal }
  | { readonly kind: "ambiguous"; readonly candidates: readonly PendingProposal[] }
  /** The prefix matches more than one completed / withdrawn proposal (nothing pending). */
  | { readonly kind: "ambiguous-closed"; readonly proposalSeqs: readonly number[] }
  | { readonly kind: "completed"; readonly proposalSeq: number; readonly completedAtSeq: number }
  | { readonly kind: "withdrawn"; readonly proposalSeq: number }
  | { readonly kind: "unknown" }
  | { readonly kind: "malformed" };

/**
 * Resolves a prefix of at least the first 8 characters of a proposal id
 * (hex 64) against the pending set. On zero matches it distinguishes
 * completed / withdrawn (core's `indexProposals`) from unknown (telling an
 * old id from a typo).
 */
export function resolveProposalRef(verified: VerifiedProject, ref: string): ProposalRefResolution {
  const normalized = ref.trim().toLowerCase();
  // `#<seq>`: reference by the proposal entry's seq (K6-F′ — an immutable
  // value fixed by the chain; the `#` prefix separates it structurally from
  // hex prefixes)
  const bySeq = /^#(\d{1,9})$/.exec(normalized);
  if (bySeq !== null) {
    return resolveProposalSeq(verified, Number(bySeq[1]));
  }
  if (
    normalized.length < MIN_PROPOSAL_REF_LENGTH ||
    normalized.length > 64 ||
    !/^[0-9a-f]+$/.test(normalized)
  ) {
    return { kind: "malformed" };
  }
  const pending = [...verified.state.pendingProposals.values()]
    .filter((proposal) => proposal.proposalHashHex.startsWith(normalized))
    .toSorted((a, b) => a.proposalSeq - b.proposalSeq);
  const first = pending[0];
  if (first !== undefined) {
    return pending.length === 1
      ? { kind: "pending", proposal: first }
      : { kind: "ambiguous", candidates: pending };
  }
  const closed = [...proposalIndexOf(verified)].filter(([hash]) => hash.startsWith(normalized));
  const only = closed[0]?.[1];
  if (only === undefined) {
    return { kind: "unknown" };
  }
  if (closed.length > 1) {
    return {
      kind: "ambiguous-closed",
      proposalSeqs: closed.map(([, indexed]) => indexed.entry.seq).toSorted((a, b) => a - b),
    };
  }
  return only.completedAtSeq === null
    ? { kind: "withdrawn", proposalSeq: only.entry.seq }
    : { kind: "completed", proposalSeq: only.entry.seq, completedAtSeq: only.completedAtSeq };
}

/** Resolves by proposal seq (distinguishes pending → completed / withdrawn → unknown, in that order). */
function resolveProposalSeq(verified: VerifiedProject, seq: number): ProposalRefResolution {
  for (const proposal of verified.state.pendingProposals.values()) {
    if (proposal.proposalSeq === seq) {
      return { kind: "pending", proposal };
    }
  }
  for (const indexed of proposalIndexOf(verified).values()) {
    if (indexed.entry.seq === seq) {
      return indexed.completedAtSeq === null
        ? { kind: "withdrawn", proposalSeq: seq }
        : { kind: "completed", proposalSeq: seq, completedAtSeq: indexed.completedAtSeq };
    }
  }
  return { kind: "unknown" };
}

/**
 * Detects key-FP re-registration (design record K5-K / K6-I / K6-I′): the
 * user_id under which the key being registered appears in a different
 * membership interval of the verified chain's history (`keyHistory` —
 * including proposal-mediated additions). Distinguishes a past membership
 * of the same user_id from a different user_id. The proposer side
 * (`member add`) and the approver side (`approval show`) use the same
 * single predicate.
 */
export function keyReuseOf(
  verified: VerifiedProject,
  key: { readonly targetUserId: string; readonly encPubHex: string; readonly sigPubHex: string },
): readonly { readonly userId: string; readonly sameUser: boolean }[] {
  const reuse: { readonly userId: string; readonly sameUser: boolean }[] = [];
  for (const [userId, bindings] of verified.keyHistory) {
    const reused = bindings.some(
      (binding) => binding.encPubHex === key.encPubHex || binding.sigPubHex === key.sigPubHex,
    );
    if (reused) {
      reuse.push({ userId, sameUser: userId === key.targetUserId });
    }
  }
  return reuse;
}

/** Warning text for key-FP re-registration (same wording on the proposer and approver sides. `subject` = "the acceptance key" etc.). */
export function describeKeyReuse(
  subject: string,
  reuse: { readonly userId: string; readonly sameUser: boolean },
): string {
  return reuse.sameUser
    ? `${subject} was registered before for this same user (a previous membership that has since ended). If that key was removed because it was compromised, do not re-register it: a re-registered key revives the four-eyes approval votes it cast (CRYPTO_SPEC §6.2) — issue a fresh invite for a new key instead`
    : `${subject} was registered before for a different user (${displayText(reuse.userId)}). A key must not move between identities — unless this is expected, abort and ask the acceptor to generate a new key`;
}

/** Human-readable failure for a reference that did not resolve to a pending proposal. */
export function describeUnresolvedRef(
  resolution: Exclude<ProposalRefResolution, { readonly kind: "pending" }>,
): string {
  switch (resolution.kind) {
    case "malformed":
      return `A proposal id is the propose entry's hash (64 hex digits; at least the first ${MIN_PROPOSAL_REF_LENGTH} digits) or #<seq> of the propose entry (see \`maruhi approval list\`)`;
    case "ambiguous":
      return `The prefix matches more than one pending proposal (${resolution.candidates.map((candidate) => candidate.proposalHashHex.slice(0, 12)).join(", ")}) — use a longer prefix`;
    case "ambiguous-closed":
      return `The prefix matches more than one completed / withdrawn proposal (seq ${resolution.proposalSeqs.join(", ")}) and nothing pending — use a longer prefix or #<seq>`;
    case "completed":
      return `That proposal (seq=${resolution.proposalSeq}) was already completed at seq=${resolution.completedAtSeq} — nothing is pending for it`;
    case "withdrawn":
      return `That proposal (seq=${resolution.proposalSeq}) was withdrawn — nothing is pending for it`;
    case "unknown":
      return "No proposal matches that id (check `maruhi approval list`)";
  }
}

// ---------------------------------------------------------------------------
// Expiry (`--expires <duration>` — K6-K)
// ---------------------------------------------------------------------------

export type ProposalExpiryParse =
  | { readonly ok: true; readonly lifetimeMs: number }
  | { readonly ok: false; readonly message: string };

/**
 * `<n>m` / `<n>h` / `<n>d` into a duration (ms). Omitted = 7 days (ruling
 * P6). 0 and over 30 days are refused (the pre-flight checks
 * `expires_at_ms > now` and `≤ now + 30 days` — K5-S; they are folded here
 * by construction).
 */
export function parseProposalExpiry(text: string | undefined): ProposalExpiryParse {
  if (text === undefined) {
    return { ok: true, lifetimeMs: DEFAULT_PROPOSAL_LIFETIME_MS };
  }
  const match = /^(\d{1,6})([mhd])$/.exec(text.trim());
  if (match === null) {
    return {
      ok: false,
      message:
        "--expires takes a duration such as 7d, 48h or 90m (default 7d; at most 30d — the server's acceptance limit)",
    };
  }
  const amount = Number(match[1]);
  const unit = match[2] === "m" ? MS_PER_MINUTE : match[2] === "h" ? MS_PER_HOUR : MS_PER_DAY;
  const lifetimeMs = amount * unit;
  if (lifetimeMs <= 0) {
    return { ok: false, message: "--expires must be a positive duration (e.g. 7d)" };
  }
  if (lifetimeMs > MAX_PROPOSAL_LIFETIME_MS) {
    return {
      ok: false,
      message:
        "--expires must not exceed 30d (the server does not accept proposals that expire later than 30 days from now — AUTH_SPEC §12-8)",
    };
  }
  return { ok: true, lifetimeMs };
}

// ---------------------------------------------------------------------------
// Display of the inner op
// ---------------------------------------------------------------------------

/** One-line human summary of the inner operation (ids are neutralized). */
export function describeInnerOperation(operation: ProposableOperation): string {
  switch (operation.op) {
    case "add_member":
      return `add_member ${displayText(operation.payload.targetUserId)} as ${operation.payload.role} (scope: ${describeScope(operation.payload)})`;
    case "remove_member":
      return `remove_member ${displayText(operation.payload.targetUserId)}`;
    case "change_role":
      return `change_role ${displayText(operation.payload.targetUserId)} to ${operation.payload.newRole} (scope: ${describeScope(operation.payload)})`;
    case "grant_server":
      return `grant_server key ${operation.payload.serverKeyFingerprintHex} (scope: ${operation.payload.scopeEnvironmentIds.length === 0 ? "no environments" : operation.payload.scopeEnvironmentIds.map(displayText).join(", ")}; lease_policy: ${operation.payload.leasePolicy.length} element${operation.payload.leasePolicy.length === 1 ? "" : "s"})`;
    case "revoke_server":
      return `revoke_server key ${operation.payload.serverKeyFingerprintHex}`;
    case "set_approval_policy":
      return operation.payload.requiredApprovals === 0
        ? "set_approval_policy off"
        : `set_approval_policy required=${operation.payload.requiredApprovals} ops=${[...operation.payload.ops].toSorted().join(",")}`;
    default:
      return operation.op;
  }
}

/** Detail lines for `approval show` (one field per line, all values neutralized). */
export function describeInnerOperationLines(operation: ProposableOperation): readonly string[] {
  switch (operation.op) {
    case "add_member":
      return [
        `target:  ${displayText(operation.payload.targetUserId)}`,
        `role:    ${operation.payload.role}`,
        `scope:   ${describeScope(operation.payload)}`,
        `enc key: ${operation.payload.encPubHex}`,
        `sig key: ${operation.payload.sigPubHex}`,
      ];
    case "remove_member":
      return [`target:  ${displayText(operation.payload.targetUserId)}`];
    case "change_role":
      return [
        `target:  ${displayText(operation.payload.targetUserId)}`,
        `role:    ${operation.payload.newRole}`,
        `scope:   ${describeScope(operation.payload)}`,
      ];
    case "grant_server":
      return [
        `server key fp: ${operation.payload.serverKeyFingerprintHex}`,
        `enc key:       ${operation.payload.serverEncPubHex}`,
        `scope:         ${operation.payload.scopeEnvironmentIds.length === 0 ? "no environments" : operation.payload.scopeEnvironmentIds.map(displayText).join(", ")}`,
        `lease_policy:  ${operation.payload.leasePolicy.length} element${operation.payload.leasePolicy.length === 1 ? "" : "s"}`,
      ];
    case "revoke_server":
      return [`server key fp: ${operation.payload.serverKeyFingerprintHex}`];
    case "set_approval_policy":
      return operation.payload.requiredApprovals === 0
        ? ["policy:  off"]
        : [
            `required approvals: ${operation.payload.requiredApprovals}`,
            `ops:                ${[...operation.payload.ops].toSorted().join(", ")} (plus the always-targeted set_approval_policy and owner-establishing add_member / change_role)`,
          ];
    default:
      return [`op: ${operation.op}`];
  }
}

/** Policy summary for `project policy approvals` / `approval list` (null = off). */
export function describePolicy(policy: ApprovalPolicy | null): string {
  if (policy === null) {
    return "off (every operation is appended directly)";
  }
  return `on — required approvals: ${policy.requiredApprovals}; targeted ops: ${[...policy.ops].toSorted().join(", ")} (plus set_approval_policy itself and any add_member / change_role that establishes an owner)`;
}
