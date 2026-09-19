// 四眼(CRYPTO_SPEC §6.2 — PF1)の CLI 側の純関数(設計録 es-design.md §12 K6-F / G / K / O)。
//
// - 対象判定 `isApprovalTarget` と票の再集計 `countOwnerVotes` は crypto の合意規則
//   (chain-verify.ts の非公開関数)の CLI 側の 2 実装目。公開 API(`APPROVAL_TARGET_OPS` /
//   `ApprovalPolicy` / `PendingProposal` / `ApprovalVote` / `ChainMember`)から導出し、
//   内部実装はコピーしない(K4-I の包含述語と同じ構図)。ずれは合意規則の 422 が
//   最終判定として拾い、`verifyChain` との差分テスト(approval-rules.test.ts)が回帰を
//   捕まえる。次に crypto を触る段で公開 API 化を検討する(K6-Q の申し送り)
// - 票数は記録(`PendingProposal.approvals`)をそのまま出さず、**現方針と現メンバーで
//   再集計する**(記録は失効票を保持する — 設計録 §8 K2 の実装メモ)
// - 提案の識別子は提案エントリの entry_hash(hex 64)だけで、CLI は別名を作らない。
//   先頭 8 文字以上の一意接頭辞を受け付ける(承認項目 23)

import {
  APPROVAL_TARGET_OPS,
  type ApprovalPolicy,
  type ApprovalTargetOp,
  type ApprovalVote,
  canonicalChainPayloadBytes,
  type ChainMember,
  type PendingProposal,
  type ProposableOperation,
} from "@maruhi/crypto";

import { proposalIndexOf } from "./chain-applied.ts";
import { displayText, formatUtcMinutes } from "./display.ts";
import { describeScope } from "./scope.ts";
import type { VerifiedProject } from "./sync.ts";

const MS_PER_MINUTE = 60_000;
const MS_PER_HOUR = 60 * MS_PER_MINUTE;
const MS_PER_DAY = 24 * MS_PER_HOUR;

/** Default proposal lifetime (裁定 P6 — 7 days). */
export const DEFAULT_PROPOSAL_LIFETIME_MS = 7 * MS_PER_DAY;
/** Server acceptance-policy upper bound of `expires_at_ms` (CRYPTO_SPEC §6.4 — 30 days). */
export const MAX_PROPOSAL_LIFETIME_MS = 30 * MS_PER_DAY;

/** Default `--ops` set when a policy is enabled (承認項目 17 — 既定推奨集合). */
export const DEFAULT_POLICY_OPS: readonly ApprovalTargetOp[] = [
  "change_role",
  "grant_server",
  "remove_member",
  "set_approval_policy",
];

/** Shortest proposal-id prefix accepted on the command line (承認項目 23). */
const MIN_PROPOSAL_REF_LENGTH = 8;

// ---------------------------------------------------------------------------
// 対象判定と票の再集計(§6.2 原則 2 の CLI 側の写し)
// ---------------------------------------------------------------------------

/** Whether `value` names an operation a policy may list in `ops` (closed set — CRYPTO_SPEC §6.2). */
export function isApprovalTargetOp(value: string): value is ApprovalTargetOp {
  return APPROVAL_TARGET_OPS.some((op) => op === value);
}

/** owner role を確立する add_member / change_role(方針の単調性 (a) の常時対象)。 */
function establishesOwner(operation: ProposableOperation): boolean {
  return (
    (operation.op === "add_member" && operation.payload.role === "owner") ||
    (operation.op === "change_role" && operation.payload.newRole === "owner")
  );
}

/**
 * 四眼の対象判定(§6.2): 方針が有効で、op が `ops` に列挙されているか、常時対象
 * (`set_approval_policy` 自身と owner を確立する add_member / change_role)であること。
 * `propose` / `approve` / 直接追記の拒否が共有する 1 述語の CLI 側の写し。
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
 * 原則 2(§6.2)の署名者集合 S = {owner として提案した提案者} ∪ {受理済み approve の actor}。
 * 要素は (user_id, 署名時の鍵 FP)。admin として提案した提案者は S に入らない(昇格後に
 * approve を追記できる — 2026-09-15 裁定 ②)。
 */
export function signersOf(pending: PendingProposal): readonly ApprovalVote[] {
  const proposer: readonly ApprovalVote[] =
    pending.proposerRoleAtProposal === "owner"
      ? [{ userId: pending.proposerUserId, keyFingerprintHex: pending.proposerKeyFingerprintHex }]
      : [];
  return [...proposer, ...pending.approvals];
}

/** S の要素のうち、現時点で署名時と同じ鍵 FP を持つ現メンバーとして owner である distinct user_id。 */
function countedVoters(
  members: ReadonlyMap<string, ChainMember>,
  signers: readonly ApprovalVote[],
): readonly string[] {
  const voters = new Set<string>();
  for (const signer of signers) {
    const member = members.get(signer.userId);
    if (member?.role === "owner" && member.keyFingerprintHex === signer.keyFingerprintHex) {
      voters.add(signer.userId);
    }
  }
  return [...voters].toSorted();
}

/** 票数 = |S ∩ 適用時点の owners|(原則 2 — 離脱・降格・鍵更新済みの投票者の票は数えない)。 */
export function countOwnerVotes(
  members: ReadonlyMap<string, ChainMember>,
  signers: readonly ApprovalVote[],
): number {
  return countedVoters(members, signers).length;
}

/** actor の (user_id, 現在の鍵 FP) が既に S の要素か(`duplicate-approval` の予告)。 */
function hasVoted(pending: PendingProposal, member: ChainMember): boolean {
  return signersOf(pending).some(
    (signer) =>
      signer.userId === member.userId && signer.keyFingerprintHex === member.keyFingerprintHex,
  );
}

/** 同じ操作か(op と正規化 payload_bytes の一致 — 提案の冪等性の判定に使う。K6-A)。 */
export function sameOperation(a: ProposableOperation, b: ProposableOperation): boolean {
  if (a.op !== b.op) {
    return false;
  }
  const left = canonicalChainPayloadBytes(a);
  const right = canonicalChainPayloadBytes(b);
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

// ---------------------------------------------------------------------------
// pending 提案の表示ビュー(再集計込み)
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

/** 1 提案のビュー(現方針・現メンバーで再集計)。 */
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
    .filter((member) => member.role === "owner" && !hasVoted(proposal, member))
    .map((member) => member.userId)
    .toSorted();
  return {
    proposal,
    target,
    required,
    voters,
    votes: voters.length,
    // 次の approve の actor 自身が 1 票なので、残り = required − 現票数 − 1(下限 0)
    needed: required === null ? null : Math.max(0, required - voters.length - 1),
    eligibleApprovers,
    expired: nowMs > proposal.expiresAtMs,
  };
}

/** pending 提案の一覧(提案 seq 昇順 — K6-F)。 */
export function proposalViews(verified: VerifiedProject, nowMs: number): readonly ProposalView[] {
  return [...verified.state.pendingProposals.values()]
    .toSorted((a, b) => a.proposalSeq - b.proposalSeq)
    .map((proposal) => proposalViewOf(verified, proposal, nowMs));
}

/** 自分が approve できるかの判定(通信前検査 — §6.2 の approve の検査順に沿う)。 */
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
        | "insufficient-role"
        | "duplicate-approval"
        | "approval-not-required"
        | "proposal-expired";
      readonly message: string;
    };

export function voteEligibility(
  verified: VerifiedProject,
  userId: string,
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
  if (member.role !== "owner") {
    return {
      ok: false,
      reason: "insufficient-role",
      message: `only an owner can approve (your role: ${member.role} — CRYPTO_SPEC §6.2)`,
    };
  }
  if (hasVoted(view.proposal, member)) {
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
// id(entry_hash)の接頭辞解決
// ---------------------------------------------------------------------------

export type ProposalRefResolution =
  | { readonly kind: "pending"; readonly proposal: PendingProposal }
  | { readonly kind: "ambiguous"; readonly candidates: readonly PendingProposal[] }
  | { readonly kind: "completed"; readonly proposalSeq: number; readonly completedAtSeq: number }
  | { readonly kind: "withdrawn"; readonly proposalSeq: number }
  | { readonly kind: "unknown" }
  | { readonly kind: "malformed" };

/**
 * 提案 id(hex 64)の先頭 8 文字以上の接頭辞を pending 集合で解決する。0 件のときは
 * 完成済み / 撤回済み(core の `indexProposals`)と未知を言い分ける(古い id と typo の区別)。
 */
export function resolveProposalRef(verified: VerifiedProject, ref: string): ProposalRefResolution {
  const normalized = ref.trim().toLowerCase();
  // `#<seq>`: 提案エントリの seq による参照(K6-F′ — チェーンが定める不変の値。`#` 接頭で
  // hex 接頭辞と構造的に分ける)
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
  if (only === undefined || closed.length > 1) {
    return { kind: "unknown" };
  }
  return only.completedAtSeq === null
    ? { kind: "withdrawn", proposalSeq: only.entry.seq }
    : { kind: "completed", proposalSeq: only.entry.seq, completedAtSeq: only.completedAtSeq };
}

/** 提案 seq での解決(pending → 完成 / 撤回 → 未知の順に言い分ける)。 */
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
 * 鍵 FP 再登録の判定(設計録 K5-K / K6-I / K6-I′): 登録しようとする鍵が検証済みチェーンの
 * 履歴(`keyHistory` — 提案経由の追加も含む)の別の在籍区間に現れる user_id。同一 user_id の
 * 過去の在籍と別 user_id を言い分ける。提案者側(`member add`)と承認者側(`approval show`)
 * が同じ 1 述語を使う。
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

/** 鍵 FP 再登録の警告文(提案者側・承認者側で同じ文言。`subject` = 「the acceptance key」等)。 */
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
    case "completed":
      return `That proposal (seq=${resolution.proposalSeq}) was already completed at seq=${resolution.completedAtSeq} — nothing is pending for it`;
    case "withdrawn":
      return `That proposal (seq=${resolution.proposalSeq}) was withdrawn — nothing is pending for it`;
    case "unknown":
      return "No proposal matches that id (check `maruhi approval list`)";
  }
}

// ---------------------------------------------------------------------------
// 期限(`--expires <duration>` — K6-K)
// ---------------------------------------------------------------------------

export type ProposalExpiryParse =
  | { readonly ok: true; readonly lifetimeMs: number }
  | { readonly ok: false; readonly message: string };

/**
 * `<n>m` / `<n>h` / `<n>d` を期間(ms)へ。省略 = 7 日(裁定 P6)。0 と 30 日超は拒否
 * (`expires_at_ms > now` と `≤ now + 30 日` の通信前検査 — K5-S。構成上ここに畳まれる)。
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
// 内側 op の表示
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
