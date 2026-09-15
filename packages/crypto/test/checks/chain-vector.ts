// chain-entries.json のベクターを @maruhi/crypto の型付きエントリへ変換するヘルパ。

import {
  type ApprovalPolicy,
  type ApprovalTargetOp,
  type ApprovalVote,
  canonicalChainPayloadBytes,
  type ChainEntry,
  type ChainMember,
  type ChainOperation,
  type PendingProposal,
  type ProposableOperation,
  type Role,
  type ScopeKind,
  type ServerGrant,
} from "../../src/index.ts";
import chainVectors from "../../test-vectors/chain-entries.json" with { type: "json" };
import { toHex } from "./support.ts";

export interface VectorEntry {
  readonly seq: number;
  readonly suite: string;
  readonly prev_hash_hex: string;
  readonly op: string;
  readonly actor: { readonly user_id: string; readonly key_fingerprint_hex: string };
  readonly payload: Readonly<Record<string, unknown>>;
  readonly timestamp_ms: number;
  readonly payload_bytes_hex: string;
  readonly signed_bytes_hex: string;
  readonly signature_hex: string;
  readonly entry_bytes_hex: string;
  readonly entry_hash_hex: string;
}

interface VectorNegative {
  readonly name: string;
  readonly kind?: string;
  readonly base_seq?: number;
  readonly payload?: Readonly<Record<string, unknown>>;
  readonly signed_bytes_hex?: string;
  readonly signature_hex?: string;
  readonly verify_key_hex?: string;
  readonly claimed_prev_hash_hex?: string;
  readonly expected_prev_hash_hex?: string;
  readonly entry?: VectorEntry;
  readonly expected_reason?: string;
  /** 認可 negative の前提チェーン(extended_chains のキー。無指定 = 正規チェーン)。 */
  readonly chain?: string;
  readonly must_fail: boolean;
}

/** grant_server payload / 導出状態の lease_policy のベクター表現(§6.2)。 */
interface VectorLeasePolicyIssuer {
  readonly issuer_url: string;
  readonly audience: string;
  readonly claim_constraints: readonly {
    readonly claim_name: string;
    readonly claim_value: string;
  }[];
}

interface VectorServerGrant {
  readonly server_key_fingerprint_hex: string;
  readonly server_enc_pub_hex: string;
  readonly scope_environments: readonly string[];
  readonly lease_policy: readonly VectorLeasePolicyIssuer[];
  /** 有効 grant を確立したエントリの seq(再 grant で前進 — §6.3 / AUDIT_SPEC §3.5)。 */
  readonly grant_seq: number;
}

/** 受理後の環境ごとの最新チェックポイント期待値(§6.2 checkpoint)。 */
export interface VectorCheckpointState {
  readonly seq: number;
  readonly epoch: string;
  readonly manifest_version: string;
  readonly manifest_sig_hash_hex: string;
  readonly values_digest_hex: string;
}

/** メンバー状態の期待値(role + scope — §6.2 の検証状態。2026-09-14 ES)。 */
export interface VectorMemberState {
  readonly role: string;
  readonly scope: { readonly kind: string; readonly environments?: readonly string[] };
}

/** 四眼の方針の期待値(null = オフ)。 */
export interface VectorApprovalPolicy {
  readonly ops: readonly string[];
  readonly required_approvals: string;
}

/** pending 提案の期待値(提案エントリ hash → 提案)。 */
export interface VectorPendingProposal {
  readonly proposal_seq: number;
  readonly proposer_user_id: string;
  readonly proposer_key_fingerprint_hex: string;
  readonly proposer_role_at_proposal: string;
  readonly inner_op: string;
  readonly inner_payload: Readonly<Record<string, unknown>>;
  readonly expires_at_ms: string;
  /** 受理済み approve の署名 (user_id, 鍵 FP) — 2026-09-15 裁定 ⑤(票の鍵束縛)。 */
  readonly approvals: readonly { readonly user_id: string; readonly key_fingerprint_hex: string }[];
}

interface VectorValidAppend {
  readonly name: string;
  readonly entry: VectorEntry;
  /** 接続先(extended_chains のキー。無指定 = 正規チェーンの entry.seq - 1 まで)。 */
  readonly chain?: string;
  readonly expected_members: Readonly<Record<string, VectorMemberState>>;
  readonly expected_policy?: VectorApprovalPolicy | null;
  readonly expected_pending?: Readonly<Record<string, VectorPendingProposal>>;
  /** 受理後の環境ごとの現エポック(§6.2 環境ライフサイクル)。 */
  readonly expected_environments: Readonly<Record<string, string>>;
  /** 受理後の有効 grant 集合(§6.2 再 grant 二層)。 */
  readonly expected_server_grants: readonly VectorServerGrant[];
  /** 受理後の環境ごとの最新チェックポイント(checkpoint の valid append のみ)。 */
  readonly expected_checkpoints?: Readonly<Record<string, VectorCheckpointState>>;
  readonly note?: string;
}

/** 正規チェーンの途中ヘッドへ追記した派生チェーン(認可 negative の前提状態)。 */
interface VectorExtendedChain {
  readonly description: string;
  readonly base_seq: number;
  readonly entries: readonly VectorEntry[];
  readonly expected_members: Readonly<Record<string, VectorMemberState>>;
  /** 派生チェーン検証後の環境ごとの最新チェックポイント(checkpoint-baseline)。 */
  readonly expected_checkpoints?: Readonly<Record<string, VectorCheckpointState>>;
  readonly expected_policy?: VectorApprovalPolicy | null;
  readonly expected_pending?: Readonly<Record<string, VectorPendingProposal>>;
}

interface VectorEnvironmentState {
  readonly current_epoch: string;
  readonly created_at_seq: number;
  readonly epoch_start_seqs: Readonly<Record<string, number>>;
  readonly dek_commitments: Readonly<Record<string, string>>;
}

interface VectorHeadState {
  readonly after_seq: number;
  readonly members: Readonly<Record<string, VectorMemberState>>;
  readonly server_grants: readonly VectorServerGrant[];
  readonly environments: Readonly<Record<string, VectorEnvironmentState>>;
  readonly approval_policy: VectorApprovalPolicy | null;
  readonly pending_proposals: Readonly<Record<string, VectorPendingProposal>>;
}

/** 導出状態のメンバー集合がベクター期待(role + scope)と一致するか(集合として比較)。 */
export function membersMatchVector(
  members: ReadonlyMap<string, ChainMember>,
  expected: Readonly<Record<string, VectorMemberState>>,
): boolean {
  return (
    members.size === Object.keys(expected).length &&
    Object.entries(expected).every(([userId, state]) => {
      const actual = members.get(userId);
      if (actual === undefined || actual.role !== state.role) {
        return false;
      }
      if (state.scope.kind === "all") {
        return actual.scope.kind === "all";
      }
      const expectedIds = new Set(state.scope.environments ?? []);
      return (
        actual.scope.kind === "listed" &&
        actual.scope.environmentIds.length === expectedIds.size &&
        actual.scope.environmentIds.every((id) => expectedIds.has(id))
      );
    })
  );
}

/** 導出状態の方針がベクター期待と一致するか(ops は集合として比較。無指定は検査しない)。 */
export function policyMatchesVector(
  policy: ApprovalPolicy | null,
  expected: VectorApprovalPolicy | null | undefined,
): boolean {
  if (expected === undefined) {
    return true;
  }
  if (expected === null || policy === null) {
    return expected === policy;
  }
  const expectedOps = new Set(expected.ops);
  return (
    policy.requiredApprovals === Number(expected.required_approvals) &&
    policy.ops.length === expectedOps.size &&
    policy.ops.every((op) => expectedOps.has(op))
  );
}

/** pending 提案 1 件の比較用の正規形(順序・型を揃えた JSON — 内側 payload は正規化バイト列)。 */
function pendingProposalKey(input: {
  readonly hash: string;
  readonly proposalSeq: number;
  readonly proposerUserId: string;
  readonly proposerKeyFingerprintHex: string;
  readonly proposerRoleAtProposal: string;
  readonly inner: ProposableOperation;
  readonly expiresAtMs: number;
  readonly approvals: readonly ApprovalVote[];
}): string {
  return JSON.stringify([
    input.hash,
    input.proposalSeq,
    input.proposerUserId,
    input.proposerKeyFingerprintHex,
    input.proposerRoleAtProposal,
    input.inner.op,
    toHex(canonicalChainPayloadBytes(input.inner)),
    input.expiresAtMs,
    input.approvals.map((vote) => [vote.userId, vote.keyFingerprintHex]),
  ]);
}

/** 導出状態の pending 提案集合がベクター期待と一致するか(無指定は検査しない)。 */
export function pendingMatchesVector(
  pending: ReadonlyMap<string, PendingProposal>,
  expected: Readonly<Record<string, VectorPendingProposal>> | undefined,
): boolean {
  if (expected === undefined) {
    return true;
  }
  const expectedKeys = Object.entries(expected).map(([hash, proposal]) =>
    pendingProposalKey({
      hash,
      proposalSeq: proposal.proposal_seq,
      proposerUserId: proposal.proposer_user_id,
      proposerKeyFingerprintHex: proposal.proposer_key_fingerprint_hex,
      proposerRoleAtProposal: proposal.proposer_role_at_proposal,
      inner: decodeInner(proposal.inner_op, proposal.inner_payload),
      expiresAtMs: Number(proposal.expires_at_ms),
      approvals: proposal.approvals.map((vote) => ({
        userId: vote.user_id,
        keyFingerprintHex: vote.key_fingerprint_hex,
      })),
    }),
  );
  const actualKeys = [...pending.entries()].map(([hash, actual]) =>
    pendingProposalKey({ ...actual, hash: actual.proposalHashHex === hash ? hash : `${hash}!` }),
  );
  return expectedKeys.toSorted().join("\n") === actualKeys.toSorted().join("\n");
}

/**
 * 導出状態の有効 grant 集合がベクター期待(snake_case)と一致するか
 * (§6.2 — scope + lease_policy 込み。chain.ts / chain-negative.ts で共用)。
 */
export function serverGrantsMatchVector(
  serverGrants: ReadonlyMap<string, ServerGrant>,
  expected: readonly VectorServerGrant[],
): boolean {
  return (
    serverGrants.size === expected.length &&
    expected.every((grant) => {
      const actual = serverGrants.get(grant.server_key_fingerprint_hex);
      return (
        actual !== undefined &&
        actual.serverEncPubHex === grant.server_enc_pub_hex &&
        actual.grantSeq === grant.grant_seq &&
        actual.scopeEnvironmentIds.join(",") === grant.scope_environments.join(",") &&
        // lease_policy(§6.2)も導出状態の一部(順序込みで一致 — as-signed 順)
        JSON.stringify(
          actual.leasePolicy.map((element) => ({
            issuer_url: element.issuerUrl,
            audience: element.audience,
            claim_constraints: element.claimConstraints.map((constraint) => ({
              claim_name: constraint.claimName,
              claim_value: constraint.claimValue,
            })),
          })),
        ) === JSON.stringify(grant.lease_policy)
      );
    })
  );
}

export const vectorEntries = chainVectors.entries as readonly VectorEntry[];
export const vectorNegatives = chainVectors.negative as readonly VectorNegative[];
export const vectorHeadStates =
  chainVectors.expected_head_states as unknown as readonly VectorHeadState[];
export const vectorValidAppends =
  chainVectors.valid_appends as unknown as readonly VectorValidAppend[];
export const vectorExtendedChains = chainVectors.extended_chains as unknown as Readonly<
  Record<string, VectorExtendedChain>
>;
export const vectorKeys = chainVectors.keys as Readonly<
  Record<
    string,
    {
      readonly enc_sk_seed_hex: string;
      readonly sig_sk_seed_hex: string;
      readonly enc_pub_hex: string;
      readonly sig_pub_hex: string;
      readonly key_fingerprint_hex: string;
    }
  >
>;
/** checkpoint の values_digest 正規形の単体ベクター(§6.2)。 */
export const vectorValuesDigests = chainVectors.values_digests as readonly {
  readonly name: string;
  readonly entries: readonly {
    readonly variable_id: string;
    readonly version: string;
    readonly value_sig_hash_hex: string;
  }[];
  readonly values_digest_hex: string;
  readonly note?: string;
}[];
/** 各 (environment, epoch) のダミー DEK と §5.2 コミットメント(実計算値)。 */
export const vectorEnvironmentDeks = chainVectors.environment_deks as Readonly<
  Record<
    string,
    Readonly<Record<string, { readonly dek_hex: string; readonly dek_commitment_hex: string }>>
  >
>;
function str(payload: Readonly<Record<string, unknown>>, key: string): string {
  const value = payload[key];
  if (typeof value !== "string") {
    throw new Error(`chain vector payload: expected string field ${key}`);
  }
  return value;
}

/** scope の 2 フィールド(§6.2 — add_member / change_role の末尾 2 フィールド)。 */
function scopeFields(payload: Readonly<Record<string, unknown>>): {
  readonly scopeKind: ScopeKind;
  readonly scopeEnvironmentIds: readonly string[];
} {
  return {
    scopeKind: str(payload, "scope_kind") as ScopeKind,
    scopeEnvironmentIds: payload["scope_environments"] as readonly string[],
  };
}

// op ごとの snake_case → typed payload 変換表(cyclomatic の高い switch を
// 表引きへ — 実装側の PAYLOAD_SHAPES / OPERATION_APPLIERS と同じ形)
const OPERATION_DECODERS: Readonly<
  Record<string, (payload: Readonly<Record<string, unknown>>) => ChainOperation>
> = {
  genesis: (payload) => ({
    op: "genesis",
    payload: { encPubHex: str(payload, "enc_pub_hex"), sigPubHex: str(payload, "sig_pub_hex") },
  }),
  add_member: (payload) => ({
    op: "add_member",
    payload: {
      targetUserId: str(payload, "target_user_id"),
      encPubHex: str(payload, "enc_pub_hex"),
      sigPubHex: str(payload, "sig_pub_hex"),
      role: str(payload, "role") as Role,
      ...scopeFields(payload),
    },
  }),
  remove_member: (payload) => ({
    op: "remove_member",
    payload: { targetUserId: str(payload, "target_user_id") },
  }),
  change_role: (payload) => ({
    op: "change_role",
    payload: {
      targetUserId: str(payload, "target_user_id"),
      newRole: str(payload, "new_role") as Role,
      ...scopeFields(payload),
    },
  }),
  create_environment: (payload) => ({
    op: "create_environment",
    payload: {
      environmentId: str(payload, "environment_id"),
      dekCommitmentHex: str(payload, "dek_commitment_hex"),
    },
  }),
  rotate_epoch: (payload) => ({
    op: "rotate_epoch",
    payload: {
      environmentId: str(payload, "environment_id"),
      newEpoch: Number(str(payload, "new_epoch")),
      reason: str(payload, "reason"),
      dekCommitmentHex: str(payload, "dek_commitment_hex"),
    },
  }),
  grant_server: (payload) => {
    const leasePolicy = payload["lease_policy"] as readonly VectorLeasePolicyIssuer[];
    return {
      op: "grant_server",
      payload: {
        serverEncPubHex: str(payload, "server_enc_pub_hex"),
        serverKeyFingerprintHex: str(payload, "server_key_fingerprint_hex"),
        scopeEnvironmentIds: payload["scope_environments"] as readonly string[],
        leasePolicy: leasePolicy.map((element) => ({
          issuerUrl: element.issuer_url,
          audience: element.audience,
          claimConstraints: element.claim_constraints.map((constraint) => ({
            claimName: constraint.claim_name,
            claimValue: constraint.claim_value,
          })),
        })),
      },
    };
  },
  revoke_server: (payload) => ({
    op: "revoke_server",
    payload: { serverKeyFingerprintHex: str(payload, "server_key_fingerprint_hex") },
  }),
  checkpoint: (payload) => {
    const environments = payload["environments"] as readonly Readonly<Record<string, unknown>>[];
    return {
      op: "checkpoint",
      payload: {
        environments: environments.map((entry) => ({
          environmentId: str(entry, "environment_id"),
          epoch: Number(str(entry, "epoch")),
          manifestVersion: Number(str(entry, "manifest_version")),
          manifestSigHashHex: str(entry, "manifest_sig_hash_hex"),
          valuesDigestHex: str(entry, "values_digest_hex"),
        })),
        auditHeadHashHex: str(payload, "audit_head_hash_hex"),
      },
    };
  },
  // 四眼(§6.2 — PF1)。propose の内側 op は同じ変換表で再帰的に復号する
  set_approval_policy: (payload) => ({
    op: "set_approval_policy",
    payload: {
      ops: payload["ops"] as readonly ApprovalTargetOp[],
      requiredApprovals: Number(str(payload, "required_approvals")),
    },
  }),
  propose: (payload) => ({
    op: "propose",
    payload: {
      inner: decodeInner(
        str(payload, "inner_op"),
        payload["inner_payload"] as Readonly<Record<string, unknown>>,
      ),
      expiresAtMs: Number(str(payload, "expires_at_ms")),
    },
  }),
  approve: (payload) => ({
    op: "approve",
    payload: { proposalHashHex: str(payload, "proposal_hash_hex") },
  }),
  withdraw: (payload) => ({
    op: "withdraw",
    payload: { proposalHashHex: str(payload, "proposal_hash_hex") },
  }),
};

/**
 * propose の内側 op の復号。構造 negative(未知 op・入れ子・フィールド欠落)は変換表で
 * 復号できないため、その場合は生の payload をそのまま載せ、実装の構造検査が
 * invalid-payload に落とすことを検査対象にする(throw で検査を止めない)
 */
function decodeInner(op: string, payload: Readonly<Record<string, unknown>>): ProposableOperation {
  try {
    return toOperation(op, payload) as ProposableOperation;
  } catch {
    return { op, payload } as unknown as ProposableOperation;
  }
}

function toOperation(op: string, payload: Readonly<Record<string, unknown>>): ChainOperation {
  const decode = OPERATION_DECODERS[op];
  if (decode === undefined) {
    throw new Error(`chain vector: unknown op ${op}`);
  }
  return decode(payload);
}

/** ベクターエントリを型付き ChainEntry へ変換する */
export function toTypedEntry(vector: VectorEntry): ChainEntry {
  return {
    ...toOperation(vector.op, vector.payload),
    suite: vector.suite,
    seq: vector.seq,
    prevHashHex: vector.prev_hash_hex,
    actor: {
      userId: vector.actor.user_id,
      keyFingerprintHex: vector.actor.key_fingerprint_hex,
    },
    timestampMs: vector.timestamp_ms,
    signatureHex: vector.signature_hex,
  };
}

export const typedEntries: readonly ChainEntry[] = vectorEntries.map(toTypedEntry);
