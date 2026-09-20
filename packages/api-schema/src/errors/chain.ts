// メンバーシップログ(チェーン)API の型付きエラー(CRYPTO_SPEC §6.4)。
//
// エラーには識別子・カウンタしか載せない(平文値・鍵素材の断片を運ばない)。

import type { ChainInvalidReason } from "@maruhi/crypto";
import { Schema } from "effect";

// crypto の ChainInvalidReason と同期する理由コード一覧(satisfies で静的検査)。
// 値の実体をここに持つのは、api-schema をランタイムで crypto に依存させないため。
const CHAIN_INVALID_REASONS = [
  "empty-chain",
  "bad-suite",
  "bad-seq",
  "bad-prev-hash",
  "bad-genesis",
  "bad-signature",
  "invalid-payload",
  "insufficient-role",
  "actor-not-member",
  "actor-key-mismatch",
  "last-owner-protected",
  "unknown-target",
  "duplicate-member",
  "duplicate-member-key",
  "duplicate-environment",
  "unknown-environment",
  "unknown-server-grant",
  "grant-scope-narrowed",
  "duplicate-server-key",
  "epoch-out-of-sequence",
  // checkpoint op(CRYPTO_SPEC §6.2)
  "checkpoint-audit-role-insufficient",
  "checkpoint-epoch-mismatch",
  "checkpoint-regression",
  // 環境スコープ(CRYPTO_SPEC §6.2 — 2026-09-14 ES)
  "scope-role-mismatch",
  "scope-not-contained",
  "environment-out-of-scope",
  // 四眼(CRYPTO_SPEC §6.2 — 2026-09-14 PF1)
  "approval-required",
  "approval-not-required",
  "approval-quorum-unreachable",
  "unknown-proposal",
  "duplicate-approval",
  "proposal-expired",
  "proposal-void",
  // 端末鍵(CRYPTO_SPEC §6.2 — 2026-09-19 DK)
  "unknown-device",
  "last-device-protected",
  "device-cap-exceeded",
] as const satisfies readonly ChainInvalidReason[];

// 逆方向の静的検査: crypto 側に理由コードが追加されたらここがコンパイルエラーになる
type AllReasonsListed = ChainInvalidReason extends (typeof CHAIN_INVALID_REASONS)[number]
  ? true
  : never;
const allReasonsListed: AllReasonsListed = true;
void allReasonsListed;

/** Reason codes a server-side chain verification can reject an entry with. */
export const ChainInvalidReasonSchema = Schema.Literals(CHAIN_INVALID_REASONS);

/** 404: no chain has been initialized under this project id. */
export class ProjectNotFoundError extends Schema.TaggedError<ProjectNotFoundError>()(
  "ProjectNotFound",
  { projectId: Schema.String },
  { httpApiStatus: 404 },
) {}

/** 409: a chain already exists under this project id (duplicate genesis submission). */
export class ProjectAlreadyInitializedError extends Schema.TaggedError<ProjectAlreadyInitializedError>()(
  "ProjectAlreadyInitialized",
  { projectId: Schema.String },
  { httpApiStatus: 409 },
) {}

/**
 * 429: the org already holds the maximum number of active projects (AUTH_SPEC
 * §11-3 — テナント quota。起草値 100). Returned only for a **fresh** genesis:
 * the §11-3 repair path (already-initialized + missing `projects` row +
 * genesis actor) is never blocked by this limit. Carries the limit only.
 */
export class ProjectLimitError extends Schema.TaggedError<ProjectLimitError>()(
  "ProjectLimit",
  { limit: Schema.Number },
  { httpApiStatus: 429 },
) {}

/**
 * 409: compare-and-swap failure (CRYPTO_SPEC §6.4) — the append named a parent
 * head that is no longer the current head. The current head is returned so the
 * client can fetch, re-verify, and retry.
 */
export class ChainHeadConflictError extends Schema.TaggedError<ChainHeadConflictError>()(
  "ChainHeadConflict",
  { currentHeadSeq: Schema.Number, currentHeadHashHex: Schema.String },
  { httpApiStatus: 409 },
) {}

/**
 * 422: server-side chain verification (CRYPTO_SPEC §6.4 = verifyChain の再実行)
 * rejected the entry at `seq` for `reason`.
 */
export class ChainEntryInvalidError extends Schema.TaggedError<ChainEntryInvalidError>()(
  "ChainEntryInvalid",
  { seq: Schema.Number, reason: ChainInvalidReasonSchema },
  { httpApiStatus: 422 },
) {}

/** 413: the entry's canonical byte length exceeds the §6.4 acceptance policy (1 MiB). */
export class ChainEntryTooLargeError extends Schema.TaggedError<ChainEntryTooLargeError>()(
  "ChainEntryTooLarge",
  { limitBytes: Schema.Number },
  { httpApiStatus: 413 },
) {}

/**
 * 422: accepting the entry would exceed the §6.4 chain-wide acceptance policy
 * (10,000 entries / 32 MiB cumulative canonical bytes).
 */
export class ChainCapacityExceededError extends Schema.TaggedError<ChainCapacityExceededError>()(
  "ChainCapacityExceeded",
  { maxEntries: Schema.Number, maxTotalBytes: Schema.Number },
  { httpApiStatus: 422 },
) {}

/**
 * 422: `create_environment` / `rotate_epoch` entries may only be submitted
 * through their composite endpoints (AUTH_SPEC §6 / §12-4) — the
 * generic chain append rejects them so the entry-plus-data atomicity cannot
 * be bypassed ("エポックはあるがラップがない" 中間状態を作らせない).
 *
 * `checkpoint` は本エラーの対象ではない: standalone
 * (周期)チェックポイントは §16-2 のとおり汎用 append が受理検証(内容突合 +
 * スナップショット原子保存)つきで受理する。
 */
export class CompositeRequiredError extends Schema.TaggedError<CompositeRequiredError>()(
  "CompositeRequired",
  { op: Schema.Literals(["create_environment", "rotate_epoch"]) },
  { httpApiStatus: 422 },
) {}

/**
 * 422: the four-eyes operations (`set_approval_policy` / `propose` / `approve`
 * / `withdraw` — CRYPTO_SPEC §6.2 PF1) are part of the chain format but the
 * server does not accept them. Raised by servers before ES + PF1 K5 (the
 * acceptance side effects — audit mirror rows for the applied inner op,
 * rotation detection, wrap cleanup, pending-proposal limit — landed together
 * with acceptance in K5). A K5+ server never raises it; the declaration stays
 * on the wire so a newer CLI gets a typed message against an older self-hosted
 * server (設計録 es-design.md §11 K5-A — ワイヤからの削除は所有者裁定)。
 */
export class ApprovalNotAcceptedError extends Schema.TaggedError<ApprovalNotAcceptedError>()(
  "ApprovalNotAccepted",
  { op: Schema.Literals(["set_approval_policy", "propose", "approve", "withdraw"]) },
  { httpApiStatus: 422 },
) {}

/**
 * 422: the device-key operations (`add_device` / `revoke_device` — CRYPTO_SPEC
 * §6.2, 2026-09-19 DK) are part of the chain format but this server does not
 * accept them yet. Raised by servers before DK K3 (the acceptance side effects —
 * mirror rows, rotation detection for revoked devices, attestation-row cleanup,
 * the per-member device limit — land together with acceptance in K3; 設計録
 * dk-design.md §3 / §7 K2-6 — ES K2-10 の原則「サーバーが受理する op の集合 =
 * 受理副作用が実装済みの op の集合」). A K3+ server never raises it; the
 * declaration stays on the wire so a newer CLI gets a typed message against an
 * older self-hosted server (ApprovalNotAccepted と同じ扱い). K3(2026-09-20)で
 * サーバーの発生源は消えた(設計録 dk-design.md §8 — ES K5-A と同じ「ワイヤに残す」)。
 * 削除の節目: K4(端末鍵 CLI)の配布後、K3 未満のセルフホストサーバーを支える互換窓が
 * 終わった時点(所有者裁定 — ApprovalNotAccepted と同じ扱い)。それまでは CLI の型付き
 * エラー表示のためだけに残る。
 */
export class DeviceOpsNotAcceptedError extends Schema.TaggedError<DeviceOpsNotAcceptedError>()(
  "DeviceOpsNotAccepted",
  { op: Schema.Literals(["add_device", "revoke_device"]) },
  { httpApiStatus: 422 },
) {}

/**
 * 422: an `add_device` entry would exceed the per-member active-device limit
 * (AUTH_SPEC §12-8 / CRYPTO_SPEC §6.4 — 16 active devices per member per
 * project, 2026-09-19 DK). Counted on the chain-derived state before the entry
 * (revoked devices do not count — `revoke_device` / `remove_member` free
 * slots). An acceptance policy, not a consensus rule. Carries the limit only.
 */
export class DeviceLimitError extends Schema.TaggedError<DeviceLimitError>()(
  "DeviceLimit",
  { limit: Schema.Number },
  { httpApiStatus: 422 },
) {}

/**
 * Why a `propose` entry was refused by the pending-proposal acceptance policy
 * (AUTH_SPEC §12-8 / CRYPTO_SPEC §6.4 — 合意規則ではない):
 *
 * - `pending-proposals`: the project already holds the maximum number of live
 *   (unexpired by the server clock) pending proposals; `limit` = that count.
 *   Withdrawing or completing a proposal frees a slot.
 * - `proposal-lifetime`: `expires_at_ms` lies beyond the server clock plus the
 *   maximum lifetime; `limit` = that lifetime in milliseconds.
 */
export const ProposalLimitReasonSchema = Schema.Literals([
  "pending-proposals",
  "proposal-lifetime",
]);

/**
 * 422: a `propose` entry exceeds the pending-proposal acceptance policy
 * (AUTH_SPEC §12-8: 32 live proposals per project, `expires_at_ms` at most 30
 * days past the server clock). An acceptance policy, not a consensus rule —
 * the entry may be valid under CRYPTO_SPEC §6.2 and still be refused here.
 */
export class ProposalLimitError extends Schema.TaggedError<ProposalLimitError>()(
  "ProposalLimit",
  { reason: ProposalLimitReasonSchema, limit: Schema.Number },
  { httpApiStatus: 422 },
) {}
