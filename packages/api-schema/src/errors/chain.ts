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
  // checkpoint op(CRYPTO_SPEC §6.2。2026-08-27 セッション 33 — PR-F3a)
  "checkpoint-audit-role-insufficient",
  "checkpoint-epoch-mismatch",
  "checkpoint-regression",
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
 * through their composite endpoints (AUTH_SPEC §6 / §12-4, 2026-08-03) — the
 * generic chain append rejects them so the entry-plus-data atomicity cannot
 * be bypassed ("エポックはあるがラップがない" 中間状態を作らせない).
 *
 * `checkpoint` は本エラーの対象ではない(2026-08-28 — PR-M2): standalone
 * (周期)チェックポイントは §16-2 のとおり汎用 append が受理検証(内容突合 +
 * スナップショット原子保存)つきで受理する。PR-F3a〜M2 実装前の過渡期のみ
 * fail-closed の拒否対象だった。
 */
export class CompositeRequiredError extends Schema.TaggedError<CompositeRequiredError>()(
  "CompositeRequired",
  { op: Schema.Literals(["create_environment", "rotate_epoch"]) },
  { httpApiStatus: 422 },
) {}
