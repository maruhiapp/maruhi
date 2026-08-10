// メンバーシップログ API の型付きエラー(CRYPTO_SPEC §6.4)。
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
  "epoch-out-of-sequence",
] as const satisfies readonly ChainInvalidReason[];

// 逆方向の静的検査: crypto 側に理由コードが追加されたらここがコンパイルエラーになる
type AllReasonsListed = ChainInvalidReason extends (typeof CHAIN_INVALID_REASONS)[number]
  ? true
  : never;
const allReasonsListed: AllReasonsListed = true;
void allReasonsListed;

/** Reason codes a server-side chain verification can reject an entry with. */
export const ChainInvalidReasonSchema = Schema.Literals(CHAIN_INVALID_REASONS);

/** 401: the request presented no valid session cookie or API token. */
export class UnauthorizedError extends Schema.TaggedErrorClass<UnauthorizedError>()(
  "Unauthorized",
  {},
  { httpApiStatus: 401 },
) {}

/** Reason codes for a 403 (AUTH_SPEC §5 CSRF / §9-2 実効権限 / §11-1 / §11-3 / §12-3). */
export const ForbiddenReasonSchema = Schema.Literals([
  "csrf-header-required",
  "insufficient-permission",
  "actor-mismatch",
  "org-membership-required",
  "insufficient-role",
]);

/** 403: the authenticated principal may not perform this operation. */
export class ForbiddenError extends Schema.TaggedErrorClass<ForbiddenError>()(
  "Forbidden",
  { reason: ForbiddenReasonSchema },
  { httpApiStatus: 403 },
) {}

/** Reason codes for a failed authentication flow (AUTH_SPEC §3 / §4). */
export const AuthFlowFailureReasonSchema = Schema.Literals([
  "state-mismatch",
  "code-exchange-failed",
  "github-token-invalid",
]);

/**
 * 400: the OAuth / device-flow dance failed (state mismatch, code exchange
 * rejection, or an invalid GitHub token presented to the device exchange).
 * 提示された外部 ID・トークン値は運ばない(理由コードのみ)。
 */
export class AuthFlowError extends Schema.TaggedErrorClass<AuthFlowError>()(
  "AuthFlow",
  { reason: AuthFlowFailureReasonSchema },
  { httpApiStatus: 400 },
) {}

/** Reason codes for a 503 on an unconfigured self-hosted server (AUTH_SPEC §3). */
export const SetupIncompleteReasonSchema = Schema.Literals(["github-oauth-unconfigured"]);

/**
 * 503: this deployment has not finished self-host setup — the GitHub OAuth
 * App is not configured (AUTH_SPEC §3: client_id がプレースホルダ / 空 / 欠落、
 * または client_secret が未登録 / 空)。クライアントは docs/SELF_HOSTING.md の
 * セットアップ手順へ誘導する(成功応答 = 両方登録済み、の意味論を支える)。
 */
export class SetupIncompleteError extends Schema.TaggedErrorClass<SetupIncompleteError>()(
  "SetupIncomplete",
  { reason: SetupIncompleteReasonSchema },
  { httpApiStatus: 503 },
) {}

/** 429: the per-user API token limit has been reached (AUTH_SPEC §6). */
export class TokenLimitError extends Schema.TaggedErrorClass<TokenLimitError>()(
  "TokenLimit",
  { limit: Schema.Number },
  { httpApiStatus: 429 },
) {}

/** 404: no recovery wrap is registered for the authenticated user (AUTH_SPEC §13). */
export class RecoveryWrapNotFoundError extends Schema.TaggedErrorClass<RecoveryWrapNotFoundError>()(
  "RecoveryWrapNotFound",
  {},
  { httpApiStatus: 404 },
) {}

/**
 * 429: the recovery-blob fetch window is exhausted (AUTH_SPEC §13-3 —
 * CRYPTO_SPEC §8 のレート制限)。`retryAfterSeconds` は固定窓の残り秒数。
 */
export class RecoveryRateLimitedError extends Schema.TaggedErrorClass<RecoveryRateLimitedError>()(
  "RecoveryRateLimited",
  { retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}

/** 404: no chain has been initialized under this project id. */
export class ProjectNotFoundError extends Schema.TaggedErrorClass<ProjectNotFoundError>()(
  "ProjectNotFound",
  { projectId: Schema.String },
  { httpApiStatus: 404 },
) {}

/** 409: a chain already exists under this project id (duplicate genesis submission). */
export class ProjectAlreadyInitializedError extends Schema.TaggedErrorClass<ProjectAlreadyInitializedError>()(
  "ProjectAlreadyInitialized",
  { projectId: Schema.String },
  { httpApiStatus: 409 },
) {}

/**
 * 409: compare-and-swap failure (CRYPTO_SPEC §6.4) — the append named a parent
 * head that is no longer the current head. The current head is returned so the
 * client can fetch, re-verify, and retry.
 */
export class ChainHeadConflictError extends Schema.TaggedErrorClass<ChainHeadConflictError>()(
  "ChainHeadConflict",
  { currentHeadSeq: Schema.Number, currentHeadHashHex: Schema.String },
  { httpApiStatus: 409 },
) {}

/**
 * 422: server-side chain verification (CRYPTO_SPEC §6.4 = verifyChain の再実行)
 * rejected the entry at `seq` for `reason`.
 */
export class ChainEntryInvalidError extends Schema.TaggedErrorClass<ChainEntryInvalidError>()(
  "ChainEntryInvalid",
  { seq: Schema.Number, reason: ChainInvalidReasonSchema },
  { httpApiStatus: 422 },
) {}

/** 413: the entry's canonical byte length exceeds the §6.4 acceptance policy (1 MiB). */
export class ChainEntryTooLargeError extends Schema.TaggedErrorClass<ChainEntryTooLargeError>()(
  "ChainEntryTooLarge",
  { limitBytes: Schema.Number },
  { httpApiStatus: 413 },
) {}

/**
 * 422: accepting the entry would exceed the §6.4 chain-wide acceptance policy
 * (10,000 entries / 32 MiB cumulative canonical bytes).
 */
export class ChainCapacityExceededError extends Schema.TaggedErrorClass<ChainCapacityExceededError>()(
  "ChainCapacityExceeded",
  { maxEntries: Schema.Number, maxTotalBytes: Schema.Number },
  { httpApiStatus: 422 },
) {}

/**
 * 422: `create_environment` / `rotate_epoch` entries may only be submitted
 * through their composite endpoints (AUTH_SPEC §6 / §12-4, 2026-08-03) — the
 * generic chain append rejects them so the entry-plus-data atomicity cannot
 * be bypassed ("エポックはあるがラップがない" 中間状態を作らせない).
 */
export class CompositeRequiredError extends Schema.TaggedErrorClass<CompositeRequiredError>()(
  "CompositeRequired",
  { op: Schema.Literals(["create_environment", "rotate_epoch"]) },
  { httpApiStatus: 422 },
) {}

// ---------------------------------------------------------------------------
// データプレーン API の型付きエラー(AUTH_SPEC §12)。
// チェーン API と同じく、エラーは識別子・カウンタのみを運ぶ(平文値・鍵素材なし)。
// EnvironmentNotFound / VariableNotFound が返るのはチェーン導出メンバーに対して
// のみ(プロジェクト自体の存在秘匿 §11-2 が先行する — §12-3)。
// ---------------------------------------------------------------------------

/** 404: no active environment under this id (returned to chain members only). */
export class EnvironmentNotFoundError extends Schema.TaggedErrorClass<EnvironmentNotFoundError>()(
  "EnvironmentNotFound",
  { environmentId: Schema.String },
  { httpApiStatus: 404 },
) {}

/** 404: no active variable under this id (returned to chain members only). */
export class VariableNotFoundError extends Schema.TaggedErrorClass<VariableNotFoundError>()(
  "VariableNotFound",
  { variableId: Schema.String },
  { httpApiStatus: 404 },
) {}

/**
 * Reason codes for a 409 on variable creation or rename (AUTH_SPEC §12-1):
 * `exists` = the id is in use, `retired` = the id was used before (tombstone)
 * and may not be reused, `duplicate-name` = the display name is taken within
 * the uniqueness scope.
 */
export const ResourceConflictReasonSchema = Schema.Literals([
  "exists",
  "retired",
  "duplicate-name",
]);

/**
 * Reason codes for a 409 on environment creation or rename. Only the display
 * name remains a data-plane check: id uniqueness (`exists` / `retired`) was
 * absorbed into the chain consensus rule `duplicate-environment`
 * (ChainEntryInvalid — CRYPTO_SPEC §6.2 / AUTH_SPEC §12-4, 2026-08-03).
 */
export const EnvironmentConflictReasonSchema = Schema.Literals(["duplicate-name"]);

/** 409: the environment display name conflicts (AUTH_SPEC §12-1 / §12-4). */
export class EnvironmentConflictError extends Schema.TaggedErrorClass<EnvironmentConflictError>()(
  "EnvironmentConflict",
  { environmentId: Schema.String, reason: EnvironmentConflictReasonSchema },
  { httpApiStatus: 409 },
) {}

/** 409: the variable id or display name conflicts (AUTH_SPEC §12-1 / §12-5). */
export class VariableConflictError extends Schema.TaggedErrorClass<VariableConflictError>()(
  "VariableConflict",
  { variableId: Schema.String, reason: ResourceConflictReasonSchema },
  { httpApiStatus: 409 },
) {}

/**
 * 409: push CAS failure (AUTH_SPEC §12-5) — the declared AAD version is not
 * `currentVersion + 1`. The client re-encrypts under the next version and
 * retries (the version is part of the AAD, so the server cannot renumber).
 */
export class VersionConflictError extends Schema.TaggedErrorClass<VersionConflictError>()(
  "VersionConflict",
  { currentVersion: Schema.Number },
  { httpApiStatus: 409 },
) {}

/**
 * 409: the declared AAD epoch is not the current chain epoch (AUTH_SPEC
 * §12-5). After a rotation the client fetches the new DEK, re-encrypts and
 * retries under `currentEpoch`.
 */
export class EpochConflictError extends Schema.TaggedErrorClass<EpochConflictError>()(
  "EpochConflict",
  { currentEpoch: Schema.Number },
  { httpApiStatus: 409 },
) {}

/**
 * 422: a declared AAD component does not match the storage coordinates named
 * by the request (AUTH_SPEC §12-2). `field` names the mismatching component.
 */
export class PayloadMismatchError extends Schema.TaggedErrorClass<PayloadMismatchError>()(
  "PayloadMismatch",
  { field: Schema.String },
  { httpApiStatus: 422 },
) {}

/**
 * Reason codes for a 422 on a value push / create (AUTH_SPEC §12-5 =
 * CRYPTO_SPEC §4.1 / §6.4 のサーバー検証。仮裁定 — 確定条件 = PR レビュー承認):
 *
 * - `signature-invalid` — valid-format の Ed25519 検証失敗
 * - `chain-head-unknown` — 署名は有効だが宣言 seq が自チェーンに存在しない、
 *   またはその seq の保存ハッシュと不一致
 * - `chain-head-state-mismatch` — ヘッドは既知だがヘッド時点の鍵 / role / 環境 /
 *   エポックが不一致、または保存 predecessor と prev が不一致
 *
 * 検査順: 署名壊れ → unknown head → state mismatch。仕様(session-12 §6-7)の
 * 3 理由のみ — 4 つ目の理由はワイヤ変更なので本 PR では作らない。
 */
export const ValueSignatureRejectReasonSchema = Schema.Literals([
  "signature-invalid",
  "chain-head-unknown",
  "chain-head-state-mismatch",
]);

/**
 * 422: the value write signature (CRYPTO_SPEC §4.1) was rejected. Carries a
 * reason code only — never signature bytes, hashes or ciphertext fragments.
 */
export class ValueSignatureRejectedError extends Schema.TaggedErrorClass<ValueSignatureRejectedError>()(
  "ValueSignatureRejected",
  { reason: ValueSignatureRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

/**
 * 422: a metadata-statement signature (CRYPTO_SPEC §4.2) was rejected. The
 * reason vocabulary is shared with the value write signature (session-12
 * §6-7 — 新理由コードを作らない): `signature-invalid` / `chain-head-unknown` /
 * `chain-head-state-mismatch`(state-mismatch はヘッド時点の在籍・鍵束縛・
 * role、prev の形 / 保存 predecessor との不一致、削除後の再ステートメントを
 * 含む)。
 */
export class MetaStatementRejectedError extends Schema.TaggedErrorClass<MetaStatementRejectedError>()(
  "MetaStatementRejected",
  { reason: ValueSignatureRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

/**
 * 409: metaVersion CAS failure (AUTH_SPEC §12-5) — the statement's declared
 * metaVersion is not `currentMetaVersion + 1`. Carries the latest metaVersion
 * **number only** (never the winner's signed-bytes hash — クライアントは勝者を
 * 再取得・検証して prev を自計算する。§12-5 の 409 規律)。
 */
export class MetaVersionConflictError extends Schema.TaggedErrorClass<MetaVersionConflictError>()(
  "MetaVersionConflict",
  { currentMetaVersion: Schema.Number },
  { httpApiStatus: 409 },
) {}

/**
 * 422: the statement's display name is not in NFC normal form (AUTH_SPEC
 * §12-1). Normalization is the signing client's responsibility — the server
 * only checks and never normalizes (byte-exact 署名との両立 — CRYPTO_SPEC §4.2)。
 */
export class NameNotNfcError extends Schema.TaggedErrorClass<NameNotNfcError>()(
  "NameNotNfc",
  {},
  { httpApiStatus: 422 },
) {}

/** Reason codes for rejecting a DEK-wrap registration (AUTH_SPEC §12-6). */
export const DekWrapRejectReasonSchema = Schema.Literals([
  "recipient-not-member",
  "recipient-key-mismatch",
  "recipient-missing",
  "duplicate-recipient",
  "epoch-out-of-range",
  "signature-invalid",
]);

/**
 * 422: the wrap set violates §12-6 — a recipient is not a current chain
 * member / has a different chain key, the initial registration for an epoch
 * does not cover the member set exactly, a recipient is duplicated, the
 * epoch is outside 1..currentEpoch, or a registration signature does not
 * verify under the caller's chain signing key (CRYPTO_SPEC §5.1).
 */
export class DekWrapRejectedError extends Schema.TaggedErrorClass<DekWrapRejectedError>()(
  "DekWrapRejected",
  { reason: DekWrapRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

/**
 * 409: a wrap for this (environment, epoch, recipient) already exists.
 * Overwriting is forbidden (§12-6: replacing a valid wrap with an
 * undecryptable blob would be an availability attack the server cannot
 * detect).
 */
export class DekWrapExistsError extends Schema.TaggedErrorClass<DekWrapExistsError>()(
  "DekWrapExists",
  { epoch: Schema.Number, recipientUserId: Schema.String },
  { httpApiStatus: 409 },
) {}

/**
 * 404: no wrap is stored for this (environment, epoch, recipient). Returned by
 * the §12-6 repair path (deletion targets must exist — silently succeeding
 * would let an admin believe a poisoned wrap was removed when it was not).
 */
export class DekWrapNotFoundError extends Schema.TaggedErrorClass<DekWrapNotFoundError>()(
  "DekWrapNotFound",
  { epoch: Schema.Number, recipientUserId: Schema.String },
  { httpApiStatus: 404 },
) {}

/** 413: the value ciphertext exceeds the §12-8 acceptance policy (64 KiB). */
export class ValueTooLargeError extends Schema.TaggedErrorClass<ValueTooLargeError>()(
  "ValueTooLarge",
  { limitBytes: Schema.Number },
  { httpApiStatus: 413 },
) {}

/** Resources bounded by the §12-8 count / cumulative-size acceptance policy. */
export const DataLimitResourceSchema = Schema.Literals([
  "environments",
  "environment-rows",
  "variables",
  "variable-rows",
  "versions",
  // metaVersion 行 / 変数(環境)。仮裁定: §12-8 の「バージョン数 / 変数」と
  // 同値(1,000)を rename / 削除のステートメント行にも適用する(無制限の
  // rename 連打による DO ストレージ肥大の遮断。確定条件 = PR レビュー承認)
  "meta-versions",
  "project-ciphertext-bytes",
  "dek-wraps-per-request",
  "dek-wrap-rows",
]);

/** 422: accepting the request would exceed a §12-8 count / size limit. */
export class DataLimitExceededError extends Schema.TaggedErrorClass<DataLimitExceededError>()(
  "DataLimitExceeded",
  { resource: DataLimitResourceSchema, limit: Schema.Number },
  { httpApiStatus: 422 },
) {}
