// データプレーン API の型付きエラー(AUTH_SPEC §12)。
//
// チェーン API と同じく、エラーは識別子・カウンタのみを運ぶ(平文値・鍵素材なし)。
// EnvironmentNotFound / VariableNotFound が返るのはチェーン導出メンバーに対して
// のみ(プロジェクト自体の存在秘匿 §11-2 が先行する — §12-3)。

import { Schema } from "effect";

/** 404: no active environment under this id (returned to chain members only). */
export class EnvironmentNotFoundError extends Schema.TaggedError<EnvironmentNotFoundError>()(
  "EnvironmentNotFound",
  { environmentId: Schema.String },
  { httpApiStatus: 404 },
) {}

/** 404: no active variable under this id (returned to chain members only). */
export class VariableNotFoundError extends Schema.TaggedError<VariableNotFoundError>()(
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
export class EnvironmentConflictError extends Schema.TaggedError<EnvironmentConflictError>()(
  "EnvironmentConflict",
  { environmentId: Schema.String, reason: EnvironmentConflictReasonSchema },
  { httpApiStatus: 409 },
) {}

/** 409: the variable id or display name conflicts (AUTH_SPEC §12-1 / §12-5). */
export class VariableConflictError extends Schema.TaggedError<VariableConflictError>()(
  "VariableConflict",
  { variableId: Schema.String, reason: ResourceConflictReasonSchema },
  { httpApiStatus: 409 },
) {}

/**
 * 409: push CAS failure (AUTH_SPEC §12-5) — the declared AAD version is not
 * `currentVersion + 1`. The client re-encrypts under the next version and
 * retries (the version is part of the AAD, so the server cannot renumber).
 */
export class VersionConflictError extends Schema.TaggedError<VersionConflictError>()(
  "VersionConflict",
  { currentVersion: Schema.Number },
  { httpApiStatus: 409 },
) {}

/**
 * 409: the declared AAD epoch is not the current chain epoch (AUTH_SPEC
 * §12-5). After a rotation the client fetches the new DEK, re-encrypts and
 * retries under `currentEpoch`.
 */
export class EpochConflictError extends Schema.TaggedError<EpochConflictError>()(
  "EpochConflict",
  { currentEpoch: Schema.Number },
  { httpApiStatus: 409 },
) {}

/**
 * 422: a declared AAD component does not match the storage coordinates named
 * by the request (AUTH_SPEC §12-2). `field` names the mismatching component.
 */
export class PayloadMismatchError extends Schema.TaggedError<PayloadMismatchError>()(
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
export class ValueSignatureRejectedError extends Schema.TaggedError<ValueSignatureRejectedError>()(
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
export class MetaStatementRejectedError extends Schema.TaggedError<MetaStatementRejectedError>()(
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
export class MetaVersionConflictError extends Schema.TaggedError<MetaVersionConflictError>()(
  "MetaVersionConflict",
  { currentMetaVersion: Schema.Number },
  { httpApiStatus: 409 },
) {}

/**
 * 422: the statement's display name is not in NFC normal form (AUTH_SPEC
 * §12-1). Normalization is the signing client's responsibility — the server
 * only checks and never normalizes (byte-exact 署名との両立 — CRYPTO_SPEC §4.2)。
 */
export class NameNotNfcError extends Schema.TaggedError<NameNotNfcError>()(
  "NameNotNfc",
  {},
  { httpApiStatus: 422 },
) {}

/** 413: the value ciphertext exceeds the §12-8 acceptance policy (64 KiB). */
export class ValueTooLargeError extends Schema.TaggedError<ValueTooLargeError>()(
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
  // 取り下げ対象の列挙上限(AUDIT_SPEC §7 の取り下げ操作 — Wave 2 B2)
  "rotation-dismissals-per-request",
]);

/** 422: accepting the request would exceed a §12-8 count / size limit. */
export class DataLimitExceededError extends Schema.TaggedError<DataLimitExceededError>()(
  "DataLimitExceeded",
  { resource: DataLimitResourceSchema, limit: Schema.Number },
  { httpApiStatus: 422 },
) {}
