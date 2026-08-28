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
 * Reason codes for a 422 on an environment manifest (AUTH_SPEC §12-5 =
 * CRYPTO_SPEC §4.3。2026-08-18): 既存の 3 語彙(署名・ヘッド系)を共有し、
 * マニフェスト固有の 2 理由を加える —
 *
 * - `manifest-digest-mismatch` — サーバーが受理後のメタ状態(同梱ステートメント
 *   適用後の全変数ステートメント + 環境メタステートメント)から再計算した
 *   variablesDigestHex / envMetaVersion / envMetaSigHashHex と申告値の不一致
 *   (§12-5 (7))
 * - `manifest-epoch-mismatch` — エポック整合の失敗(§12-5 (4): 宣言ヘッド時点の
 *   現エポック — rotate / 作成複合の同梱分は同梱エントリ適用後の状態)
 * - `checkpoint-binding-mismatch` / `checkpoint-equivocation` /
 *   `checkpoint-regressed` — チェックポイント束縛(CRYPTO_SPEC §4.3 (2) —
 *   2026-08-27 セッション 33: 検証済みチェーン上の当該 (environment_id,
 *   manifest_version) タプルとの完全一致必須 / 同座標の相違タプル併存 =
 *   equivocation の証拠 / 最新チェックポイント基準に対する非後退〔§6.3 整合
 *   規則 1〕の失敗)
 */
export const ManifestRejectReasonSchema = Schema.Literals([
  "signature-invalid",
  "chain-head-unknown",
  "chain-head-state-mismatch",
  "manifest-digest-mismatch",
  "manifest-epoch-mismatch",
  "checkpoint-binding-mismatch",
  "checkpoint-equivocation",
  "checkpoint-regressed",
]);

/**
 * 422: the environment manifest (CRYPTO_SPEC §4.3) was rejected. Carries a
 * reason code only — never signature bytes, hashes or digests.
 */
export class ManifestRejectedError extends Schema.TaggedError<ManifestRejectedError>()(
  "ManifestRejected",
  { reason: ManifestRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

/**
 * Reason codes for a 422 on a `checkpoint` entry's acceptance-time state
 * matching (CRYPTO_SPEC §6.4 / AUTH_SPEC §16-2。境界同梱分〔§12-4 — 突合
 * 基準は複合の適用後の保存状態〕と standalone 分〔汎用チェーン追記 — 受理
 * 時点 = 適用前の保存状態〕の両経路で共通):
 *
 * - `manifest-mismatch` — タプルの (manifest_version, manifest_sig_hash) が
 *   受理時点の当該環境の**最新**マニフェストと不一致(発行者のビューが古い
 *   場合と、実在しない先行 manifest_version の公証 — 悪意 member による
 *   checkpoint-regressed 詰まらせ — の両方を含む。session-33 §5 の申し送り)
 * - `values-digest-mismatch` — タプルの values_digest が受理時点の保存状態
 *   (全 active 変数の最新 version とその value_signed_bytes ハッシュ)からの
 *   再計算と不一致。宣言ヘッド確定後の並行 push で正当に起きる —
 *   クライアントは再 pull の上で有界再試行する(§12-4 / §16-2)
 * - `audit-head-unknown` — 非空 audit_head_hash が保存済みの累積ハッシュ列
 *   (AUDIT_SPEC §5.1)に存在しない(偽公証の拒否)
 * - `audit-head-stale` — 出現位置が直前 checkpoint(公証の有無を問わない)の
 *   ミラー行(chain.checkpointed)未満(CRYPTO_SPEC §6.4 の位置下限。直前が
 *   存在しない初回は課さない。CAS 競合後に申告を取り直さなかった発行の拒否 —
 *   クライアントは申告も取得し直して再試行する)
 * - `environment-deleted` — 削除済み(tombstone)環境のエントリ(受理時点
 *   状態との一致が定義できない — チェーンは削除を観測しないため合意規則には
 *   できない。CRYPTO_SPEC §6.4)
 */
export const CheckpointMismatchReasonSchema = Schema.Literals([
  "manifest-mismatch",
  "values-digest-mismatch",
  "audit-head-unknown",
  "audit-head-stale",
  "environment-deleted",
]);

/**
 * 422: a `checkpoint` entry's attested content does not match the
 * acceptance-time stored state (CRYPTO_SPEC §6.4 / AUTH_SPEC §16-2).
 */
export class CheckpointStateMismatchError extends Schema.TaggedError<CheckpointStateMismatchError>()(
  "CheckpointStateMismatch",
  { reason: CheckpointMismatchReasonSchema },
  { httpApiStatus: 422 },
) {}

/**
 * 409: manifestVersion CAS failure (AUTH_SPEC §12-5 (6)) — the manifest's
 * declared manifestVersion is not `currentManifestVersion + 1`. Carries the
 * latest manifestVersion **number only**(勝者のハッシュを載せない規律は
 * metaVersion CAS と同一 — §12-5)。再試行ではステートメントとマニフェストの
 * **両方**を再署名する。
 */
export class ManifestVersionConflictError extends Schema.TaggedError<ManifestVersionConflictError>()(
  "ManifestVersionConflict",
  { currentManifestVersion: Schema.Number },
  { httpApiStatus: 409 },
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
