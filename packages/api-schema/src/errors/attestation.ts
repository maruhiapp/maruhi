// ヘッド申告 API の型付きエラー(CRYPTO_SPEC §6.6 / AUTH_SPEC §16-1)。
//
// エラーには識別子・カウンタしか載せない(平文値・鍵素材の断片を運ばない)。

import { Schema } from "effect";

/**
 * 申告の受理検証(CRYPTO_SPEC §6.4)の拒否理由。crypto の詳細理由からの写像は
 * 値署名(ValueSignatureRejectReason)と同じ畳み方:
 *
 * - `signature-invalid` — 呼び出し主体の受理時点チェーン導出 sig 鍵での
 *   署名検証失敗
 * - `chain-head-unknown` — 申告ヘッド(hash + seq)の exact pair が自チェーン上に
 *   存在しない(seq が現ヘッドより先の場合を含む — クライアント側の再同期分岐は
 *   サーバーには無い)
 * - `chain-head-state-mismatch` — 申告ヘッド時点の在籍・鍵束縛の不一致
 *   (remove → 別鍵 re-add の旧在籍区間ヘッド申告の拒否を含む)
 */
export const AttestationRejectReasonSchema = Schema.Literals([
  "signature-invalid",
  "chain-head-unknown",
  "chain-head-state-mismatch",
]);

/** 422: the head-attestation acceptance verification rejected the submission. */
export class AttestationRejectedError extends Schema.TaggedError<AttestationRejectedError>()(
  "AttestationRejected",
  { reason: AttestationRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

/**
 * 409: seq regression against the stored attestation (CRYPTO_SPEC §6.4 /
 * AUTH_SPEC §16-1 — 黙って成功させない規律). The stored seq is returned: an
 * honest client hitting this indicates floor damage or a concurrent CLI whose
 * view regressed, which must surface instead of being silently swallowed.
 * Resubmitting the same seq is idempotent (204), so this only fires on a
 * strict regression.
 */
export class AttestationRegressionError extends Schema.TaggedError<AttestationRegressionError>()(
  "AttestationRegression",
  { storedSeq: Schema.Number },
  { httpApiStatus: 409 },
) {}

/**
 * 429: the per-member fixed-window submission limit is exhausted
 * (AUTH_SPEC §16-1 — 起草値: 1 時間 60 回).
 */
export class AttestationRateLimitedError extends Schema.TaggedError<AttestationRateLimitedError>()(
  "AttestationRateLimited",
  { retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}
