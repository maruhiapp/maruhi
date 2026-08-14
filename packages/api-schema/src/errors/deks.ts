// DEK ラップ登録・修復 API の型付きエラー(AUTH_SPEC §12-6 / CRYPTO_SPEC §5.1)。
//
// エラーには識別子・カウンタしか載せない(ラップ・鍵素材の断片を運ばない)。

import { Schema } from "effect";

/**
 * Reason codes for rejecting a DEK-wrap registration (AUTH_SPEC §12-6).
 * 受信者クラス server(2026-08-12): FP に一致する有効 grant がない =
 * `recipient-not-granted`、grant はあるが対象環境が開示スコープ外 =
 * `scope-out-of-range`(いずれも 422)。enc 公開鍵の不一致はクラス共通の
 * `recipient-key-mismatch`。
 */
export const DekWrapRejectReasonSchema = Schema.Literals([
  "recipient-not-member",
  "recipient-not-granted",
  "recipient-key-mismatch",
  "recipient-missing",
  "duplicate-recipient",
  "epoch-out-of-range",
  "scope-out-of-range",
  "signature-invalid",
]);

/**
 * 422: the wrap set violates §12-6 — a recipient is not a current chain
 * member / has a different chain key, the initial registration for an epoch
 * does not cover the member set exactly, a recipient is duplicated, the
 * epoch is outside 1..currentEpoch, or a registration signature does not
 * verify under the caller's chain signing key (CRYPTO_SPEC §5.1).
 */
export class DekWrapRejectedError extends Schema.TaggedError<DekWrapRejectedError>()(
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
export class DekWrapExistsError extends Schema.TaggedError<DekWrapExistsError>()(
  "DekWrapExists",
  { epoch: Schema.Number, recipientUserId: Schema.String },
  { httpApiStatus: 409 },
) {}

/**
 * 404: no wrap is stored for this (environment, epoch, recipient). Returned by
 * the §12-6 repair path (deletion targets must exist — silently succeeding
 * would let an admin believe a poisoned wrap was removed when it was not).
 */
export class DekWrapNotFoundError extends Schema.TaggedError<DekWrapNotFoundError>()(
  "DekWrapNotFound",
  { epoch: Schema.Number, recipientUserId: Schema.String },
  { httpApiStatus: 404 },
) {}
