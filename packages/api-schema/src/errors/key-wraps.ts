// master 鍵ラップ台帳 API の型付きエラー(AUTH_SPEC §13-6〜13-10 — KL3)。
//
// エラーには識別子・理由コード・カウンタしか載せない(ラップ・分片・鍵素材を
// 運ばない)。存在秘匿(§11-2 と同じ規律): ハンドオフ要求の照会・承認は
// 「ward 本人か ward の保護者」以外・不明・失効をすべて一様な 404 に畳む。

import { Schema } from "effect";

/** 404: no ledger row (passkey wrap / guardian group / share) is addressable by the caller. */
export class KeyWrapNotFoundError extends Schema.TaggedError<KeyWrapNotFoundError>()(
  "KeyWrapNotFound",
  {},
  { httpApiStatus: 404 },
) {}

/**
 * 404: the handoff request is unknown, expired, or not visible to the caller
 * (neither the ward nor one of the ward's guardians — AUTH_SPEC §13-7 の一様 404)。
 */
export class HandoffNotFoundError extends Schema.TaggedError<HandoffNotFoundError>()(
  "HandoffNotFound",
  {},
  { httpApiStatus: 404 },
) {}

/** 409 の理由: 要求 id の衝突 / 同一 (request, source, share_index) の二重承認。 */
export const HandoffConflictReasonSchema = Schema.Literals(["request-exists", "already-approved"]);

/** 409: the handoff request or approval already exists (AUTH_SPEC §13-7). */
export class HandoffConflictError extends Schema.TaggedError<HandoffConflictError>()(
  "HandoffConflict",
  { reason: HandoffConflictReasonSchema },
  { httpApiStatus: 409 },
) {}

/**
 * 422 の理由(AUTH_SPEC §13-8 の受理ポリシーと §13-7 の構造条件):
 * - too-many-passkeys / too-many-groups: user あたりの上限(5)
 * - share-count: 分片数が 1..5 の外、`all` で 2 未満、または share_index が 1..n を
 *   ちょうど 1 回ずつ覆っていない
 * - unknown-guardian / self-guardian / duplicate-guardian: 分片の受信者条件
 * - source-mismatch: 承認の source / share_index / blob の組み合わせが呼び出し
 *   主体の役割(ward = device のみ、保護者 = 自分の分片のみ)と合わない
 * - approvals-exceeded: 1 要求あたりの承認数上限
 */
export const KeyWrapPolicyReasonSchema = Schema.Literals([
  "too-many-passkeys",
  "too-many-groups",
  "share-count",
  "unknown-guardian",
  "self-guardian",
  "duplicate-guardian",
  "source-mismatch",
  "approvals-exceeded",
]);

/** 422: the registration / approval violates a ledger policy (AUTH_SPEC §13-7 / §13-8). */
export class KeyWrapPolicyError extends Schema.TaggedError<KeyWrapPolicyError>()(
  "KeyWrapPolicy",
  { reason: KeyWrapPolicyReasonSchema },
  { httpApiStatus: 422 },
) {}

/** 固定窓の種別(AUTH_SPEC §13-8): ブロブ取得(合算)/ ハンドオフ要求 / 承認。 */
export const KeyWrapWindowSchema = Schema.Literals(["blob-fetch", "handoff-request", "approval"]);

/** 429: a §13-8 fixed window is exhausted. `retryAfterSeconds` は窓の残り秒数。 */
export class KeyWrapRateLimitedError extends Schema.TaggedError<KeyWrapRateLimitedError>()(
  "KeyWrapRateLimited",
  { window: KeyWrapWindowSchema, retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}
