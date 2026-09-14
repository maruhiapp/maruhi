// 招待 API の型付きエラー(AUTH_SPEC §15)。
//
// エラーには識別子・カウンタしか載せない(トークン生値・鍵素材を運ばない)。
// InviteNotFound はプロジェクト座標を一切運ばない: トークン保持が capability で
// あり(§15-1)、未知トークンへの応答からプロジェクトの存在を推定させない
// (§11-2 の存在秘匿と同じ規律の受諾経路版)。

import { Schema } from "effect";

/**
 * 404: no invitation matches the presented token (accept) or id (revoke).
 * 存在秘匿のためフィールドを持たない。
 */
export class InviteNotFoundError extends Schema.TaggedError<InviteNotFoundError>()(
  "InviteNotFound",
  {},
  { httpApiStatus: 404 },
) {}

/**
 * 410 の理由(AUTH_SPEC §15-1 の単回使用 + 期限切れ導出)。観測できるのは
 * 2^256 空間のトークン保持者(capability 保持者)のみであり、正規受諾者が
 * リンク横取りの先着受諾を「うるさい競合」として検出する(CRYPTO_SPEC §6.5)
 * ために理由を返す。判定順は状態 → 期限(revoked かつ期限切れは revoked)。
 */
export const InviteGoneReasonSchema = Schema.Literals([
  "accepted",
  "completed",
  "revoked",
  "expired",
]);

/** 410: the invitation is no longer usable (single-use CAS — AUTH_SPEC §15-1). */
export class InviteGoneError extends Schema.TaggedError<InviteGoneError>()(
  "InviteGone",
  { reason: InviteGoneReasonSchema },
  { httpApiStatus: 410 },
) {}

/**
 * 422: one of the acceptance co-signatures failed verification (CRYPTO_SPEC
 * §6.5 v2)。`which` は落ちた署名(`link` = リンク鍵の共同署名 — 判定順で先、
 * `accept` = 受諾者のチェーン鍵)。signed_bytes の project_id / link_pub は
 * 保存行から、invitee_user_id は呼び出し主体から再構成される(§15-2)ため、
 * 別人の署名・別招待からの移植・鍵すり替えはすべてこのエラーに畳まれる
 * (専用の actor-mismatch を持たない)。
 */
export class InviteSignatureInvalidError extends Schema.TaggedError<InviteSignatureInvalidError>()(
  "InviteSignatureInvalid",
  { which: Schema.Literals(["link", "accept"]) },
  { httpApiStatus: 422 },
) {}

/**
 * 409: the client-chosen invite id or link public key already exists
 * (AUTH_SPEC §15-2 — 招待 id はクライアント採番、link_pub は UNIQUE)。
 * クライアントは採番・生成し直して再試行する。
 */
export class InviteConflictError extends Schema.TaggedError<InviteConflictError>()(
  "InviteConflict",
  { field: Schema.Literals(["id", "linkPub"]) },
  { httpApiStatus: 409 },
) {}

/** 429: the per-project pending-invitation cap is reached (AUTH_SPEC §15-2). */
export class InvitePendingLimitError extends Schema.TaggedError<InvitePendingLimitError>()(
  "InvitePendingLimit",
  { limit: Schema.Number },
  { httpApiStatus: 429 },
) {}

/**
 * 429: the per-project issuance window is exhausted (AUTH_SPEC §15-2 —
 * 固定窓 1 時間 30 回)。`retryAfterSeconds` は窓の残り秒数。
 */
export class InviteRateLimitedError extends Schema.TaggedError<InviteRateLimitedError>()(
  "InviteRateLimited",
  { retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}
