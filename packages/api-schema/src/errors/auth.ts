// 認証・アイデンティティ API の型付きエラー(AUTH_SPEC §3-§6 / §13)。
//
// エラーには識別子・カウンタしか載せない(平文値・鍵素材・外部トークン値を運ばない)。

import { Schema } from "effect";

/** 401: the request presented no valid session cookie or API token. */
export class UnauthorizedError extends Schema.TaggedError<UnauthorizedError>()(
  "Unauthorized",
  {},
  { httpApiStatus: 401 },
) {}

/**
 * Reason codes for a 403 (AUTH_SPEC §5 CSRF / セッション能力制限 / §9-2 実効権限 /
 * §11-1 / §11-3 / §12-3).
 *
 * `session-not-allowed` = セッション主体の能力制限(§5 の肯定列挙外 — W2b)。
 * エンドポイント同一性と主体種別のみから決まる一様応答であり、プロジェクトの
 * 存在・状態情報を運ばない(§11-2 の存在秘匿と両立する — §12-3 の認可先行例外と
 * 同じ「リクエスト内容のみから計算できる」論法)。
 */
export const ForbiddenReasonSchema = Schema.Literals([
  "csrf-header-required",
  "session-not-allowed",
  "insufficient-permission",
  "actor-mismatch",
  "org-membership-required",
  "insufficient-role",
]);

/** 403: the authenticated principal may not perform this operation. */
export class ForbiddenError extends Schema.TaggedError<ForbiddenError>()(
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
export class AuthFlowError extends Schema.TaggedError<AuthFlowError>()(
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
export class SetupIncompleteError extends Schema.TaggedError<SetupIncompleteError>()(
  "SetupIncomplete",
  { reason: SetupIncompleteReasonSchema },
  { httpApiStatus: 503 },
) {}

/**
 * 429: too many device exchanges from this source address (AUTH_SPEC §4 —
 * deepsec M3/B11)。交換はリクエストごとに GitHub check-token API への
 * アウトバウンドを伴い、その枠は OAuth App 単位の共有クォータなので、
 * 発信元 IP 単位の best-effort 制限を既定デプロイでも強制する。
 * `retryAfterSeconds` は次に試してよい目安(固定窓の周期)。
 */
export class AuthRateLimitedError extends Schema.TaggedError<AuthRateLimitedError>()(
  "AuthRateLimited",
  { retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}

/** 429: the per-user API token limit has been reached (AUTH_SPEC §6). */
export class TokenLimitError extends Schema.TaggedError<TokenLimitError>()(
  "TokenLimit",
  { limit: Schema.Number },
  { httpApiStatus: 429 },
) {}

/** 404: no recovery wrap is registered for the authenticated user (AUTH_SPEC §13). */
export class RecoveryWrapNotFoundError extends Schema.TaggedError<RecoveryWrapNotFoundError>()(
  "RecoveryWrapNotFound",
  {},
  { httpApiStatus: 404 },
) {}

/**
 * 429: the recovery-blob fetch window is exhausted (AUTH_SPEC §13-3 —
 * CRYPTO_SPEC §8 のレート制限)。`retryAfterSeconds` は固定窓の残り秒数。
 */
export class RecoveryRateLimitedError extends Schema.TaggedError<RecoveryRateLimitedError>()(
  "RecoveryRateLimited",
  { retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}
