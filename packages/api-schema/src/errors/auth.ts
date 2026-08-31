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
 * 400: the web OAuth dance failed (state mismatch, code exchange rejection,
 * or a user-info fetch failure on the obtained token).
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
 * 429: too many requests to an unauthenticated auth surface from this source
 * address (AUTH_SPEC §3 / §4 — deepsec M3/B11)。OAuth callback は GitHub への
 * アウトバウンド(OAuth App 単位の共有クォータ)を伴い、CLI ログインの
 * start / poll は未認証の CPU 消費面なので、発信元 IP 単位の best-effort
 * 制限を既定デプロイでも強制する(§4-1 の Workers Rate Limiting binding
 * パターン)。`retryAfterSeconds` は次に試してよい目安(固定窓の周期)。
 */
export class AuthRateLimitedError extends Schema.TaggedError<AuthRateLimitedError>()(
  "AuthRateLimited",
  { retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}

/**
 * 410: the CLI login flow credential has expired (AUTH_SPEC §4-2)。正当な
 * flowToken 保持者への型付き終了指示で、CLI はポーリングをやめ再ログインを
 * 案内する。期限は flowToken の署名に含まれる自己申告値であり、この応答は
 * フロー状態(行の有無・承認状況)を一切開示しない。
 */
export class CliFlowExpiredError extends Schema.TaggedError<CliFlowExpiredError>()(
  "CliFlowExpired",
  {},
  { httpApiStatus: 410 },
) {}

/**
 * 400: uniform rejection of a CLI login poll (AUTH_SPEC §4-2 の一様拒否規律)。
 * MAC 不一致・署名内 flowId と提示 flowId の組不一致・consumed 後の再 poll・
 * 並行 poll の CAS 敗者 — すべて同一の応答で、失敗理由を出し分けない
 * (フロー状態のオラクルを作らない)。理由・識別子は運ばない。
 */
export class CliFlowRejectedError extends Schema.TaggedError<CliFlowRejectedError>()(
  "CliFlowRejected",
  {},
  { httpApiStatus: 400 },
) {}

/** 429: the per-user API token limit has been reached (AUTH_SPEC §6). */
export class TokenLimitError extends Schema.TaggedError<TokenLimitError>()(
  "TokenLimit",
  { limit: Schema.Number },
  { httpApiStatus: 429 },
) {}

/**
 * 404: the token id does not name a token owned by the authenticated principal
 * (AUTH_SPEC §6 — W3a 指定失効). 他人の・存在しないトークン id への一様応答で
 * あり(存在秘匿 — §12-6 の削除系と同じ規律)、対象 id を運ばない(呼び出し側が
 * 送った値をエラーに写さない)。
 */
export class TokenNotFoundError extends Schema.TaggedError<TokenNotFoundError>()(
  "TokenNotFound",
  {},
  { httpApiStatus: 404 },
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
