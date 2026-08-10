// 認証エンドポイントの HttpApi 定義(AUTH_SPEC §3 / §4 / §5 / §6 / §11-4)。
//
// 2026-08-02 裁定 4: OAuth リダイレクト系(start / callback)も含めてすべて
// api-schema に置く(サーバー実装とクライアント導出の共有源を単一に保つ)。
// start / callback の成功応答は 302 リダイレクト(+ Set-Cookie)であり、
// ハンドラが HttpServerResponse を直接返す(success スキーマは Void)。
//
// 禁止事項(AUTH_SPEC §10): GitHub トークンはリクエスト処理中のメモリ上でのみ
// 扱われ、どのレスポンス型にも現れない。セッション / トークン生値がレスポンスに
// 現れるのは発行時の一度だけ(deviceExchange の success)。

import { OrgRoleSchema, TokenScopeSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/unstable/httpapi";

import { AuthMiddleware } from "./auth-middleware.ts";
import {
  AuthFlowError,
  ForbiddenError,
  RecoveryRateLimitedError,
  RecoveryWrapNotFoundError,
  SetupIncompleteError,
  TokenLimitError,
} from "./errors.ts";

/**
 * 302 リダイレクト(+ Set-Cookie)で完結するエンドポイントの成功宣言。
 * githubStart / githubCallback はブラウザナビゲーション専用であり、HttpApi 導出
 * クライアント(fetch は既定でリダイレクトを追従する)から呼ぶ設計ではない。
 */
const Redirect = HttpApiSchema.Empty(302);

/**
 * Public (unauthenticated) server configuration (AUTH_SPEC §4). The GitHub
 * OAuth client_id is public information — it appears in the authorize URL —
 * so exposing it lets a self-hosted CLI resolve it from the server URL alone.
 */
export const AuthConfigSchema = Schema.Struct({
  githubClientId: Schema.String,
});

/** Result of the device-flow exchange (AUTH_SPEC §4): the raw token, shown once. */
export const DeviceExchangeResultSchema = Schema.Struct({
  token: Schema.String,
  tokenId: Schema.String,
  userId: Schema.String,
});

/** One org the authenticated user belongs to (AUTH_SPEC §9-1). */
export const UserOrgSchema = Schema.Struct({
  orgId: Schema.String,
  slug: Schema.String,
  name: Schema.String,
  role: OrgRoleSchema,
});

/** The authenticated user and their orgs (project creation needs an org id — §11-3). */
export const MeSchema = Schema.Struct({
  userId: Schema.String,
  orgs: Schema.Array(UserOrgSchema),
});

// リカバリーブロブ(AUTH_SPEC §13。CRYPTO_SPEC §8 のラップ済み master 秘密鍵)。
// サーバーから見て不透明な暗号文であり、リカバリーコード自体はワイヤに現れない。
const RecoveryNonceHex = Schema.String.check(
  Schema.isPattern(/^[0-9a-f]{24}$/, { description: "lowercase hex nonce (12 bytes)" }),
);
// AES-256-GCM の ct || tag: タグ込み 16 バイト以上・16 KiB 以下(§13-4 受理ポリシー)
const RecoveryCiphertextHex = Schema.String.check(
  Schema.isPattern(/^(?:[0-9a-f]{2}){16,16384}$/, {
    description: "lowercase hex AES-GCM ciphertext (16 bytes .. 16 KiB incl. tag)",
  }),
);

/** A wrapped master-secret blob on the wire (AUTH_SPEC §13-4). */
export const RecoveryWrapSchema = Schema.Struct({
  suite: Schema.Literal("maruhi/v1"),
  nonceHex: RecoveryNonceHex,
  ciphertextHex: RecoveryCiphertextHex,
});

/** GET /auth/recovery: the stored blob plus its last-update time. */
export const RecoveryWrapResultSchema = Schema.Struct({
  suite: Schema.Literal("maruhi/v1"),
  nonceHex: RecoveryNonceHex,
  ciphertextHex: RecoveryCiphertextHex,
  updatedAtMs: Schema.Number,
});

/** GET /auth/recovery/status: registration state only — never the blob (§13-2). */
export const RecoveryStatusSchema = Schema.Struct({
  registered: Schema.Boolean,
  updatedAtMs: Schema.NullOr(Schema.Number),
});

/**
 * Authentication endpoints (AUTH_SPEC §3 web OAuth, §4 device flow, §5
 * sessions, §6 tokens). Token issuance happens only through the device flow;
 * management is limited to revoking the presented token (2026-08-02 v1 線引き).
 */
export const authGroup = HttpApiGroup.make("auth")
  .add(
    // 公開設定エンドポイント(AUTH_SPEC §4。セッション 11 裁定 B)。未認証。
    // 未設定サーバー(§3 プレースホルダ)は 503 でセットアップガイドへ誘導する
    HttpApiEndpoint.get("authConfig", "/auth/config", {
      success: AuthConfigSchema,
      error: [SetupIncompleteError],
    }),
  )
  .add(
    HttpApiEndpoint.get("githubStart", "/auth/github/start", {
      success: Redirect,
      error: [SetupIncompleteError],
    }),
  )
  .add(
    HttpApiEndpoint.get("githubCallback", "/auth/github/callback", {
      query: { code: Schema.String, state: Schema.String },
      success: Redirect,
      error: [AuthFlowError],
    }),
  )
  .add(
    HttpApiEndpoint.post("deviceExchange", "/auth/device/exchange", {
      // 認証前に到達できる書き込み系のため、フィールドに明示的な上限を課す
      // (D1 への肥大 JSON 蓄積の遮断。AUTH_SPEC §6)
      payload: Schema.Struct({
        githubAccessToken: Schema.String.check(Schema.isMaxLength(512)),
        tokenName: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(128))),
        scopes: Schema.optionalKey(Schema.Array(TokenScopeSchema).check(Schema.isMaxLength(100))),
      }),
      success: DeviceExchangeResultSchema,
      error: [AuthFlowError, TokenLimitError],
    }),
  )
  .add(
    HttpApiEndpoint.get("me", "/auth/me", {
      success: MeSchema,
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("logout", "/auth/logout", {
      success: HttpApiSchema.NoContent,
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("revokeToken", "/auth/token/revoke", {
      success: HttpApiSchema.NoContent,
    }).middleware(AuthMiddleware),
  )
  .add(
    // 登録・再発行 = 置換 upsert(AUTH_SPEC §13-1。旧ラップは受理と同時に消える)
    HttpApiEndpoint.put("recoveryPut", "/auth/recovery", {
      payload: RecoveryWrapSchema,
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("recoveryGet", "/auth/recovery", {
      success: RecoveryWrapResultSchema,
      error: [ForbiddenError, RecoveryWrapNotFoundError, RecoveryRateLimitedError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("recoveryStatus", "/auth/recovery/status", {
      success: RecoveryStatusSchema,
    }).middleware(AuthMiddleware),
  );
