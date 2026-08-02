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
import { AuthFlowError, TokenLimitError } from "./errors.ts";

/**
 * 302 リダイレクト(+ Set-Cookie)で完結するエンドポイントの成功宣言。
 * githubStart / githubCallback はブラウザナビゲーション専用であり、HttpApi 導出
 * クライアント(fetch は既定でリダイレクトを追従する)から呼ぶ設計ではない。
 */
const Redirect = HttpApiSchema.Empty(302);

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

/**
 * Authentication endpoints (AUTH_SPEC §3 web OAuth, §4 device flow, §5
 * sessions, §6 tokens). Token issuance happens only through the device flow;
 * management is limited to revoking the presented token (2026-08-02 v1 線引き).
 */
export const authGroup = HttpApiGroup.make("auth")
  .add(
    HttpApiEndpoint.get("githubStart", "/auth/github/start", {
      success: Redirect,
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
  );
