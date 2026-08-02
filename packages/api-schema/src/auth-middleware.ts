// 認証ミドルウェアの API 契約(AUTH_SPEC §5 / §11-4)。
//
// 認証必須エンドポイントはこのミドルウェアを宣言し、ハンドラは RequestAuth
// (@maruhi/core)から認証済み主体を受け取る。実装(セッション / トークンの解決、
// CSRF custom header の一括検査)は apps/server 側の Layer が提供する。

import { RequestAuth, SessionService, TokenService } from "@maruhi/core";
import { HttpApiMiddleware } from "effect/unstable/httpapi";

import { ForbiddenError, UnauthorizedError } from "./errors.ts";

/**
 * Authentication middleware (AUTH_SPEC §5, §11-4): resolves the session cookie
 * or `Authorization: Bearer maruhi_pat_…` header into a `RequestAuth`
 * principal, failing with 401 for anonymous requests. Cookie-authenticated
 * write requests must carry the `x-maruhi-csrf: 1` header (403 otherwise).
 */
export class AuthMiddleware extends HttpApiMiddleware.Service<
  AuthMiddleware,
  { provides: RequestAuth; requires: SessionService | TokenService }
>()("AuthMiddleware", { error: [UnauthorizedError, ForbiddenError] }) {}
