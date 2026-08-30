// 認証ミドルウェアの API 契約(AUTH_SPEC §5 / §11-4)。
//
// 認証必須エンドポイントはこのミドルウェアを宣言し、ハンドラは RequestAuth
// (@maruhi/core)から認証済み主体を受け取る。実装(セッション / トークンの解決、
// CSRF custom header の一括検査)は apps/server 側の Layer が提供する。

import { RequestAuth, SessionService, TokenService } from "@maruhi/core";
import { HttpApiMiddleware } from "effect/unstable/httpapi";

import { ForbiddenError, UnauthorizedError } from "./errors/index.ts";

/**
 * CSRF 対抗のカスタムヘッダー名(AUTH_SPEC §11-4: `x-maruhi-csrf: 1`)。
 * サーバーのミドルウェア・クライアントの送信側が同じ名前を見るための共有定数
 * (session-43 §14 の申し送り — 名前のリネームが「CLI 誘導文言 → 一般 403」の
 * 無音フォールバックにならないよう、真実源を api-schema に 1 箇所化する)。
 * apps/web の消費側の束縛は W3b(web を触る次 PR)で行う。
 */
export const CSRF_HEADER_NAME = "x-maruhi-csrf";

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
