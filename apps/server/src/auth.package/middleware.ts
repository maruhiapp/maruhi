// AuthMiddleware(@maruhi/api-schema)の本実装(AUTH_SPEC §5 / §11-1 / §11-4)。
//
// - 資格情報の優先順: `Authorization: Bearer maruhi_pat_…` → セッションクッキー。
//   どちらも解決できなければ 401(認証必須エンドポイントにのみ適用される)
// - CSRF(§5): クッキー認証の書き込み系(GET / HEAD / OPTIONS 以外)は
//   `x-maruhi-csrf: 1` を要求する。Authorization ヘッダーはクロスサイトの
//   フォーム送信では付与できないため対象外
// - 解決済み主体は RequestAuth としてハンドラへ提供する

import { ForbiddenError, UnauthorizedError } from "@maruhi/api-schema";
import type { Principal } from "@maruhi/core";
import { anonymousPrincipal, RequestAuth, SessionService, TokenService } from "@maruhi/core";
import { Effect, Option } from "effect";
import { Cookies, HttpServerRequest, HttpServerResponse } from "effect/unstable/http";
import type { HttpApiMiddleware } from "effect/unstable/httpapi";

export const SESSION_COOKIE = "__Host-maruhi_session";
/** CSRF 対抗ヘッダー。状態を持つ GET(リカバリーブロブ取得)もハンドラ側で要求する。 */
export const CSRF_HEADER = "x-maruhi-csrf";
// RFC 7235: auth-scheme は大文字小文字を区別しない。空白の連続も許容する
const BEARER_PATTERN = /^bearer\s+(\S+)$/i;
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** Authorization ヘッダーから Bearer トークンを取り出す(解釈不能は null)。 */
export function parseBearerToken(authorization: string): string | null {
  return BEARER_PATTERN.exec(authorization)?.[1] ?? null;
}

/**
 * 資格情報の優先順位(固定): Authorization ヘッダーが存在するならそれのみを見る
 * (Bearer として解釈できない・トークンが無効な場合もクッキーへフォールバック
 * しない — 「トークンを提示したのにセッションで認可された」を起こさない)。
 * Authorization がないときだけセッションクッキーを解決する。
 */
function resolvePrincipal(
  request: HttpServerRequest.HttpServerRequest,
): Effect.Effect<Principal, never, SessionService | TokenService> {
  return Effect.gen(function* () {
    const authorization = request.headers["authorization"];
    if (authorization !== undefined) {
      const rawToken = parseBearerToken(authorization);
      if (rawToken === null) {
        return anonymousPrincipal;
      }
      const tokens = yield* TokenService;
      return yield* tokens.resolveApiToken(rawToken);
    }
    const rawSession = request.cookies[SESSION_COOKIE];
    if (rawSession !== undefined) {
      const sessions = yield* SessionService;
      return yield* sessions.resolveSession(rawSession);
    }
    return anonymousPrincipal;
  });
}

function csrfViolated(request: HttpServerRequest.HttpServerRequest, principal: Principal): boolean {
  return (
    principal.kind === "session" &&
    !SAFE_METHODS.has(request.method) &&
    request.headers[CSRF_HEADER] !== "1"
  );
}

/**
 * セッション認証の応答でクッキーの Max-Age を毎回更新する(§5 のスライディングを
 * ブラウザ側にも反映する — DB だけ延長してもクッキーが 30 日で失効しては意味が
 * ない)。ハンドラが同名クッキーを操作した応答(ログアウトの expire 等)には
 * 触れない。
 */
function refreshSessionCookie(
  response: HttpServerResponse.HttpServerResponse,
  principal: Principal,
  rawSession: string | undefined,
): Effect.Effect<HttpServerResponse.HttpServerResponse> {
  if (
    principal.kind !== "session" ||
    rawSession === undefined ||
    Option.isSome(Cookies.get(response.cookies, SESSION_COOKIE))
  ) {
    return Effect.succeed(response);
  }
  return HttpServerResponse.setCookie(response, SESSION_COOKIE, rawSession, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: "30 days",
  }).pipe(Effect.orDie);
}

/**
 * AuthMiddleware の実装本体。index.ts が `Layer.succeed(AuthMiddleware, …)` で
 * 提供する。SessionService / TokenService は env ごとの Layer 経由。
 */
export const authMiddlewareImpl: HttpApiMiddleware.HttpApiMiddleware<
  RequestAuth,
  readonly [typeof UnauthorizedError, typeof ForbiddenError],
  SessionService | TokenService
> = (httpEffect) =>
  Effect.gen(function* () {
    const request = yield* HttpServerRequest.HttpServerRequest;
    const principal = yield* resolvePrincipal(request);
    if (principal.kind === "anonymous") {
      return yield* Effect.fail(new UnauthorizedError());
    }
    if (csrfViolated(request, principal)) {
      return yield* Effect.fail(new ForbiddenError({ reason: "csrf-header-required" }));
    }
    const response = yield* Effect.provideService(httpEffect, RequestAuth, {
      principal: Effect.succeed(principal),
    });
    return yield* refreshSessionCookie(response, principal, request.cookies[SESSION_COOKIE]);
  });
