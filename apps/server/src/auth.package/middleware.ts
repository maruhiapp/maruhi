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
import { Effect } from "effect";
import { HttpServerRequest } from "effect/unstable/http";
import type { HttpApiMiddleware } from "effect/unstable/httpapi";

export const SESSION_COOKIE = "__Host-maruhi_session";
const CSRF_HEADER = "x-maruhi-csrf";
const BEARER_PREFIX = "Bearer ";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function resolvePrincipal(
  request: HttpServerRequest.HttpServerRequest,
): Effect.Effect<Principal, never, SessionService | TokenService> {
  return Effect.gen(function* () {
    const authorization = request.headers["authorization"];
    if (authorization !== undefined && authorization.startsWith(BEARER_PREFIX)) {
      const tokens = yield* TokenService;
      return yield* tokens.resolveApiToken(authorization.slice(BEARER_PREFIX.length));
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
    return yield* Effect.provideService(httpEffect, RequestAuth, {
      principal: Effect.succeed(principal),
    });
  });
