import {
  CSRF_HEADER_NAME,
  ForbiddenError,
  isSessionAllowedEndpoint,
  UnauthorizedError,
} from "@maruhi/api-schema";
import type { Principal } from "@maruhi/core";
import { anonymousPrincipal, RequestAuth, SessionService, TokenService } from "@maruhi/core";
import { Effect, Option } from "effect";
import { Digest } from "effect/crypto";
import { Cookies, HttpServerRequest, HttpServerResponse } from "effect/http";
import type { HttpApiMiddleware } from "effect/http-api";

export const SESSION_COOKIE = "__Host-maruhi_session";
const CSRF_HEADER = CSRF_HEADER_NAME;
const BEARER_PATTERN = /^bearer\s+(\S+)$/i;
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function parseBearerToken(authorization: string): string | null {
  return BEARER_PATTERN.exec(authorization)?.[1] ?? null;
}

const resolvePrincipal = Effect.fn("middleware.resolvePrincipal")(function* (
  request: HttpServerRequest.HttpServerRequest,
): Effect.fn.Return<Principal, never, SessionService | TokenService | Digest.Digest> {
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

function csrfViolated(request: HttpServerRequest.HttpServerRequest, principal: Principal): boolean {
  return (
    principal.kind === "session" &&
    !SAFE_METHODS.has(request.method) &&
    request.headers[CSRF_HEADER] !== "1"
  );
}

export function statefulGetCsrfViolated(
  principal: Principal,
  headers: Readonly<Record<string, string | undefined>>,
): boolean {
  return principal.kind === "session" && headers[CSRF_HEADER] !== "1";
}

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

export const authMiddlewareImpl: HttpApiMiddleware.HttpApiMiddleware<
  RequestAuth,
  readonly [typeof UnauthorizedError, typeof ForbiddenError],
  SessionService | TokenService | Digest.Digest
> = Effect.fn("middleware.authMiddlewareImpl")(function* (httpEffect, options) {
  const request = yield* HttpServerRequest.HttpServerRequest;
  const principal = yield* resolvePrincipal(request);
  if (principal.kind === "anonymous") {
    return yield* Effect.fail(new UnauthorizedError());
  }
  if (
    principal.kind === "session" &&
    !isSessionAllowedEndpoint(options.group.identifier, options.endpoint.identifier)
  ) {
    return yield* Effect.fail(new ForbiddenError({ reason: "session-not-allowed" }));
  }
  if (csrfViolated(request, principal)) {
    return yield* Effect.fail(new ForbiddenError({ reason: "csrf-header-required" }));
  }
  const response = yield* Effect.provideService(httpEffect, RequestAuth, {
    principal: Effect.succeed(principal),
  });
  return yield* refreshSessionCookie(response, principal, request.cookies[SESSION_COOKIE]);
});
