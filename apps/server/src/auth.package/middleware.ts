// The actual implementation of AuthMiddleware (@maruhi/api-schema)
// (AUTH_SPEC §5 / §11-1 / §11-4).
//
// - Credential precedence: `Authorization: Bearer maruhi_pat_…` → session
//   cookie. When neither resolves: 401 (applied only to endpoints requiring
//   authentication)
// - Session capability restriction (§5): a session principal gets 403
//   `session-not-allowed` on every endpoint outside the allow enumeration
//   (@maruhi/api-schema's SESSION_ALLOWED_ENDPOINTS). This is the single
//   implementation point, deciding on the { group, endpoint } identifiers
//   the middleware receives; there is no per-handler manual check
// - CSRF (§5): cookie-authenticated writes (anything other than GET / HEAD
//   / OPTIONS) require `x-maruhi-csrf: 1`. The Authorization header cannot
//   be attached by a cross-site form submission, so it is out of scope
// - The resolved principal is provided to handlers as RequestAuth

import {
  CSRF_HEADER_NAME,
  ForbiddenError,
  isSessionAllowedEndpoint,
  UnauthorizedError,
} from "@maruhi/api-schema";
import type { Principal } from "@maruhi/core";
import { anonymousPrincipal, RequestAuth, SessionService, TokenService } from "@maruhi/core";
import { Effect, Option } from "effect";
import { Cookies, HttpServerRequest, HttpServerResponse } from "effect/http";
import type { HttpApiMiddleware } from "effect/http-api";

export const SESSION_COOKIE = "__Host-maruhi_session";
/**
 * The CSRF countermeasure header. Stateful GETs (bulk pull with values,
 * recovery-blob fetch) also require it on the handler side
 * (statefulGetCsrfViolated below confines that, header name included).
 * The name's source of truth is api-schema's shared constant.
 */
const CSRF_HEADER = CSRF_HEADER_NAME;
// RFC 7235: auth-scheme is case-insensitive. Runs of whitespace are also tolerated
const BEARER_PATTERN = /^bearer\s+(\S+)$/i;
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** Extracts the Bearer token from the Authorization header (null when unparseable). */
export function parseBearerToken(authorization: string): string | null {
  return BEARER_PATTERN.exec(authorization)?.[1] ?? null;
}

/**
 * Credential precedence (fixed): when an Authorization header exists, only
 * it is consulted (no fallback to the cookie even when it is unparseable as
 * Bearer or the token is invalid — "presented a token yet authorized as the
 * session" must not happen). The session cookie is resolved only when no
 * Authorization is present.
 */
const resolvePrincipal = Effect.fn("middleware.resolvePrincipal")(function* (
  request: HttpServerRequest.HttpServerRequest,
): Effect.fn.Return<Principal, never, SessionService | TokenService> {
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

/**
 * CSRF check for session principals on stateful GETs (AUTH_SPEC §11-4's
 * explicit list). The middleware's check (csrfViolated above) exempts GET,
 * so endpoints that are GET yet stateful — bulk pull with values (§12-7),
 * recovery-blob fetch (§13-2) — have their handler call this and return the
 * same 403 (csrf-header-required). A `SameSite=Lax` session cookie rides
 * along on cross-site top-level navigations, but a custom header cannot be
 * sent cross-site in the absence of CORS (§5). Bearer cannot be attached
 * cross-site, so it is out of scope.
 */
export function statefulGetCsrfViolated(
  principal: Principal,
  headers: Readonly<Record<string, string | undefined>>,
): boolean {
  return principal.kind === "session" && headers[CSRF_HEADER] !== "1";
}

/**
 * Refreshes the cookie's Max-Age on every session-authenticated response
 * (reflects §5's sliding expiry on the browser side too — extending only
 * the DB would be pointless when the cookie expires after 30 days). Does
 * not touch responses where a handler manipulated the same-named cookie
 * (logout's expire, etc.).
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
 * The implementation body of AuthMiddleware. index.ts provides it via
 * `Layer.succeed(AuthMiddleware, …)`. SessionService / TokenService come
 * via per-env Layers.
 */
export const authMiddlewareImpl: HttpApiMiddleware.HttpApiMiddleware<
  RequestAuth,
  readonly [typeof UnauthorizedError, typeof ForbiddenError],
  SessionService | TokenService
> = Effect.fn("middleware.authMiddlewareImpl")(function* (httpEffect, options) {
  const request = yield* HttpServerRequest.HttpServerRequest;
  const principal = yield* resolvePrincipal(request);
  if (principal.kind === "anonymous") {
    return yield* Effect.fail(new UnauthorizedError());
  }
  // Session capability restriction (AUTH_SPEC §5 — outside the allow
  // enumeration is fail-closed 403). The decision material is only
  // (principal kind, group/endpoint identifier): a uniform response that
  // never consults project existence or state — consistent with §11-2's
  // existence hiding (same argument as §12-3's authorization-first
  // exception). Placed before the CSRF check so that the denial reason
  // for a disallowed endpoint does not vary with the presence of a header
  // the attacker can attach themselves
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
