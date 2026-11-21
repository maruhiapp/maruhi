import {
  AuthFlowError,
  AuthRateLimitedError,
  ForbiddenError,
  maruhiApi,
  RecoveryRateLimitedError,
  RecoveryWrapNotFoundError,
  TokenNotFoundError,
} from "@maruhi/api-schema";
import { auditActorOf, RequestAuth, SessionService, TokenService } from "@maruhi/core";
import { Clock, Effect } from "effect";
import { HttpServerResponse } from "effect/http";
import { HttpApiBuilder } from "effect/http-api";

import {
  authFlowFailure,
  callbackUri,
  ensureGitHubOAuthConfigured,
  HOST_COOKIE_OPTIONS,
  recordLoginFailed,
  recordSignupDenied,
  redirectToGitHubAuthorize,
  requestOrigin,
  SIGNUP_CODE_COOKIE,
  STATE_COOKIE,
} from "../auth-shared.ts";
import {
  GitHubApi,
  parseBearerToken,
  renderSignupClosedPage,
  renderSignupInviteInvalidPage,
  renderSignupInviteRequiredPage,
  SESSION_COOKIE,
  statefulGetCsrfViolated,
} from "../auth.package/index.ts";
import { ensureKeyMaterialAccess, ensureTokenManagementAccess } from "../authz.ts";
import { IdentityRepo, RecoveryRepo, TokenRepo } from "../db.package/index.ts";
import { constantTimeEqual, randomHex, sha256Hex } from "../ids.ts";
import { ServerKey } from "../server-key.ts";
import {
  IP_RATE_LIMIT_PERIOD_SECONDS,
  ipRateLimitAllowed,
  WorkerEnv,
  WorkerSecrets,
} from "../worker-env.ts";
import { handleCliCallback, htmlResponse, isCliCallbackState } from "./handlers-auth-cli.ts";

function signupCookieValue(state: string, tokenHashHex: string): string {
  return `${state}.${tokenHashHex}`;
}

const SIGNUP_HASH_PATTERN = /^[0-9a-f]{64}$/;

function signupInviteHashFromCookie(cookie: string | undefined, state: string): string | null {
  if (cookie === undefined) {
    return null;
  }
  const dot = cookie.indexOf(".");
  if (dot === -1) {
    return null;
  }
  const tokenHashHex = cookie.slice(dot + 1);
  return constantTimeEqual(cookie.slice(0, dot), state) && SIGNUP_HASH_PATTERN.test(tokenHashHex)
    ? tokenHashHex
    : null;
}

function expireSignupCookieIfPresent(
  request: { readonly cookies: Readonly<Record<string, string | undefined>> },
  response: HttpServerResponse.HttpServerResponse,
): Effect.Effect<HttpServerResponse.HttpServerResponse> {
  return request.cookies[SIGNUP_CODE_COOKIE] === undefined
    ? Effect.succeed(response)
    : HttpServerResponse.expireCookie(response, SIGNUP_CODE_COOKIE, HOST_COOKIE_OPTIONS).pipe(
        Effect.orDie,
      );
}

export const authLive = HttpApiBuilder.group(maruhiApi, "auth", (handlers) =>
  handlers
    .handle(
      "authConfig",
      Effect.fn("handlers-auth.authConfig")(function* () {
        const secrets = yield* WorkerSecrets;
        const clientId = yield* ensureGitHubOAuthConfigured(
          secrets.githubClientId,
          secrets.githubClientSecret,
        );
        const serverKey = yield* ServerKey;
        const serverKeyInfo = yield* serverKey.info;
        const identities = yield* IdentityRepo;
        const signupPolicy = yield* identities.signupPolicy;
        return {
          githubClientId: clientId,
          signupPolicy,
          ...(serverKeyInfo === null
            ? {}
            : {
                serverKeyFingerprintHex: serverKeyInfo.serverKeyFingerprintHex,
                serverEncPubHex: serverKeyInfo.serverEncPubHex,
              }),
        };
      }),
    )
    .handle(
      "githubStart",
      Effect.fn("handlers-auth.githubStart")(function* ({ request, query }) {
        const env = yield* WorkerEnv;
        const secrets = yield* WorkerSecrets;
        const clientId = yield* ensureGitHubOAuthConfigured(
          secrets.githubClientId,
          secrets.githubClientSecret,
        );
        const state = yield* randomHex(16);
        const signupCode = query.signup_code;
        if (signupCode === undefined) {
          return yield* redirectToGitHubAuthorize(request, clientId, state, {
            name: STATE_COOKIE,
            value: state,
          });
        }
        const allowed = yield* ipRateLimitAllowed(env.SIGNUP_START_RATE_LIMIT, request);
        if (!allowed) {
          return yield* Effect.fail(
            new AuthRateLimitedError({ retryAfterSeconds: IP_RATE_LIMIT_PERIOD_SECONDS }),
          );
        }
        const identities = yield* IdentityRepo;
        const tokenHash = yield* Effect.orDie(sha256Hex(signupCode));
        const valid = yield* identities.hasPendingSignupInvite(
          tokenHash,
          yield* Clock.currentTimeMillis,
        );
        if (!valid) {
          return htmlResponse(renderSignupInviteInvalidPage(), 400);
        }
        const response = yield* redirectToGitHubAuthorize(request, clientId, state, {
          name: STATE_COOKIE,
          value: state,
        });
        return yield* HttpServerResponse.setCookie(
          response,
          SIGNUP_CODE_COOKIE,
          signupCookieValue(state, tokenHash),
          { ...HOST_COOKIE_OPTIONS, maxAge: "10 minutes" },
        ).pipe(Effect.orDie);
      }),
    )
    .handle(
      "githubCallback",
      Effect.fn("handlers-auth.githubCallback")(function* ({ request, query }) {
        const env = yield* WorkerEnv;
        const allowed = yield* ipRateLimitAllowed(env.OAUTH_CALLBACK_RATE_LIMIT, request);
        if (!allowed) {
          return yield* Effect.fail(
            new AuthRateLimitedError({ retryAfterSeconds: IP_RATE_LIMIT_PERIOD_SECONDS }),
          );
        }
        if (isCliCallbackState(query.state)) {
          const cliResponse = yield* handleCliCallback(request, query);
          return yield* expireSignupCookieIfPresent(request, cliResponse);
        }
        const expectedState = request.cookies[STATE_COOKIE];
        if (expectedState === undefined || !constantTimeEqual(expectedState, query.state)) {
          yield* recordLoginFailed("github_oauth", "state-mismatch");
          return yield* Effect.fail(new AuthFlowError({ reason: "state-mismatch" }));
        }
        const origin = requestOrigin(request);
        const github = yield* GitHubApi;
        const accessToken = yield* github.exchangeCode(query.code, callbackUri(origin)).pipe(
          Effect.mapError(authFlowFailure("code-exchange-failed")),
          Effect.tapError(() => recordLoginFailed("github_oauth", "code-exchange-failed")),
        );
        const identity = yield* github.fetchIdentity(accessToken).pipe(
          Effect.mapError(authFlowFailure("github-token-invalid")),
          Effect.tapError(() => recordLoginFailed("github_oauth", "github-token-invalid")),
        );
        const identities = yield* IdentityRepo;
        const signupInviteTokenHash = signupInviteHashFromCookie(
          request.cookies[SIGNUP_CODE_COOKIE],
          query.state,
        );
        const resolved = yield* identities.getOrCreateUser(
          identity,
          yield* Clock.currentTimeMillis,
          signupInviteTokenHash,
        );
        if ("denied" in resolved) {
          yield* recordSignupDenied(resolved.denied);
          const deniedPage =
            resolved.denied === "policy-closed"
              ? renderSignupClosedPage()
              : resolved.denied === "invite-required"
                ? renderSignupInviteRequiredPage()
                : renderSignupInviteInvalidPage();
          const deniedResponse = yield* HttpServerResponse.expireCookie(
            htmlResponse(deniedPage, 403),
            STATE_COOKIE,
            HOST_COOKIE_OPTIONS,
          ).pipe(Effect.orDie);
          return yield* expireSignupCookieIfPresent(request, deniedResponse);
        }
        const sessions = yield* SessionService;
        const issued = yield* sessions.issueSession(resolved.userId, "github_oauth");
        const response = HttpServerResponse.redirect(`${origin}/`, { status: 302 });
        const withSession = yield* HttpServerResponse.setCookie(
          response,
          SESSION_COOKIE,
          issued.rawValue,
          { ...HOST_COOKIE_OPTIONS, maxAge: "30 days" },
        ).pipe(Effect.orDie);
        const withStateExpired = yield* HttpServerResponse.expireCookie(
          withSession,
          STATE_COOKIE,
          HOST_COOKIE_OPTIONS,
        ).pipe(Effect.orDie);
        return yield* expireSignupCookieIfPresent(request, withStateExpired);
      }),
    )
    .handle(
      "me",
      Effect.fn("handlers-auth.me")(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        const identities = yield* IdentityRepo;
        const orgs = yield* identities.listUserOrgs(principal.userId);
        const providerLogin = yield* identities.providerLoginOf(principal.userId);
        return {
          userId: principal.userId,
          orgs,
          ...(providerLogin === null ? {} : { providerLogin }),
          ...(principal.kind === "token"
            ? { tokenScopes: principal.scopes, tokenExpiresAtMs: principal.expiresAtMs }
            : {}),
        };
      }),
    )
    .handle(
      "logout",
      Effect.fn("handlers-auth.logout")(function* ({ request }) {
        const principal = yield* (yield* RequestAuth).principal;
        const response = HttpServerResponse.empty({ status: 204 });
        if (principal.kind !== "session") {
          return response;
        }
        const rawSession = request.cookies[SESSION_COOKIE];
        if (rawSession !== undefined) {
          const sessions = yield* SessionService;
          yield* sessions.revokeSession(rawSession);
        }
        return yield* HttpServerResponse.expireCookie(
          response,
          SESSION_COOKIE,
          HOST_COOKIE_OPTIONS,
        ).pipe(Effect.orDie);
      }),
    )
    .handle(
      "revokeToken",
      Effect.fn("handlers-auth.revokeToken")(function* ({ request }) {
        const principal = yield* (yield* RequestAuth).principal;
        const rawToken = parseBearerToken(request.headers["authorization"] ?? "");
        if (principal.kind !== "token" || rawToken === null) {
          return yield* Effect.fail(new ForbiddenError({ reason: "insufficient-permission" }));
        }
        const tokens = yield* TokenService;
        yield* tokens.revokePresentedToken(rawToken);
        return HttpServerResponse.empty({ status: 204 });
      }),
    )
    .handle(
      "listTokens",
      Effect.fn("handlers-auth.listTokens")(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureTokenManagementAccess(principal);
        const tokens = yield* TokenRepo;
        const summaries = yield* tokens.listForUser(principal.userId);
        return { tokens: summaries };
      }),
    )
    .handle(
      "revokeTokenById",
      Effect.fn("handlers-auth.revokeTokenById")(function* ({ params }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureTokenManagementAccess(principal);
        const tokens = yield* TokenRepo;
        const revoked = yield* tokens.revokeById(
          params.tokenId,
          principal.userId,
          yield* Clock.currentTimeMillis,
          auditActorOf(principal),
        );
        if (!revoked) {
          return yield* Effect.fail(new TokenNotFoundError());
        }
        return HttpServerResponse.empty({ status: 204 });
      }),
    )
    .handle(
      "recoveryPut",
      Effect.fn("handlers-auth.recoveryPut")(function* ({ payload }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const recovery = yield* RecoveryRepo;
        yield* recovery.upsert(
          principal.userId,
          {
            suite: payload.suite,
            nonceHex: payload.nonceHex,
            ciphertextHex: payload.ciphertextHex,
          },
          yield* Clock.currentTimeMillis,
          auditActorOf(principal),
        );
        return HttpServerResponse.empty({ status: 204 });
      }),
    )
    .handle(
      "recoveryGet",
      Effect.fn("handlers-auth.recoveryGet")(function* ({ request }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        if (statefulGetCsrfViolated(principal, request.headers)) {
          return yield* Effect.fail(new ForbiddenError({ reason: "csrf-header-required" }));
        }
        const recovery = yield* RecoveryRepo;
        const wrap = yield* recovery.find(principal.userId);
        if (wrap === null) {
          return yield* Effect.fail(new RecoveryWrapNotFoundError());
        }
        if (wrap.suite !== "maruhi/v1") {
          return yield* Effect.die(new Error("stored recovery wrap has an unknown suite"));
        }
        const decision = yield* recovery.recordFetch(
          principal.userId,
          yield* Clock.currentTimeMillis,
          auditActorOf(principal),
        );
        if (!decision.allowed) {
          return yield* Effect.fail(
            new RecoveryRateLimitedError({ retryAfterSeconds: decision.retryAfterSeconds }),
          );
        }
        return {
          suite: "maruhi/v1" as const,
          nonceHex: wrap.nonceHex,
          ciphertextHex: wrap.ciphertextHex,
          updatedAtMs: wrap.updatedAtMs,
        };
      }),
    )
    .handle(
      "recoveryStatus",
      Effect.fn("handlers-auth.recoveryStatus")(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        const recovery = yield* RecoveryRepo;
        const wrap = yield* recovery.find(principal.userId);
        return wrap === null
          ? { registered: false, updatedAtMs: null }
          : { registered: true, updatedAtMs: wrap.updatedAtMs };
      }),
    ),
);
