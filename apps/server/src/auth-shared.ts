import { AuthFlowError, SetupIncompleteError } from "@maruhi/api-schema";
import type { AuthMethod } from "@maruhi/core";
import { Clock, Effect, type Redacted } from "effect";
import type { Cookies, HttpServerRequest } from "effect/http";
import { HttpServerResponse } from "effect/http";

import type { SignupDenialReason } from "./auth-domain.ts";
import { D1AuditRepo } from "./db.package/index.ts";

const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const OAUTH_SCOPE = "read:user user:email";

export const STATE_COOKIE = "__Host-maruhi_oauth_state";

export const CLI_STATE_COOKIE = "__Host-maruhi_oauth_cli";

export const CLI_STATE_PREFIX = "cli.";

export const SIGNUP_CODE_COOKIE = "__Host-maruhi_signup";

export const HOST_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  path: "/",
} as const satisfies Cookies.Cookie["options"];

export function requestOrigin(request: HttpServerRequest.HttpServerRequest): string {
  const source: unknown = request.source;
  if (source instanceof Request) {
    return new URL(source.url).origin;
  }
  throw new Error("request origin unavailable: source is not a web Request");
}

export function callbackUri(origin: string): string {
  return `${origin}/auth/github/callback`;
}

function githubAuthorizeUrl(clientId: string, origin: string, state: string): URL {
  const authorize = new URL(GITHUB_AUTHORIZE_URL);
  authorize.searchParams.set("client_id", clientId);
  authorize.searchParams.set("redirect_uri", callbackUri(origin));
  authorize.searchParams.set("scope", OAUTH_SCOPE);
  authorize.searchParams.set("state", state);
  return authorize;
}

export function redirectToGitHubAuthorize(
  request: HttpServerRequest.HttpServerRequest,
  clientId: string,
  state: string,
  cookie: { readonly name: string; readonly value: string },
): Effect.Effect<HttpServerResponse.HttpServerResponse> {
  const origin = requestOrigin(request);
  const authorize = githubAuthorizeUrl(clientId, origin, state);
  const response = HttpServerResponse.redirect(authorize, { status: 302 });
  return HttpServerResponse.setCookie(response, cookie.name, cookie.value, {
    ...HOST_COOKIE_OPTIONS,
    maxAge: "10 minutes",
  }).pipe(Effect.orDie);
}

export function ensureGitHubOAuthConfigured(
  clientId: string | undefined,
  clientSecret: Redacted.Redacted<string> | undefined,
): Effect.Effect<string, SetupIncompleteError> {
  const clientIdMissing = clientId === undefined || clientId === "";
  return clientIdMissing || clientSecret === undefined
    ? Effect.fail(new SetupIncompleteError({ reason: "github-oauth-unconfigured" }))
    : Effect.succeed(clientId);
}

export function authFlowFailure(
  reason: "state-mismatch" | "code-exchange-failed" | "github-token-invalid",
): () => AuthFlowError {
  return () => new AuthFlowError({ reason });
}

export function recordLoginFailed(
  authMethod: AuthMethod,
  reason: AuthFlowError["reason"],
): Effect.Effect<void, never, D1AuditRepo> {
  return Effect.flatMap(D1AuditRepo, (audit) =>
    Effect.flatMap(Clock.currentTimeMillis, (now) =>
      audit.appendLoginFailed(
        { event: "auth.login_failed", actor: {}, payload: { authMethod, reason } },
        now,
        { authMethod, reason },
      ),
    ),
  );
}

export function recordSignupDenied(
  reason: SignupDenialReason,
): Effect.Effect<void, never, D1AuditRepo> {
  return Effect.flatMap(D1AuditRepo, (audit) =>
    Effect.flatMap(Clock.currentTimeMillis, (now) =>
      audit.appendSignupDenied(
        {
          event: "auth.signup_denied",
          actor: {},
          payload: { authMethod: "github_oauth", reason },
        },
        now,
        reason,
      ),
    ),
  );
}
