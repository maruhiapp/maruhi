// Shared helpers between the auth handlers (handlers-auth.ts /
// handlers-auth-cli.ts).
//
// Web login (AUTH_SPEC §3) and the CLI login browser leg (§4-1 (3)-(4))
// share stages 1-2 of GitHub OAuth (authorize redirect, state verification,
// code exchange). To avoid a circular import (handlers-auth ⇄
// handlers-auth-cli), the parts both sides use live in this module.

import { AuthFlowError, SetupIncompleteError } from "@maruhi/api-schema";
import { Effect } from "effect";
import type { Cookies, HttpServerRequest } from "effect/unstable/http";
import { HttpServerResponse } from "effect/unstable/http";

import type { SignupDenialReason } from "./auth-domain.ts";
import { D1AuditRepo } from "./db.package/index.ts";

const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const OAUTH_SCOPE = "read:user user:email";

/** Web login state cookie (§3-2). */
export const STATE_COOKIE = "__Host-maruhi_oauth_state";

/**
 * State + flow-binding cookie dedicated to the CLI browser leg (§4-1 (3)).
 * Deliberately named apart from the web login STATE_COOKIE: a cookie from an
 * old CLI flow must not break a normal web login, and vice versa. The value
 * is a query string of "state + vsig'd parameter set" (since the callback
 * re-verifies the vsig, the cookie itself needs no tamper protection).
 */
export const CLI_STATE_COOKIE = "__Host-maruhi_oauth_cli";

/** CLI-flow identification prefix for the GitHub state parameter (§4-1 (3)). */
export const CLI_STATE_PREFIX = "cli.";

/**
 * Carrier cookie for the signup invite code (AUTH_SPEC §3).
 * Carries the **SHA-256 hash** of a code that passed the start-time
 * pre-verification of `GET /auth/github/start?signup_code=…`, bound to the
 * issued state, through to the callback (HttpOnly; the raw value appears on
 * the wire only once at start and never sits in the cookie store — the
 * value's shape and rationale are in handlers-auth.ts's signupCookieValue).
 * The consuming CAS is performed on the callback side (getOrCreateUser's
 * creation batch). Same 10-minute maxAge as the state cookie; expires at the
 * callback's HTML / 302 terminal.
 */
export const SIGNUP_CODE_COOKIE = "__Host-maruhi_signup";

/** Common attributes of `__Host-` cookies (§5). */
export const HOST_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  path: "/",
} as const satisfies Cookies.Cookie["options"];

export function requestOrigin(request: HttpServerRequest.HttpServerRequest): string {
  // effect's HttpServerRequest.url carries only the path. The absolute URL
  // lives on the raw Web Request. The Host header (attacker-spoofable) is not
  // used to build the redirect_uri — workerd's entry point is always a Web
  // Request, so anything else is a wiring bug (defect)
  const source: unknown = request.source;
  if (source instanceof Request) {
    return new URL(source.url).origin;
  }
  throw new Error("request origin unavailable: source is not a web Request");
}

export function callbackUri(origin: string): string {
  return `${origin}/auth/github/callback`;
}

/** Builds the GitHub authorize URL (§3-2; shared by the web / CLI browser legs). */
function githubAuthorizeUrl(clientId: string, origin: string, state: string): URL {
  const authorize = new URL(GITHUB_AUTHORIZE_URL);
  authorize.searchParams.set("client_id", clientId);
  authorize.searchParams.set("redirect_uri", callbackUri(origin));
  authorize.searchParams.set("scope", OAUTH_SCOPE);
  authorize.searchParams.set("state", state);
  return authorize;
}

/**
 * Terminal of the §3-1 first leg (shared by the web / CLI browser legs): the
 * 302 to GitHub authorize carries a state-transport cookie. Only the cookie
 * name and value differ between the two paths (web = STATE_COOKIE with a
 * state nonce; CLI = CLI_STATE_COOKIE with state + the vsig'd parameter set).
 */
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

/**
 * Detects missing self-hosted configuration (AUTH_SPEC §3): either
 * client_id or client_secret unregistered (a missed `cf workers secrets update`)
 * or empty (the Env type is string, but a deploy lacking the secret can
 * become undefined at runtime). Letting it pass through would land on a
 * GitHub error page or an opaque token-exchange failure (AuthFlow 400) with
 * no traceable cause, so it redirects to the setup guide
 * (docs/SELF_HOSTING.md) with a 503.
 */
export function ensureGitHubOAuthConfigured(
  clientId: string | undefined,
  clientSecret: string | undefined,
): Effect.Effect<void, SetupIncompleteError> {
  const clientIdMissing = clientId === undefined || clientId === "";
  const clientSecretMissing = clientSecret === undefined || clientSecret === "";
  return clientIdMissing || clientSecretMissing
    ? Effect.fail(new SetupIncompleteError({ reason: "github-oauth-unconfigured" }))
    : Effect.void;
}

/** Maps a GitHub authentication-dance failure to the API's typed error (for web login). */
export function authFlowFailure(
  reason: "state-mismatch" | "code-exchange-failed" | "github-token-invalid",
): () => AuthFlowError {
  return () => new AuthFlowError({ reason });
}

/**
 * Records auth.login_failed (AUDIT_SPEC §3.1). The actor is a user with no
 * user_id = an unauthenticated external principal. Records only the reason
 * kind; the presented external ID, code, and token are not recorded (same
 * §3.1 prohibition). To bound write amplification from the unauthenticated
 * path, uses a dedicated append with a fixed-window cap
 * (db.package/audit.ts).
 *
 * The cap counts with authMethod + reason as the bucket: an anonymous flood
 * on one path or reason must not silently erase failures of other reasons.
 */
export function recordLoginFailed(
  authMethod: "github_oauth" | "cli_handoff",
  reason: AuthFlowError["reason"],
): Effect.Effect<void, never, D1AuditRepo> {
  return Effect.flatMap(D1AuditRepo, (audit) =>
    audit.appendLoginFailed(
      { event: "auth.login_failed", actor: {}, payload: { authMethod, reason } },
      Date.now(),
      { authMethod, reason },
    ),
  );
}

/**
 * Records auth.signup_denied (AUDIT_SPEC §3.1). The actor is the same
 * type=user with no user_id as login_failed (no internal user_id exists at
 * denial time). Presented external IDs and raw code values are not recorded.
 * Fixed-window capped (bounding write amplification from denial floods —
 * the bucket is per reason). The operations "count signup denials"
 * tripwire counts these rows.
 */
export function recordSignupDenied(
  reason: SignupDenialReason,
): Effect.Effect<void, never, D1AuditRepo> {
  return Effect.flatMap(D1AuditRepo, (audit) =>
    audit.appendSignupDenied(
      {
        event: "auth.signup_denied",
        actor: {},
        payload: { authMethod: "github_oauth", reason },
      },
      Date.now(),
      reason,
    ),
  );
}
