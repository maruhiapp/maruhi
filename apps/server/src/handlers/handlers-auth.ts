// Handlers for the auth endpoints (AUTH_SPEC §3 / §4 / §5 / §6).
//
// - A GitHub access token exists only in local variables of this file's
//   handlers and never reaches a response, a log, or storage (§10: GitHub
//   tokens must not be persisted)
// - `__Host-` cookies require Secure / Path=/ (note that a browser will not
//   store them under http cf dev — tests verify the header instead)

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

/**
 * The shape of the signup-code cookie value: `<state>.<sha256(code)>`
 * (AUTH_SPEC §3).
 *
 * **Carry the hash, not the raw value**: the callback needs only the hash
 * comparison (signup_invites.token_hash) and the consumption CAS; there is
 * no point where the raw value resurfaces. Carrying the hash means the code's
 * raw value appears on the wire only once — in the start request — and no
 * raw value is left in the browser's cookie store (the surface visible to
 * devtools, sync, and extensions): the "the raw value appears only once at
 * issuance" discipline (§5 / §15) applied to the carrying surface.
 *
 * The cookie is also **bound** to the OAuth state of issuance: a `__Host-` /
 * path=/ cookie is sent along with any later, unrelated OAuth completion (a
 * different state) in the same browser, so without binding a carried-over
 * code could be consumed as "the code presented for that flow". The callback
 * adopts the hash only when the state matches — even if a cookie survives on
 * a typed-error terminal (a response carrying no Set-Cookie), it does not
 * become a credential of another flow (neutralization of leftovers).
 */
function signupCookieValue(state: string, tokenHashHex: string): string {
  return `${state}.${tokenHashHex}`;
}

/** The hash's wire form (lowercase SHA-256 hex). Deviations fold into "not presented". */
const SIGNUP_HASH_PATTERN = /^[0-9a-f]{64}$/;

/** Restore the code hash from the cookie (a state mismatch or malformed shape is "not presented"). */
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

/**
 * Single-use expiry of the signup-code cookie (AUTH_SPEC §3). The expiry is
 * attached only when the request carried the cookie (the response shape of a
 * plain login is unchanged). Applies to every terminal that returns HTML /
 * 302 — success, denial, and the CLI browser leg. A cookie left over on a
 * typed-error terminal (AuthFlow 400 / 429 — no Set-Cookie carried) is
 * neutralized by the state binding (above) and dies naturally at the
 * 10-minute maxAge.
 */
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
        const env = yield* WorkerEnv;
        const secrets = yield* WorkerSecrets;
        // Public config (AUTH_SPEC §4): only public information — client_id
        // already appears in plaintext on the authorize URL. Do not add
        // client_secret etc. to this response (it is part of the check — a
        // 200 works as confirmation that "client_id / secret are both
        // registered")
        yield* ensureGitHubOAuthConfigured(env.GITHUB_CLIENT_ID, secrets.githubClientSecret);
        // If the deployment keypair (CRYPTO_SPEC §9) is configured, add its
        // public face (AUTH_SPEC §4 — serverKeyFingerprintHex is the
        // verification target when running grant_server; serverEncPubHex is
        // the distribution channel of the "enc public key the server
        // distributes" of §9 — both are public information). Omit both fields
        // when unconfigured
        const serverKey = yield* ServerKey;
        const serverKeyInfo = yield* serverKey.info;
        // signupPolicy is advisory (AUTH_SPEC §3 — public information, the
        // same content as the landing-page guidance text, never an input to
        // verification or authorization rules). Input for the CLI's login
        // pre-flight fail-fast (hosted-design.md §2-2 (i)(ii))
        const identities = yield* IdentityRepo;
        const signupPolicy = yield* identities.signupPolicy;
        return {
          githubClientId: env.GITHUB_CLIENT_ID,
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
        yield* ensureGitHubOAuthConfigured(env.GITHUB_CLIENT_ID, secrets.githubClientSecret);
        const state = randomHex(16);
        const signupCode = query.signup_code;
        if (signupCode === undefined) {
          // A plain start (login, or signup under open) behaves as before
          return yield* redirectToGitHubAuthorize(request, env.GITHUB_CLIENT_ID, state, {
            name: STATE_COOKIE,
            value: state,
          });
        }
        // Start-time pre-validation of a signup invite code (AUTH_SPEC §3):
        // fail fast instead of running the OAuth dance for an invalid code.
        // A code-bearing start is an unauthenticated surface that reads D1,
        // so the per-IP rate limit sits first in the handler (the check is a
        // hash comparison of a 256-bit single-use code and is not an
        // existence oracle)
        const allowed = yield* ipRateLimitAllowed(env.SIGNUP_START_RATE_LIMIT, request);
        if (!allowed) {
          return yield* Effect.fail(
            new AuthRateLimitedError({ retryAfterSeconds: IP_RATE_LIMIT_PERIOD_SECONDS }),
          );
        }
        const identities = yield* IdentityRepo;
        const tokenHash = yield* Effect.promise(() => sha256Hex(signupCode));
        const valid = yield* identities.hasPendingSignupInvite(
          tokenHash,
          yield* Clock.currentTimeMillis,
        );
        if (!valid) {
          // Script-less guidance that does not distinguish unknown /
          // revoked / consumed (§3). The pre-validation is fail-fast, not
          // the acceptance decision — the acceptance authority is the
          // callback's consumption CAS
          return htmlResponse(renderSignupInviteInvalidPage(), 400);
        }
        // Carry the **hash** of the verified code in an HttpOnly cookie up
        // to the callback (§3 — the raw value's wire appearance is this
        // single start request. Consumption is in the same transaction as
        // the account creation — it is not consumed here). The value is
        // bound to this start's state (signupCookieValue — a carry-over is
        // not a credential for another flow)
        const response = yield* redirectToGitHubAuthorize(request, env.GITHUB_CLIENT_ID, state, {
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
        // The source-IP rate limit sits first in the handler: the callback
        // is reachable unauthenticated, and each hit triggers an exchange
        // against the GitHub token endpoint. That budget is the **same**
        // shared quota per OAuth App as the device exchange; if exhausted,
        // every user's login stops.
        //
        // The state check cannot serve as a throttle: it relies only on the
        // cookie-plus-query double submit with no server-side state, so a
        // non-browser source can supply both itself (it need not even go
        // through githubStart) and the check always passes. The
        // state-mismatch record (recordLoginFailed) is also placed after
        // this judgment, bounding even the audit-write amplification from
        // the unauthenticated path
        const allowed = yield* ipRateLimitAllowed(env.OAUTH_CALLBACK_RATE_LIMIT, request);
        if (!allowed) {
          return yield* Effect.fail(
            new AuthRateLimitedError({ retryAfterSeconds: IP_RATE_LIMIT_PERIOD_SECONDS }),
          );
        }
        // The browser leg of a CLI login (AUTH_SPEC §4-1 (3)-(4)): the
        // GitHub callback URL remains the single URL of §3, branching on the
        // state's `cli.` prefix. Every terminal of the CLI branch is
        // browser-facing HTML (handlers-auth-cli.ts) and issues no session
        // (§4-1 (3) — the only artifact is the PAT that poll returns)
        if (isCliCallbackState(query.state)) {
          // The CLI browser leg never references a signup code (ruling DH —
          // codes do not ride the CLI path), but a cookie left in the same
          // browser is still given its single-use expiry here (the §3
          // single-use discipline — leave no unreferenced leftover)
          const cliResponse = yield* handleCliCallback(request, query);
          return yield* expireSignupCookieIfPresent(request, cliResponse);
        }
        const expectedState = request.cookies[STATE_COOKIE];
        // §3-2: the state check (a mismatch is refused immediately)
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
        // The GitHub token's job ends here (not stored. §3 / §10)
        const identities = yield* IdentityRepo;
        // Signup invite code (AUTH_SPEC §3): the **hash** of a code that
        // passed the start-time pre-validation arrives via cookie (the raw
        // value never flows through this path). The value is bound to the
        // issuance-time state; a carried-over cookie whose state does not
        // match (from another flow) folds into "not presented"
        // (signupInviteHashFromCookie). Consumption is a CAS in the same
        // transaction as the account creation (repo side). Resolving an
        // existing user does not consume it
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
          // A signupPolicy denial of new-account creation (AUTH_SPEC §3):
          // the OAuth flow completed, but no users / linked_identities rows
          // were created (fail-closed). The record is the fixed-window-
          // capped auth.signup_denied (AUDIT_SPEC §3.1); the response is a
          // script-less guidance page (the denial reason is the consequence
          // of the presenter's own application, not an existence oracle to
          // third parties)
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
        // Input for the invite link's `il` (AUTH_SPEC §15-3 — IV): a
        // display snapshot of the user's own GitHub login (self information
        // only)
        const providerLogin = yield* identities.providerLoginOf(principal.userId);
        // A token principal gets back the presented token's scopes and
        // expiry (AUTH_SPEC §16-2 / §6 — ruling CI. Inputs for the client to
        // pre-compute its effective permission min(scope, chain role) and to
        // self-observe the expiry. Both are attributes of the credential the
        // caller itself presented and disclose nothing new). For a session
        // principal the fields are absent = no scopes (the callable surface
        // is limited to the §5 capability-limit permission enumeration —
        // W2b)
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
        // Already through AuthMiddleware (401 / CSRF 403 are the
        // middleware's job)
        const principal = yield* (yield* RequestAuth).principal;
        const response = HttpServerResponse.empty({ status: 204 });
        if (principal.kind !== "session") {
          // Logout is a session-principal operation. A token principal is a
          // no-op and does not touch the session cookie the browser sent
          // along (so a Bearer-authenticated request cannot destroy an
          // unrelated Web session)
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
        // The revocation target is only "the presented token itself" (the
        // v1 line). Arriving via session is out of scope
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
        // A token principal must be `*` × admin (ruling CH). A session
        // principal already passed the §5 permission enumeration. The 403 is
        // computed from calling credentials alone (no target information)
        yield* ensureTokenManagementAccess(principal);
        const tokens = yield* TokenRepo;
        // The response contains only the caller's own rows (userId is
        // server-derived — the wire has no target selector, so no surface
        // for probing others' tokens exists structurally). No audit event is
        // recorded (a read of self information touching neither values nor
        // keys — the same discipline as §11-5)
        const summaries = yield* tokens.listForUser(principal.userId);
        return { tokens: summaries };
      }),
    )
    .handle(
      "revokeTokenById",
      Effect.fn("handlers-auth.revokeTokenById")(function* ({ params }) {
        const principal = yield* (yield* RequestAuth).principal;
        // Check order (ruling CG): 401 (middleware) → 403 (principal
        // condition — computed from calling credentials alone) → uniform
        // 404 (does not distinguish a foreign-owned id from a nonexistent
        // one). Session-principal CSRF is the middleware's job (DELETE is a
        // write)
        yield* ensureTokenManagementAccess(principal);
        const tokens = yield* TokenRepo;
        // The ownership condition (id × userId) is enforced at the repo
        // boundary. auth.token_revoked is recorded the moment the delete
        // succeeds, with actor = the executing principal (session / another
        // token) and payload.tokenId = the revocation target
        // (AUDIT_SPEC §3.1)
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
        // Registration and reissue are the same replacement upsert (§13-1).
        // The old wrap row disappears here. The audit
        // (auth.recovery_code_reissued) is recorded by upsert in the same
        // batch (§13-5)
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
        // A GET, but it carries state: the fetch count (an explicit §13-2
        // provision; counting is §13-3) — blocks third-party sites from
        // consuming the window = an availability nuisance (rationale in
        // statefulGetCsrfViolated's JSDoc)
        if (statefulGetCsrfViolated(principal, request.headers)) {
          return yield* Effect.fail(new ForbiddenError({ reason: "csrf-header-required" }));
        }
        const recovery = yield* RecoveryRepo;
        // The rate limit (§13-3) is not counted ahead of the existence
        // check: unregistered (404) is out of the counted set, and without a
        // row recordFetch always returns allowed
        const wrap = yield* recovery.find(principal.userId);
        if (wrap === null) {
          return yield* Effect.fail(new RecoveryWrapNotFoundError());
        }
        if (wrap.suite !== "maruhi/v1") {
          // PUT pins the suite as a Literal (§13-4), so the v1 write path
          // can never produce a row of another suite. If one exists it is a
          // future version's write or DB corruption; do not silently serve
          // it as v1 (treat as an implementation bug). Judge before the
          // count (recordFetch) so an unservable request does not consume
          // quota (§13-3 counts only blob serves)
          return yield* Effect.die(new Error("stored recovery wrap has an unknown suite"));
        }
        // The audit (auth.recovery_blob_fetched) is recorded by recordFetch
        // in the same batch as the count (§13-5. A denial = no serve is not
        // recorded)
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
