// Handlers for CLI login (server-mediated web-flow handoff —
// AUTH_SPEC §4).
//
// - `flowToken` is a CLI-only bearer credential. It appears on none of
//   the browser channel (URL, pages, redirects), logs, or error
//   messages (§4-1 (1))
// - Failures on the browser leg (cliVerify / the callback's CLI branch
//   / cliApprove) follow §4-2's uniform-refusal discipline and return
//   the same scriptless error page (no oracle for flow state or
//   refusal reasons)
// - The callback's CLI branch (handleCliCallback) is called from
//   githubCallback in handlers-auth.ts (GitHub's callback URL stays
//   the single URL of §3 — branching happens on the state's `cli.`
//   prefix)

import {
  AuthRateLimitedError,
  CliFlowExpiredError,
  CliFlowRejectedError,
  DEFAULT_TOKEN_TTL_DAYS,
  maruhiApi,
  MIN_CLI_POLL_INTERVAL_SECONDS,
  TokenLimitError,
} from "@maruhi/api-schema";
import type { TokenScope } from "@maruhi/core";
import { parseTokenScopes, TokenService } from "@maruhi/core";
import { Clock, Effect, Option } from "effect";
import type { HttpServerRequest } from "effect/http";
import { HttpServerResponse } from "effect/http";
import { HttpApiBuilder } from "effect/http-api";

import {
  CLI_STATE_COOKIE,
  CLI_STATE_PREFIX,
  callbackUri,
  ensureGitHubOAuthConfigured,
  HOST_COOKIE_OPTIONS,
  recordLoginFailed,
  redirectToGitHubAuthorize,
  requestOrigin,
} from "../auth-shared.ts";
import type { CliVerifyParams } from "../auth.package/index.ts";
import {
  CLI_FLOW_TTL_MS,
  CLI_PAGE_CSP_HEADER,
  computeVsig,
  createFlowToken,
  generateUserCode,
  GitHubApi,
  importFlowSigningKey,
  renderApprovalPage,
  renderApprovedPage,
  renderCliErrorPage,
  renderDeniedPage,
  renderSignupGuidancePage,
  verificationQuery,
  verifyCliVerifyQuery,
  verifyFlowToken,
} from "../auth.package/index.ts";
import type { D1AuditRepo } from "../db.package/index.ts";
import { CliFlowRepo, FlowSigningKeyRepo, IdentityRepo, OpsRepo } from "../db.package/index.ts";
import { constantTimeEqual, randomHex, sha256Hex } from "../ids.ts";
import { noteOpsCounter } from "../ops/ops-signals.ts";
import {
  IP_RATE_LIMIT_PERIOD_SECONDS,
  ipRateLimitAllowed,
  WorkerEnv,
  WorkerSecrets,
} from "../worker-env.ts";

/** The default token name when issuance parameters are omitted (§6's semantics treat it the same as the default scope). */
const DEFAULT_TOKEN_NAME = "cli-login";

/** The default scope when omitted (AUTH_SPEC §6: * × admin when omitted). */
const DEFAULT_TOKEN_SCOPES: readonly TokenScope[] = [{ project: "*", permission: "admin" }];

/**
 * Resolution of the flow-signing key (AUTH_SPEC §4-2): on first use a
 * candidate key is generated and stored in D1 (idempotent,
 * first-writer-wins — on contention the later candidate is discarded
 * and the stored key is used). The key is not cached in the isolate:
 * flows are a low-frequency 15-minute-TTL surface, and there is no
 * value in bringing in cache coherency (cross-isolate drift on manual
 * rotation).
 */
const flowSigningKey: Effect.Effect<CryptoKey, never, FlowSigningKeyRepo> = Effect.gen(
  function* () {
    const repo = yield* FlowSigningKeyRepo;
    const keyHex = yield* repo.getOrCreate(randomHex(32), yield* Clock.currentTimeMillis);
    // Malformed form (only ever written by our own generation path) is a defect
    return yield* Effect.promise(() => importFlowSigningKey(keyHex));
  },
);

/**
 * Response for scriptless HTML pages (§4-1 (4) — same delivery
 * discipline as §15-3's invite landing page). CSP is duplicated in the
 * page's meta (frame-ancestors on the header side only — ineffective
 * in meta); Referrer-Policy also blocks external leaks of the page
 * URL (navigations off the approval page). X-Frame-Options is kept
 * alongside for old browsers without frame-ancestors. The signup
 * control guidance pages (handlers-auth.ts — AUTH_SPEC §3) share the
 * same response point.
 */
export function htmlResponse(html: string, status: number): HttpServerResponse.HttpServerResponse {
  return HttpServerResponse.text(html, {
    status,
    contentType: "text/html; charset=utf-8",
    headers: {
      "content-security-policy": CLI_PAGE_CSP_HEADER,
      "referrer-policy": "no-referrer",
      "x-frame-options": "DENY",
    },
  });
}

/** The uniform error page (§4-2 — failure reasons are not differentiated even in HTTP status). */
function uniformErrorPage(): HttpServerResponse.HttpServerResponse {
  return htmlResponse(renderCliErrorPage(), 400);
}

/** Cleans the flow-binding cookie off the CLI branch's terminal responses (single use). */
function withCliCookieExpired(
  response: HttpServerResponse.HttpServerResponse,
): Effect.Effect<HttpServerResponse.HttpServerResponse> {
  return HttpServerResponse.expireCookie(response, CLI_STATE_COOKIE, HOST_COOKIE_OPTIONS).pipe(
    Effect.orDie,
  );
}

/** Whether GitHub's state belongs to the CLI browser leg (the callback's branch check — §4-1 (3)). */
export function isCliCallbackState(state: string): boolean {
  return state.startsWith(CLI_STATE_PREFIX);
}

/** The (i)-a restore result: binding parameters that passed verification, or a uniform-refusal class. */
type FlowBinding =
  | { readonly params: CliVerifyParams; readonly vsig: string }
  | "state-mismatch"
  | "invalid";

/**
 * The callback's CLI branch (i)-a: restore and verify the
 * flow-binding cookie. The CLI branch carries the state and the
 * vsig-signed parameter set on a dedicated cookie (CLI_STATE_COOKIE)
 * (§4-1 (3)'s "flow binding on state" — GitHub's state parameter
 * itself stays a bare nonce; the substance of the binding lives on
 * the cookie side, which only the same browser holds). After matching
 * the state, the vsig is re-verified (the same stateless verification
 * as on verify's arrival — the cookie value is client-held data that
 * can be tampered with, and no flow row is created for parameters
 * that fail the signature).
 */
function restoreFlowBinding(
  request: HttpServerRequest.HttpServerRequest,
  queryState: string,
  key: CryptoKey,
): Effect.Effect<FlowBinding> {
  const cookie = request.cookies[CLI_STATE_COOKIE];
  const bound = cookie === undefined ? null : new URLSearchParams(cookie);
  const cookieState = bound?.get("state") ?? null;
  if (bound === null || cookieState === null || !constantTimeEqual(cookieState, queryState)) {
    return Effect.succeed("state-mismatch");
  }
  const readParam = (name: string): string | undefined => bound.get(name) ?? undefined;
  const vsig = readParam("vsig");
  return Effect.flatMap(Clock.currentTimeMillis, (nowMs) =>
    Effect.promise(async () => {
      const params = await verifyCliVerifyQuery(
        key,
        {
          flow: readParam("flow"),
          exp: readParam("exp"),
          code: readParam("code"),
          name: readParam("name"),
          scopes: readParam("scopes"),
          days: readParam("days"),
          vsig,
        },
        nowMs,
      );
      return params === null || vsig === undefined ? "invalid" : { params, vsig };
    }),
  );
}

/**
 * The callback's CLI branch (iii)–(iv): creation CAS of the flow row
 * (create-or-match) and rendering of the approval page. user_id, the
 * issuance parameters, and the ticket are all fixed at creation (no
 * intermediate state exists). scopesJson is a value start itself
 * JSON.stringify'd from Schema-validated scopes and is
 * vsig-verified — a decode failure is a defect.
 */
function admitAndRenderApproval(
  params: CliVerifyParams,
  userId: string,
  identityLabel: string,
): Effect.Effect<HttpServerResponse.HttpServerResponse, never, CliFlowRepo | OpsRepo> {
  return Effect.gen(function* () {
    const ticket = randomHex(32);
    const ticketHash = yield* Effect.promise(() => sha256Hex(ticket));
    const scopes = parseTokenScopes(params.scopesJson);
    if (scopes === null) {
      // The only signer is the server (cliStart JSON.stringify's
      // Schema-validated scopes). A value that does not decode = an
      // implementation bug / signing-key compromise = defect
      return yield* Effect.die(new Error("verified CLI flow scopes are not a valid scope array"));
    }
    const flows = yield* CliFlowRepo;
    const admission = yield* flows.createOrMatch(
      {
        flowId: params.flowId,
        userId,
        tokenName: params.tokenName,
        scopes,
        expiresInDays: params.expiresInDays,
        userCode: params.userCode,
        ticketHash,
        expiresAtMs: params.expiresAtMs,
      },
      yield* Clock.currentTimeMillis,
    );
    // rejected (different user_id, expired, terminal state) and
    // capacity (overall cap) both get the uniform error page
    // (§4-1 (4) (iii) / §4-2 — the ticket is not rotated)
    if (admission === "capacity") {
      // Reaching the cap is an event that does not occur in normal
      // operation = the H3 tripwire (hosted-ops.md §3 row 4). Counted
      // only; the response is unchanged
      yield* noteOpsCounter("cli_flow_capacity");
    }
    if (admission === "rejected" || admission === "capacity") {
      return uniformErrorPage();
    }
    // (iv): the approval page (scriptless). Shows the authenticated
    // identity + what is being granted. The raw ticket value is
    // embedded only on this page (always the latest one)
    return htmlResponse(
      renderApprovalPage({
        userCode: params.userCode,
        identityLabel,
        tokenName: params.tokenName,
        scopes,
        expiresInDays: params.expiresInDays,
        flowId: params.flowId,
        ticket,
      }),
      200,
    );
  });
}

/**
 * The callback's CLI flow branch (AUTH_SPEC §4-1 (4) — the
 * processing order is fixed by the spec).
 * (i) state verification + code exchange + user-info fetch (confirms
 * OAuth completion) →
 * (ii) account lookup (absent = ends with signup guidance, zero side
 * effects) →
 * (iii) flow-row creation CAS (create-or-match) → (iv) approval page.
 *
 * Every terminal is browser-facing HTML (no typed errors returned).
 * The caller (githubCallback) has already passed per-IP rate
 * limiting.
 */
export function handleCliCallback(
  request: HttpServerRequest.HttpServerRequest,
  query: { readonly code: string; readonly state: string },
): Effect.Effect<
  HttpServerResponse.HttpServerResponse,
  never,
  WorkerEnv | GitHubApi | IdentityRepo | CliFlowRepo | FlowSigningKeyRepo | D1AuditRepo | OpsRepo
> {
  return Effect.gen(function* () {
    // (i)-a: restore the flow-binding cookie (state match + vsig
    //    re-verification)
    const key = yield* flowSigningKey;
    const binding = yield* restoreFlowBinding(request, query.state, key);
    if (binding === "state-mismatch") {
      yield* recordLoginFailed("cli_handoff", "state-mismatch");
      return yield* withCliCookieExpired(uniformErrorPage());
    }
    if (binding === "invalid") {
      return yield* withCliCookieExpired(uniformErrorPage());
    }
    const { params, vsig } = binding;
    // (i)-b: code exchange + user-info fetch (§3's second stage). On
    //    failure none of the later processing happens (the flow row is
    //    created only after OAuth completes — §4-1 (4))
    const origin = requestOrigin(request);
    const github = yield* GitHubApi;
    const exchanged = yield* github
      .exchangeCode(query.code, callbackUri(origin))
      .pipe(Effect.option);
    if (Option.isNone(exchanged)) {
      yield* recordLoginFailed("cli_handoff", "code-exchange-failed");
      return yield* withCliCookieExpired(uniformErrorPage());
    }
    const fetched = yield* github.fetchIdentity(exchanged.value).pipe(Effect.option);
    if (Option.isNone(fetched)) {
      yield* recordLoginFailed("cli_handoff", "github-token-invalid");
      return yield* withCliCookieExpired(uniformErrorPage());
    }
    const identity = fetched.value;
    // (ii): account lookup only (no creation — ruling DH). Absence
    //    ends with signup guidance and triggers no irreversible side
    //    effects at all. The resume link is verificationUrl (restored
    //    from the vsig-signed parameters) — this page itself cannot
    //    resume the flow on reload
    const identities = yield* IdentityRepo;
    const userId = yield* identities.lookupUser(identity);
    if (userId === null) {
      const verificationUrl = `${origin}/auth/cli/verify?${verificationQuery(params, vsig).toString()}`;
      // Only the guidance wording follows signupPolicy (AUTH_SPEC §3)
      // — under invite-only mode, showing a plain signup link would
      // just lead to the refusal page. The source of truth for
      // acceptance stays the server gate (§3 — the Web signup side)
      const signupPolicy = yield* identities.signupPolicy;
      return yield* withCliCookieExpired(
        htmlResponse(renderSignupGuidancePage(origin, verificationUrl, signupPolicy), 200),
      );
    }
    const identityLabel = identity.providerLogin ?? `GitHub account #${identity.providerUserId}`;
    return yield* withCliCookieExpired(
      yield* admitAndRenderApproval(params, userId, identityLabel),
    );
  });
}

export const authCliLive = HttpApiBuilder.group(maruhiApi, "authCli", (handlers) =>
  handlers
    .handle("cliStart", ({ payload, request }) =>
      Effect.gen(function* () {
        const env = yield* WorkerEnv;
        // per-IP rate limiting placed first in the handler (§4-1 (1)
        // — being record-free, this protects CPU rather than the DB;
        // the same binding pattern as the old device exchange)
        const allowed = yield* ipRateLimitAllowed(env.CLI_START_RATE_LIMIT, request);
        if (!allowed) {
          return yield* Effect.fail(
            new AuthRateLimitedError({ retryAfterSeconds: IP_RATE_LIMIT_PERIOD_SECONDS }),
          );
        }
        // An unconfigured server fails closed before reaching GitHub
        // (§4-1 (1))
        const secrets = yield* WorkerSecrets;
        yield* ensureGitHubOAuthConfigured(env.GITHUB_CLIENT_ID, secrets.githubClientSecret);
        const key = yield* flowSigningKey;
        const nowMs = yield* Clock.currentTimeMillis;
        const flowId = randomHex(16);
        const expiresAtMs = nowMs + CLI_FLOW_TTL_MS;
        const params: CliVerifyParams = {
          flowId,
          expiresAtMs,
          userCode: generateUserCode(),
          tokenName: payload.tokenName ?? DEFAULT_TOKEN_NAME,
          scopesJson: JSON.stringify(payload.scopes ?? DEFAULT_TOKEN_SCOPES),
          expiresInDays: payload.expiresInDays ?? DEFAULT_TOKEN_TTL_DAYS,
        };
        // The server stores nothing at this point (record-free —
        // ruling DH). Authenticity is carried by the two MAC systems:
        // flowToken (whose signed content includes flowId) and vsig
        const flowToken = yield* Effect.promise(() => createFlowToken(key, flowId, expiresAtMs));
        const vsig = yield* Effect.promise(() => computeVsig(key, params));
        const origin = requestOrigin(request);
        return {
          flowId,
          flowToken,
          userCode: params.userCode,
          verificationUrl: `${origin}/auth/cli/verify?${verificationQuery(params, vsig).toString()}`,
          expiresInSeconds: Math.floor(CLI_FLOW_TTL_MS / 1000),
          pollIntervalSeconds: MIN_CLI_POLL_INTERVAL_SECONDS,
        };
      }),
    )
    .handle("cliVerify", ({ request, query }) =>
      Effect.gen(function* () {
        const env = yield* WorkerEnv;
        const secrets = yield* WorkerSecrets;
        // Stateless verification of vsig and expiry (§4-1 (3)).
        // Failure ends with the uniform error page before any GitHub
        // redirect happens (do not run the OAuth dance for a
        // fabricated flowId — fail-closed). An unconfigured server
        // gets the same page (start has already failed with 503, so
        // reaching here means a forged URL or lost configuration)
        const configured = yield* ensureGitHubOAuthConfigured(
          env.GITHUB_CLIENT_ID,
          secrets.githubClientSecret,
        ).pipe(Effect.option);
        if (Option.isNone(configured)) {
          return uniformErrorPage();
        }
        const key = yield* flowSigningKey;
        const nowMs = yield* Clock.currentTimeMillis;
        const params = yield* Effect.promise(() => verifyCliVerifyQuery(key, query, nowMs));
        if (params === null || query.vsig === undefined) {
          return uniformErrorPage();
        }
        // §3's first stage (issue state → 302 to GitHub authorize).
        // The state carries the `cli.` prefix to tell callback this is
        // the CLI branch; the cookie carries state + the vsig-signed
        // parameter set (flow binding)
        const state = `${CLI_STATE_PREFIX}${randomHex(16)}`;
        const bound = verificationQuery(params, query.vsig);
        bound.set("state", state);
        return yield* redirectToGitHubAuthorize(request, env.GITHUB_CLIENT_ID, state, {
          name: CLI_STATE_COOKIE,
          value: bound.toString(),
        });
      }),
    )
    .handle("cliApprove", ({ payload }) =>
      Effect.gen(function* () {
        // The credential is the approval ticket alone (§4-1 (4) — not
        // a session). A missing or unknown decision gets the uniform
        // error page (§4-2 — not differentiated from ticket
        // verification)
        const { flowId, ticket, decision } = payload;
        if (
          flowId === undefined ||
          ticket === undefined ||
          (decision !== "approve" && decision !== "deny")
        ) {
          return uniformErrorPage();
        }
        const ticketHash = yield* Effect.promise(() => sha256Hex(ticket));
        const flows = yield* CliFlowRepo;
        // CAS of awaiting → approved | denied. The credential is the
        // single latest ticket (unknown, expired, or used uniformly
        // yields false). The approval's auth.login_succeeded
        // (authMethod cli_handoff) is recorded in the same batch as the
        // CAS (repos)
        const decided = yield* flows.decideCas(
          flowId,
          ticketHash,
          decision === "approve" ? "approved" : "denied",
          yield* Clock.currentTimeMillis,
        );
        if (!decided) {
          return uniformErrorPage();
        }
        if (decision === "deny") {
          return htmlResponse(renderDeniedPage(), 200);
        }
        // The row just CAS-won always exists (deletion happens only
        // after expiry + slack). Pulls the display userCode (shows the
        // same match code as the approval page on the completion page)
        const row = yield* flows.findById(flowId);
        return htmlResponse(renderApprovedPage(row === null ? "" : row.userCode), 200);
      }),
    )
    .handle("cliPoll", ({ payload, request }) =>
      Effect.gen(function* () {
        const env = yield* WorkerEnv;
        const allowed = yield* ipRateLimitAllowed(env.CLI_POLL_RATE_LIMIT, request);
        if (!allowed) {
          return yield* Effect.fail(
            new AuthRateLimitedError({ retryAfterSeconds: IP_RATE_LIMIT_PERIOD_SECONDS }),
          );
        }
        // Stateless verification (§4-1 (5)): MAC, expiry, and the
        // signed flowId matching the presented flowId as a set.
        // invalid = uniform refusal (recombination or tampering —
        // credential mismatch); expired = a typed termination
        // instruction to the legitimate holder (§4-2)
        const key = yield* flowSigningKey;
        const nowMs = yield* Clock.currentTimeMillis;
        const verdict = yield* Effect.promise(() =>
          verifyFlowToken(key, payload.flowId, payload.flowToken, nowMs),
        );
        if (verdict === "invalid") {
          return yield* Effect.fail(new CliFlowRejectedError());
        }
        if (verdict === "expired") {
          return yield* Effect.fail(new CliFlowExpiredError());
        }
        const flows = yield* CliFlowRepo;
        const row = yield* flows.findById(payload.flowId);
        // No row = the browser leg simply hasn't arrived yet (the
        // normal case of a record-free start — §4-1 (5))
        if (row === null || row.status === "awaiting") {
          return { status: "pending" as const };
        }
        if (row.status === "denied") {
          return { status: "denied" as const };
        }
        if (row.status === "consumed") {
          // A re-poll of an already-issued flow (same uniform refusal
          // as a CAS loser — §4-2)
          return yield* Effect.fail(new CliFlowRejectedError());
        }
        // approved: only the winner of the CAS into consumed issues
        // (single-issuance = the structural exclusion of double
        // distribution. flowToken is a bearer not bound to one
        // process, so concurrent polls are expected input). A failed
        // issuance after a successful CAS ends still consumed
        // (fail-closed — no half-distribution left behind; the CLI
        // logs in again)
        const won = yield* flows.consumeCas(payload.flowId);
        if (!won) {
          return yield* Effect.fail(new CliFlowRejectedError());
        }
        const tokens = yield* TokenService;
        // §6 issuance (same-name rotation, issuance cap,
        // auth.token_created audit — all under the existing
        // discipline). The issuance parameters are the row's stored
        // values
        const ttlMs = row.expiresInDays * 24 * 60 * 60 * 1000;
        const issued = yield* tokens
          .issueToken(row.userId, row.tokenName, row.scopes, ttlMs)
          .pipe(
            Effect.catchTag("TokenLimitReached", (error) =>
              Effect.fail(new TokenLimitError({ limit: error.limit })),
            ),
          );
        return {
          status: "approved" as const,
          token: issued.rawToken,
          tokenId: issued.tokenId,
          userId: row.userId,
          expiresAtMs: issued.expiresAtMs,
        };
      }),
    ),
);
