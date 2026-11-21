import {
  AuthRateLimitedError,
  CliFlowExpiredError,
  CliFlowRejectedError,
  DEFAULT_TOKEN_TTL_DAYS,
  maruhiApi,
  MIN_CLI_POLL_INTERVAL_SECONDS,
  SetupIncompleteError,
  TokenLimitError,
} from "@maruhi/api-schema";
import type { TokenScope, UserId } from "@maruhi/core";
import { parseTokenScopes, TokenService } from "@maruhi/core";
import { Clock, Effect, Option } from "effect";
import { Digest, SecureRandom } from "effect/crypto";
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

const DEFAULT_TOKEN_NAME = "cli-login";

const DEFAULT_TOKEN_SCOPES: readonly TokenScope[] = [{ project: "*", permission: "admin" }];

const flowSigningKey: Effect.Effect<
  CryptoKey,
  never,
  FlowSigningKeyRepo | SecureRandom.SecureRandom
> = Effect.gen(function* () {
  const repo = yield* FlowSigningKeyRepo;
  const candidateKeyHex = yield* randomHex(32);
  const keyHex = yield* repo.getOrCreate(candidateKeyHex, yield* Clock.currentTimeMillis);
  return yield* Effect.promise(() => importFlowSigningKey(keyHex));
});

const ensureIpRateLimit = (
  limiter: RateLimit | undefined,
  request: { readonly source: unknown },
): Effect.Effect<void, SetupIncompleteError | AuthRateLimitedError> =>
  ipRateLimitAllowed(limiter, request).pipe(
    Effect.flatMap((allowed) =>
      allowed
        ? Effect.void
        : Effect.fail(
            new AuthRateLimitedError({ retryAfterSeconds: IP_RATE_LIMIT_PERIOD_SECONDS }),
          ),
    ),
  );

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

function uniformErrorPage(): HttpServerResponse.HttpServerResponse {
  return htmlResponse(renderCliErrorPage(), 400);
}

function withCliCookieExpired(
  response: HttpServerResponse.HttpServerResponse,
): Effect.Effect<HttpServerResponse.HttpServerResponse> {
  return HttpServerResponse.expireCookie(response, CLI_STATE_COOKIE, HOST_COOKIE_OPTIONS).pipe(
    Effect.orDie,
  );
}

export function isCliCallbackState(state: string): boolean {
  return state.startsWith(CLI_STATE_PREFIX);
}

type FlowBinding =
  | { readonly params: CliVerifyParams; readonly vsig: string }
  | "state-mismatch"
  | "invalid";

function restoreFlowBinding(
  request: HttpServerRequest.HttpServerRequest,
  queryState: string,
  key: CryptoKey,
): Effect.Effect<FlowBinding> {
  const cookie = request.cookies[CLI_STATE_COOKIE];
  const bound = cookie === undefined ? null : new URLSearchParams(cookie);
  const cookieState = bound?.get("state") ?? null;
  const stateNonce = (state: string | null): string | null =>
    state !== null && isCliCallbackState(state) ? state.slice(CLI_STATE_PREFIX.length) : null;
  const cookieNonce = stateNonce(cookieState);
  const queryNonce = stateNonce(queryState);
  if (
    bound === null ||
    cookieNonce === null ||
    queryNonce === null ||
    !constantTimeEqual(cookieNonce, queryNonce)
  ) {
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

const admitAndRenderApproval = Effect.fn("handlers-auth-cli.admitAndRenderApproval")(function* (
  params: CliVerifyParams,
  userId: UserId,
  identityLabel: string,
): Effect.fn.Return<
  HttpServerResponse.HttpServerResponse,
  never,
  CliFlowRepo | OpsRepo | SecureRandom.SecureRandom | Digest.Digest
> {
  const ticket = yield* randomHex(32);
  const ticketHash = yield* Effect.orDie(sha256Hex(ticket));
  const scopes = parseTokenScopes(params.scopesJson);
  if (scopes === null) {
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
  if (admission === "capacity") {
    yield* noteOpsCounter("cli_flow_capacity");
  }
  if (admission === "rejected" || admission === "capacity") {
    return uniformErrorPage();
  }
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

export const handleCliCallback = Effect.fn("handlers-auth-cli.handleCliCallback")(function* (
  request: HttpServerRequest.HttpServerRequest,
  query: { readonly code: string; readonly state: string },
): Effect.fn.Return<
  HttpServerResponse.HttpServerResponse,
  never,
  | WorkerEnv
  | GitHubApi
  | IdentityRepo
  | CliFlowRepo
  | FlowSigningKeyRepo
  | D1AuditRepo
  | OpsRepo
  | SecureRandom.SecureRandom
  | Digest.Digest
> {
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
  const origin = requestOrigin(request);
  const github = yield* GitHubApi;
  const exchanged = yield* github.exchangeCode(query.code, callbackUri(origin)).pipe(Effect.option);
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
  const identities = yield* IdentityRepo;
  const userId = yield* identities.lookupUser(identity);
  if (userId === null) {
    const verificationUrl = `${origin}/auth/cli/verify?${verificationQuery(params, vsig).toString()}`;
    const signupPolicy = yield* identities.signupPolicy;
    return yield* withCliCookieExpired(
      htmlResponse(renderSignupGuidancePage(origin, verificationUrl, signupPolicy), 200),
    );
  }
  const identityLabel = identity.providerLogin ?? `GitHub account #${identity.providerUserId}`;
  return yield* withCliCookieExpired(yield* admitAndRenderApproval(params, userId, identityLabel));
});

export const authCliLive = HttpApiBuilder.group(maruhiApi, "authCli", (handlers) =>
  handlers
    .handle(
      "cliStart",
      Effect.fn("handlers-auth-cli.cliStart")(function* ({ payload, request }) {
        const env = yield* WorkerEnv;
        yield* ensureIpRateLimit(env.CLI_START_RATE_LIMIT, request);
        const secrets = yield* WorkerSecrets;
        yield* ensureGitHubOAuthConfigured(secrets.githubClientId, secrets.githubClientSecret);
        const key = yield* flowSigningKey;
        const nowMs = yield* Clock.currentTimeMillis;
        const flowId = yield* randomHex(16);
        const expiresAtMs = nowMs + CLI_FLOW_TTL_MS;
        const params: CliVerifyParams = {
          flowId,
          expiresAtMs,
          userCode: yield* generateUserCode(),
          tokenName: payload.tokenName ?? DEFAULT_TOKEN_NAME,
          scopesJson: JSON.stringify(payload.scopes ?? DEFAULT_TOKEN_SCOPES),
          expiresInDays: payload.expiresInDays ?? DEFAULT_TOKEN_TTL_DAYS,
        };
        const flowToken = yield* createFlowToken(key, flowId, expiresAtMs);
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
    .handle(
      "cliVerify",
      Effect.fn("handlers-auth-cli.cliVerify")(function* ({ request, query }) {
        const env = yield* WorkerEnv;
        yield* ensureIpRateLimit(env.CLI_VERIFY_RATE_LIMIT, request);
        const secrets = yield* WorkerSecrets;
        const configured = yield* ensureGitHubOAuthConfigured(
          secrets.githubClientId,
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
        const state = `${CLI_STATE_PREFIX}${yield* randomHex(16)}`;
        const bound = verificationQuery(params, query.vsig);
        bound.set("state", state);
        return yield* redirectToGitHubAuthorize(request, configured.value, state, {
          name: CLI_STATE_COOKIE,
          value: bound.toString(),
        });
      }),
    )
    .handle(
      "cliApprove",
      Effect.fn("handlers-auth-cli.cliApprove")(function* ({ payload, request }) {
        const env = yield* WorkerEnv;
        yield* ensureIpRateLimit(env.CLI_APPROVE_RATE_LIMIT, request);
        const { flowId, ticket, decision } = payload;
        if (
          flowId === undefined ||
          ticket === undefined ||
          (decision !== "approve" && decision !== "deny")
        ) {
          return uniformErrorPage();
        }
        const ticketHash = yield* Effect.orDie(sha256Hex(ticket));
        const flows = yield* CliFlowRepo;
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
        const row = yield* flows.findById(flowId);
        return htmlResponse(renderApprovedPage(row === null ? "" : row.userCode), 200);
      }),
    )
    .handle(
      "cliPoll",
      Effect.fn("handlers-auth-cli.cliPoll")(function* ({ payload, request }) {
        const env = yield* WorkerEnv;
        yield* ensureIpRateLimit(env.CLI_POLL_RATE_LIMIT, request);
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
        if (row === null || row.status === "awaiting") {
          return { status: "pending" as const };
        }
        if (row.status === "denied") {
          return { status: "denied" as const };
        }
        if (row.status === "consumed") {
          return yield* Effect.fail(new CliFlowRejectedError());
        }
        const won = yield* flows.consumeCas(payload.flowId);
        if (!won) {
          return yield* Effect.fail(new CliFlowRejectedError());
        }
        const tokens = yield* TokenService;
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
