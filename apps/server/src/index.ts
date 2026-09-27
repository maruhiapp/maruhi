// @maruhi/server — Workers + DO + D1. Effect v4 HttpApi (ADR-0005).
// Server code uses Web standards + the Workers API only. Bun-specific
// APIs (bun:*) are forbidden.
//
// The source keeps the plain Workers API shape (export default
// { fetch } + DurableObject classes) while the internals are
// implemented in Effect (ADR-0012: works under both wrangler and
// Alchemy v2).
//
// Wiring of request authentication (AUTH_SPEC):
//   - The AuthMiddleware (api-schema contract) implementation is in
//     auth.package/middleware.ts
//   - SessionService / TokenService / repositories are built once at
//     worker startup from env (the D1 binding) and passed to handlers
//     as request context

import { AuthMiddleware, maruhiApi } from "@maruhi/api-schema";
import { SessionService, TokenService } from "@maruhi/core";
import { Context, Effect, FileSystem, Layer, Path } from "effect";
import { Etag, HttpPlatform, HttpRouter } from "effect/unstable/http";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import {
  authMiddlewareImpl,
  GitHubApi,
  makeGitHubApi,
  makeSessionService,
  makeTokenService,
} from "./auth.package/index.ts";
import type { Env } from "./chain-do.ts";
import type { DbServices } from "./db.package/index.ts";
import { makeDbServices, OpsRepo, SessionRepo, TokenRepo } from "./db.package/index.ts";
import { auditLive } from "./handlers-audit.ts";
import { authCliLive } from "./handlers-auth-cli.ts";
import { authLive } from "./handlers-auth.ts";
import { deksLive } from "./handlers-deks.ts";
import { devicesLive } from "./handlers-devices.ts";
import { environmentsLive } from "./handlers-environments.ts";
import { invitesLive } from "./handlers-invites.ts";
import { keyWrapsLive } from "./handlers-key-wraps.ts";
import { leaseLive } from "./handlers-lease.ts";
import { membershipLive } from "./handlers-membership.ts";
import { rotationLive } from "./handlers-rotation.ts";
import { schemaPolicyLive } from "./handlers-schema-policy.ts";
import { variablesLive } from "./handlers-variables.ts";
import { makeOidcVerifier, OidcVerifier } from "./oidc.package/index.ts";
import { makeWebhookNotifier, OpsNotifier, runOpsAlerts } from "./ops-alerts.ts";
import { runBackupSweep } from "./ops-backup.ts";
import { OPS_HOURLY_CRON } from "./ops-policy.ts";
import { countingGitHubApi } from "./ops-signals.ts";
import { MAX_REQUEST_BODY_BYTES } from "./policy.ts";
import { makeServerKey, ServerKey } from "./server-key.ts";
import { WorkerEnv } from "./worker-env.ts";

export { ProjectChainDO } from "./chain-do.ts";
export type { Env } from "./chain-do.ts";

// Findings from spike-b: HttpApiBuilder.layer nominally requires
// HttpPlatform / FileSystem / Etag.Generator / Path (for a pure JSON
// API they are never invoked at runtime). workerd has no FS, so
// FileSystem.layerNoop satisfies the type requirement only
const platformContext = Layer.mergeAll(
  HttpPlatform.layer.pipe(Layer.provide(FileSystem.layerNoop({}))),
  FileSystem.layerNoop({}),
  Etag.layer,
  Path.layer,
);

type RequestServices =
  | DbServices
  | WorkerEnv
  | GitHubApi
  | SessionService
  | TokenService
  | ServerKey
  | OidcVerifier;

function buildServices(env: Env): Context.Context<RequestServices> {
  const dbServices = makeDbServices(env.DB);
  return dbServices.pipe(
    Context.add(WorkerEnv, env),
    // In-house counting of GitHub token requests (ops-signals.ts —
    // the acceptance surface's behavior is unchanged)
    Context.add(
      GitHubApi,
      countingGitHubApi(
        makeGitHubApi(env.GITHUB_CLIENT_ID, env.GITHUB_CLIENT_SECRET),
        Context.get(dbServices, OpsRepo),
      ),
    ),
    Context.add(ServerKey, makeServerKey(env.SERVER_ENC_KEY_IKM)),
    // The OIDC verifier (AUTH_SPEC §14-1). Since it holds the JWKS
    // cache per isolate, exactly one is built per env (same lifetime
    // as handlerCache)
    Context.add(OidcVerifier, makeOidcVerifier()),
    Context.add(SessionService, makeSessionService(Context.get(dbServices, SessionRepo))),
    Context.add(TokenService, makeTokenService(Context.get(dbServices, TokenRepo))),
  );
}

interface EnvHandler {
  readonly handler: (request: Request) => Promise<Response>;
}

// Keep HttpApi Layer construction to once per env (stable per
// isolate). The middleware's requires (SessionService / TokenService)
// must be satisfied statically by a Layer, so webHandler is built per
// env
const handlerCache = new WeakMap<Env, EnvHandler>();

function handlerFor(env: Env): EnvHandler {
  const cached = handlerCache.get(env);
  if (cached !== undefined) {
    return cached;
  }
  const services = buildServices(env);
  const apiLive = HttpApiBuilder.layer(maruhiApi).pipe(
    Layer.provide(membershipLive),
    Layer.provide(authLive),
    Layer.provide(authCliLive),
    Layer.provide(environmentsLive),
    Layer.provide(variablesLive),
    Layer.provide(deksLive),
    Layer.provide(schemaPolicyLive),
    Layer.provide(invitesLive),
    Layer.provide(keyWrapsLive),
    Layer.provide(devicesLive),
    Layer.provide(rotationLive),
    Layer.provide(auditLive),
    Layer.provide(leaseLive),
    Layer.provide(Layer.succeed(AuthMiddleware, authMiddlewareImpl)),
    Layer.provide(platformContext),
    Layer.provide(Layer.succeedContext(services)),
  );
  // Disable Effect's default HTTP logger (HttpMiddleware.logger —
  // annotates `http.url` on "Sent HTTP response"). Left enabled,
  // Workers Logs would record /projects/:id (a capability — AUTH_SPEC
  // §11-2) per request, and the hole plugged by wrangler's
  // `observability.logs.invocation_logs: false` would reopen via the
  // console path (found by checking real Workers Logs data during an
  // ops exercise — hosted-ops.md §5-3). The console lines that remain
  // are static messages + aggregates only (DC-2)
  const webHandler = HttpRouter.toWebHandler(apiLive, { disableLogger: true });
  const built: EnvHandler = {
    handler: (request) => webHandler.handler(request, services),
  };
  handlerCache.set(env, built);
  return built;
}

/** Concatenates a chunk list into one byte string. */
function concatChunks(chunks: readonly Uint8Array[], total: number): Uint8Array {
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

/**
 * Buffers the stream up to the cap and returns it (over-cap → null).
 * Content-Length is a client-declared value and cannot be trusted
 * (missing, forged, or chunked), so the cap is enforced by
 * measurement.
 */
async function readStreamWithinLimit(
  stream: ReadableStream<Uint8Array>,
  limitBytes: number,
): Promise<Uint8Array | null> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      return concatChunks(chunks, total);
    }
    total += value.length;
    if (total > limitBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
}

/** A cheap early rejection on the declared Content-Length (a missing header counts as 0 = passes). */
function declaredLengthExceedsCap(request: Request): boolean {
  const declared = Number(request.headers.get("content-length"));
  return Number.isFinite(declared) && declared > MAX_REQUEST_BODY_BYTES;
}

/**
 * The raw-body cap at the HTTP boundary (policy.ts). Memory-DoS
 * defense ahead of JSON parsing. Over-cap returns null (the caller
 * answers with a schema-less plain 413). An in-cap body is replaced
 * by the buffered bytes and handed to the later stage (JSON
 * parsing).
 */
async function capRequestBody(request: Request): Promise<Request | null> {
  if (declaredLengthExceedsCap(request)) {
    return null;
  }
  if (request.body === null) {
    return request;
  }
  const body = await readStreamWithinLimit(request.body, MAX_REQUEST_BODY_BYTES);
  if (body === null) {
    return null;
  }
  // The Request constructor refuses a non-null body for GET / HEAD
  // (the Fetch spec). The read still happens; a body the later stages
  // do not reference is discarded at reconstruction.
  const allowsBody = request.method !== "GET" && request.method !== "HEAD";
  return new Request(request.url, {
    method: request.method,
    headers: request.headers,
    body: allowsBody ? (body.buffer as ArrayBuffer) : null,
  });
}

/**
 * Common security headers on every response.
 * - `X-Content-Type-Options: nosniff` — this is a JSON-only API and
 *   returns no HTML, but it forecloses MIME-sniffing room including
 *   against future regressions
 * - `Cache-Control: no-store` — responses carry raw token values
 *   (device exchange), ciphertexts, and wraps. They must not remain in
 *   caches along the path (browsers, shared proxies). If a route sets
 *   its own cache policy that one wins (none do at present)
 * - `Strict-Transport-Security` — the API worker can also get a
 *   custom domain via routes (an origin carrying session cookies and
 *   OAuth flows), so it blocks first-connection downgrade like web's
 *   `_headers`. The reason for omitting includeSubDomains is the same
 *   as web's (write-headers.ts)
 */
function withSecurityHeaders(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set("x-content-type-options", "nosniff");
  headers.set("strict-transport-security", "max-age=31536000");
  if (!headers.has("cache-control")) {
    headers.set("cache-control", "no-store");
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/**
 * Adds the standard `Retry-After` header to 429 responses. The typed
 * errors (TokenLimit / RecoveryRateLimited / InviteRateLimited /
 * AuthRateLimited / LeaseRateLimited) carry retryAfterSeconds in the
 * JSON body, but non-maruhi-CLI clients (curl, SDK retry wrappers,
 * RFC 9110-compliant backoff) look only at the header and would keep
 * consuming the window with immediate retries. Only on 429 (a rare
 * path), the body is parsed once and copied.
 */
async function withRetryAfterHeader(response: Response): Promise<Response> {
  if (response.status !== 429 || response.headers.has("retry-after")) {
    return response;
  }
  let seconds: unknown;
  try {
    seconds = ((await response.clone().json()) as { retryAfterSeconds?: unknown })
      .retryAfterSeconds;
  } catch {
    // A 429 without a JSON body (a future path) is returned as-is
    // without the header — this is a representation enhancement and
    // must not promote an unparseable body into a failure (deliberate
    // degradation). But it is not swallowed silently (CLAUDE.md):
    // since a missing header invites immediate retries from non-maruhi
    // clients, a static message that makes the regression noticeable
    // is left in Workers Logs (same discipline as ipRateLimitAllowed's
    // fail-open; the body content is not logged)
    console.warn("429 response body is not JSON; returning it without a Retry-After header");
    return response;
  }
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds <= 0) {
    return response;
  }
  const headers = new Headers(response.headers);
  headers.set("retry-after", String(Math.ceil(seconds)));
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export default {
  async fetch(request, env): Promise<Response> {
    const cappedRequest = await capRequestBody(request);
    if (cappedRequest === null) {
      return withSecurityHeaders(new Response(null, { status: 413 }));
    }
    const response = await withRetryAfterHeader(await handlerFor(env).handler(cappedRequest));
    // Since disableLogger (handlerFor) also stops the Effect logger's
    // failure branch (with cause), unhandled failures / defects would
    // leave nothing in Workers Logs. Instead a single static line
    // carrying no identifiers is left. Intended 5xx like 503
    // SetupIncomplete are out of scope — 500 covers only paths where
    // HttpApi could not map to a typed error
    if (response.status === 500) {
      console.error("unhandled failure at the HTTP boundary (500)");
    }
    return withSecurityHeaders(response);
  },
  // Scheduled jobs (wrangler.jsonc's triggers.crons — branch on the
  // cron string):
  // - Hourly (OPS_HOURLY_CRON): the DO → R2 evacuation sweep
  //   (ops-backup.ts; a no-op without the binding) → tripwire
  //   evaluation and notification (ops-alerts.ts)
  // - Otherwise (daily): cleanup of expired session rows. The
  //   resolve-time cleanup (auth.package/session.ts) can only delete
  //   "the row that was presented". A call with an empty cron string
  //   (tests' createScheduledController()) also lands here = the
  //   existing contract
  async scheduled(controller, env, _ctx): Promise<void> {
    const dbServices = makeDbServices(env.DB);
    if (controller.cron === OPS_HOURLY_CRON) {
      const services = dbServices.pipe(
        Context.add(OpsNotifier, makeWebhookNotifier(env.OPS_ALERT_WEBHOOK_URL)),
      );
      await Effect.runPromise(
        runBackupSweep(env).pipe(
          Effect.andThen(runOpsAlerts(Date.now())),
          Effect.provideContext(services),
        ),
      );
      return;
    }
    const sessions = Context.get(dbServices, SessionRepo);
    await Effect.runPromise(sessions.deleteExpired(Date.now()));
  },
} satisfies ExportedHandler<Env>;
