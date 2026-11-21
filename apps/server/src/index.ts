import { AuthMiddleware, maruhiApi } from "@maruhi/api-schema";
import { cryptoServicesLayer, SessionService, TokenService } from "@maruhi/core";
import { Clock, Context, Effect, FileSystem, Layer, Path, Scope } from "effect";
import { Digest, SecureRandom, Signature } from "effect/crypto";
import { Etag, HttpPlatform, HttpRouter } from "effect/http";
import { HttpApiBuilder, HttpApiMiddleware } from "effect/http-api";

import {
  authMiddlewareImpl,
  GitHubApi,
  makeGitHubApi,
  makeSessionService,
  makeTokenService,
} from "./auth.package/index.ts";
import type { DbServices } from "./db.package/index.ts";
import { makeDbServices, OpsRepo, SessionRepo, TokenRepo } from "./db.package/index.ts";
import type { Env } from "./do/chain-do.ts";
import { auditLive } from "./handlers/handlers-audit.ts";
import { authCliLive } from "./handlers/handlers-auth-cli.ts";
import { authLive } from "./handlers/handlers-auth.ts";
import { deksLive } from "./handlers/handlers-deks.ts";
import { devicesLive } from "./handlers/handlers-devices.ts";
import { environmentsLive } from "./handlers/handlers-environments.ts";
import { exportLive } from "./handlers/handlers-export.ts";
import { invitesLive } from "./handlers/handlers-invites.ts";
import { keyWrapsLive } from "./handlers/handlers-key-wraps.ts";
import { leaseLive } from "./handlers/handlers-lease.ts";
import { membershipLive } from "./handlers/handlers-membership.ts";
import { mirrorLive } from "./handlers/handlers-mirror.ts";
import { rotationLive } from "./handlers/handlers-rotation.ts";
import { schemaPolicyLive } from "./handlers/handlers-schema-policy.ts";
import { variablesLive } from "./handlers/handlers-variables.ts";
import { makeOidcVerifier, OidcVerifier } from "./oidc.package/index.ts";
import { makeWebhookNotifier, OpsNotifier, runOpsAlerts } from "./ops/ops-alerts.ts";
import { runBackupSweep } from "./ops/ops-backup.ts";
import { OPS_HOURLY_CRON } from "./ops/ops-policy.ts";
import { countingGitHubApi } from "./ops/ops-signals.ts";
import { MAX_REQUEST_BODY_BYTES } from "./policy.ts";
import { makeServerKey, ServerKey } from "./server-key.ts";
import { ServerLoggerLive } from "./server-logger.ts";
import { readWorkerSecret, readWorkerSecrets, WorkerEnv, WorkerSecrets } from "./worker-env.ts";

export { ProjectChainDO } from "./do/chain-do.ts";
export type { Env } from "./do/chain-do.ts";

const platformContext = Layer.mergeAll(
  HttpPlatform.layer.pipe(Layer.provide(FileSystem.layerNoop({}))),
  FileSystem.layerNoop({}),
  Etag.layer,
  Path.layer,
);

type RequestServices =
  | DbServices
  | WorkerEnv
  | WorkerSecrets
  | GitHubApi
  | SessionService
  | TokenService
  | ServerKey
  | OidcVerifier
  | SecureRandom.SecureRandom
  | Digest.Digest
  | Signature.Signature;

const cryptoServicesContext: Context.Context<
  SecureRandom.SecureRandom | Digest.Digest | Signature.Signature
> = Effect.runSync(Layer.buildWithScope(cryptoServicesLayer, Scope.makeUnsafe()));

async function buildServices(env: Env): Promise<Context.Context<RequestServices>> {
  const dbServices = makeDbServices(env.DB);
  const secrets = await Effect.runPromise(readWorkerSecrets(env));
  return dbServices.pipe(
    Context.add(WorkerEnv, env),
    Context.add(WorkerSecrets, secrets),
    Context.add(
      GitHubApi,
      countingGitHubApi(
        makeGitHubApi(secrets.githubClientId ?? "", secrets.githubClientSecret),
        Context.get(dbServices, OpsRepo),
      ),
    ),
    Context.add(ServerKey, makeServerKey(secrets.serverEncKeyIkm)),
    Context.add(OidcVerifier, makeOidcVerifier()),
    Context.add(SessionService, makeSessionService(Context.get(dbServices, SessionRepo))),
    Context.add(TokenService, makeTokenService(Context.get(dbServices, TokenRepo))),
    Context.merge(cryptoServicesContext),
  );
}

interface EnvHandler {
  readonly handler: (request: Request) => Promise<Response>;
}

const handlerCache = new WeakMap<Env, Promise<EnvHandler>>();

function handlerFor(env: Env): Promise<EnvHandler> {
  const cached = handlerCache.get(env);
  if (cached !== undefined) {
    return cached;
  }
  const built = buildHandler(env);
  handlerCache.set(env, built);
  built.catch(() => {
    if (handlerCache.get(env) === built) {
      handlerCache.delete(env);
    }
  });
  return built;
}

async function buildHandler(env: Env): Promise<EnvHandler> {
  const services = await buildServices(env);
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
    Layer.provide(exportLive),
    Layer.provide(mirrorLive),
    Layer.provide(Layer.succeed(AuthMiddleware, authMiddlewareImpl)),
    Layer.provide(HttpApiMiddleware.layerProblemDetails()),
    Layer.provide(platformContext),
    Layer.provide(cryptoServicesLayer),
    Layer.provide(Layer.succeedContext(services)),
  );
  const webHandler = HttpRouter.toWebHandler(apiLive.pipe(Layer.provideMerge(ServerLoggerLive)), {
    disableLogger: true,
  });
  return {
    handler: (request) => webHandler.handler(request, services),
  };
}

function concatChunks(chunks: readonly Uint8Array[], total: number): Uint8Array {
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

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

function declaredLengthExceedsCap(request: Request): boolean {
  const declared = Number(request.headers.get("content-length"));
  return Number.isFinite(declared) && declared > MAX_REQUEST_BODY_BYTES;
}

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
  const allowsBody = request.method !== "GET" && request.method !== "HEAD";
  return new Request(request.url, {
    method: request.method,
    headers: request.headers,
    body: allowsBody ? (body.buffer as ArrayBuffer) : null,
  });
}

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

async function withRetryAfterHeader(response: Response): Promise<Response> {
  if (response.status !== 429 || response.headers.has("retry-after")) {
    return response;
  }
  let seconds: unknown;
  try {
    seconds = ((await response.clone().json()) as { retryAfterSeconds?: unknown })
      .retryAfterSeconds;
  } catch {
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
    const response = await withRetryAfterHeader(
      await (await handlerFor(env)).handler(cappedRequest),
    );
    if (response.status === 500) {
      console.error("unhandled failure at the HTTP boundary (500)");
    }
    return withSecurityHeaders(response);
  },
  async scheduled(controller, env, _ctx): Promise<void> {
    const dbServices = makeDbServices(env.DB);
    if (controller.cron === OPS_HOURLY_CRON) {
      const opsAlertWebhookUrl = await Effect.runPromise(
        readWorkerSecret(env.OPS_ALERT_WEBHOOK_URL, "OPS_ALERT_WEBHOOK_URL"),
      );
      const services = dbServices.pipe(
        Context.add(OpsNotifier, makeWebhookNotifier(opsAlertWebhookUrl)),
      );
      await Effect.runPromise(
        Clock.currentTimeMillis.pipe(
          Effect.flatMap((nowMs) => runBackupSweep(env).pipe(Effect.andThen(runOpsAlerts(nowMs)))),
          Effect.provideContext(services),
          Effect.provide(ServerLoggerLive),
        ),
      );
      return;
    }
    const sessions = Context.get(dbServices, SessionRepo);
    await Effect.runPromise(
      Clock.currentTimeMillis.pipe(
        Effect.flatMap((nowMs) => sessions.deleteExpired(nowMs)),
        Effect.provide(ServerLoggerLive),
      ),
    );
  },
} satisfies ExportedHandler<Env>;
