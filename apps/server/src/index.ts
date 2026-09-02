// @maruhi/server — Workers + DO + D1。Effect v4 HttpApi(ADR-0005)。
// サーバーコードは Web 標準 + Workers API のみ。Bun 固有 API(bun:*)は使用禁止。
//
// ソースは素の Workers API(export default { fetch } + DurableObject クラス)の
// まま内部を Effect で実装する(ADR-0012: wrangler / Alchemy v2 両対応)。
//
// リクエスト認証(AUTH_SPEC)の結線:
//   - AuthMiddleware(api-schema 契約)の実装は auth.package/middleware.ts
//   - SessionService / TokenService / リポジトリは env(D1 binding)から worker
//     起動時に一度だけ構築し、リクエストコンテキストとして handler へ渡す

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
import { environmentsLive } from "./handlers-environments.ts";
import { invitesLive } from "./handlers-invites.ts";
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

// spike-b の検証知見: HttpApiBuilder.layer は型上 HttpPlatform / FileSystem /
// Etag.Generator / Path を要求する(JSON API だけなら実行時には呼ばれない)。
// workerd には FS がないので FileSystem.layerNoop で型要求だけ満たす
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
    // GitHub token 請求の自前計数(H3 — ops-signals.ts。受理面の挙動は不変)
    Context.add(
      GitHubApi,
      countingGitHubApi(
        makeGitHubApi(env.GITHUB_CLIENT_ID, env.GITHUB_CLIENT_SECRET),
        Context.get(dbServices, OpsRepo),
      ),
    ),
    Context.add(ServerKey, makeServerKey(env.SERVER_ENC_KEY_IKM)),
    // OIDC verifier(AUTH_SPEC §14-1)。JWKS キャッシュを isolate 単位で
    // 抱えるため env ごとに 1 つだけ作る(handlerCache と同じ寿命)
    Context.add(OidcVerifier, makeOidcVerifier()),
    Context.add(SessionService, makeSessionService(Context.get(dbServices, SessionRepo))),
    Context.add(TokenService, makeTokenService(Context.get(dbServices, TokenRepo))),
  );
}

interface EnvHandler {
  readonly handler: (request: Request) => Promise<Response>;
}

// env(isolate ごとに安定)単位で HttpApi の Layer 構築を 1 回に抑える。
// ミドルウェアの requires(SessionService / TokenService)は Layer で静的に
// 満たす必要があるため、webHandler は env ごとに構築する
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
    Layer.provide(rotationLive),
    Layer.provide(auditLive),
    Layer.provide(leaseLive),
    Layer.provide(Layer.succeed(AuthMiddleware, authMiddlewareImpl)),
    Layer.provide(platformContext),
    Layer.provide(Layer.succeedContext(services)),
  );
  const webHandler = HttpRouter.toWebHandler(apiLive);
  const built: EnvHandler = {
    handler: (request) => webHandler.handler(request, services),
  };
  handlerCache.set(env, built);
  return built;
}

/** チャンク列を 1 本のバイト列へ連結する。 */
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
 * ストリームを上限までバッファして返す(超過は null)。Content-Length は
 * クライアント申告値であり信用できない(欠落・偽装・chunked)ため、上限は
 * 実測で強制する。
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

/** Content-Length 申告値による安価な事前棄却(ヘッダー欠落は 0 扱い = 通す)。 */
function declaredLengthExceedsCap(request: Request): boolean {
  const declared = Number(request.headers.get("content-length"));
  return Number.isFinite(declared) && declared > MAX_REQUEST_BODY_BYTES;
}

/**
 * HTTP 境界の生ボディ上限(policy.ts)。JSON パース前のメモリ DoS 防御。
 * 超過は null(呼び出し側がスキーマ外の素の 413 で返す)。上限内のボディは
 * バッファ済みバイト列に置き換えて後段(JSON パース)へ渡す。
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
  return new Request(request.url, {
    method: request.method,
    headers: request.headers,
    body: body.buffer as ArrayBuffer,
  });
}

/**
 * 全応答に付ける共通セキュリティヘッダー(セキュリティレビュー L-5)。
 * - `X-Content-Type-Options: nosniff` — JSON のみの API で HTML は返さないが、
 *   MIME スニッフィングの余地を将来の退行込みで塞ぐ
 * - `Cache-Control: no-store` — 応答にはトークン生値(device 交換)・暗号文・
 *   ラップが載る。経路上のキャッシュ(ブラウザ・共有プロキシ)に残さない。
 *   ルートが自前のキャッシュ方針を設定した場合はそちらを優先する(現状は皆無)
 * - `Strict-Transport-Security` — API worker も routes で custom domain を
 *   割り当てうる(セッションクッキー・OAuth フローを持つオリジン)ため、web の
 *   `_headers` と同様に初回接続ダウングレードを塞ぐ。includeSubDomains を
 *   付けない理由も web 側(write-headers.ts)と同じ
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
 * 429 応答へ標準 `Retry-After` ヘッダーを付与する(レビューループ 8)。型付き
 * エラー(TokenLimit / RecoveryRateLimited / InviteRateLimited / AuthRateLimited /
 * LeaseRateLimited)は retryAfterSeconds を JSON ボディで運ぶが、maruhi CLI 以外の
 * クライアント(curl・SDK の再試行ラッパー・RFC 9110 準拠のバックオフ)は
 * ヘッダーしか見ず、即時リトライで窓を消費し続ける。429 のみ(稀な経路)で
 * ボディを 1 回パースして写す。
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
    // JSON ボディを持たない 429(将来の経路)はヘッダーなしのまま返す — ここは
    // 表現の補強であり、パース不能を失敗に昇格させない(意図的な劣化)。ただし
    // 無言では飲まない(CLAUDE.md): ヘッダー欠落は非 maruhi クライアントの
    // 即時リトライを招くため、退行に気づける静的メッセージだけ Workers ログへ
    // 残す(ipRateLimitAllowed の fail-open と同じ規律。ボディ内容は書かない)
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
    return withSecurityHeaders(
      await withRetryAfterHeader(await handlerFor(env).handler(cappedRequest)),
    );
  },
  // 定期ジョブ(wrangler.jsonc の triggers.crons — cron 文字列で分岐):
  // - 毎時(OPS_HOURLY_CRON): 運用基盤 H3 — DO → R2 退避スイープ(ops-backup.ts。
  //   バインディング無しなら no-op)→ トリップワイヤの評価と通知(ops-alerts.ts)
  // - それ以外(日次): 期限切れセッション行の掃除。resolve 時の掃除
  //   (auth.package/session.ts)は「提示された行」しか消せない。cron 文字列が
  //   空の呼び出し(テストの createScheduledController())もこちら = 既存の契約
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
