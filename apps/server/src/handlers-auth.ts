// 認証エンドポイントのハンドラ(AUTH_SPEC §3 / §4 / §5 / §6)。
//
// - GitHub アクセストークンはこのファイルのハンドラのローカル変数にのみ存在し、
//   レスポンス・ログ・ストレージへ出ない(§10: GitHub トークンの永続化禁止)
// - `__Host-` クッキーは Secure / Path=/ が必須(http の wrangler dev ではブラウザに
//   保存されない点に注意 — テストはヘッダー検証で行う)

import {
  AuthFlowError,
  ForbiddenError,
  maruhiApi,
  RecoveryRateLimitedError,
  RecoveryWrapNotFoundError,
  TokenLimitError,
} from "@maruhi/api-schema";
import type { AuthenticatedPrincipal, TokenScope } from "@maruhi/core";
import { RequestAuth, SessionService, TokenService } from "@maruhi/core";
import { Effect } from "effect";
import type { Cookies } from "effect/unstable/http";
import { HttpServerRequest, HttpServerResponse } from "effect/unstable/http";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { GitHubApi, parseBearerToken, SESSION_COOKIE } from "./auth.package/index.ts";
import { IdentityRepo, RecoveryRepo } from "./db.package/index.ts";
import { constantTimeEqual, randomHex } from "./ids.ts";
import { WorkerEnv } from "./worker-env.ts";

const STATE_COOKIE = "__Host-maruhi_oauth_state";
const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const OAUTH_SCOPE = "read:user user:email";

/** device flow 交換の既定スコープ(AUTH_SPEC §6: 省略時は * × admin)。 */
const DEFAULT_TOKEN_SCOPES: readonly TokenScope[] = [{ project: "*", permission: "admin" }];

/** `__Host-` クッキーの共通属性(§5)。 */
const HOST_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  path: "/",
} as const satisfies Cookies.Cookie["options"];

function requestOrigin(request: HttpServerRequest.HttpServerRequest): string {
  // effect の HttpServerRequest.url はパスのみ。絶対 URL は生の Web Request が持つ。
  // Host ヘッダー(攻撃者が偽装可能)を redirect_uri の組み立てに使わない —
  // workerd の入口は常に Web Request なので、そうでないのは配線バグ(defect)
  const source: unknown = request.source;
  if (source instanceof Request) {
    return new URL(source.url).origin;
  }
  throw new Error("request origin unavailable: source is not a web Request");
}

function callbackUri(origin: string): string {
  return `${origin}/auth/github/callback`;
}

/** GitHub の認証ダンス失敗を API の型付きエラーへ写す。 */
function authFlowFailure(
  reason: "state-mismatch" | "code-exchange-failed" | "github-token-invalid",
): () => AuthFlowError {
  return () => new AuthFlowError({ reason });
}

/**
 * 鍵素材管理操作(リカバリーブロブの登録・再発行・取得)のトークン条件
 * (AUTH_SPEC §13-2): セッション主体は常に可、トークン主体は `*` × admin
 * スコープを含む場合のみ可。スコープ限定トークンにラップの置換(可用性攻撃)や
 * 要監視のブロブ取得を許さない。
 */
function ensureKeyMaterialAccess(
  principal: AuthenticatedPrincipal,
): Effect.Effect<void, ForbiddenError> {
  if (principal.kind === "session") {
    return Effect.void;
  }
  const allowed = principal.scopes.some(
    (scope) => scope.project === "*" && scope.permission === "admin",
  );
  return allowed
    ? Effect.void
    : Effect.fail(new ForbiddenError({ reason: "insufficient-permission" }));
}

export const authLive = HttpApiBuilder.group(maruhiApi, "auth", (handlers) =>
  handlers
    .handle("githubStart", ({ request }) =>
      Effect.gen(function* () {
        const env = yield* WorkerEnv;
        const state = randomHex(16);
        const origin = requestOrigin(request);
        const authorize = new URL(GITHUB_AUTHORIZE_URL);
        authorize.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
        authorize.searchParams.set("redirect_uri", callbackUri(origin));
        authorize.searchParams.set("scope", OAUTH_SCOPE);
        authorize.searchParams.set("state", state);
        const response = HttpServerResponse.redirect(authorize, { status: 302 });
        return yield* HttpServerResponse.setCookie(response, STATE_COOKIE, state, {
          ...HOST_COOKIE_OPTIONS,
          maxAge: "10 minutes",
        }).pipe(Effect.orDie);
      }),
    )
    .handle("githubCallback", ({ request, query }) =>
      Effect.gen(function* () {
        const expectedState = request.cookies[STATE_COOKIE];
        // §3-2: state 検証(不一致は即拒否)
        if (expectedState === undefined || !constantTimeEqual(expectedState, query.state)) {
          return yield* Effect.fail(new AuthFlowError({ reason: "state-mismatch" }));
        }
        const origin = requestOrigin(request);
        const github = yield* GitHubApi;
        const accessToken = yield* github
          .exchangeCode(query.code, callbackUri(origin))
          .pipe(Effect.mapError(authFlowFailure("code-exchange-failed")));
        const identity = yield* github
          .fetchIdentity(accessToken)
          .pipe(Effect.mapError(authFlowFailure("github-token-invalid")));
        // GitHub トークンはここで役目を終える(保存しない。§3 / §10)
        const identities = yield* IdentityRepo;
        const resolved = yield* identities.getOrCreateUser(identity, Date.now());
        const sessions = yield* SessionService;
        const issued = yield* sessions.issueSession(resolved.userId, "github_oauth");
        const response = HttpServerResponse.redirect(`${origin}/`, { status: 302 });
        const withSession = yield* HttpServerResponse.setCookie(
          response,
          SESSION_COOKIE,
          issued.rawValue,
          { ...HOST_COOKIE_OPTIONS, maxAge: "30 days" },
        ).pipe(Effect.orDie);
        return yield* HttpServerResponse.expireCookie(
          withSession,
          STATE_COOKIE,
          HOST_COOKIE_OPTIONS,
        ).pipe(Effect.orDie);
      }),
    )
    .handle("deviceExchange", ({ payload }) =>
      Effect.gen(function* () {
        const github = yield* GitHubApi;
        // §4-4: 持ち込みトークンは check-token API で「自 OAuth App 発行」まで検証する
        // (他 App 向けに発行されたトークンの流用 = confused-deputy を遮断)
        const identity = yield* github
          .verifyAppToken(payload.githubAccessToken)
          .pipe(Effect.mapError(authFlowFailure("github-token-invalid")));
        const identities = yield* IdentityRepo;
        const resolved = yield* identities.getOrCreateUser(identity, Date.now());
        const tokens = yield* TokenService;
        const issued = yield* tokens
          .issueToken(
            resolved.userId,
            payload.tokenName ?? "device-flow",
            payload.scopes ?? DEFAULT_TOKEN_SCOPES,
          )
          .pipe(
            Effect.catchTag("TokenLimitReached", (error) =>
              Effect.fail(new TokenLimitError({ limit: error.limit })),
            ),
          );
        return { token: issued.rawToken, tokenId: issued.tokenId, userId: resolved.userId };
      }),
    )
    .handle("me", () =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        const identities = yield* IdentityRepo;
        const orgs = yield* identities.listUserOrgs(principal.userId);
        return { userId: principal.userId, orgs };
      }),
    )
    .handle("logout", ({ request }) =>
      Effect.gen(function* () {
        // AuthMiddleware 通過済み(401 / CSRF 403 はミドルウェアが担う)
        const principal = yield* (yield* RequestAuth).principal;
        const response = HttpServerResponse.empty({ status: 204 });
        if (principal.kind !== "session") {
          // ログアウトはセッション主体の操作。トークン主体は no-op とし、同送された
          // ブラウザのセッションクッキーに触れない(Bearer 認証のリクエストが
          // 無関係な Web セッションを破壊しないため)
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
    .handle("revokeToken", ({ request }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        const rawToken = parseBearerToken(request.headers["authorization"] ?? "");
        // 失効対象は「提示されたトークン自身」のみ(v1 線引き)。セッション経由は対象外
        if (principal.kind !== "token" || rawToken === null) {
          return yield* Effect.fail(new ForbiddenError({ reason: "insufficient-permission" }));
        }
        const tokens = yield* TokenService;
        yield* tokens.revokePresentedToken(rawToken);
        return HttpServerResponse.empty({ status: 204 });
      }),
    )
    .handle("recoveryPut", ({ payload }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const recovery = yield* RecoveryRepo;
        // 登録と再発行は同じ置換 upsert(§13-1)。旧ラップ行はここで消える。
        // 監査(auth.recovery_code_reissued)は D1 側監査基盤の導入と同時(§13-5)
        yield* recovery.upsert(
          principal.userId,
          {
            suite: payload.suite,
            nonceHex: payload.nonceHex,
            ciphertextHex: payload.ciphertextHex,
          },
          Date.now(),
        );
        return HttpServerResponse.empty({ status: 204 });
      }),
    )
    .handle("recoveryGet", () =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const recovery = yield* RecoveryRepo;
        // レート制限(§13-3)は存在判定より先に計数しない: 未登録(404)は
        // 計数対象外で、行がなければ recordFetch は常に allowed を返す
        const wrap = yield* recovery.find(principal.userId);
        if (wrap === null) {
          return yield* Effect.fail(new RecoveryWrapNotFoundError());
        }
        const decision = yield* recovery.recordFetch(principal.userId, Date.now());
        if (!decision.allowed) {
          return yield* Effect.fail(
            new RecoveryRateLimitedError({ retryAfterSeconds: decision.retryAfterSeconds }),
          );
        }
        if (wrap.suite !== "maruhi/v1") {
          // PUT は Literal でピン留めされており(§13-4)、v1 の書き込み経路では
          // 他スイートの行は生まれない。存在したら将来バージョンの書き込みか
          // DB 破損であり、黙って v1 として配布しない(実装バグとして扱う)
          return yield* Effect.die(new Error("stored recovery wrap has an unknown suite"));
        }
        // 監査(auth.recovery_blob_fetched)は D1 側監査基盤の導入と同時(§13-5)
        return {
          suite: "maruhi/v1" as const,
          nonceHex: wrap.nonceHex,
          ciphertextHex: wrap.ciphertextHex,
          updatedAtMs: wrap.updatedAtMs,
        };
      }),
    )
    .handle("recoveryStatus", () =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        const recovery = yield* RecoveryRepo;
        const wrap = yield* recovery.find(principal.userId);
        return wrap === null
          ? { registered: false, updatedAtMs: null }
          : { registered: true, updatedAtMs: wrap.updatedAtMs };
      }),
    ),
);
