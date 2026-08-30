// 認証エンドポイントのハンドラ(AUTH_SPEC §3 / §4 / §5 / §6)。
//
// - GitHub アクセストークンはこのファイルのハンドラのローカル変数にのみ存在し、
//   レスポンス・ログ・ストレージへ出ない(§10: GitHub トークンの永続化禁止)
// - `__Host-` クッキーは Secure / Path=/ が必須(http の wrangler dev ではブラウザに
//   保存されない点に注意 — テストはヘッダー検証で行う)

import {
  AuthFlowError,
  AuthRateLimitedError,
  DEFAULT_TOKEN_TTL_DAYS,
  ForbiddenError,
  maruhiApi,
  RecoveryRateLimitedError,
  RecoveryWrapNotFoundError,
  SetupIncompleteError,
  TokenLimitError,
  TokenNotFoundError,
} from "@maruhi/api-schema";
import type { TokenScope } from "@maruhi/core";
import { auditActorOf, RequestAuth, SessionService, TokenService } from "@maruhi/core";
import { Effect } from "effect";
import type { Cookies } from "effect/unstable/http";
import { HttpServerRequest, HttpServerResponse } from "effect/unstable/http";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import {
  GitHubApi,
  parseBearerToken,
  SESSION_COOKIE,
  statefulGetCsrfViolated,
} from "./auth.package/index.ts";
import { ensureKeyMaterialAccess, ensureTokenManagementAccess } from "./authz.ts";
import { D1AuditRepo, IdentityRepo, RecoveryRepo, TokenRepo } from "./db.package/index.ts";
import { constantTimeEqual, randomHex } from "./ids.ts";
import { ServerKey } from "./server-key.ts";
import { IP_RATE_LIMIT_PERIOD_SECONDS, ipRateLimitAllowed, WorkerEnv } from "./worker-env.ts";

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

/**
 * セルフホスト未設定の検出(AUTH_SPEC §3): client_id / client_secret の
 * どちらかが未登録(`wrangler secret put` 漏れ)・空(Env 型は string だが、
 * secret を欠いたデプロイでは実行時に undefined になり得る)。素通しすると
 * GitHub のエラーページや不透明なトークン交換失敗(AuthFlow 400)に落ちて
 * 原因に辿り着けないため、503 でセットアップガイド(docs/SELF_HOSTING.md)へ
 * 誘導する。プレースホルダ検出は旧テンプレート(client_id を wrangler vars で
 * 配布していた時期)のフォークが値未置換のまま立てた場合への後方互換の防御。
 */
const CLIENT_ID_PLACEHOLDER = "replace-with-your-github-oauth-app-client-id";

function ensureGitHubOAuthConfigured(
  clientId: string | undefined,
  clientSecret: string | undefined,
): Effect.Effect<void, SetupIncompleteError> {
  const clientIdMissing =
    clientId === undefined || clientId === "" || clientId === CLIENT_ID_PLACEHOLDER;
  const clientSecretMissing = clientSecret === undefined || clientSecret === "";
  return clientIdMissing || clientSecretMissing
    ? Effect.fail(new SetupIncompleteError({ reason: "github-oauth-unconfigured" }))
    : Effect.void;
}

/** GitHub の認証ダンス失敗を API の型付きエラーへ写す。 */
function authFlowFailure(
  reason: "state-mismatch" | "code-exchange-failed" | "github-token-invalid",
): () => AuthFlowError {
  return () => new AuthFlowError({ reason });
}

/**
 * auth.login_failed の記録(AUDIT_SPEC §3.1)。actor は user_id なしの user =
 * 未認証の外部主体。理由種別のみ記録し、提示された外部 ID・コード・トークンは
 * 記録しない(同 §3.1 の禁止)。未認証経路からの書き込み増幅を有界にするため
 * 固定窓上限つきの専用追記を使う(db.package/audit.ts)。
 *
 * 上限は authMethod + reason をバケットとして数える(deepsec R4/S5):
 * 片方の経路・理由への匿名洪水が、別理由の失敗まで黙って消さないようにする。
 */
function recordLoginFailed(
  authMethod: "github_oauth" | "device_flow",
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

export const authLive = HttpApiBuilder.group(maruhiApi, "auth", (handlers) =>
  handlers
    .handle("authConfig", () =>
      Effect.gen(function* () {
        const env = yield* WorkerEnv;
        // 公開設定(AUTH_SPEC §4): client_id は authorize URL に平文で現れる
        // 公開情報のみ。client_secret 等をこの応答に足さないこと(検査条件には
        // 含む — 200 が「client_id / secret とも登録済み」の確認として機能する)
        yield* ensureGitHubOAuthConfigured(env.GITHUB_CLIENT_ID, env.GITHUB_CLIENT_SECRET);
        // デプロイメント keypair(CRYPTO_SPEC §9)が設定済みなら公開面を加える
        // (AUTH_SPEC §4 — serverKeyFingerprintHex は grant_server 実行時の照合
        // 対象。serverEncPubHex は §9 の「サーバーが配布する enc 公開鍵」の
        // 配布チャネルで、どちらも公開情報)。未設定なら両フィールドを省略する
        const serverKey = yield* ServerKey;
        const serverKeyInfo = yield* serverKey.info;
        return {
          githubClientId: env.GITHUB_CLIENT_ID,
          ...(serverKeyInfo === null
            ? {}
            : {
                serverKeyFingerprintHex: serverKeyInfo.serverKeyFingerprintHex,
                serverEncPubHex: serverKeyInfo.serverEncPubHex,
              }),
        };
      }),
    )
    .handle("githubStart", ({ request }) =>
      Effect.gen(function* () {
        const env = yield* WorkerEnv;
        yield* ensureGitHubOAuthConfigured(env.GITHUB_CLIENT_ID, env.GITHUB_CLIENT_SECRET);
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
        const env = yield* WorkerEnv;
        // 発信元 IP のレート制限をハンドラ最初に置く(deepsec R7): callback は
        // 未認証で到達でき、1 回ごとに GitHub token endpoint への交換を起こす。
        // その枠は device exchange と**同じ** OAuth App 単位の共有クォータで、
        // 枯渇すると全ユーザーのログインが止まる。
        //
        // state 検査は throttle にならない: cookie と query の二重送信のみで
        // サーバー側に状態を持たないため、非ブラウザの発信元は両方を自分で
        // 用意でき(githubStart を経由する必要さえない)、検査は常に通る。
        // 状態不一致の記録(recordLoginFailed)もこの判定より後に置き、未認証
        // 経路からの監査書き込み増幅ごと有界にする
        const allowed = yield* ipRateLimitAllowed(env.OAUTH_CALLBACK_RATE_LIMIT, request);
        if (!allowed) {
          return yield* Effect.fail(
            new AuthRateLimitedError({ retryAfterSeconds: IP_RATE_LIMIT_PERIOD_SECONDS }),
          );
        }
        const expectedState = request.cookies[STATE_COOKIE];
        // §3-2: state 検証(不一致は即拒否)
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
    .handle("deviceExchange", ({ payload, request }) =>
      Effect.gen(function* () {
        const env = yield* WorkerEnv;
        // 発信元 IP のレート制限をハンドラ最初に置く(deepsec M3/B11): 交換
        // 1 回ごとの GitHub check-token 呼び出しは OAuth App 単位の共有クォータを
        // 消費し、枯渇すると**全ユーザー**の CLI login が止まる。ワイヤ Schema の
        // 形式事前検査(トークン形式・サイズ上限)は HttpApi がハンドラより先に
        // 走るため、形式不正の洪水はこの窓を消費せずに 400 で落ち、ここへ届く
        // 形式適合のリクエストだけが計数される。判定はアウトバウンドより手前
        // (制限時はそもそも仕事をしない)
        const allowed = yield* ipRateLimitAllowed(env.DEVICE_EXCHANGE_RATE_LIMIT, request);
        if (!allowed) {
          return yield* Effect.fail(
            new AuthRateLimitedError({ retryAfterSeconds: IP_RATE_LIMIT_PERIOD_SECONDS }),
          );
        }
        // 未設定サーバーは不透明なトークン交換失敗(GitHub 401 → AuthFlow 400)
        // より先に fail-closed する(AUTH_SPEC §3)
        yield* ensureGitHubOAuthConfigured(env.GITHUB_CLIENT_ID, env.GITHUB_CLIENT_SECRET);
        const github = yield* GitHubApi;
        // §4-4: 持ち込みトークンは check-token API で「自 OAuth App 発行」まで検証する
        // (他 App 向けに発行されたトークンの流用 = confused-deputy を遮断)
        const identity = yield* github.verifyAppToken(payload.githubAccessToken).pipe(
          Effect.mapError(authFlowFailure("github-token-invalid")),
          Effect.tapError(() => recordLoginFailed("device_flow", "github-token-invalid")),
        );
        const identities = yield* IdentityRepo;
        const resolved = yield* identities.getOrCreateUser(identity, Date.now());
        // device flow 完了 = ログイン成功(AUDIT_SPEC §3.1)。セッションは作らない
        // ため、Web と違いセッション挿入に相乗りせずここで記録する。後続の
        // トークン発行が上限で失敗しても GitHub 検証は成功している
        const audit = yield* D1AuditRepo;
        yield* audit.appendUserEvent(
          {
            event: "auth.login_succeeded",
            actor: { userId: resolved.userId, authMethod: "device_flow" },
          },
          Date.now(),
        );
        const tokens = yield* TokenService;
        // TTL は発行時に固定(AUTH_SPEC §6 — W3a)。明示指定(expiresInDays —
        // 上限はワイヤ Schema の 1..365)はリース非対応実行環境の無人 PAT 用の
        // 逃し弁(裁定 CF)。省略時は既定 90 日
        const ttlMs = (payload.expiresInDays ?? DEFAULT_TOKEN_TTL_DAYS) * 24 * 60 * 60 * 1000;
        const issued = yield* tokens
          .issueToken(
            resolved.userId,
            payload.tokenName ?? "device-flow",
            payload.scopes ?? DEFAULT_TOKEN_SCOPES,
            ttlMs,
          )
          .pipe(
            Effect.catchTag("TokenLimitReached", (error) =>
              Effect.fail(new TokenLimitError({ limit: error.limit })),
            ),
          );
        return {
          token: issued.rawToken,
          tokenId: issued.tokenId,
          userId: resolved.userId,
          expiresAtMs: issued.expiresAtMs,
        };
      }),
    )
    .handle("me", () =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        const identities = yield* IdentityRepo;
        const orgs = yield* identities.listUserOrgs(principal.userId);
        // トークン主体には提示トークンのスコープを返す(AUTH_SPEC §16-2 —
        // クライアントが実効権限 min(スコープ, チェーン role) を事前判定する
        // 材料。自分が提示した資格情報の属性であり新しい情報を開示しない)。
        // セッション主体は欠落 = スコープなし(呼べる面は §5 の能力制限の
        // 許可列挙に限られる — W2b)
        return {
          userId: principal.userId,
          orgs,
          ...(principal.kind === "token" ? { tokenScopes: principal.scopes } : {}),
        };
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
    .handle("listTokens", () =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        // トークン主体は `*` × admin のみ(裁定 CH)。セッション主体は §5 の
        // 許可列挙を通過済み。403 は呼び出し資格のみから計算される(対象情報なし)
        yield* ensureTokenManagementAccess(principal);
        const tokens = yield* TokenRepo;
        // 応答は本人の行のみ(userId はサーバー導出 — ワイヤに対象指定がなく、
        // 他人のトークンを探れる面が構造的に存在しない)。監査イベントは
        // 記録しない(値・鍵に触れない自己情報の読み取り — §11-5 と同じ規律)
        const summaries = yield* tokens.listForUser(principal.userId);
        return { tokens: summaries };
      }),
    )
    .handle("revokeTokenById", ({ params }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        // 判定順(裁定 CG): 401(ミドルウェア)→ 403(主体条件 — 呼び出し資格
        // のみから計算)→ 一様 404(本人所有でない・存在しない id を区別しない)。
        // セッション主体の CSRF はミドルウェアが担う(DELETE は書き込み系)
        yield* ensureTokenManagementAccess(principal);
        const tokens = yield* TokenRepo;
        // 所有条件(id × userId)は repo 境界が強制する(deepsec S8)。
        // auth.token_revoked は削除の成立と同時に記録され、actor = 実行主体
        // (セッション / 別トークン)、payload.tokenId = 失効対象(AUDIT_SPEC §3.1)
        const revoked = yield* tokens.revokeById(
          params.tokenId,
          principal.userId,
          Date.now(),
          auditActorOf(principal),
        );
        if (!revoked) {
          return yield* Effect.fail(new TokenNotFoundError());
        }
        return HttpServerResponse.empty({ status: 204 });
      }),
    )
    .handle("recoveryPut", ({ payload }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const recovery = yield* RecoveryRepo;
        // 登録と再発行は同じ置換 upsert(§13-1)。旧ラップ行はここで消える。
        // 監査(auth.recovery_code_reissued)は upsert が同一 batch で記録する(§13-5)
        yield* recovery.upsert(
          principal.userId,
          {
            suite: payload.suite,
            nonceHex: payload.nonceHex,
            ciphertextHex: payload.ciphertextHex,
          },
          Date.now(),
          auditActorOf(principal),
        );
        return HttpServerResponse.empty({ status: 204 });
      }),
    )
    .handle("recoveryGet", ({ request }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        // GET だが取得計数という状態を持つ(§13-2 の明示規定。計数は §13-3)—
        // 第三者サイトからの窓消費 = 可用性いやがらせの遮断(論拠は
        // statefulGetCsrfViolated の JSDoc)
        if (statefulGetCsrfViolated(principal, request.headers)) {
          return yield* Effect.fail(new ForbiddenError({ reason: "csrf-header-required" }));
        }
        const recovery = yield* RecoveryRepo;
        // レート制限(§13-3)は存在判定より先に計数しない: 未登録(404)は
        // 計数対象外で、行がなければ recordFetch は常に allowed を返す
        const wrap = yield* recovery.find(principal.userId);
        if (wrap === null) {
          return yield* Effect.fail(new RecoveryWrapNotFoundError());
        }
        if (wrap.suite !== "maruhi/v1") {
          // PUT は Literal でピン留めされており(§13-4)、v1 の書き込み経路では
          // 他スイートの行は生まれない。存在したら将来バージョンの書き込みか
          // DB 破損であり、黙って v1 として配布しない(実装バグとして扱う)。
          // 計数(recordFetch)より先に判定し、配布できないリクエストで
          // クォータを消費しない(§13-3 の計数対象はブロブ配布のみ)
          return yield* Effect.die(new Error("stored recovery wrap has an unknown suite"));
        }
        // 監査(auth.recovery_blob_fetched)は recordFetch が計数と同一 batch で
        // 記録する(§13-5。拒否 = 配布なしは記録しない)
        const decision = yield* recovery.recordFetch(
          principal.userId,
          Date.now(),
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
