// 認証エンドポイントのハンドラ(AUTH_SPEC §3 / §4 / §5 / §6)。
//
// - GitHub アクセストークンはこのファイルのハンドラのローカル変数にのみ存在し、
//   レスポンス・ログ・ストレージへ出ない(§10: GitHub トークンの永続化禁止)
// - `__Host-` クッキーは Secure / Path=/ が必須(http の wrangler dev ではブラウザに
//   保存されない点に注意 — テストはヘッダー検証で行う)

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
import { Effect } from "effect";
import { HttpServerResponse } from "effect/unstable/http";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import {
  authFlowFailure,
  callbackUri,
  ensureGitHubOAuthConfigured,
  githubAuthorizeUrl,
  HOST_COOKIE_OPTIONS,
  recordLoginFailed,
  requestOrigin,
  STATE_COOKIE,
} from "./auth-shared.ts";
import {
  GitHubApi,
  parseBearerToken,
  SESSION_COOKIE,
  statefulGetCsrfViolated,
} from "./auth.package/index.ts";
import { ensureKeyMaterialAccess, ensureTokenManagementAccess } from "./authz.ts";
import { IdentityRepo, RecoveryRepo, TokenRepo } from "./db.package/index.ts";
import { handleCliCallback, isCliCallbackState } from "./handlers-auth-cli.ts";
import { constantTimeEqual, randomHex } from "./ids.ts";
import { ServerKey } from "./server-key.ts";
import { IP_RATE_LIMIT_PERIOD_SECONDS, ipRateLimitAllowed, WorkerEnv } from "./worker-env.ts";

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
        const authorize = githubAuthorizeUrl(env.GITHUB_CLIENT_ID, origin, state);
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
        // CLI ログインのブラウザ脚(AUTH_SPEC §4-1 (3)〜(4)): GitHub の callback
        // URL は §3 の単一 URL のままで、state の `cli.` プレフィックスで分岐する。
        // CLI 分岐の全終端はブラウザ向け HTML(handlers-auth-cli.ts)であり、
        // セッションを発行しない(§4-1 (3) — 成果物は poll の PAT のみ)
        if (isCliCallbackState(query.state)) {
          return yield* handleCliCallback(request, query);
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
    .handle("me", () =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        const identities = yield* IdentityRepo;
        const orgs = yield* identities.listUserOrgs(principal.userId);
        // トークン主体には提示トークンのスコープと有効期限を返す(AUTH_SPEC
        // §16-2 / §6 — 裁定 CI。クライアントが実効権限 min(スコープ, チェーン
        // role) の事前判定・期限の自己観測を行う材料。どちらも自分が提示した
        // 資格情報の属性であり新しい情報を開示しない)。セッション主体は欠落 =
        // スコープなし(呼べる面は §5 の能力制限の許可列挙に限られる — W2b)
        return {
          userId: principal.userId,
          orgs,
          ...(principal.kind === "token"
            ? { tokenScopes: principal.scopes, tokenExpiresAtMs: principal.expiresAtMs }
            : {}),
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
