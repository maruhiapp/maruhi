// 認証ハンドラ間の共有ヘルパ(handlers-auth.ts / handlers-auth-cli.ts)。
//
// Web ログイン(AUTH_SPEC §3)と CLI ログインのブラウザ脚(§4-1 (3)〜(4))は
// GitHub OAuth の 1〜2 段(authorize リダイレクト・state 検証・code 交換)を
// 共有する。循環 import(handlers-auth ⇄ handlers-auth-cli)を作らないため、
// 両者が使う部品をこのモジュールに置く。

import { AuthFlowError, SetupIncompleteError } from "@maruhi/api-schema";
import { Effect } from "effect";
import type { Cookies, HttpServerRequest } from "effect/unstable/http";

import { D1AuditRepo } from "./db.package/index.ts";

export const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
export const OAUTH_SCOPE = "read:user user:email";

/** Web ログインの state クッキー(§3-2)。 */
export const STATE_COOKIE = "__Host-maruhi_oauth_state";

/**
 * CLI ブラウザ脚専用の state + フロー束縛クッキー(§4-1 (3))。Web ログインの
 * STATE_COOKIE とは意図的に別名: 古い CLI フローのクッキーが通常の Web ログインを
 * 壊さず、その逆もない。値は「state + vsig 済みパラメータ一式」のクエリ文字列
 * (callback で vsig を再検証するため、クッキー自体は改竄防御を持たなくてよい)。
 */
export const CLI_STATE_COOKIE = "__Host-maruhi_oauth_cli";

/** GitHub の state パラメータの CLI フロー識別プレフィックス(§4-1 (3))。 */
export const CLI_STATE_PREFIX = "cli.";

/** `__Host-` クッキーの共通属性(§5)。 */
export const HOST_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  path: "/",
} as const satisfies Cookies.Cookie["options"];

export function requestOrigin(request: HttpServerRequest.HttpServerRequest): string {
  // effect の HttpServerRequest.url はパスのみ。絶対 URL は生の Web Request が持つ。
  // Host ヘッダー(攻撃者が偽装可能)を redirect_uri の組み立てに使わない —
  // workerd の入口は常に Web Request なので、そうでないのは配線バグ(defect)
  const source: unknown = request.source;
  if (source instanceof Request) {
    return new URL(source.url).origin;
  }
  throw new Error("request origin unavailable: source is not a web Request");
}

export function callbackUri(origin: string): string {
  return `${origin}/auth/github/callback`;
}

/** GitHub authorize URL の組み立て(§3-2。web / CLI ブラウザ脚で共通)。 */
export function githubAuthorizeUrl(clientId: string, origin: string, state: string): URL {
  const authorize = new URL(GITHUB_AUTHORIZE_URL);
  authorize.searchParams.set("client_id", clientId);
  authorize.searchParams.set("redirect_uri", callbackUri(origin));
  authorize.searchParams.set("scope", OAUTH_SCOPE);
  authorize.searchParams.set("state", state);
  return authorize;
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

export function ensureGitHubOAuthConfigured(
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

/** GitHub の認証ダンス失敗を API の型付きエラーへ写す(web ログイン用)。 */
export function authFlowFailure(
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
