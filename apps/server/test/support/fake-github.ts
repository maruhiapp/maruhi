// miniflare の outboundService に差すフェイク GitHub(Node 側で実行される)。
//
// worker からのアウトバウンド fetch(実 GitHub 宛)をここで横取りする。
// 本番コード(src/)にはスタブ分岐が存在せず、テストは実装の実経路を通る。
// 実ネットワークへは一切出ない(想定外の宛先は 500 で落として検知する)。
//
// 実 GitHub の挙動への忠実性(実装の退行をフェイクが隠さないため):
// - api.github.com は User-Agent 必須(なければ 403)
// - トークン交換は Accept: application/json がないとフォームエンコード文字列を返す
// - check-token(POST /applications/{client_id}/token)は Basic 認証 + 自 App 発行
//   トークンのみ 200(それ以外 404)
//
// 決定論的な対応: code-<n> → gh-token-<n> → GitHub user { id: n, login: user<n> }。
// メール応答は ID 帯で分岐(§3-3 の verified/primary フィルタを判別可能にする):
//   通常        → [{ primary: true, verified: true }]
//   666         → verified: false のみ
//   667         → primary: false のみ
//   668         → /user/emails が 404(user:email スコープなし相当)
// 自 App 外トークン: gh-token-other-app-<n>(/user では有効、check-token では 404)。
//
// GitHub Actions の OIDC issuer(AUTH_SPEC §14-1 のリース経路)も同じ
// outboundService が受ける — discovery / JWKS は support/oidc-issuer.ts。

import { fakeOidcIssuer } from "./oidc-issuer.ts";

interface OutboundRequest {
  readonly url: string;
  readonly headers: { get(name: string): string | null };
  json(): Promise<unknown>;
  text(): Promise<string>;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** 実 GitHub: Accept が JSON でなければフォームエンコード文字列を返す。 */
function formEncodedFallback(request: OutboundRequest): Response | null {
  if ((request.headers.get("accept") ?? "").includes("application/json")) {
    return null;
  }
  return new Response("access_token=gh-token-0&token_type=bearer", {
    headers: { "content-type": "application/x-www-form-urlencoded" },
  });
}

/** RFC 6749 §4.1.3: ボディは form-urlencoded(JSON を送る実装退行はここで割れる)。 */
function wrongContentType(request: OutboundRequest): Response | null {
  const contentType = request.headers.get("content-type") ?? "";
  return contentType.includes("application/x-www-form-urlencoded")
    ? null
    : json({ error: "unsupported_content_type" }, 400);
}

function exchangeCodeResponse(params: URLSearchParams): Response {
  const match = /^code-(\d+)$/.exec(params.get("code") ?? "");
  // GitHub は不正 code でも 200 + error ボディを返す(実挙動に合わせる)
  return match === null
    ? json({ error: "bad_verification_code" })
    : json({ access_token: `gh-token-${match[1]}` });
}

async function exchangeCode(request: OutboundRequest): Promise<Response> {
  const rejected = formEncodedFallback(request) ?? wrongContentType(request);
  if (rejected !== null) {
    return rejected;
  }
  return exchangeCodeResponse(new URLSearchParams(await request.text()));
}

/** Bearer トークンから GitHub ユーザー ID を引く(other-app トークンも /user では有効)。 */
function githubUserId(request: OutboundRequest): number | null {
  const auth = request.headers.get("authorization") ?? "";
  const match = /^Bearer gh-token-(?:other-app-)?(\d+)$/.exec(auth);
  return match === null ? null : Number(match[1]);
}

function emailEntries(userId: number): { body: unknown; status: number } {
  if (userId === 666) {
    return {
      body: [{ email: `user${userId}@example.com`, primary: true, verified: false }],
      status: 200,
    };
  }
  if (userId === 667) {
    return {
      body: [{ email: `user${userId}@example.com`, primary: false, verified: true }],
      status: 200,
    };
  }
  if (userId === 668) {
    return { body: { message: "Not Found" }, status: 404 };
  }
  return {
    body: [{ email: `user${userId}@example.com`, primary: true, verified: true }],
    status: 200,
  };
}

/**
 * Basic 認証を検証する: パスの {client_id} と Basic 側の client_id が一致し、
 * secret が非空であること(実装の配線 = 「自分の client_id/secret で照会している」を
 * 検査する。env の実値には依存しない — テストの注入元は vitest.config.ts の
 * miniflare bindings、wrangler dev は .dev.vars と環境で異なるため、値そのものを
 * 固定すると環境で割れる)。
 */
function decodeBasicPair(auth: string): readonly [string, string] | null {
  if (!auth.startsWith("Basic ")) {
    return null;
  }
  const decoded = atob(auth.slice("Basic ".length));
  const separator = decoded.indexOf(":");
  return separator <= 0 ? null : [decoded.slice(0, separator), decoded.slice(separator + 1)];
}

function basicAuthMatches(request: OutboundRequest, clientIdFromPath: string): boolean {
  const pair = decodeBasicPair(request.headers.get("authorization") ?? "");
  return pair !== null && pair[0] === clientIdFromPath && pair[1] !== "";
}

/** §4-4 の audience 検証: 自 App 発行(other-app でない)トークンのみ 200 + user を返す。 */
function checkAppToken(
  request: OutboundRequest,
  clientIdFromPath: string,
  body: { access_token?: string },
): Response {
  if (!basicAuthMatches(request, clientIdFromPath)) {
    return json({ message: "Bad credentials" }, 401);
  }
  const match = /^gh-token-(\d+)$/.exec(body.access_token ?? "");
  if (match === null) {
    // 他 App 発行・不正トークンはいずれも 404(実 GitHub の挙動)
    return json({ message: "Not Found" }, 404);
  }
  const id = Number(match[1]);
  return json({ user: { id, login: `user${id}` } });
}

async function handleOAuth(request: OutboundRequest, url: URL): Promise<Response | null> {
  if (url.hostname !== "github.com" || url.pathname !== "/login/oauth/access_token") {
    return null;
  }
  return exchangeCode(request);
}

function apiResponse(url: URL, userId: number): Response | null {
  if (url.pathname === "/user") {
    return json({ id: userId, login: `user${userId}` });
  }
  if (url.pathname === "/user/emails") {
    const { body, status } = emailEntries(userId);
    return json(body, status);
  }
  return null;
}

function bearerApiResponse(request: OutboundRequest, url: URL): Response {
  const userId = githubUserId(request);
  if (userId === null) {
    return json({ message: "Bad credentials" }, 401);
  }
  return (
    apiResponse(url, userId) ??
    new Response(`unexpected api.github.com path in tests: ${url.pathname}`, { status: 500 })
  );
}

/** 実 GitHub: api.github.com は User-Agent 必須。 */
function missingUserAgent(request: OutboundRequest): Response | null {
  if ((request.headers.get("user-agent") ?? "") !== "") {
    return null;
  }
  return json({ message: "Request forbidden: missing User-Agent" }, 403);
}

async function routeCheckToken(request: OutboundRequest, url: URL): Promise<Response | null> {
  const match = /^\/applications\/([^/]+)\/token$/.exec(url.pathname);
  if (match?.[1] === undefined) {
    return null;
  }
  return checkAppToken(
    request,
    decodeURIComponent(match[1]),
    (await request.json()) as { access_token?: string },
  );
}

async function handleApi(request: OutboundRequest, url: URL): Promise<Response | null> {
  if (url.hostname !== "api.github.com") {
    return null;
  }
  const forbidden = missingUserAgent(request);
  if (forbidden !== null) {
    return forbidden;
  }
  return (await routeCheckToken(request, url)) ?? bearerApiResponse(request, url);
}

export async function fakeGitHub(request: OutboundRequest): Promise<Response> {
  const url = new URL(request.url);
  const handled =
    (await handleOAuth(request, url)) ?? (await handleApi(request, url)) ?? fakeOidcIssuer(url);
  return (
    handled ?? new Response(`unexpected outbound request in tests: ${request.url}`, { status: 500 })
  );
}
