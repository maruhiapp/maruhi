// miniflare の outboundService に差すフェイク GitHub(Node 側で実行される)。
//
// worker からのアウトバウンド fetch(実 GitHub 宛)をここで横取りする。
// 本番コード(src/)にはスタブ分岐が存在せず、テストは実装の実経路を通る。
// 実ネットワークへは一切出ない(想定外の宛先は 500 で落として検知する)。
//
// 決定論的な対応: code-<n> → gh-token-<n> → GitHub user { id: n, login: user<n> }。

interface OutboundRequest {
  readonly url: string;
  readonly headers: { get(name: string): string | null };
  json(): Promise<unknown>;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function exchangeCode(body: { code?: string }): Response {
  const match = /^code-(\d+)$/.exec(body.code ?? "");
  // GitHub は不正 code でも 200 + error ボディを返す(実挙動に合わせる)
  return match === null
    ? json({ error: "bad_verification_code" })
    : json({ access_token: `gh-token-${match[1]}` });
}

function githubUserId(request: OutboundRequest): number | null {
  const match = /^Bearer gh-token-(\d+)$/.exec(request.headers.get("authorization") ?? "");
  return match === null ? null : Number(match[1]);
}

async function handleOAuth(request: OutboundRequest, url: URL): Promise<Response | null> {
  if (url.hostname !== "github.com" || url.pathname !== "/login/oauth/access_token") {
    return null;
  }
  return exchangeCode((await request.json()) as { code?: string });
}

function apiResponse(url: URL, userId: number): Response | null {
  if (url.pathname === "/user") {
    return json({ id: userId, login: `user${userId}` });
  }
  if (url.pathname === "/user/emails") {
    return json([{ email: `user${userId}@example.com`, primary: true, verified: true }]);
  }
  return null;
}

function handleApi(request: OutboundRequest, url: URL): Response | null {
  if (url.hostname !== "api.github.com") {
    return null;
  }
  const userId = githubUserId(request);
  return userId === null ? json({ message: "Bad credentials" }, 401) : apiResponse(url, userId);
}

export async function fakeGitHub(request: OutboundRequest): Promise<Response> {
  const url = new URL(request.url);
  const handled = (await handleOAuth(request, url)) ?? handleApi(request, url);
  return (
    handled ?? new Response(`unexpected outbound request in tests: ${request.url}`, { status: 500 })
  );
}
