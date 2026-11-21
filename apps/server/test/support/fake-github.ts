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

function formEncodedFallback(request: OutboundRequest): Response | null {
  if ((request.headers.get("accept") ?? "").includes("application/json")) {
    return null;
  }
  return new Response("access_token=gho_test0&token_type=bearer", {
    headers: { "content-type": "application/x-www-form-urlencoded" },
  });
}

function wrongContentType(request: OutboundRequest): Response | null {
  const contentType = request.headers.get("content-type") ?? "";
  return contentType.includes("application/x-www-form-urlencoded")
    ? null
    : json({ error: "unsupported_content_type" }, 400);
}

function exchangeCodeResponse(params: URLSearchParams): Response {
  const match = /^code-(\d+)$/.exec(params.get("code") ?? "");
  return match === null
    ? json({ error: "bad_verification_code" })
    : json({ access_token: `gho_test${match[1]}` });
}

async function exchangeCode(request: OutboundRequest): Promise<Response> {
  const rejected = formEncodedFallback(request) ?? wrongContentType(request);
  if (rejected !== null) {
    return rejected;
  }
  return exchangeCodeResponse(new URLSearchParams(await request.text()));
}

function githubUserId(request: OutboundRequest): number | null {
  const auth = request.headers.get("authorization") ?? "";
  const match = /^Bearer gho_(?:test|otherapp)(\d+)$/.exec(auth);
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

function checkAppToken(
  request: OutboundRequest,
  clientIdFromPath: string,
  body: { access_token?: string },
): Response {
  if (!basicAuthMatches(request, clientIdFromPath)) {
    return json({ message: "Bad credentials" }, 401);
  }
  const match = /^gho_test(\d+)$/.exec(body.access_token ?? "");
  if (match === null) {
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

function fakeOpsWebhook(url: URL): Response | null {
  return url.hostname === "ops-webhook.test" ? new Response(null, { status: 204 }) : null;
}

async function routeOutbound(request: OutboundRequest, url: URL): Promise<Response | null> {
  return (
    fakeOpsWebhook(url) ??
    (await handleOAuth(request, url)) ??
    (await handleApi(request, url)) ??
    fakeOidcIssuer(url)
  );
}

export async function fakeGitHub(request: OutboundRequest): Promise<Response> {
  const url = new URL(request.url);
  return (
    (await routeOutbound(request, url)) ??
    new Response(`unexpected outbound request in tests: ${request.url}`, { status: 500 })
  );
}
