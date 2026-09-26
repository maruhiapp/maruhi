// Fake GitHub plugged into miniflare's outboundService (runs on the Node side).
//
// It intercepts outbound fetches from the worker (destined for real GitHub).
// Production code (src/) has no stub branch — tests go through the
// implementation's real path. Nothing ever reaches the real network
// (unexpected destinations are killed with a 500 so they are detected).
//
// Fidelity to real GitHub behavior (so the fake does not hide implementation
// regressions):
// - api.github.com requires a User-Agent (403 without one)
// - The token exchange returns a form-encoded string unless
//   Accept: application/json is present
// - check-token (POST /applications/{client_id}/token) requires Basic auth +
//   only tokens issued by the same App return 200 (everything else 404)
//
// Deterministic correspondence: code-<n> → gho_test<n> → GitHub user
// { id: n, login: user<n> } (same `gho_` prefix shape as real GitHub OAuth
// tokens).
// Email responses branch by ID band (to make the §3-3 verified/primary
// filter distinguishable):
//   normal      → [{ primary: true, verified: true }]
//   666         → verified: false only
//   667         → primary: false only
//   668         → /user/emails returns 404 (equivalent to no user:email scope)
// Non-own-App tokens: gho_otherapp<n> (valid on /user, 404 on check-token).
//
// The GitHub Actions OIDC issuer (the lease path of AUTH_SPEC §14-1) is also
// served by the same outboundService — discovery / JWKS is support/oidc-issuer.ts.

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

/** Real GitHub: unless Accept is JSON it returns a form-encoded string. */
function formEncodedFallback(request: OutboundRequest): Response | null {
  if ((request.headers.get("accept") ?? "").includes("application/json")) {
    return null;
  }
  return new Response("access_token=gho_test0&token_type=bearer", {
    headers: { "content-type": "application/x-www-form-urlencoded" },
  });
}

/** RFC 6749 §4.1.3: the body is form-urlencoded (an implementation regression that sends JSON breaks here). */
function wrongContentType(request: OutboundRequest): Response | null {
  const contentType = request.headers.get("content-type") ?? "";
  return contentType.includes("application/x-www-form-urlencoded")
    ? null
    : json({ error: "unsupported_content_type" }, 400);
}

function exchangeCodeResponse(params: URLSearchParams): Response {
  const match = /^code-(\d+)$/.exec(params.get("code") ?? "");
  // GitHub returns 200 + an error body even for an invalid code (match the real behavior)
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

/** Pull the GitHub user ID from the Bearer token (other-app tokens are also valid on /user). */
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

/**
 * Verify Basic auth: the path's {client_id} must match the Basic-side
 * client_id and the secret must be non-empty (checking the implementation's
 * wiring = "it queried with its own client_id/secret". It does not depend on
 * the env's actual values — the injection source for tests is the miniflare
 * bindings in vitest.config.ts, and wrangler dev differs per environment via
 * .dev.vars, so pinning the values themselves would break per environment).
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

/** The §4-4 audience check: only tokens issued by the same App (not other-app) get 200 + user. */
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
    // Other-App-issued and invalid tokens alike get 404 (real GitHub behavior)
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

/** Real GitHub: api.github.com requires a User-Agent. */
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

/**
 * The ops-infrastructure tripwire notification webhook (OPS_ALERT_WEBHOOK_URL
 * in vitest.config.ts). The receiver just returns 204 (the body is checked
 * via the OpsNotifier substitution — ops-alerts.test.ts).
 */
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
