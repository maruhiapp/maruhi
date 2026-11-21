import { cryptoServicesLayer } from "@maruhi/core";
import { computeServerKeyFingerprint, decodeHex, encodeHex } from "@maruhi/crypto";
import { createExecutionContext, createScheduledController, env, SELF } from "cloudflare:test";
import { Effect } from "effect";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import {
  CLI_FLOW_TTL_MS,
  type CliVerifyParams,
  computeVsig,
  createFlowToken,
  importFlowSigningKey,
  verificationQuery,
} from "../src/auth.package/index.ts";
import {
  D1FailureError,
  D1UniqueConflictError,
  MAX_CONCURRENT_CLI_FLOWS,
  tryD1,
} from "../src/db.package/index.ts";
import worker from "../src/index.ts";
import {
  approvalTicketOf,
  approveCliFlow,
  BASE,
  bearer,
  CLI_STATE_COOKIE,
  cliBrowserLeg,
  cliIssue,
  type CliFlowStart,
  cliToken,
  CSRF_HEADERS,
  JSON_HEADERS,
  loginSession,
  pollCliFlow,
  readCookieValue,
  resetAuthDb,
  seedUser,
  SESSION_COOKIE,
  sessionHeaders,
  startCliFlow,
  STATE_COOKIE,
} from "./support/auth.ts";

beforeEach(async () => {
  await resetAuthDb();
});

describe("GET /auth/github/start(§3-1)", () => {
  it("redirects to GitHub with client_id, redirect_uri, scope and a state cookie", async () => {
    const response = await SELF.fetch(`${BASE}/auth/github/start`, { redirect: "manual" });
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location") ?? "");
    expect(location.origin).toBe("https://github.com");
    expect(location.pathname).toBe("/login/oauth/authorize");
    expect(location.searchParams.get("client_id")).toBe(env.GITHUB_CLIENT_ID);
    expect(location.searchParams.get("redirect_uri")).toBe(`${BASE}/auth/github/callback`);
    expect(location.searchParams.get("scope")).toBe("read:user user:email");
    const state = location.searchParams.get("state") ?? "";
    expect(state).toMatch(/^[0-9a-f]{32}$/);
    const cookie = response.headers.getSetCookie().find((c) => c.startsWith(`${STATE_COOKIE}=`));
    expect(cookie).toBeDefined();
    expect(cookie).toContain(`${STATE_COOKIE}=${state}`);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("Path=/");
    expect(cookie).toContain("SameSite=Lax");
  });
});

describe("GET /auth/github/callback (§3-2–§3-4)", () => {
  it("sets the session cookie with the full __Host- attribute set (§5)", async () => {
    const start = await SELF.fetch(`${BASE}/auth/github/start`, { redirect: "manual" });
    const state = new URL(start.headers.get("location") ?? "").searchParams.get("state") ?? "";
    const callback = await SELF.fetch(`${BASE}/auth/github/callback?code=code-100&state=${state}`, {
      headers: { cookie: `${STATE_COOKIE}=${state}` },
      redirect: "manual",
    });
    expect(callback.status).toBe(302);
    const setCookies = callback.headers.getSetCookie();
    expect(setCookies).toHaveLength(2);
    const cookie = setCookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
    expect(cookie).toBeDefined();
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("Path=/");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Max-Age=2592000");
    const stateCookie = setCookies.find((c) => c.startsWith(`${STATE_COOKIE}=`));
    expect(stateCookie).toBeDefined();
    expect(stateCookie).toContain("Max-Age=0");
  });

  it("creates the user + personal org and issues a DB-backed session", async () => {
    const session = await loginSession(101);
    expect(session).toMatch(/^[0-9a-f]{64}$/);

    const user = await env.DB.prepare(
      "SELECT u.id, u.email, u.email_verified FROM users u JOIN linked_identities li ON li.user_id = u.id WHERE li.provider = 'github' AND li.provider_user_id = '101'",
    ).first<{ id: string; email: string; email_verified: number }>();
    expect(user).not.toBeNull();
    expect(user?.email).toBe("user101@example.com");
    expect(user?.email_verified).toBe(1);
    const membership = await env.DB.prepare("SELECT role FROM memberships WHERE user_id = ?")
      .bind(user?.id)
      .first<{ role: string }>();
    expect(membership?.role).toBe("owner");

    const rawRow = await env.DB.prepare("SELECT id FROM sessions WHERE id = ?")
      .bind(session)
      .first();
    expect(rawRow).toBeNull();
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM sessions").first<{ n: number }>();
    expect(count?.n).toBe(1);
  });

  it("does not store an unverified email (§3-3)", async () => {
    await loginSession(666);
    const user = await env.DB.prepare("SELECT email, email_verified FROM users").first<{
      email: string | null;
      email_verified: number;
    }>();
    expect(user?.email).toBeNull();
    expect(user?.email_verified).toBe(0);
  });

  it("does not store a non-primary email (§3-3)", async () => {
    await loginSession(667);
    const user = await env.DB.prepare("SELECT email FROM users").first<{ email: string | null }>();
    expect(user?.email).toBeNull();
  });

  it("treats an email API failure as no email (id 668: /user/emails is 404)", async () => {
    await loginSession(668);
    const user = await env.DB.prepare("SELECT email FROM users").first<{ email: string | null }>();
    expect(user?.email).toBeNull();
  });

  it("self-heals a missing email on a later login (re-fetch at §1-5's idempotent entry)", async () => {
    await seedUser("user-heal-0001", 301);
    const session = await loginSession(301);
    expect(session).toMatch(/^[0-9a-f]{64}$/);
    const user = await env.DB.prepare("SELECT email, email_verified FROM users WHERE id = ?")
      .bind("user-heal-0001")
      .first<{ email: string | null; email_verified: number }>();
    expect(user?.email).toBe("user301@example.com");
    expect(user?.email_verified).toBe(1);
  });

  it("is idempotent: logging in twice resolves the same user (get-or-create §1-5)", async () => {
    await loginSession(102);
    await loginSession(102);
    const users = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first<{ n: number }>();
    const orgs = await env.DB.prepare("SELECT COUNT(*) AS n FROM organizations").first<{
      n: number;
    }>();
    expect(users?.n).toBe(1);
    expect(orgs?.n).toBe(1);
  });

  it("rejects a state mismatch with 400 (state-mismatch)", async () => {
    const response = await SELF.fetch(
      `${BASE}/auth/github/callback?code=code-103&state=${"ab".repeat(16)}`,
      { headers: { cookie: `${STATE_COOKIE}=${"cd".repeat(16)}` }, redirect: "manual" },
    );
    expect(response.status).toBe(400);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("state-mismatch");
  });

  it("rejects a missing state cookie with 400 (state-mismatch)", async () => {
    const response = await SELF.fetch(
      `${BASE}/auth/github/callback?code=code-103&state=${"ab".repeat(16)}`,
      { redirect: "manual" },
    );
    expect(response.status).toBe(400);
  });

  it("rejects an oversized code at the wire schema, before any outbound call (addendum 3 A-6)", async () => {
    const state = "ab".repeat(16);
    const response = await SELF.fetch(
      `${BASE}/auth/github/callback?code=${"c".repeat(513)}&state=${state}`,
      { headers: { cookie: `${STATE_COOKIE}=${state}` }, redirect: "manual" },
    );
    expect(response.status).toBe(400);
    expect(await response.text()).not.toContain("code-exchange-failed");
  });

  it("rejects an invalid authorization code with 400 (code-exchange-failed)", async () => {
    const state = "ab".repeat(16);
    const response = await SELF.fetch(
      `${BASE}/auth/github/callback?code=not-a-code&state=${state}`,
      { headers: { cookie: `${STATE_COOKIE}=${state}` }, redirect: "manual" },
    );
    expect(response.status).toBe(400);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("code-exchange-failed");
  });

  it("rate-limits callbacks per source IP before any GitHub outbound", async () => {
    const state = "ab".repeat(16);
    const attempt = (): Promise<Response> =>
      SELF.fetch(`${BASE}/auth/github/callback?code=not-a-code&state=${state}`, {
        headers: { cookie: `${STATE_COOKIE}=${state}`, "cf-connecting-ip": "203.0.113.9" },
        redirect: "manual",
      });
    const responses: Response[] = [];
    for (let batch = 0; batch < 2; batch += 1) {
      responses.push(...(await Promise.all(Array.from({ length: 31 }, attempt))));
    }
    let limited: Response | null = null;
    for (const response of responses) {
      if (response.status === 429) {
        limited ??= response;
      } else {
        expect(response.status).toBe(400);
      }
    }
    if (limited === null) {
      throw new Error("expected a 429 within two full rate-limit windows");
    }
    expect(limited.headers.get("retry-after")).toMatch(/^\d+$/);
    const body = (await limited.json()) as Record<string, unknown>;
    expect(body["_tag"]).toBe("AuthRateLimited");
    expect(body["retryAfterSeconds"] as number).toBeGreaterThan(0);
    const other = await SELF.fetch(`${BASE}/auth/github/callback?code=not-a-code&state=${state}`, {
      headers: { cookie: `${STATE_COOKIE}=${state}`, "cf-connecting-ip": "203.0.113.10" },
      redirect: "manual",
    });
    expect(other.status).toBe(400);
  }, 60_000);
});

async function flowSigningKeyFromDb(): Promise<CryptoKey> {
  const row = await env.DB.prepare("SELECT key_hex FROM flow_signing_keys").first<{
    key_hex: string;
  }>();
  if (row === null) {
    throw new Error("no flow signing key in D1");
  }
  return importFlowSigningKey(row.key_hex);
}

const DUMMY_FLOW_ID = "ab".repeat(16);

const startAttempt = (): Promise<Response> =>
  SELF.fetch(`${BASE}/auth/cli/start`, {
    method: "POST",
    headers: { ...JSON_HEADERS, "cf-connecting-ip": "203.0.113.7" },
    body: JSON.stringify({}),
  });

const startWithPayload = (payload: unknown): Promise<Response> =>
  SELF.fetch(`${BASE}/auth/cli/start`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(payload),
  });

function expectStyledScriptFreePage(response: Response, html: string): void {
  const metaCsp =
    html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]*)"/)?.[1] ?? "";
  for (const csp of [response.headers.get("content-security-policy") ?? "", metaCsp]) {
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'none'");
    expect(csp).toContain("style-src 'self'");
    expect(csp).toContain("img-src 'self'");
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).not.toContain("sha256-");
  }
  expect(html).toContain('<link rel="stylesheet" href="/theme.css" />');
  expect(html).toContain('<link rel="stylesheet" href="/pages.css" />');
  expect(html).not.toContain("<script");
  expect(html).not.toContain("<style");
  expect(html).not.toContain(" style=");
}

describe("CLI login (AUTH_SPEC §4 — the server-brokered web-flow handoff)", () => {
  it("issues a PAT exactly once via start → verify → callback → approve → poll (the §4-1 happy path)", async () => {
    await seedUser("user-cli-0001", 901);
    const started = await startCliFlow({
      tokenName: "cli-test",
      scopes: [{ project: "*", permission: "read" }],
      expiresInDays: 30,
    });
    expect(started.flowId).toMatch(/^[0-9a-f]{32}$/);
    expect(started.userCode).toMatch(/^[0-9A-Z]{4}-[0-9A-Z]{4}$/);
    expect(started.verificationUrl).not.toContain(started.flowToken);
    const flowsAfterStart = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM cli_login_flows",
    ).first<{ n: number }>();
    expect(flowsAfterStart?.n).toBe(0);
    const early = await pollCliFlow(started.flowId, started.flowToken);
    expect(early.status).toBe(200);
    expect(((await early.json()) as { status: string }).status).toBe("pending");

    const callback = await cliBrowserLeg(started.verificationUrl, 901);
    expect(callback.status).toBe(200);
    expect(callback.headers.get("content-security-policy")).toContain("script-src 'none'");
    expect(callback.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(callback.headers.get("x-frame-options")).toBe("DENY");
    expect(callback.headers.get("referrer-policy")).toBe("no-referrer");
    const html = await callback.text();
    expect(html).toContain(started.userCode);
    expectStyledScriptFreePage(callback, html);
    expect(html).toContain(`<code class="user-code">${started.userCode}</code>`);
    expect(html).toContain("user901");
    expect(html).toContain("cli-test");
    expect(html).toContain("read");
    expect(html).toContain("30");
    expect(html).not.toContain(started.flowToken);
    const ticket = approvalTicketOf(html);

    const awaiting = await pollCliFlow(started.flowId, started.flowToken);
    expect(((await awaiting.json()) as { status: string }).status).toBe("pending");

    const approve = await approveCliFlow(started.flowId, ticket);
    expect(approve.status).toBe(200);
    expect(await approve.text()).toContain("Sign-in approved");

    const poll = await pollCliFlow(started.flowId, started.flowToken);
    expect(poll.status).toBe(200);
    const body = (await poll.json()) as {
      status: string;
      token: string;
      tokenId: string;
      userId: string;
      expiresAtMs: number;
    };
    expect(body.status).toBe("approved");
    expect(body.token).toMatch(/^maruhi_pat_[0-9A-Za-z]{43}$/);
    expect(body.userId).toBe("user-cli-0001");

    const row = await env.DB.prepare(
      "SELECT name, scopes, expires_at, created_at FROM api_tokens WHERE id = ?",
    )
      .bind(body.tokenId)
      .first<{ name: string; scopes: string; expires_at: number; created_at: number }>();
    expect(row?.name).toBe("cli-test");
    expect(JSON.parse(row?.scopes ?? "[]")).toEqual([{ project: "*", permission: "read" }]);
    expect(row?.expires_at).toBe((row?.created_at ?? 0) + 30 * 24 * 60 * 60 * 1000);
    expect(body.expiresAtMs).toBe(row?.expires_at);

    const raw = await env.DB.prepare("SELECT id FROM api_tokens WHERE token_hash = ?")
      .bind(body.token)
      .first();
    expect(raw).toBeNull();

    const me = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(body.token) });
    expect(me.status).toBe(200);
    const meBody = (await me.json()) as { userId: string; providerLogin?: string };
    expect(meBody.userId).toBe("user-cli-0001");
    expect(meBody.providerLogin).toBe("user901");

    const again = await pollCliFlow(started.flowId, started.flowToken);
    expect(again.status).toBe(400);
    expect(((await again.json()) as Record<string, unknown>)["_tag"]).toBe("CliFlowRejected");
  });

  it("rate-limits start per source IP (§4-1 (1))", async () => {
    const responses: Response[] = [];
    for (let batch = 0; batch < 2; batch += 1) {
      responses.push(...(await Promise.all(Array.from({ length: 11 }, startAttempt))));
    }
    let limited: Response | null = null;
    for (const response of responses) {
      if (response.status === 429) {
        limited ??= response;
      } else {
        expect(response.status).toBe(200);
      }
    }
    if (limited === null) {
      throw new Error("expected a 429 within two full rate-limit windows");
    }
    expect(limited.headers.get("retry-after")).toMatch(/^\d+$/);
    const body = (await limited.json()) as Record<string, unknown>;
    expect(body["_tag"]).toBe("AuthRateLimited");
    expect(body["retryAfterSeconds"] as number).toBeGreaterThan(0);
    const other = await SELF.fetch(`${BASE}/auth/cli/start`, {
      method: "POST",
      headers: { ...JSON_HEADERS, "cf-connecting-ip": "203.0.113.8" },
      body: JSON.stringify({}),
    });
    expect(other.status).toBe(200);
  }, 60_000);

  it("rate-limits poll per source IP before any verification (§4-1 (5))", async () => {
    const attempt = (): Promise<Response> =>
      SELF.fetch(`${BASE}/auth/cli/poll`, {
        method: "POST",
        headers: { ...JSON_HEADERS, "cf-connecting-ip": "203.0.113.9" },
        body: JSON.stringify({ flowId: DUMMY_FLOW_ID, flowToken: "v1.bogus" }),
      });
    const responses: Response[] = [];
    for (let batch = 0; batch < 2; batch += 1) {
      responses.push(...(await Promise.all(Array.from({ length: 31 }, attempt))));
    }
    let limited: Response | null = null;
    for (const response of responses) {
      if (response.status === 429) {
        limited ??= response;
      } else {
        expect(response.status).toBe(400);
      }
    }
    if (limited === null) {
      throw new Error("expected a 429 within two full rate-limit windows");
    }
    expect(((await limited.json()) as Record<string, unknown>)["_tag"]).toBe("AuthRateLimited");
  }, 60_000);

  it("rotates the token for the same (user, name): the old one stops working", async () => {
    const first = await cliToken(202);
    const second = await cliToken(202);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM api_tokens").first<{
      n: number;
    }>();
    expect(count?.n).toBe(1);
    const oldMe = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(first) });
    expect(oldMe.status).toBe(401);
    const newMe = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(second) });
    expect(newMe.status).toBe(200);
  });

  it("keeps at most one token per (user, name) under concurrent issuance", async () => {
    await Promise.all([cliToken(203), cliToken(203), cliToken(203)]);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM api_tokens").first<{
      n: number;
    }>();
    expect(count?.n).toBe(1);
  });

  it("rejects issuing beyond the per-user token limit with 429 (§6)", async () => {
    const seed = await cliIssue(204, { tokenName: "seed" });
    const rows = Array.from({ length: 99 }, (_, i) =>
      env.DB.prepare(
        "INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, scopes, expires_at, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, '[]', 9999999999999, 1, NULL)",
      ).bind(`tok-${i}`, seed.userId, `filler-${i}`, `hash-${i}`, "maruhi_pat_x"),
    );
    await env.DB.batch(rows);

    const started = await startCliFlow({ tokenName: "one-too-many" });
    const page = await cliBrowserLeg(started.verificationUrl, 204);
    const ticket = approvalTicketOf(await page.text());
    expect((await approveCliFlow(started.flowId, ticket)).status).toBe(200);
    const overflow = await pollCliFlow(started.flowId, started.flowToken);
    expect(overflow.status).toBe(429);
    expect(((await overflow.json()) as Record<string, unknown>)["_tag"]).toBe("TokenLimit");
    const retry = await pollCliFlow(started.flowId, started.flowToken);
    expect(retry.status).toBe(400);
    expect(((await retry.json()) as Record<string, unknown>)["_tag"]).toBe("CliFlowRejected");

    const rotated = await cliIssue(204, { tokenName: "seed" });
    expect(rotated.userId).toBe(seed.userId);
  });

  it("admits exactly the remaining slot under concurrent distinct-name issuance", async () => {
    const seed = await cliIssue(206, { tokenName: "seed" });
    const userId = seed.userId;
    await env.DB.batch(
      Array.from({ length: 98 }, (_, index) =>
        env.DB.prepare(
          "INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, scopes, expires_at, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, '[]', 9999999999999, 1, NULL)",
        ).bind(
          `race-seed-${index}`,
          userId,
          `race-filler-${index}`,
          `race-hash-${index}`,
          "maruhi_pat_x",
        ),
      ),
    );

    const flows: CliFlowStart[] = [];
    for (let index = 0; index < 8; index += 1) {
      const started = await startCliFlow({ tokenName: `race-new-${index}` });
      const page = await cliBrowserLeg(started.verificationUrl, 206);
      const ticket = approvalTicketOf(await page.text());
      expect((await approveCliFlow(started.flowId, ticket)).status).toBe(200);
      flows.push(started);
    }
    const responses = await Promise.all(
      flows.map((flow) => pollCliFlow(flow.flowId, flow.flowToken)),
    );
    expect(responses.filter((response) => response.status === 200)).toHaveLength(1);
    const rejected = responses.filter((response) => response.status !== 200);
    expect(rejected).toHaveLength(7);
    expect(
      await Promise.all(
        rejected.map(async (response) => {
          expect(response.status).toBe(429);
          const body = (await response.json()) as { _tag?: string };
          return body["_tag"];
        }),
      ),
    ).toEqual(Array<string>(7).fill("TokenLimit"));

    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM api_tokens WHERE user_id = ?")
      .bind(userId)
      .first<{ n: number }>();
    expect(count?.n).toBe(100);
    const audit = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM user_audit_events WHERE event = 'auth.token_created' AND actor_user_id = ?",
    )
      .bind(userId)
      .first<{ n: number }>();
    expect(audit?.n).toBe(2);
  });

  it("rejects out-of-bounds start payloads at the schema boundary (400)", async () => {
    const tooManyScopes = await startWithPayload({
      scopes: Array.from({ length: 101 }, () => ({ project: "*", permission: "read" })),
    });
    expect(tooManyScopes.status).toBe(400);

    const badProject = await startWithPayload({
      scopes: [{ project: "x".repeat(500_000), permission: "read" }],
    });
    expect(badProject.status).toBe(400);

    expect((await startWithPayload({ tokenName: "n".repeat(129) })).status).toBe(400);

    expect((await startWithPayload({ tokenName: "evil\u0007name" })).status).toBe(400);
    expect((await startWithPayload({ tokenName: "evil\u202Ename" })).status).toBe(400);
  });

  it("rejects a mix-and-match poll: victim flowId with the attacker's own flowToken (§4-1 (1))", async () => {
    const victim = await startCliFlow();
    const attacker = await startCliFlow();
    const response = await pollCliFlow(victim.flowId, attacker.flowToken);
    expect(response.status).toBe(400);
    expect(((await response.json()) as Record<string, unknown>)["_tag"]).toBe("CliFlowRejected");
  });

  it("rejects a tampered flowToken uniformly (§4-2)", async () => {
    const started = await startCliFlow();
    const flipped = started.flowToken.endsWith("0") ? "1" : "0";
    const tampered = started.flowToken.slice(0, -1) + flipped;
    const macBroken = await pollCliFlow(started.flowId, tampered);
    expect(macBroken.status).toBe(400);
    expect(((await macBroken.json()) as Record<string, unknown>)["_tag"]).toBe("CliFlowRejected");
    const [version, expiresPart, random, mac] = started.flowToken.split(".") as [
      string,
      string,
      string,
      string,
    ];
    const extended = [version, String(Number(expiresPart) + 3_600_000), random, mac].join(".");
    const expiryForged = await pollCliFlow(started.flowId, extended);
    expect(expiryForged.status).toBe(400);
    expect(((await expiryForged.json()) as Record<string, unknown>)["_tag"]).toBe(
      "CliFlowRejected",
    );
  });

  it("tells the legitimate holder about expiry with a typed 410 (§4-2)", async () => {
    const started = await startCliFlow();
    const key = await flowSigningKeyFromDb();
    const expiredToken = await Effect.runPromise(
      createFlowToken(key, started.flowId, Date.now() - 1_000).pipe(
        Effect.provide(cryptoServicesLayer),
      ),
    );
    const response = await pollCliFlow(started.flowId, expiredToken);
    expect(response.status).toBe(410);
    expect(((await response.json()) as Record<string, unknown>)["_tag"]).toBe("CliFlowExpired");
  });

  it("rejects a tampered verificationUrl before redirecting to GitHub (§4-1 (3))", async () => {
    const started = await startCliFlow({ tokenName: "honest" });
    const url = new URL(started.verificationUrl);
    url.searchParams.set("name", "sneaky");
    const tampered = await SELF.fetch(url.toString(), { redirect: "manual" });
    expect(tampered.status).toBe(400);
    expect(tampered.headers.get("location")).toBeNull();
    expect(tampered.headers.get("content-type")).toContain("text/html");
    expect(tampered.headers.get("content-security-policy")).toContain("script-src 'none'");
    const bare = new URL(started.verificationUrl);
    bare.searchParams.delete("vsig");
    const missing = await SELF.fetch(bare.toString(), { redirect: "manual" });
    expect(missing.status).toBe(400);
    expect(missing.headers.get("location")).toBeNull();
  });

  it("re-verifies the flow binding at the callback: a tampered cookie creates no flow row (§4-1 (3))", async () => {
    await seedUser("user-cli-forge", 917);
    const started = await startCliFlow({ tokenName: "honest" });
    const verify = await SELF.fetch(started.verificationUrl, { redirect: "manual" });
    expect(verify.status).toBe(302);
    const state = new URL(verify.headers.get("location") ?? "").searchParams.get("state") ?? "";
    const bound = readCookieValue(verify.headers.getSetCookie(), CLI_STATE_COOKIE);
    if (bound === null) {
      throw new Error("verify did not set the flow-binding cookie");
    }
    const params = new URLSearchParams(decodeURIComponent(bound));
    expect(params.get("name")).toBe("honest");
    params.set("name", "sneaky");
    const forged = encodeURIComponent(params.toString());
    expect(forged).not.toBe(bound);
    const callback = await SELF.fetch(`${BASE}/auth/github/callback?code=code-917&state=${state}`, {
      headers: { cookie: `${CLI_STATE_COOKIE}=${forged}` },
      redirect: "manual",
    });
    expect(callback.status).toBe(400);
    expect(await callback.text()).toContain("This sign-in link can&#39;t be used");
    const flows = await env.DB.prepare("SELECT COUNT(*) AS n FROM cli_login_flows").first<{
      n: number;
    }>();
    expect(flows?.n).toBe(0);
  });

  it("dies on a vsig-signed scopesJson that is not a scope array (signed-but-corrupt params = defect)", async () => {
    await seedUser("user-cli-malformed", 918);
    await startCliFlow();
    const key = await flowSigningKeyFromDb();
    const params: CliVerifyParams = {
      flowId: DUMMY_FLOW_ID,
      expiresAtMs: Date.now() + 60_000,
      userCode: "AAAA-AAAA",
      tokenName: "malformed-scopes",
      scopesJson: "{}",
      expiresInDays: 30,
    };
    const vsig = await computeVsig(key, params);
    const bound = verificationQuery(params, vsig);
    const state = `cli.${"cd".repeat(16)}`;
    bound.set("state", state);
    const callback = await SELF.fetch(`${BASE}/auth/github/callback?code=code-918&state=${state}`, {
      headers: { cookie: `${CLI_STATE_COOKIE}=${encodeURIComponent(bound.toString())}` },
      redirect: "manual",
    });
    expect(callback.status).toBe(500);
    const flows = await env.DB.prepare("SELECT COUNT(*) AS n FROM cli_login_flows").first<{
      n: number;
    }>();
    expect(flows?.n).toBe(0);
  });

  it("rejects an expired verificationUrl with the same uniform page (§4-2)", async () => {
    await startCliFlow();
    const key = await flowSigningKeyFromDb();
    const params: CliVerifyParams = {
      flowId: DUMMY_FLOW_ID,
      expiresAtMs: Date.now() - 1_000,
      userCode: "AAAA-AAAA",
      tokenName: "expired",
      scopesJson: JSON.stringify([{ project: "*", permission: "read" }]),
      expiresInDays: 30,
    };
    const vsig = await computeVsig(key, params);
    const response = await SELF.fetch(
      `${BASE}/auth/cli/verify?${verificationQuery(params, vsig).toString()}`,
      { redirect: "manual" },
    );
    expect(response.status).toBe(400);
    expect(response.headers.get("location")).toBeNull();
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(response.headers.get("content-security-policy")).toContain("script-src 'none'");
  });

  it("shows the signup guidance page for an unknown account with zero side effects (ruling DH)", async () => {
    const started = await startCliFlow();
    const callback = await cliBrowserLeg(started.verificationUrl, 908);
    expect(callback.status).toBe(200);
    expect(callback.headers.get("content-security-policy")).toContain("script-src 'none'");
    const html = await callback.text();
    expect(html).toContain("No maruhi account yet");
    expect(html).toContain("/auth/github/start");
    expect(html).toContain(`flow=${started.flowId}`);
    expect(html).not.toContain(started.flowToken);
    const users = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first<{ n: number }>();
    expect(users?.n).toBe(0);
    const flows = await env.DB.prepare("SELECT COUNT(*) AS n FROM cli_login_flows").first<{
      n: number;
    }>();
    expect(flows?.n).toBe(0);
    await loginSession(908);
    const resumed = await cliBrowserLeg(started.verificationUrl, 908);
    expect(resumed.status).toBe(200);
    expect(await resumed.text()).toContain(started.userCode);
  });

  it("does not rotate the ticket on a different-user revisit (§4-1 (4) (iii))", async () => {
    await seedUser("user-cli-a", 911);
    await seedUser("user-cli-b", 912);
    const started = await startCliFlow();
    const first = await cliBrowserLeg(started.verificationUrl, 911);
    expect(first.status).toBe(200);
    const ticket = approvalTicketOf(await first.text());

    const hijack = await cliBrowserLeg(started.verificationUrl, 912);
    expect(hijack.status).toBe(400);
    expect(await hijack.text()).toContain("This sign-in link can&#39;t be used");

    expect((await approveCliFlow(started.flowId, ticket)).status).toBe(200);
    const poll = await pollCliFlow(started.flowId, started.flowToken);
    expect(poll.status).toBe(200);
    const body = (await poll.json()) as { status: string; userId: string };
    expect(body.status).toBe("approved");
    expect(body.userId).toBe("user-cli-a");
  });

  it("replaces the ticket idempotently on a same-user revisit (§4-1 (4) (iii))", async () => {
    await seedUser("user-cli-c", 916);
    const started = await startCliFlow();
    const first = await cliBrowserLeg(started.verificationUrl, 916);
    const staleTicket = approvalTicketOf(await first.text());

    const again = await cliBrowserLeg(started.verificationUrl, 916);
    expect(again.status).toBe(200);
    const freshTicket = approvalTicketOf(await again.text());
    expect(freshTicket).not.toBe(staleTicket);

    const stale = await approveCliFlow(started.flowId, staleTicket);
    expect(stale.status).toBe(400);
    const pending = await pollCliFlow(started.flowId, started.flowToken);
    expect(((await pending.json()) as { status: string }).status).toBe("pending");
    expect((await approveCliFlow(started.flowId, freshTicket)).status).toBe(200);
  });

  it("rejects the ticket of an expired flow row uniformly (§4-1 (4) (iv) — tickets are short-lived)", async () => {
    await seedUser("user-cli-late", 918);
    const ticket = "ee".repeat(32);
    const ticketHash = encodeHex(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(ticket))),
    );
    const flowId = "cd".repeat(16);
    await env.DB.prepare(
      "INSERT INTO cli_login_flows (id, user_id, status, token_name, scopes, expires_in_days, user_code, ticket_hash, expires_at, created_at) VALUES (?, ?, 'awaiting', 'late', '[]', 30, 'AAAA-AAAA', ?, ?, ?)",
    )
      .bind(flowId, "user-cli-late", ticketHash, Date.now() - 1_000, Date.now() - CLI_FLOW_TTL_MS)
      .run();
    const late = await approveCliFlow(flowId, ticket);
    expect(late.status).toBe(400);
    expect(await late.text()).toContain("This sign-in link can&#39;t be used");
    const row = await env.DB.prepare("SELECT status FROM cli_login_flows WHERE id = ?")
      .bind(flowId)
      .first<{ status: string }>();
    expect(row?.status).toBe("awaiting");
    const audit = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM user_audit_events WHERE event = 'auth.login_succeeded'",
    ).first<{ n: number }>();
    expect(audit?.n).toBe(0);
  });

  it("reports an explicit denial to the CLI as a typed denied status (§4-1 (4) (iv))", async () => {
    await seedUser("user-cli-deny", 913);
    const started = await startCliFlow();
    const page = await cliBrowserLeg(started.verificationUrl, 913);
    const ticket = approvalTicketOf(await page.text());
    const deny = await approveCliFlow(started.flowId, ticket, "deny");
    expect(deny.status).toBe(200);
    expect(await deny.text()).toContain("Sign-in denied");
    const poll = await pollCliFlow(started.flowId, started.flowToken);
    expect(poll.status).toBe(200);
    expect(((await poll.json()) as { status: string }).status).toBe("denied");
    const reuse = await approveCliFlow(started.flowId, ticket);
    expect(reuse.status).toBe(400);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM api_tokens").first<{
      n: number;
    }>();
    expect(count?.n).toBe(0);
  });

  it("issues exactly once under concurrent polls (approved → consumed CAS — §4-1 (5))", async () => {
    await seedUser("user-cli-race", 914);
    const started = await startCliFlow();
    const page = await cliBrowserLeg(started.verificationUrl, 914);
    const ticket = approvalTicketOf(await page.text());
    expect((await approveCliFlow(started.flowId, ticket)).status).toBe(200);

    const responses = await Promise.all(
      Array.from({ length: 6 }, () => pollCliFlow(started.flowId, started.flowToken)),
    );
    const issued = responses.filter((response) => response.status === 200);
    expect(issued).toHaveLength(1);
    const body = (await issued[0]?.json()) as { status: string; token: string };
    expect(body.status).toBe("approved");
    for (const response of responses.filter((candidate) => candidate.status !== 200)) {
      expect(response.status).toBe(400);
      expect(((await response.json()) as Record<string, unknown>)["_tag"]).toBe("CliFlowRejected");
    }
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM api_tokens").first<{
      n: number;
    }>();
    expect(count?.n).toBe(1);
  });

  it("generates the flow signing key exactly once under concurrent first use (§4-2)", async () => {
    const starts = await Promise.all(Array.from({ length: 4 }, () => startCliFlow()));
    const keys = await env.DB.prepare("SELECT COUNT(*) AS n FROM flow_signing_keys").first<{
      n: number;
    }>();
    expect(keys?.n).toBe(1);
    for (const started of starts) {
      const poll = await pollCliFlow(started.flowId, started.flowToken);
      expect(poll.status).toBe(200);
      expect(((await poll.json()) as { status: string }).status).toBe("pending");
    }
  });

  it("rejects new flows beyond the global unconsumed cap with the uniform page (§4-1 (4) (iii))", async () => {
    await seedUser("user-cli-cap", 915);
    await env.DB.prepare(
      `WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?)
       INSERT INTO cli_login_flows (id, user_id, status, token_name, scopes, expires_in_days, user_code, ticket_hash, expires_at, created_at)
       SELECT printf('cap%029d', n), ?, 'awaiting', 'filler', '[]', 30, 'AAAA-AAAA', printf('%064d', n), ?, ?
       FROM seq`,
    )
      .bind(MAX_CONCURRENT_CLI_FLOWS - 1, "user-cli-cap", Date.now() + CLI_FLOW_TTL_MS, Date.now())
      .run();

    const atCap = await startCliFlow();
    const admitted = await cliBrowserLeg(atCap.verificationUrl, 915);
    expect(admitted.status).toBe(200);
    const afterAdmit = await env.DB.prepare("SELECT COUNT(*) AS n FROM cli_login_flows").first<{
      n: number;
    }>();
    expect(afterAdmit?.n).toBe(MAX_CONCURRENT_CLI_FLOWS);

    const overCap = await startCliFlow();
    const callback = await cliBrowserLeg(overCap.verificationUrl, 915);
    expect(callback.status).toBe(400);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM cli_login_flows").first<{
      n: number;
    }>();
    expect(count?.n).toBe(MAX_CONCURRENT_CLI_FLOWS);
  });

  it("keeps terminal rows through the +5min grace and sweeps only past-grace rows (§4-1 (5))", async () => {
    await seedUser("user-cli-grace", 919);
    const graceMs = 5 * 60 * 1000;
    const nowMs = Date.now();
    const seedFlow = (id: string, status: string, expiresAt: number) =>
      env.DB.prepare(
        "INSERT INTO cli_login_flows (id, user_id, status, token_name, scopes, expires_in_days, user_code, ticket_hash, expires_at, created_at) VALUES (?, ?, ?, 'sweep', '[]', 30, 'AAAA-AAAA', ?, ?, ?)",
      ).bind(id, "user-cli-grace", status, `hash-${id}`, expiresAt, nowMs - CLI_FLOW_TTL_MS);
    await env.DB.batch([
      seedFlow("aa".repeat(16), "consumed", nowMs - 60_000),
      seedFlow("bb".repeat(16), "denied", nowMs - graceMs - 60_000),
    ]);
    const started = await startCliFlow();
    expect((await cliBrowserLeg(started.verificationUrl, 919)).status).toBe(200);
    const rows = await env.DB.prepare("SELECT id FROM cli_login_flows ORDER BY id").all<{
      id: string;
    }>();
    expect(rows.results.map((row) => row.id).toSorted()).toEqual(
      ["aa".repeat(16), started.flowId].toSorted(),
    );
  });
});

describe("GET /auth/me (auth required)", () => {
  it("returns 401 without credentials", async () => {
    const response = await SELF.fetch(`${BASE}/auth/me`);
    expect(response.status).toBe(401);
  });

  it("resolves a session cookie principal", async () => {
    const session = await loginSession(301);
    const response = await SELF.fetch(`${BASE}/auth/me`, {
      headers: { cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(response.status).toBe(200);
  });

  it("returns 401 for an expired session (DB-backed expiry)", async () => {
    const session = await loginSession(302);
    await env.DB.prepare("UPDATE sessions SET expires_at = 1").run();
    const response = await SELF.fetch(`${BASE}/auth/me`, {
      headers: { cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(response.status).toBe(401);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM sessions").first<{ n: number }>();
    expect(count?.n).toBe(0);
  });

  it("returns 401 for a revoked (unknown) token", async () => {
    const response = await SELF.fetch(`${BASE}/auth/me`, {
      headers: bearer(`maruhi_pat_${"A".repeat(43)}`),
    });
    expect(response.status).toBe(401);
  });

  it("returns 401 for an expired token (§6)", async () => {
    const token = await cliToken(303);
    await env.DB.prepare("UPDATE api_tokens SET expires_at = 1").run();
    const response = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(token) });
    expect(response.status).toBe(401);
  });
});

describe("credential precedence (the Authorization header always wins)", () => {
  it("accepts a case-insensitive bearer scheme (RFC 7235)", async () => {
    const token = await cliToken(311);
    const response = await SELF.fetch(`${BASE}/auth/me`, {
      headers: { authorization: `bearer ${token}` },
    });
    expect(response.status).toBe(200);
  });

  it("does not fall back to a valid session cookie when the Bearer token is invalid", async () => {
    const session = await loginSession(312);
    const response = await SELF.fetch(`${BASE}/auth/me`, {
      headers: {
        authorization: `Bearer maruhi_pat_${"B".repeat(43)}`,
        cookie: `${SESSION_COOKIE}=${session}`,
      },
    });
    expect(response.status).toBe(401);
  });

  it("does not fall back to the session cookie for a non-bearer Authorization header", async () => {
    const session = await loginSession(313);
    const response = await SELF.fetch(`${BASE}/auth/me`, {
      headers: { authorization: "Basic dXNlcjpwYXNz", cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(response.status).toBe(401);
  });

  it("token principal wins over a session cookie and skips the CSRF requirement", async () => {
    const session = await loginSession(314);
    const token = await cliToken(315);
    const response = await SELF.fetch(`${BASE}/auth/token/revoke`, {
      method: "POST",
      headers: { ...bearer(token), cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(response.status).toBe(204);
  });
});

describe("POST /auth/logout (§5: session revocation)", () => {
  it("revokes the session server-side and expires the cookie", async () => {
    const session = await loginSession(401);
    const response = await SELF.fetch(`${BASE}/auth/logout`, {
      method: "POST",
      headers: sessionHeaders(session),
    });
    expect(response.status).toBe(204);
    const expired = readCookieValue(response.headers.getSetCookie(), SESSION_COOKIE);
    expect(expired).toBe("");

    const me = await SELF.fetch(`${BASE}/auth/me`, {
      headers: { cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(me.status).toBe(401);
  });

  it("rejects a cookie-authenticated write without the CSRF header (403)", async () => {
    const session = await loginSession(402);
    const response = await SELF.fetch(`${BASE}/auth/logout`, {
      method: "POST",
      headers: { cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("csrf-header-required");
  });

  it('rejects a CSRF header whose value is not "1" (403)', async () => {
    const session = await loginSession(404);
    const response = await SELF.fetch(`${BASE}/auth/logout`, {
      method: "POST",
      headers: { cookie: `${SESSION_COOKIE}=${session}`, "x-maruhi-csrf": "yes" },
    });
    expect(response.status).toBe(403);
  });

  it("a second logout with the revoked cookie is 401 (session is gone server-side)", async () => {
    const session = await loginSession(405);
    const first = await SELF.fetch(`${BASE}/auth/logout`, {
      method: "POST",
      headers: sessionHeaders(session),
    });
    expect(first.status).toBe(204);
    const second = await SELF.fetch(`${BASE}/auth/logout`, {
      method: "POST",
      headers: sessionHeaders(session),
    });
    expect(second.status).toBe(401);
  });

  it("token-authenticated logout is a 204 no-op (idempotent behavior for a session-less principal)", async () => {
    const token = await cliToken(406);
    const response = await SELF.fetch(`${BASE}/auth/logout`, {
      method: "POST",
      headers: bearer(token),
    });
    expect(response.status).toBe(204);
    const me = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(token) });
    expect(me.status).toBe(200);
  });

  it("token-authenticated logout does not destroy a browser session sent alongside", async () => {
    const session = await loginSession(407);
    const token = await cliToken(408);
    const response = await SELF.fetch(`${BASE}/auth/logout`, {
      method: "POST",
      headers: { ...bearer(token), cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(response.status).toBe(204);
    const expired = response.headers
      .getSetCookie()
      .find((cookie) => cookie.startsWith(`${SESSION_COOKIE}=`));
    expect(expired).toBeUndefined();
    const me = await SELF.fetch(`${BASE}/auth/me`, {
      headers: { cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(me.status).toBe(200);
  });

  it("does not require the CSRF header for token-authenticated writes", async () => {
    const token = await cliToken(403);
    const response = await SELF.fetch(`${BASE}/auth/token/revoke`, {
      method: "POST",
      headers: bearer(token),
    });
    expect(response.status).toBe(204);
  });
});

describe("POST /auth/token/revoke (§6: revoking one's own token)", () => {
  it("revokes the presented token; it no longer authenticates", async () => {
    const token = await cliToken(501);
    const revoke = await SELF.fetch(`${BASE}/auth/token/revoke`, {
      method: "POST",
      headers: bearer(token),
    });
    expect(revoke.status).toBe(204);
    const me = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(token) });
    expect(me.status).toBe(401);
  });

  it("rejects a session-authenticated call (only the presented token can be revoked)", async () => {
    const session = await loginSession(502);
    const response = await SELF.fetch(`${BASE}/auth/token/revoke`, {
      method: "POST",
      headers: sessionHeaders(session),
    });
    expect(response.status).toBe(403);
  });
});

describe("session sliding renewal (§5)", () => {
  it("extends expires_at on resolve", async () => {
    const session = await loginSession(601);
    await env.DB.prepare("UPDATE sessions SET expires_at = ?, last_used_at = 0")
      .bind(Date.now() + 1000 * 60)
      .run();
    const me = await SELF.fetch(`${BASE}/auth/me`, {
      headers: { cookie: `${SESSION_COOKIE}=${session}`, ...CSRF_HEADERS },
    });
    expect(me.status).toBe(200);
    const row = await env.DB.prepare("SELECT expires_at, last_used_at FROM sessions").first<{
      expires_at: number;
      last_used_at: number;
    }>();
    expect(row).not.toBeNull();
    expect(row?.expires_at ?? 0).toBeGreaterThan(Date.now() + 29 * 24 * 60 * 60 * 1000);
    expect(row?.last_used_at ?? 0).toBeGreaterThan(0);
  });

  it("re-issues the session cookie with a fresh Max-Age on session-authenticated responses (§5)", async () => {
    const session = await loginSession(603);
    const me = await SELF.fetch(`${BASE}/auth/me`, {
      headers: { cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(me.status).toBe(200);
    const cookie = me.headers.getSetCookie().find((c) => c.startsWith(`${SESSION_COOKIE}=`));
    expect(cookie).toBeDefined();
    expect(cookie).toContain(`${SESSION_COOKIE}=${session}`);
    expect(cookie).toContain("Max-Age=2592000");

    const token = await cliToken(604);
    const tokenMe = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(token) });
    expect(tokenMe.headers.getSetCookie()).toEqual([]);
  });

  it("skips the D1 write when the extension gain is under the 1h threshold", async () => {
    const session = await loginSession(602);
    const before = await env.DB.prepare("SELECT expires_at FROM sessions").first<{
      expires_at: number;
    }>();
    const me = await SELF.fetch(`${BASE}/auth/me`, {
      headers: { cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(me.status).toBe(200);
    const after = await env.DB.prepare("SELECT expires_at FROM sessions").first<{
      expires_at: number;
    }>();
    expect(after?.expires_at).toBe(before?.expires_at);
  });
});

describe("tryD1 (D1 error classification)", () => {
  const failureOf = (promise: Promise<unknown>): Promise<unknown> =>
    Effect.runPromise(Effect.flip(tryD1(() => promise)));

  const UNIQUE_VIOLATION =
    "UNIQUE constraint failed: invitations.link_pub: SQLITE_CONSTRAINT (extended: SQLITE_CONSTRAINT_UNIQUE)";

  it("classifies UNIQUE violations as D1UniqueConflict directly and through cause chains", async () => {
    expect(
      await failureOf(Promise.reject(new Error(`D1_ERROR: ${UNIQUE_VIOLATION}`))),
    ).toBeInstanceOf(D1UniqueConflictError);
    expect(
      await failureOf(
        Promise.reject(
          new Error("Failed query: insert into invitations ...", {
            cause: new Error(UNIQUE_VIOLATION),
          }),
        ),
      ),
    ).toBeInstanceOf(D1UniqueConflictError);
  });

  it("classifies every other rejection as D1Failure", async () => {
    expect(
      await failureOf(Promise.reject(new Error("D1_ERROR: database is locked"))),
    ).toBeInstanceOf(D1FailureError);
    expect(await failureOf(Promise.reject("not an error"))).toBeInstanceOf(D1FailureError);
  });

  it("carries the violated constraint's target text", async () => {
    for (const error of [
      new Error(`D1_ERROR: ${UNIQUE_VIOLATION}`),
      new Error("Failed query: insert into invitations ...", {
        cause: new Error(UNIQUE_VIOLATION),
      }),
    ]) {
      const failure = await failureOf(Promise.reject(error));
      expect(failure).toBeInstanceOf(D1UniqueConflictError);
      expect((failure as D1UniqueConflictError).constraint).toBe("invitations.link_pub");
    }
  });

  it("classifies a real workerd D1 UNIQUE rejection with the constraint target", async () => {
    await env.DB.exec("CREATE TABLE IF NOT EXISTS d1_probe_unique (probe TEXT UNIQUE)");
    try {
      await env.DB.prepare("DELETE FROM d1_probe_unique").run();
      await env.DB.prepare("INSERT INTO d1_probe_unique (probe) VALUES ('dup')").run();
      const failure = await failureOf(
        env.DB.prepare("INSERT INTO d1_probe_unique (probe) VALUES ('dup')").run(),
      );
      expect(failure).toBeInstanceOf(D1UniqueConflictError);
      expect((failure as D1UniqueConflictError).constraint).toBe("d1_probe_unique.probe");
    } finally {
      await env.DB.exec("DROP TABLE IF EXISTS d1_probe_unique");
    }
  });
});

async function sha256HexOf(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

describe("scheduled: periodic sweep of expired sessions", () => {
  it("deletes only expired rows", async () => {
    const live = await loginSession(701);
    await loginSession(702);
    const liveHash = await sha256HexOf(live);
    await env.DB.prepare("UPDATE sessions SET expires_at = 1 WHERE id != ?").bind(liveHash).run();

    await worker.scheduled?.(createScheduledController(), env, createExecutionContext());

    const rows = await env.DB.prepare("SELECT id FROM sessions").all<{ id: string }>();
    expect(rows.results.map((row) => row.id)).toEqual([liveHash]);
    const me = await SELF.fetch(`${BASE}/auth/me`, {
      headers: { cookie: `${SESSION_COOKIE}=${live}` },
    });
    expect(me.status).toBe(200);
  });
});

const incoming = (url: string, init?: RequestInit): Request<unknown, IncomingRequestCfProperties> =>
  new Request(url, init) as Request<unknown, IncomingRequestCfProperties>;

describe("GET /auth/config (§4 public settings) and unconfigured detection (§3)", () => {
  it("returns the configured client_id without authentication", async () => {
    const response = await SELF.fetch(`${BASE}/auth/config`);
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["githubClientId"]).toBe(env.GITHUB_CLIENT_ID);
  });

  it("returns 503 SetupIncomplete while the client_id is empty or missing", async () => {
    const empty = { ...env, GITHUB_CLIENT_ID: "" };
    const emptyResponse = await worker.fetch(incoming(`${BASE}/auth/config`), empty);
    expect(emptyResponse.status).toBe(503);
    const emptyBody = (await emptyResponse.json()) as Record<string, unknown>;
    expect(emptyBody["_tag"]).toBe("SetupIncomplete");
    expect(emptyBody["reason"]).toBe("github-oauth-unconfigured");
    const { GITHUB_CLIENT_ID: _removed, ...missing } = env;
    const response = await worker.fetch(incoming(`${BASE}/auth/config`), missing as typeof env);
    expect(response.status).toBe(503);
  });

  it("treats a missing client_secret as unconfigured (a forgotten `cf workers secrets update`)", async () => {
    const { GITHUB_CLIENT_SECRET: _removed, ...missing } = env;
    const config = await worker.fetch(incoming(`${BASE}/auth/config`), missing as typeof env);
    expect(config.status).toBe(503);
    const start = await worker.fetch(
      incoming(`${BASE}/auth/cli/start`, {
        method: "POST",
        headers: JSON_HEADERS,
        body: JSON.stringify({}),
      }),
      missing as typeof env,
    );
    expect(start.status).toBe(503);
    const body = (await start.json()) as Record<string, unknown>;
    expect(body["_tag"]).toBe("SetupIncomplete");
  });

  it("githubStart fails closed with 503 instead of bouncing to GitHub's error page", async () => {
    const unconfigured = { ...env, GITHUB_CLIENT_ID: "" };
    const response = await worker.fetch(incoming(`${BASE}/auth/github/start`), unconfigured);
    expect(response.status).toBe(503);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["_tag"]).toBe("SetupIncomplete");
  });
});

describe("GET /auth/config's server-key public surface (AUTH_SPEC §4 / CRYPTO_SPEC §9)", () => {
  const IKM_HEX = "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30";

  it("returns the fingerprint and enc pub when the deployment keypair is configured", async () => {
    const response = await worker.fetch(incoming(`${BASE}/auth/config`), {
      ...env,
      SERVER_ENC_KEY_IKM: IKM_HEX,
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, string>;
    expect(body["serverEncPubHex"]).toMatch(/^[0-9a-f]{64}$/);
    expect(body["serverKeyFingerprintHex"]).toMatch(/^[0-9a-f]{32}$/);
    const pub = decodeHex(body["serverEncPubHex"] ?? "");
    if (pub === null) throw new Error("serverEncPubHex is not hex");
    const fp = await computeServerKeyFingerprint(pub);
    if (!fp.ok) throw new Error("fingerprint failed");
    expect(encodeHex(fp.value)).toBe(body["serverKeyFingerprintHex"]);
    const again = await worker.fetch(incoming(`${BASE}/auth/config`), {
      ...env,
      SERVER_ENC_KEY_IKM: IKM_HEX,
    });
    expect(await again.json()).toEqual(body);
  });

  it("omits the fields when the secret is absent (pure-E2EE deployment is the default)", async () => {
    const { SERVER_ENC_KEY_IKM: _omitted, ...withoutKey } = env;
    const response = await worker.fetch(incoming(`${BASE}/auth/config`), withoutKey as typeof env);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      githubClientId: env.GITHUB_CLIENT_ID,
      signupPolicy: "open",
    });
  });

  it("treats a malformed ikm as unconfigured (fields omitted, login stays available)", async () => {
    for (const bad of ["not-hex", "abcd", "ab".repeat(31), "AB".repeat(32)]) {
      const response = await worker.fetch(incoming(`${BASE}/auth/config`), {
        ...env,
        SERVER_ENC_KEY_IKM: bad,
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as Record<string, unknown>;
      expect(body["serverKeyFingerprintHex"]).toBeUndefined();
      expect(body["serverEncPubHex"]).toBeUndefined();
    }
  });
});

describe("common security headers (index.ts withSecurityHeaders)", () => {
  it("attaches nosniff / no-store / HSTS to every API response, including errors", async () => {
    const response = await SELF.fetch(`${BASE}/auth/config`);
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("strict-transport-security")).toBe("max-age=31536000");
    const unauthorized = await SELF.fetch(`${BASE}/auth/me`);
    expect(unauthorized.status).toBe(401);
    expect(unauthorized.headers.get("x-content-type-options")).toBe("nosniff");
    expect(unauthorized.headers.get("cache-control")).toBe("no-store");
    expect(unauthorized.headers.get("strict-transport-security")).toBe("max-age=31536000");
  });

  it("attaches the headers to the pre-router 413 path too (capRequestBody)", async () => {
    const oversized = new Uint8Array(8 * 1024 * 1024 + 1);
    const response = await SELF.fetch(`${BASE}/auth/device/exchange`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: oversized,
    });
    expect(response.status).toBe(413);
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("strict-transport-security")).toBe("max-age=31536000");
  });
});
