// 認証・アイデンティティ基盤の統合テスト(AUTH_SPEC §3〜§6)。
// vitest-pool-workers(workerd 実環境)で SELF 経由の実経路を検証する。
// スタブは GitHub API のみ(vitest.config.ts の outboundService フェイク)。

import { createExecutionContext, createScheduledController, env, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import worker from "../src/index.ts";
import {
  BASE,
  bearer,
  CSRF_HEADERS,
  deviceToken,
  JSON_HEADERS,
  loginSession,
  readCookieValue,
  resetAuthDb,
  seedUser,
  SESSION_COOKIE,
  sessionHeaders,
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
    // state はクッキーにも保存され、両者が一致する(§3-2 の検証の前提)
    const cookie = response.headers.getSetCookie().find((c) => c.startsWith(`${STATE_COOKIE}=`));
    expect(cookie).toBeDefined();
    expect(cookie).toContain(`${STATE_COOKIE}=${state}`);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("Path=/");
  });
});

describe("GET /auth/github/callback(§3-2〜§3-4)", () => {
  it("creates the user + personal org, issues a DB-backed session and clears the state cookie", async () => {
    const session = await loginSession(101);
    expect(session).toMatch(/^[0-9a-f]{64}$/);

    // ユーザー・リンク・パーソナル org(本人 owner)が作成される(§9-1)
    const user = await env.DB.prepare(
      "SELECT u.id, u.email, u.email_verified FROM users u JOIN linked_identities li ON li.user_id = u.id WHERE li.provider = 'github' AND li.provider_user_id = '101'",
    ).first<{ id: string; email: string; email_verified: number }>();
    expect(user).not.toBeNull();
    // email は GitHub 側で verified な primary のみ保存(§3-3)
    expect(user?.email).toBe("user101@example.com");
    expect(user?.email_verified).toBe(1);
    const membership = await env.DB.prepare("SELECT role FROM memberships WHERE user_id = ?")
      .bind(user?.id)
      .first<{ role: string }>();
    expect(membership?.role).toBe("owner");

    // セッションは DB バック(ハッシュのみ保存 = 生値の行は存在しない)
    const rawRow = await env.DB.prepare("SELECT id FROM sessions WHERE id = ?")
      .bind(session)
      .first();
    expect(rawRow).toBeNull();
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM sessions").first<{ n: number }>();
    expect(count?.n).toBe(1);
  });

  it("does not store an unverified email (§3-3)", async () => {
    // フェイク GitHub: id 666 は verified: false のメールのみ返す
    await loginSession(666);
    const user = await env.DB.prepare("SELECT email, email_verified FROM users").first<{
      email: string | null;
      email_verified: number;
    }>();
    expect(user?.email).toBeNull();
    expect(user?.email_verified).toBe(0);
  });

  it("does not store a non-primary email (§3-3)", async () => {
    // フェイク GitHub: id 667 は primary: false のメールのみ返す
    await loginSession(667);
    const user = await env.DB.prepare("SELECT email FROM users").first<{ email: string | null }>();
    expect(user?.email).toBeNull();
  });

  it("treats an email API failure as no email (id 668: /user/emails が 404)", async () => {
    await loginSession(668);
    const user = await env.DB.prepare("SELECT email FROM users").first<{ email: string | null }>();
    expect(user?.email).toBeNull();
  });

  it("self-heals a missing email on a later login (§1-5 の冪等入口での再取得)", async () => {
    // サインアップ時に email を取り損ねたユーザー(シードで email NULL)が
    // 再ログインすると、verified primary メールで補完される
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
});

describe("POST /auth/device/exchange(§4)", () => {
  it("verifies the GitHub token and issues a maruhi_pat_ token usable as Bearer auth", async () => {
    const response = await SELF.fetch(`${BASE}/auth/device/exchange`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ githubAccessToken: "gh-token-201" }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { token: string; tokenId: string; userId: string };
    expect(body.token).toMatch(/^maruhi_pat_[0-9A-Za-z]{43}$/);

    // DB には生値は存在しない(ハッシュのみ。§6)
    const raw = await env.DB.prepare("SELECT id FROM api_tokens WHERE token_hash = ?")
      .bind(body.token)
      .first();
    expect(raw).toBeNull();

    const me = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(body.token) });
    expect(me.status).toBe(200);
    const meBody = (await me.json()) as { userId: string; orgs: readonly { role: string }[] };
    expect(meBody.userId).toBe(body.userId);
    expect(meBody.orgs.map((org) => org.role)).toEqual(["owner"]);
  });

  it("rejects an invalid GitHub token with 400 (github-token-invalid)", async () => {
    const response = await SELF.fetch(`${BASE}/auth/device/exchange`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ githubAccessToken: "not-a-token" }),
    });
    expect(response.status).toBe(400);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("github-token-invalid");
  });

  it("rejects a token issued to a different OAuth App (§4-4 audience 検証)", async () => {
    // フェイク GitHub: gh-token-other-app-* は /user では有効だが check-token では 404。
    // /user 検証止まりの実装(confused-deputy)ではこのテストが緑にならない
    const response = await SELF.fetch(`${BASE}/auth/device/exchange`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ githubAccessToken: "gh-token-other-app-201" }),
    });
    expect(response.status).toBe(400);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("github-token-invalid");
  });

  it("rotates the token for the same (user, name): the old one stops working", async () => {
    const first = await deviceToken(202);
    const second = await deviceToken(202);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM api_tokens").first<{
      n: number;
    }>();
    expect(count?.n).toBe(1);
    const oldMe = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(first) });
    expect(oldMe.status).toBe(401);
    const newMe = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(second) });
    expect(newMe.status).toBe(200);
  });
});

describe("GET /auth/me(認証必須)", () => {
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
    // 期限切れ行は resolve 時に掃除される
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
    const token = await deviceToken(303);
    await env.DB.prepare("UPDATE api_tokens SET expires_at = 1").run();
    const response = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(token) });
    expect(response.status).toBe(401);
  });
});

describe("資格情報の優先順位(Authorization ヘッダーが常に優先)", () => {
  it("accepts a case-insensitive bearer scheme (RFC 7235)", async () => {
    const token = await deviceToken(311);
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
    // トークン + クッキー同時提示の書き込み(CSRF ヘッダーなし)が通る =
    // 主体はトークン(クロスサイトから Authorization は付与できないため安全)
    const session = await loginSession(314);
    const token = await deviceToken(315);
    const response = await SELF.fetch(`${BASE}/auth/token/revoke`, {
      method: "POST",
      headers: { ...bearer(token), cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(response.status).toBe(204);
  });
});

describe("POST /auth/logout(§5: セッション失効)", () => {
  it("revokes the session server-side and expires the cookie", async () => {
    const session = await loginSession(401);
    const response = await SELF.fetch(`${BASE}/auth/logout`, {
      method: "POST",
      headers: sessionHeaders(session),
    });
    expect(response.status).toBe(204);
    const expired = readCookieValue(response.headers.getSetCookie(), SESSION_COOKIE);
    expect(expired).toBe("");

    // サーバー側で失効済み: 同じクッキーはもう解決されない
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

  it("token-authenticated logout is a 204 no-op(セッションを持たない主体の冪等挙動)", async () => {
    const token = await deviceToken(406);
    const response = await SELF.fetch(`${BASE}/auth/logout`, {
      method: "POST",
      headers: bearer(token),
    });
    expect(response.status).toBe(204);
    // トークン自体は失効していない
    const me = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(token) });
    expect(me.status).toBe(200);
  });

  it("token-authenticated logout does not destroy a browser session sent alongside", async () => {
    // ブラウザ拡張等が Bearer とセッションクッキーを同送しても、トークン主体の
    // logout は Web セッションを失効させず、クッキーの expire も返さない
    const session = await loginSession(407);
    const token = await deviceToken(408);
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
    const token = await deviceToken(403);
    const response = await SELF.fetch(`${BASE}/auth/token/revoke`, {
      method: "POST",
      headers: bearer(token),
    });
    expect(response.status).toBe(204);
  });
});

describe("POST /auth/token/revoke(§6: 自トークンの失効)", () => {
  it("revokes the presented token; it no longer authenticates", async () => {
    const token = await deviceToken(501);
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

describe("セッションのスライディング更新(§5)", () => {
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
    // 30 日先へ延長され、last_used_at も更新されている
    expect(row).not.toBeNull();
    expect(row?.expires_at ?? 0).toBeGreaterThan(Date.now() + 29 * 24 * 60 * 60 * 1000);
    expect(row?.last_used_at ?? 0).toBeGreaterThan(0);
  });

  it("skips the D1 write when the extension gain is under the 1h threshold", async () => {
    const session = await loginSession(602);
    const before = await env.DB.prepare("SELECT expires_at FROM sessions").first<{
      expires_at: number;
    }>();
    // 発行直後の resolve は延長ゲイン < 1 時間なので UPDATE しない(書き込み間引き)
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

async function sha256HexOf(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

describe("scheduled: 期限切れセッションの定期掃除", () => {
  it("deletes only expired rows", async () => {
    const live = await loginSession(701);
    await loginSession(702);
    // live 以外を期限切れにする(DB の id はハッシュなのでこちらで計算して照合)
    const liveHash = await sha256HexOf(live);
    await env.DB.prepare("UPDATE sessions SET expires_at = 1 WHERE id != ?").bind(liveHash).run();

    await worker.scheduled?.(createScheduledController(), env, createExecutionContext());

    const rows = await env.DB.prepare("SELECT id FROM sessions").all<{ id: string }>();
    expect(rows.results.map((row) => row.id)).toEqual([liveHash]);
    // 生き残ったセッションは引き続き有効
    const me = await SELF.fetch(`${BASE}/auth/me`, {
      headers: { cookie: `${SESSION_COOKIE}=${live}` },
    });
    expect(me.status).toBe(200);
  });
});
