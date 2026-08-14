// 認証・アイデンティティ基盤の統合テスト(AUTH_SPEC §3〜§6)。
// vitest-pool-workers(workerd 実環境)で SELF 経由の実経路を検証する。
// スタブは GitHub API のみ(vitest.config.ts の outboundService フェイク)。

import { computeServerKeyFingerprint, decodeHex, encodeHex } from "@maruhi/crypto";
import { createExecutionContext, createScheduledController, env, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { isUniqueConflict } from "../src/db.package/index.ts";
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
    expect(cookie).toContain("SameSite=Lax");
  });
});

describe("GET /auth/github/callback(§3-2〜§3-4)", () => {
  it("sets the session cookie with the full __Host- attribute set (§5)", async () => {
    // TCB 方針(CLAUDE.md): セッションクッキーの属性退行はここで検知する
    const start = await SELF.fetch(`${BASE}/auth/github/start`, { redirect: "manual" });
    const state = new URL(start.headers.get("location") ?? "").searchParams.get("state") ?? "";
    const callback = await SELF.fetch(`${BASE}/auth/github/callback?code=code-100&state=${state}`, {
      headers: { cookie: `${STATE_COOKIE}=${state}` },
      redirect: "manual",
    });
    expect(callback.status).toBe(302);
    const cookie = callback.headers.getSetCookie().find((c) => c.startsWith(`${SESSION_COOKIE}=`));
    expect(cookie).toBeDefined();
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("Path=/");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Max-Age=2592000");
  });

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

  it("keeps at most one token per (user, name) under concurrent exchanges", async () => {
    // ローテーションは delete + insert の atomic batch(+ UNIQUE (user_id, name))。
    // 並行 device 交換でも同名トークンが複数残らない
    await Promise.all([deviceToken(203), deviceToken(203), deviceToken(203)]);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM api_tokens").first<{
      n: number;
    }>();
    expect(count?.n).toBe(1);
  });

  it("rejects issuing beyond the per-user token limit with 429 (§6)", async () => {
    // 上限 100 本(別名)。101 本目の新名は 429、同名ローテーションは引き続き可能
    const first = await SELF.fetch(`${BASE}/auth/device/exchange`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ githubAccessToken: "gh-token-204", tokenName: "seed" }),
    });
    expect(first.status).toBe(200);
    const { userId } = (await first.json()) as { userId: string };
    // 残り 99 本ぶんを直接シードして上限到達状態を作る
    const rows = Array.from({ length: 99 }, (_, i) =>
      env.DB.prepare(
        "INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, scopes, expires_at, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, '[]', NULL, 1, NULL)",
      ).bind(`tok-${i}`, userId, `filler-${i}`, `hash-${i}`, "maruhi_pat_x"),
    );
    await env.DB.batch(rows);

    const overflow = await SELF.fetch(`${BASE}/auth/device/exchange`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ githubAccessToken: "gh-token-204", tokenName: "one-too-many" }),
    });
    expect(overflow.status).toBe(429);

    // 同名(既存 "seed")のローテーションは上限に達していても通る
    const rotate = await SELF.fetch(`${BASE}/auth/device/exchange`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ githubAccessToken: "gh-token-204", tokenName: "seed" }),
    });
    expect(rotate.status).toBe(200);
  });

  it("rejects out-of-bounds payloads at the schema boundary (400)", async () => {
    // scopes 要素数上限(100)超過
    const tooManyScopes = await SELF.fetch(`${BASE}/auth/device/exchange`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({
        githubAccessToken: "gh-token-205",
        scopes: Array.from({ length: 101 }, () => ({ project: "*", permission: "read" })),
      }),
    });
    expect(tooManyScopes.status).toBe(400);

    // project はプロジェクト ID 形式(hex 64)か "*" のみ
    const badProject = await SELF.fetch(`${BASE}/auth/device/exchange`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({
        githubAccessToken: "gh-token-205",
        scopes: [{ project: "x".repeat(500_000), permission: "read" }],
      }),
    });
    expect(badProject.status).toBe(400);

    // tokenName 上限(128 文字)超過
    const longName = await SELF.fetch(`${BASE}/auth/device/exchange`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ githubAccessToken: "gh-token-205", tokenName: "n".repeat(129) }),
    });
    expect(longName.status).toBe(400);
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

  it("re-issues the session cookie with a fresh Max-Age on session-authenticated responses (§5)", async () => {
    // DB のスライディング延長だけでなく、ブラウザ側のクッキー期限も毎回更新される
    const session = await loginSession(603);
    const me = await SELF.fetch(`${BASE}/auth/me`, {
      headers: { cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(me.status).toBe(200);
    const cookie = me.headers.getSetCookie().find((c) => c.startsWith(`${SESSION_COOKIE}=`));
    expect(cookie).toBeDefined();
    expect(cookie).toContain(`${SESSION_COOKIE}=${session}`);
    expect(cookie).toContain("Max-Age=2592000");

    // トークン認証の応答ではクッキーを発行しない
    const token = await deviceToken(604);
    const tokenMe = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(token) });
    expect(tokenMe.headers.getSetCookie()).toEqual([]);
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

describe("isUniqueConflict(D1 エラー判別)", () => {
  it("detects UNIQUE violations directly and through cause chains", () => {
    // batch 経路は素の Error、単発クエリ経路は DrizzleQueryError(cause 側)に
    // メッセージが入る。どちらの形でも競合として判別できることを固定する
    expect(isUniqueConflict(new Error("D1_ERROR: UNIQUE constraint failed: users.id"))).toBe(true);
    expect(
      isUniqueConflict(
        new Error("Failed query: insert into users ...", {
          cause: new Error("UNIQUE constraint failed: users.id: SQLITE_CONSTRAINT"),
        }),
      ),
    ).toBe(true);
    expect(isUniqueConflict(new Error("D1_ERROR: database is locked"))).toBe(false);
    expect(isUniqueConflict("not an error")).toBe(false);
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

// 旧テンプレート(client_id を wrangler vars で配布していた時期)のプレースホルダ。
// 現テンプレートには現れないが、旧フォークへの後方互換防御として検出を維持している
// (handlers-auth.ts の CLIENT_ID_PLACEHOLDER と同期)
const PLACEHOLDER = "replace-with-your-github-oauth-app-client-id";

// worker.fetch を env 差し替えで直接呼ぶための着信リクエスト型合わせ
// (fetch 側は IncomingRequestCfProperties を要求するが、コンストラクタ産の
// Request は CfProperties になる — workers-types の既知の型差)
const incoming = (url: string, init?: RequestInit): Request<unknown, IncomingRequestCfProperties> =>
  new Request(url, init) as Request<unknown, IncomingRequestCfProperties>;

describe("GET /auth/config(§4 公開設定)と未設定検出(§3)", () => {
  it("returns the configured client_id without authentication", async () => {
    const response = await SELF.fetch(`${BASE}/auth/config`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ githubClientId: env.GITHUB_CLIENT_ID });
  });

  it("returns 503 SetupIncomplete while the client_id is still the placeholder", async () => {
    const unconfigured = { ...env, GITHUB_CLIENT_ID: PLACEHOLDER };
    const response = await worker.fetch(incoming(`${BASE}/auth/config`), unconfigured);
    expect(response.status).toBe(503);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["_tag"]).toBe("SetupIncomplete");
    expect(body["reason"]).toBe("github-oauth-unconfigured");
  });

  it("treats an empty or missing client_id as unconfigured too", async () => {
    const empty = { ...env, GITHUB_CLIENT_ID: "" };
    expect((await worker.fetch(incoming(`${BASE}/auth/config`), empty)).status).toBe(503);
    // vars を消したデプロイ(Env 型の外だが実行時に起こり得る)も 503 へ倒す
    // (素通しすると /auth/config は encode defect、start は client_id=undefined で
    // GitHub へ飛ぶ)
    const { GITHUB_CLIENT_ID: _removed, ...missing } = env;
    const response = await worker.fetch(incoming(`${BASE}/auth/config`), missing as typeof env);
    expect(response.status).toBe(503);
  });

  it("treats a missing client_secret as unconfigured (`wrangler secret put` 漏れ)", async () => {
    // client_id は実値でも secret 未登録なら 503: 素通しすると認証は不透明な
    // トークン交換失敗(GitHub 401 → AuthFlow 400)に落ち、/auth/config の
    // 200 が誤った安心を与える(pullfrog レビュー指摘)
    const { GITHUB_CLIENT_SECRET: _removed, ...missing } = env;
    const config = await worker.fetch(incoming(`${BASE}/auth/config`), missing as typeof env);
    expect(config.status).toBe(503);
    // deviceExchange も GitHub へのトークン検証より先に fail-closed する
    const exchange = await worker.fetch(
      incoming(`${BASE}/auth/device/exchange`, {
        method: "POST",
        headers: JSON_HEADERS,
        // ガードはトークン検証より先に走る(値は Schema を満たせば何でもよい)
        body: JSON.stringify({ githubAccessToken: "gh-token-901" }),
      }),
      missing as typeof env,
    );
    expect(exchange.status).toBe(503);
    const body = (await exchange.json()) as Record<string, unknown>;
    expect(body["_tag"]).toBe("SetupIncomplete");
  });

  it("githubStart fails closed with 503 instead of bouncing to GitHub's error page", async () => {
    const unconfigured = { ...env, GITHUB_CLIENT_ID: PLACEHOLDER };
    const response = await worker.fetch(incoming(`${BASE}/auth/github/start`), unconfigured);
    expect(response.status).toBe(503);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["_tag"]).toBe("SetupIncomplete");
  });
});

describe("GET /auth/config のサーバー鍵公開面(AUTH_SPEC §4 / CRYPTO_SPEC §9)", () => {
  // デプロイメント keypair の ikm(ダミー)。keypair は RFC 9180 DeriveKeyPair で
  // 導出されるため、同じ ikm からは常に同じ公開面が得られる(決定論)
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
    // FP = SHA-256(enc_pub)[:16](§9)の整合を再計算で確認する(CLI の照合と同じ計算)
    const pub = decodeHex(body["serverEncPubHex"] ?? "");
    if (pub === null) throw new Error("serverEncPubHex is not hex");
    const fp = await computeServerKeyFingerprint(pub);
    if (!fp.ok) throw new Error("fingerprint failed");
    expect(encodeHex(fp.value)).toBe(body["serverKeyFingerprintHex"]);
    // 導出は決定論的: 別の env オブジェクト(サービス再構築)でも同じ公開面
    const again = await worker.fetch(incoming(`${BASE}/auth/config`), {
      ...env,
      SERVER_ENC_KEY_IKM: IKM_HEX,
    });
    expect(await again.json()).toEqual(body);
  });

  it("omits the fields when the secret is absent (pure-E2EE deployment is the default)", async () => {
    // テスト既定のバインディングに SERVER_ENC_KEY_IKM はない(vitest.config.ts)
    const response = await SELF.fetch(`${BASE}/auth/config`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ githubClientId: env.GITHUB_CLIENT_ID });
  });

  it("treats a malformed ikm as unconfigured (fields omitted, login stays available)", async () => {
    // 非 hex・長さ不正・大文字 hex(decodeHex は小文字のみ)はすべて未設定扱い。
    // GitHub OAuth の 503 と違い fail-closed にしない(サーバー鍵は任意機能で、
    // ログイン経路を塞ぐ理由がない)。トラブルシュートは SELF_HOSTING.md
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
