// 認証・アイデンティティ基盤の統合テスト(AUTH_SPEC §3〜§6)。
// vitest-pool-workers(workerd 実環境)で SELF 経由の実経路を検証する。
// スタブは GitHub API のみ(vitest.config.ts の outboundService フェイク)。

import { computeServerKeyFingerprint, decodeHex, encodeHex } from "@maruhi/crypto";
import { createExecutionContext, createScheduledController, env, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import {
  CLI_FLOW_TTL_MS,
  type CliVerifyParams,
  computeVsig,
  createFlowToken,
  importFlowSigningKey,
  verificationQuery,
} from "../src/auth.package/index.ts";
import { isUniqueConflict, MAX_CONCURRENT_CLI_FLOWS } from "../src/db.package/index.ts";
import worker from "../src/index.ts";
import {
  approvalTicketOf,
  approveCliFlow,
  BASE,
  bearer,
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
    // Set-Cookie は 2 本(セッションの付与 + state の失効)がそのまま残ること。
    // 応答は index.ts の withSecurityHeaders(new Headers コピー → new Response)
    // を通るため、複数 Set-Cookie の保全はここで固定する(L-5 の退行ガード)
    const setCookies = callback.headers.getSetCookie();
    expect(setCookies).toHaveLength(2);
    const cookie = setCookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
    expect(cookie).toBeDefined();
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("Path=/");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Max-Age=2592000");
    // state クッキーは失効される(§3-2 の使い捨て)
    const stateCookie = setCookies.find((c) => c.startsWith(`${STATE_COOKIE}=`));
    expect(stateCookie).toBeDefined();
    expect(stateCookie).toContain("Max-Age=0");
  });

  it("creates the user + personal org and issues a DB-backed session", async () => {
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

  it("rejects an oversized code at the wire schema, before any outbound call (追補 3 A-6)", async () => {
    // code / state クエリの 512 文字上限(api-schema)。超過はワイヤ Schema の
    // 400 で落ち、ハンドラ(= GitHub への code 交換)に到達しない — 到達して
    // いれば fake GitHub 経由で code-exchange-failed になるので、その不在が
    // 遮断位置の裏取りになる
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

  it("rate-limits callbacks per source IP before any GitHub outbound (R7)", async () => {
    // state 検査は cookie と query の二重送信のみでサーバー側状態を持たないため、
    // 非ブラウザの発信元は両方を自分で用意して常に通せる(githubStart を経由
    // しなくてよい)。頻度を縛るのは発信元 IP のレート制限だけ、という位置関係を
    // ここで固定する。
    // 窓は wall-clock 整列の固定窓(30/60s): 逐次では 1 窓に収まらずフレークする
    // ため、並列バーストで 2 窓 + 2 発(62 リクエスト)を数秒に収める
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
        // 制限前は通常の 400(code-exchange-failed)
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
    // 別 IP は独立に数えられる(帰属単位の固定)
    const other = await SELF.fetch(`${BASE}/auth/github/callback?code=not-a-code&state=${state}`, {
      headers: { cookie: `${STATE_COOKIE}=${state}`, "cf-connecting-ip": "203.0.113.10" },
      redirect: "manual",
    });
    expect(other.status).toBe(400);
  }, 60_000);
});

/** D1 に保存された実フロー署名鍵(初回 start で自動生成される)を読む。 */
async function flowSigningKeyFromDb(): Promise<CryptoKey> {
  const row = await env.DB.prepare("SELECT key_hex FROM flow_signing_keys").first<{
    key_hex: string;
  }>();
  if (row === null) {
    throw new Error("no flow signing key in D1");
  }
  return importFlowSigningKey(row.key_hex);
}

/** ワイヤ形式は満たすが実在しないフロー資格(レート制限テスト等のダミー)。 */
const DUMMY_FLOW_ID = "ab".repeat(16);

/** 固定 IP からの start 1 発(レート制限テストのバースト単位)。 */
const startAttempt = (): Promise<Response> =>
  SELF.fetch(`${BASE}/auth/cli/start`, {
    method: "POST",
    headers: { ...JSON_HEADERS, "cf-connecting-ip": "203.0.113.7" },
    body: JSON.stringify({}),
  });

/** 任意 payload での start(ワイヤ境界テスト用 — IP 帰属なし = 制限対象外)。 */
const startWithPayload = (payload: unknown): Promise<Response> =>
  SELF.fetch(`${BASE}/auth/cli/start`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(payload),
  });

describe("CLI ログイン(AUTH_SPEC §4 — サーバー仲介 web-flow ハンドオフ)", () => {
  it("start → verify → callback → approve → poll で PAT を単回発行する(§4-1 正常系)", async () => {
    await seedUser("user-cli-0001", 901);
    const started = await startCliFlow({
      tokenName: "cli-test",
      scopes: [{ project: "*", permission: "read" }],
      expiresInDays: 30,
    });
    expect(started.flowId).toMatch(/^[0-9a-f]{32}$/);
    expect(started.userCode).toMatch(/^[0-9A-Z]{4}-[0-9A-Z]{4}$/);
    // flowToken はブラウザチャネル(verificationUrl)に載らない(§4-1 (1))
    expect(started.verificationUrl).not.toContain(started.flowToken);
    // start は無記録(裁定 DH): フロー行もユーザー系イベントも生まれない
    const flowsAfterStart = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM cli_login_flows",
    ).first<{ n: number }>();
    expect(flowsAfterStart?.n).toBe(0);
    // ブラウザ脚未到達の poll は型付き pending(行なし = 正常系 — §4-1 (5))
    const early = await pollCliFlow(started.flowId, started.flowToken);
    expect(early.status).toBe(200);
    expect(((await early.json()) as { status: string }).status).toBe("pending");

    // ブラウザ脚: 承認ページ(スクリプトなし — §4-1 (4)。§15-3 と同じ配信規律)
    const callback = await cliBrowserLeg(started.verificationUrl, 901);
    expect(callback.status).toBe(200);
    expect(callback.headers.get("content-security-policy")).toContain("script-src 'none'");
    // クリックジャッキング防御: 承認ページは iframe 埋め込み不可(default-src は
    // frame-ancestors にフォールバックしないため、明示の存在を固定する)
    expect(callback.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(callback.headers.get("x-frame-options")).toBe("DENY");
    expect(callback.headers.get("referrer-policy")).toBe("no-referrer");
    const html = await callback.text();
    expect(html).toContain(started.userCode);
    // 認証済みアイデンティティと付与内容の表示
    expect(html).toContain("user901");
    expect(html).toContain("cli-test");
    expect(html).toContain("read");
    expect(html).toContain("30");
    // flowToken はページにも現れない(§4-1 (1))
    expect(html).not.toContain(started.flowToken);
    const ticket = approvalTicketOf(html);

    // 承認までは pending のまま
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

    // 発行パラメータは start で確定した値(§4-1 (1)/(4) — 行の保持値で発行)
    const row = await env.DB.prepare(
      "SELECT name, scopes, expires_at, created_at FROM api_tokens WHERE id = ?",
    )
      .bind(body.tokenId)
      .first<{ name: string; scopes: string; expires_at: number; created_at: number }>();
    expect(row?.name).toBe("cli-test");
    expect(JSON.parse(row?.scopes ?? "[]")).toEqual([{ project: "*", permission: "read" }]);
    expect(row?.expires_at).toBe((row?.created_at ?? 0) + 30 * 24 * 60 * 60 * 1000);
    expect(body.expiresAtMs).toBe(row?.expires_at);

    // DB には生値は存在しない(ハッシュのみ。§6)
    const raw = await env.DB.prepare("SELECT id FROM api_tokens WHERE token_hash = ?")
      .bind(body.token)
      .first();
    expect(raw).toBeNull();

    const me = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(body.token) });
    expect(me.status).toBe(200);
    expect(((await me.json()) as { userId: string }).userId).toBe("user-cli-0001");

    // 単回発行: 消費済みフローへの再 poll は一様拒否(§4-2)
    const again = await pollCliFlow(started.flowId, started.flowToken);
    expect(again.status).toBe(400);
    expect(((await again.json()) as Record<string, unknown>)["_tag"]).toBe("CliFlowRejected");
  });

  it("rate-limits start per source IP (§4-1 (1))", async () => {
    // CF-Connecting-IP は本番エッジが上書き付与するヘッダー。テストでは明示して
    // 発信元を固定する(不在の直接到達は帰属不能として制限対象外)。窓は
    // wall-clock 整列の固定窓(10/60s): 2 窓 + 2 発(22 リクエスト)を並列
    // バーストで送り、フレークしない形で 429 を観測する
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
    // 別 IP は独立に数えられる(帰属単位の固定)
    const other = await SELF.fetch(`${BASE}/auth/cli/start`, {
      method: "POST",
      headers: { ...JSON_HEADERS, "cf-connecting-ip": "203.0.113.8" },
      body: JSON.stringify({}),
    });
    expect(other.status).toBe(200);
  }, 60_000);

  it("rate-limits poll per source IP before any verification (§4-1 (5))", async () => {
    // 検証前に制限する = でっち上げの資格でも CPU を消費させない。窓 30/60s:
    // 2 窓 + 2 発(62 リクエスト)の並列バースト
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
        // 制限前は一様拒否(資格不一致の 400)
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
    // ローテーションは delete + insert の atomic batch(+ UNIQUE (user_id, name))。
    // 並行ハンドオフ(別フロー・同名)でも同名トークンが複数残らない
    await Promise.all([cliToken(203), cliToken(203), cliToken(203)]);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM api_tokens").first<{
      n: number;
    }>();
    expect(count?.n).toBe(1);
  });

  it("rejects issuing beyond the per-user token limit with 429 (§6)", async () => {
    // 上限 100 本(別名)。101 本目の新名は poll の発行段で 429、同名ローテー
    // ションは引き続き可能(発行規律は §6 のまま — CLI ハンドオフは呼び出し元)
    const seed = await cliIssue(204, { tokenName: "seed" });
    // 残り 99 本ぶんを直接シードして上限到達状態を作る
    const rows = Array.from({ length: 99 }, (_, i) =>
      env.DB.prepare(
        "INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, scopes, expires_at, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, '[]', NULL, 1, NULL)",
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
    // CAS 成功後の発行失敗は consumed のまま終わる(fail-closed — 半配布を
    // 残さない)。再 poll は一様拒否で、CLI は再ログインする
    const retry = await pollCliFlow(started.flowId, started.flowToken);
    expect(retry.status).toBe(400);
    expect(((await retry.json()) as Record<string, unknown>)["_tag"]).toBe("CliFlowRejected");

    // 同名(既存 "seed")のローテーションは上限に達していても通る
    const rotated = await cliIssue(204, { tokenName: "seed" });
    expect(rotated.userId).toBe(seed.userId);
  });

  it("admits exactly the remaining slot under concurrent distinct-name issuance (S7)", async () => {
    const seed = await cliIssue(206, { tokenName: "seed" });
    const userId = seed.userId;
    // 上限100の残り1枠まで直接シード。異名なので UNIQUE(user_id,name)では
    // 競合せず、admissionが非原子的なら8件すべて入ってしまう
    await env.DB.batch(
      Array.from({ length: 98 }, (_, index) =>
        env.DB.prepare(
          "INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, scopes, expires_at, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, '[]', NULL, 1, NULL)",
        ).bind(
          `race-seed-${index}`,
          userId,
          `race-filler-${index}`,
          `race-hash-${index}`,
          "maruhi_pat_x",
        ),
      ),
    );

    // 異名の承認済みフローを 8 本用意し、発行段(poll)だけを同時に競わせる
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
    // scopes 要素数上限(100)超過
    const tooManyScopes = await startWithPayload({
      scopes: Array.from({ length: 101 }, () => ({ project: "*", permission: "read" })),
    });
    expect(tooManyScopes.status).toBe(400);

    // project はプロジェクト ID 形式(hex 64)か "*" のみ
    const badProject = await startWithPayload({
      scopes: [{ project: "x".repeat(500_000), permission: "read" }],
    });
    expect(badProject.status).toBe(400);

    // tokenName 上限(128 文字)超過
    expect((await startWithPayload({ tokenName: "n".repeat(129) })).status).toBe(400);

    // tokenName の制御文字・双方向制御文字は受理時拒否(§6 — 承認ページに
    // 到達する前のワイヤ境界で落とす。非遡及 = 既存行はマイグレーションしない)
    expect((await startWithPayload({ tokenName: "evil\u0007name" })).status).toBe(400);
    expect((await startWithPayload({ tokenName: "evil\u202Ename" })).status).toBe(400);
  });

  it("rejects a mix-and-match poll: victim flowId with the attacker's own flowToken (§4-1 (1))", async () => {
    // flowToken の MAC は flowId を署名対象に含む — 「他人の flowId + 自前の
    // flowToken」の組み替えは資格不一致の一様拒否になる(§4-2)
    const victim = await startCliFlow();
    const attacker = await startCliFlow();
    const response = await pollCliFlow(victim.flowId, attacker.flowToken);
    expect(response.status).toBe(400);
    expect(((await response.json()) as Record<string, unknown>)["_tag"]).toBe("CliFlowRejected");
  });

  it("rejects a tampered flowToken uniformly (§4-2)", async () => {
    const started = await startCliFlow();
    // MAC 末尾 1 文字の改竄
    const flipped = started.flowToken.endsWith("0") ? "1" : "0";
    const tampered = started.flowToken.slice(0, -1) + flipped;
    const macBroken = await pollCliFlow(started.flowId, tampered);
    expect(macBroken.status).toBe(400);
    expect(((await macBroken.json()) as Record<string, unknown>)["_tag"]).toBe("CliFlowRejected");
    // 自己申告の期限を伸ばす改竄も MAC で落ちる(期限判定は MAC の後 — 署名済み
    // の値しか信じない)
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
    // 正規の署名鍵で期限だけ過去の flowToken を作る = 「MAC は正しいが期限切れ」
    // の正当な保持者。組み替え(invalid)とは型で出し分ける
    const started = await startCliFlow();
    const key = await flowSigningKeyFromDb();
    const expiredToken = await createFlowToken(key, started.flowId, Date.now() - 1_000);
    const response = await pollCliFlow(started.flowId, expiredToken);
    expect(response.status).toBe(410);
    expect(((await response.json()) as Record<string, unknown>)["_tag"]).toBe("CliFlowExpired");
  });

  it("rejects a tampered verificationUrl before redirecting to GitHub (§4-1 (3))", async () => {
    const started = await startCliFlow({ tokenName: "honest" });
    // 発行パラメータの掏り替え(tokenName)は vsig で落ち、GitHub への
    // リダイレクトは起きない(一様なスクリプトなしエラーページ — §4-2)
    const url = new URL(started.verificationUrl);
    url.searchParams.set("name", "sneaky");
    const tampered = await SELF.fetch(url.toString(), { redirect: "manual" });
    expect(tampered.status).toBe(400);
    expect(tampered.headers.get("location")).toBeNull();
    expect(tampered.headers.get("content-type")).toContain("text/html");
    expect(tampered.headers.get("content-security-policy")).toContain("script-src 'none'");
    // vsig の欠落も同じ一様ページ(欠落と改竄を出し分けない)
    const bare = new URL(started.verificationUrl);
    bare.searchParams.delete("vsig");
    const missing = await SELF.fetch(bare.toString(), { redirect: "manual" });
    expect(missing.status).toBe(400);
    expect(missing.headers.get("location")).toBeNull();
  });

  it("rejects an expired verificationUrl with the same uniform page (§4-2)", async () => {
    // 正規の鍵で署名された期限切れ URL(vsig は正しい)も verify で fail-closed
    // (鍵は先行 start の初回生成に依存する — ここで 1 回起こす)
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
    // 「一様ページ」の実体まで固定する: 改竄経路(上のテスト)と同じ HTML +
    // 同じ CSP であること — 期限切れだけが型付き JSON 等へ逸れたら破れ
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(response.headers.get("content-security-policy")).toContain("script-src 'none'");
  });

  it("shows the signup guidance page for an unknown account with zero side effects (裁定 DH)", async () => {
    // CLI ログインは既存アカウント専用(get-or-create しない)。不在は案内ページ
    // で終了し、ユーザー作成もフロー行作成も起きない — 再開リンクだけを載せる
    const started = await startCliFlow();
    const callback = await cliBrowserLeg(started.verificationUrl, 908);
    expect(callback.status).toBe(200);
    expect(callback.headers.get("content-security-policy")).toContain("script-src 'none'");
    const html = await callback.text();
    expect(html).toContain("No maruhi account yet");
    expect(html).toContain("/auth/github/start");
    // 再開リンクは verificationUrl(vsig 済みパラメータの復元)
    expect(html).toContain(`flow=${started.flowId}`);
    // flowToken はブラウザチャネルに決して現れない(§4-1 (1))
    expect(html).not.toContain(started.flowToken);
    const users = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first<{ n: number }>();
    expect(users?.n).toBe(0);
    const flows = await env.DB.prepare("SELECT COUNT(*) AS n FROM cli_login_flows").first<{
      n: number;
    }>();
    expect(flows?.n).toBe(0);
    // 案内どおり Web でサインアップした後、同じ verificationUrl から再開できる
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

    // 別 user_id の再到達は一様エラー(乗っ取りにもチケット失効 DoS にも
    // させない — チケットは回転しない)
    const hijack = await cliBrowserLeg(started.verificationUrl, 912);
    expect(hijack.status).toBe(400);
    expect(await hijack.text()).toContain("This sign-in link can&#39;t be used");

    // 元のユーザーのチケットはそのまま有効で、承認 → 発行まで完走できる
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

    // 同一 user_id の再到達はべき等: 承認ページを再描画し、チケットを置換する
    const again = await cliBrowserLeg(started.verificationUrl, 916);
    expect(again.status).toBe(200);
    const freshTicket = approvalTicketOf(await again.text());
    expect(freshTicket).not.toBe(staleTicket);

    // 有効なチケットは常に最新 1 枚(置換で旧チケットは失効)
    const stale = await approveCliFlow(started.flowId, staleTicket);
    expect(stale.status).toBe(400);
    // 失敗した承認はフローを進めない(awaiting のまま = poll は pending)
    const pending = await pollCliFlow(started.flowId, started.flowToken);
    expect(((await pending.json()) as { status: string }).status).toBe("pending");
    expect((await approveCliFlow(started.flowId, freshTicket)).status).toBe(200);
  });

  it("reports an explicit denial to the CLI as a typed denied status (§4-1 (4) (iv))", async () => {
    await seedUser("user-cli-deny", 913);
    const started = await startCliFlow();
    const page = await cliBrowserLeg(started.verificationUrl, 913);
    const ticket = approvalTicketOf(await page.text());
    const deny = await approveCliFlow(started.flowId, ticket, "deny");
    expect(deny.status).toBe(200);
    expect(await deny.text()).toContain("Sign-in denied");
    // denied は正当な flowToken 保持者への型付き状態(§4-2 — 新情報を運ばない)
    const poll = await pollCliFlow(started.flowId, started.flowToken);
    expect(poll.status).toBe(200);
    expect(((await poll.json()) as { status: string }).status).toBe("denied");
    // 拒否済みフローのチケット再使用(承認への裏返し)は一様エラー
    const reuse = await approveCliFlow(started.flowId, ticket);
    expect(reuse.status).toBe(400);
    // 拒否ではトークンは 1 本も生まれない
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

    // flowToken は 1 プロセスに束縛されない bearer — 並行 poll は想定内の入力。
    // consumed への CAS 勝者だけが発行する(二重配布の構造的排除)
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
    // resetAuthDb が鍵も消している = ここが正真の初回使用。並行 start が別々の
    // 候補鍵を書き合っても先勝ち(INSERT OR IGNORE)+ 読み戻しで同じ保存鍵に
    // 収束する — 敗者候補の鍵で署名された(検証不能な)フローが生まれない
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
    // 未消費行を上限 − 1 まで直接シード(実経路での到達には「既存アカウント ×
    // OAuth 完走」の同時併走が上限件数ぶん必要で、テストでは行を直接作る)。
    // 境界は両側から固定する: N 本目(実経路の createOrMatch)は受け入れられ、
    // N+1 本目が拒否される — オフバイワンと「常に拒否」の両方の破れを検知する
    await env.DB.prepare(
      `WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?)
       INSERT INTO cli_login_flows (id, user_id, status, token_name, scopes, expires_in_days, user_code, ticket_hash, expires_at, created_at)
       SELECT printf('cap%029d', n), ?, 'awaiting', 'filler', '[]', 30, 'AAAA-AAAA', printf('%064d', n), ?, ?
       FROM seq`,
    )
      .bind(MAX_CONCURRENT_CLI_FLOWS - 1, "user-cli-cap", Date.now() + CLI_FLOW_TTL_MS, Date.now())
      .run();

    // N 本目: capAvailable ガードの条件付き INSERT を実経路で通り、承認ページに至る
    const atCap = await startCliFlow();
    const admitted = await cliBrowserLeg(atCap.verificationUrl, 915);
    expect(admitted.status).toBe(200);
    const afterAdmit = await env.DB.prepare("SELECT COUNT(*) AS n FROM cli_login_flows").first<{
      n: number;
    }>();
    expect(afterAdmit?.n).toBe(MAX_CONCURRENT_CLI_FLOWS);

    // N+1 本目: capacity も一様エラーページ(§4-2 — 上限到達を出し分けない)
    const overCap = await startCliFlow();
    const callback = await cliBrowserLeg(overCap.verificationUrl, 915);
    expect(callback.status).toBe(400);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM cli_login_flows").first<{
      n: number;
    }>();
    expect(count?.n).toBe(MAX_CONCURRENT_CLI_FLOWS);
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
    const token = await cliToken(303);
    await env.DB.prepare("UPDATE api_tokens SET expires_at = 1").run();
    const response = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(token) });
    expect(response.status).toBe(401);
  });
});

describe("資格情報の優先順位(Authorization ヘッダーが常に優先)", () => {
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
    // トークン + クッキー同時提示の書き込み(CSRF ヘッダーなし)が通る =
    // 主体はトークン(クロスサイトから Authorization は付与できないため安全)
    const session = await loginSession(314);
    const token = await cliToken(315);
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
    const token = await cliToken(406);
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

describe("POST /auth/token/revoke(§6: 自トークンの失効)", () => {
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
    const token = await cliToken(604);
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
    // テスト既定のバインディングはサーバー鍵も設定済み(リース経路 §14 の
    // テストが実鍵を要するため — vitest.config.ts)。client_id が未認証で
    // 返ることがこのテストの主題であり、鍵の公開面は下の describe が固定する
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["githubClientId"]).toBe(env.GITHUB_CLIENT_ID);
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
    // cliStart もフロー資格の発行より先に fail-closed する(§4-1 (1) — 未設定
    // サーバーで CLI を verificationUrl のエラーページまで歩かせない)
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
    // 既定バインディングは設定済みなので、未設定デプロイメントは env から
    // SERVER_ENC_KEY_IKM を落として組み立てる(secret を欠いたデプロイ = 実行時 undefined)
    const { SERVER_ENC_KEY_IKM: _omitted, ...withoutKey } = env;
    const response = await worker.fetch(incoming(`${BASE}/auth/config`), withoutKey as typeof env);
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

describe("共通セキュリティヘッダー(index.ts withSecurityHeaders — セキュリティレビュー L-5)", () => {
  it("attaches nosniff / no-store / HSTS to every API response, including errors", async () => {
    // 応答にはトークン生値・暗号文・ラップが載る経路があるため、全応答に
    // nosniff + no-store を付与する。HSTS は API worker にも custom domain を
    // routes で割り当てうるため(セッションクッキー・OAuth フローを持つ
    // オリジン)、web の _headers と同様に付ける
    const response = await SELF.fetch(`${BASE}/auth/config`);
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("strict-transport-security")).toBe("max-age=31536000");
    // エラー応答(未認証 401)にも同じヘッダーが付く
    const unauthorized = await SELF.fetch(`${BASE}/auth/me`);
    expect(unauthorized.status).toBe(401);
    expect(unauthorized.headers.get("x-content-type-options")).toBe("nosniff");
    expect(unauthorized.headers.get("cache-control")).toBe("no-store");
    expect(unauthorized.headers.get("strict-transport-security")).toBe("max-age=31536000");
  });

  it("attaches the headers to the pre-router 413 path too (capRequestBody)", async () => {
    // HTTP 境界の生ボディ上限(8 MiB)超過はルーター前の素の 413 で返る。
    // この経路も withSecurityHeaders を通ることを固定する
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
