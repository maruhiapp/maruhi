// 認証済み統合テストの共通ヘルパ(workerd 内で実行)。
//
// 方針(AUTH_SPEC §11-1 の裁定): セッション / トークンは必ず実発行経路
// (Web OAuth コールバック / device 交換)で取得する。スタブしてよいのは
// GitHub API のみ(vitest.config.ts の outboundService フェイク)。
// ベクター整合のため、users / linked_identities は固定 ID で D1 に直接シードする
// (getOrCreateUser のルックアップ経路が既存ユーザーとして解決する)。

import type { TokenScope } from "@maruhi/core";
import { applyD1Migrations, env, SELF } from "cloudflare:test";

export const BASE = "https://example.com";
export const JSON_HEADERS = { "content-type": "application/json" };
export const CSRF_HEADERS = { "x-maruhi-csrf": "1" };
export const SESSION_COOKIE = "__Host-maruhi_session";
export const STATE_COOKIE = "__Host-maruhi_oauth_state";

// FK の親子順に削除する(監査テーブルは FK なし — 末尾でよい)
const AUTH_TABLES = [
  "sessions",
  "api_tokens",
  "recovery_wraps",
  "memberships",
  "projects",
  "linked_identities",
  "organizations",
  "users",
  "user_audit_events",
  "org_audit_events",
];

const SEED_TIME_MS = 1754006400000;

/** マイグレーション適用(冪等)+ 認証系テーブルの全消去。beforeEach から呼ぶ。 */
export async function resetAuthDb(): Promise<void> {
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
  for (const table of AUTH_TABLES) {
    await env.DB.prepare(`DELETE FROM ${table}`).run();
  }
}

/** 固定 user_id のユーザー + GitHub リンクをシードする(ベクター整合)。 */
export async function seedUser(userId: string, githubId: number): Promise<void> {
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO users (id, email, email_verified, created_at, updated_at) VALUES (?, NULL, 0, ?, ?)",
    ).bind(userId, SEED_TIME_MS, SEED_TIME_MS),
    env.DB.prepare(
      "INSERT INTO linked_identities (user_id, provider, provider_user_id, provider_login, linked_at) VALUES (?, 'github', ?, ?, ?)",
    ).bind(userId, String(githubId), `user${githubId}`, SEED_TIME_MS),
  ]);
}

/** org とそのメンバーシップをシードする(init の org member 以上の要件用)。 */
export async function seedOrgMember(
  orgId: string,
  userId: string,
  role: "owner" | "admin" | "member",
): Promise<void> {
  await env.DB.batch([
    env.DB.prepare(
      "INSERT OR IGNORE INTO organizations (id, slug, name, created_at) VALUES (?, ?, ?, ?)",
    ).bind(orgId, `slug-${orgId}`, orgId, SEED_TIME_MS),
    env.DB.prepare("INSERT INTO memberships (org_id, user_id, role) VALUES (?, ?, ?)").bind(
      orgId,
      userId,
      role,
    ),
  ]);
}

/** device flow 交換(実経路)で PAT を得る。GitHub 側はフェイク(gho_test<id>)。 */
export async function deviceToken(
  githubId: number,
  scopes?: readonly TokenScope[],
): Promise<string> {
  const response = await SELF.fetch(`${BASE}/auth/device/exchange`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({
      githubAccessToken: `gho_test${githubId}`,
      ...(scopes === undefined ? {} : { scopes }),
    }),
  });
  if (response.status !== 200) {
    throw new Error(`device exchange failed: ${response.status}`);
  }
  const body = (await response.json()) as { token: string };
  return body.token;
}

export function bearer(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

/** Web OAuth の実経路(start → callback)でセッションクッキー生値を得る。 */
export async function loginSession(githubId: number): Promise<string> {
  const start = await SELF.fetch(`${BASE}/auth/github/start`, { redirect: "manual" });
  if (start.status !== 302) {
    throw new Error(`oauth start failed: ${start.status}`);
  }
  const location = start.headers.get("location") ?? "";
  const state = new URL(location).searchParams.get("state") ?? "";
  const callback = await SELF.fetch(
    `${BASE}/auth/github/callback?code=code-${githubId}&state=${state}`,
    { headers: { cookie: `${STATE_COOKIE}=${state}` }, redirect: "manual" },
  );
  if (callback.status !== 302) {
    throw new Error(`oauth callback failed: ${callback.status}`);
  }
  const session = readCookieValue(callback.headers.getSetCookie(), SESSION_COOKIE);
  if (session === null) {
    throw new Error("oauth callback did not set a session cookie");
  }
  return session;
}

/** Set-Cookie ヘッダー群から指定クッキーの値を取り出す(なければ null)。 */
export function readCookieValue(setCookies: readonly string[], name: string): string | null {
  const found = setCookies.find((cookie) => cookie.startsWith(`${name}=`));
  if (found === undefined) {
    return null;
  }
  const [pair] = found.split(";");
  return (pair ?? "").slice(name.length + 1);
}

/** セッション認証のリクエストヘッダー(書き込み系用に CSRF ヘッダー込み)。 */
export function sessionHeaders(rawSession: string): Record<string, string> {
  return { cookie: `${SESSION_COOKIE}=${rawSession}`, ...CSRF_HEADERS };
}
