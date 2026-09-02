// 認証済み統合テストの共通ヘルパ(workerd 内で実行)。
//
// 方針(AUTH_SPEC §11-1 の裁定): セッション / トークンは必ず実発行経路
// (Web OAuth コールバック / CLI ログインハンドオフ)で取得する。スタブして
// よいのは GitHub API のみ(vitest.config.ts の outboundService フェイク)。
// ベクター整合のため、users / linked_identities は固定 ID で D1 に直接シードする
// (getOrCreateUser のルックアップ経路が既存ユーザーとして解決する)。

import type { TokenScope } from "@maruhi/core";
import { applyD1Migrations, env, SELF } from "cloudflare:test";

import { randomBase62, sha256Hex, ulid } from "../../src/ids.ts";

export const BASE = "https://example.com";
export const JSON_HEADERS = { "content-type": "application/json" };
const FORM_HEADERS = { "content-type": "application/x-www-form-urlencoded" };
export const CSRF_HEADERS = { "x-maruhi-csrf": "1" };
export const SESSION_COOKIE = "__Host-maruhi_session";
export const STATE_COOKIE = "__Host-maruhi_oauth_state";
export const CLI_STATE_COOKIE = "__Host-maruhi_oauth_cli";
export const SIGNUP_CODE_COOKIE = "__Host-maruhi_signup";

// FK の親子順に削除する(invitations・監査テーブルは FK なし — 末尾でよい)
const AUTH_TABLES = [
  "sessions",
  "api_tokens",
  // CLI ログインハンドオフのフロー行(AUTH_SPEC §4)。users への FK を持つ
  "cli_login_flows",
  "recovery_wraps",
  "memberships",
  // membership 投影(AUTH_SPEC §11-5)。FK なしの導出キャッシュ
  "project_members",
  "projects",
  "linked_identities",
  "organizations",
  "users",
  "invitations",
  "user_audit_events",
  "org_audit_events",
  // login_failed / signup_denied の窓カウンタ(AUDIT_SPEC §3.1 — 監査行ではない可変状態)
  "login_failed_windows",
  // フロー署名鍵(AUTH_SPEC §4-2)も消す = 各テストが初回生成(冪等・先勝ち)
  // 経路を通る
  "flow_signing_keys",
  // サインアップ制御(AUTH_SPEC §3 — H1)。既定は行なし = signupPolicy 'open'
  "signup_invites",
  "deployment_settings",
  // 運用基盤 H3(hosted-ops.md §6)— 監査ではない運営限定の可変状態
  "ops_counters",
  "ops_backups",
  "ops_state",
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

/** signupPolicy の設定(AUTH_SPEC §3 — 運営の SQL 経路と同じ upsert)。 */
export async function setSignupPolicy(value: string): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO deployment_settings (key, value, updated_at) VALUES ('signup_policy', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
  )
    .bind(value, SEED_TIME_MS)
    .run();
}

/**
 * サインアップ招待コードのシード(AUTH_SPEC §3 — 発行スクリプトと同じ行形。
 * 生値を返し、DB にはハッシュのみ入る)。
 */
export async function seedSignupInvite(options?: {
  readonly expiresAtMs?: number;
}): Promise<{ readonly id: string; readonly code: string }> {
  const id = ulid();
  const code = `maruhi_sgn_${randomBase62()}`;
  const tokenHash = await sha256Hex(code);
  await env.DB.prepare(
    "INSERT INTO signup_invites (id, token_hash, status, expires_at, created_at) VALUES (?, ?, 'pending', ?, ?)",
  )
    .bind(id, tokenHash, options?.expiresAtMs ?? Date.now() + 7 * 24 * 60 * 60 * 1000, Date.now())
    .run();
  return { id, code };
}

/**
 * Web サインアップの実経路(start〔省略可の signup_code つき〕→ callback)。
 * 戻り値は最初に非 302 で終わった応答(start の事前検証ページ / 429)か、
 * callback の応答(成功 302 / 拒否の案内ページ)。`betweenSteps` は受理時点
 * 判定(AUTH_SPEC §3)の検査用 — start と callback の間に設定・行を動かす。
 */
export async function signupAttempt(
  githubId: number,
  options?: {
    readonly signupCode?: string;
    readonly betweenSteps?: () => Promise<void>;
  },
): Promise<Response> {
  const startUrl =
    options?.signupCode === undefined
      ? `${BASE}/auth/github/start`
      : `${BASE}/auth/github/start?signup_code=${options.signupCode}`;
  const start = await SELF.fetch(startUrl, { redirect: "manual" });
  if (start.status !== 302) {
    return start;
  }
  const state = new URL(start.headers.get("location") ?? "").searchParams.get("state") ?? "";
  const setCookies = start.headers.getSetCookie();
  const signupCookie = readCookieValue(setCookies, SIGNUP_CODE_COOKIE);
  const cookie = [
    `${STATE_COOKIE}=${state}`,
    ...(signupCookie === null ? [] : [`${SIGNUP_CODE_COOKIE}=${signupCookie}`]),
  ].join("; ");
  await options?.betweenSteps?.();
  return SELF.fetch(`${BASE}/auth/github/callback?code=code-${githubId}&state=${state}`, {
    headers: { cookie },
    redirect: "manual",
  });
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

/** `POST /auth/cli/start` の応答(AUTH_SPEC §4-1 (1))。 */
export interface CliFlowStart {
  readonly flowId: string;
  readonly flowToken: string;
  readonly userCode: string;
  readonly verificationUrl: string;
  readonly expiresInSeconds: number;
  readonly pollIntervalSeconds: number;
}

/** CLI ログインフローの開始(§4-1 (1) — 無記録・未認証)。 */
export async function startCliFlow(payload?: {
  readonly tokenName?: string;
  readonly scopes?: readonly TokenScope[];
  readonly expiresInDays?: number;
}): Promise<CliFlowStart> {
  const response = await SELF.fetch(`${BASE}/auth/cli/start`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(payload ?? {}),
  });
  if (response.status !== 200) {
    throw new Error(`cli start failed: ${response.status}`);
  }
  return (await response.json()) as CliFlowStart;
}

/**
 * ブラウザ脚(§4-1 (3)〜(4)): verify → GitHub authorize への 302 → callback。
 * 戻り値は callback の応答(正常系は承認ページ / 不在アカウントは案内ページ)。
 * クッキー値は Set-Cookie の生値をそのまま返送する(実ブラウザと同じ扱い)。
 * `options.code` で callback の code を差し替えられる(交換失敗の再現用)。
 */
export async function cliBrowserLeg(
  verificationUrl: string,
  githubId: number,
  options?: { readonly code?: string },
): Promise<Response> {
  const verify = await SELF.fetch(verificationUrl, { redirect: "manual" });
  if (verify.status !== 302) {
    throw new Error(`cli verify failed: ${verify.status}`);
  }
  const state = new URL(verify.headers.get("location") ?? "").searchParams.get("state") ?? "";
  const bound = readCookieValue(verify.headers.getSetCookie(), CLI_STATE_COOKIE);
  if (bound === null) {
    throw new Error("cli verify did not set the flow-binding cookie");
  }
  const code = options?.code ?? `code-${githubId}`;
  return SELF.fetch(`${BASE}/auth/github/callback?code=${code}&state=${state}`, {
    headers: { cookie: `${CLI_STATE_COOKIE}=${bound}` },
    redirect: "manual",
  });
}

/** 承認ページ HTML から承認チケット(hidden input)を取り出す。 */
export function approvalTicketOf(html: string): string {
  const match = /name="ticket" value="([0-9a-f]+)"/.exec(html);
  if (match?.[1] === undefined) {
    throw new Error("approval page did not contain a ticket");
  }
  return match[1];
}

/** 承認フォームの POST(§4-1 (4) — 資格は単回チケットのみ)。 */
export function approveCliFlow(
  flowId: string,
  ticket: string,
  decision: "approve" | "deny" = "approve",
): Promise<Response> {
  return SELF.fetch(`${BASE}/auth/cli/approve`, {
    method: "POST",
    headers: FORM_HEADERS,
    body: new URLSearchParams({ flowId, ticket, decision }).toString(),
  });
}

/** poll(§4-1 (5))。応答の解釈は呼び出し側(pending / approved / エラー)。 */
export function pollCliFlow(flowId: string, flowToken: string): Promise<Response> {
  return SELF.fetch(`${BASE}/auth/cli/poll`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ flowId, flowToken }),
  });
}

/** poll の approved 応答(§4-1 (5) — 発行結果の完全形)。 */
export interface CliIssued {
  readonly token: string;
  readonly tokenId: string;
  readonly userId: string;
  readonly expiresAtMs: number;
}

/**
 * CLI ログインハンドオフ(実経路)を完走して発行結果の完全形を得る。GitHub 側は
 * フェイク(code-<id> → gho_test<id>)。CLI ログインは既存アカウント専用
 * (裁定 DH)なので、リンク済みアイデンティティが無ければ先に Web ログイン
 * (get-or-create)でアカウントを作る。
 */
export async function cliIssue(
  githubId: number,
  payload?: {
    readonly tokenName?: string;
    readonly scopes?: readonly TokenScope[];
    readonly expiresInDays?: number;
  },
): Promise<CliIssued> {
  const linked = await env.DB.prepare(
    "SELECT user_id FROM linked_identities WHERE provider = 'github' AND provider_user_id = ?",
  )
    .bind(String(githubId))
    .first();
  if (linked === null) {
    await loginSession(githubId);
  }
  const started = await startCliFlow(payload);
  const callback = await cliBrowserLeg(started.verificationUrl, githubId);
  if (callback.status !== 200) {
    throw new Error(`cli callback failed: ${callback.status}`);
  }
  const ticket = approvalTicketOf(await callback.text());
  const approve = await approveCliFlow(started.flowId, ticket);
  if (approve.status !== 200) {
    throw new Error(`cli approve failed: ${approve.status}`);
  }
  const poll = await pollCliFlow(started.flowId, started.flowToken);
  if (poll.status !== 200) {
    throw new Error(`cli poll failed: ${poll.status}`);
  }
  const body = (await poll.json()) as { status: string } & Partial<CliIssued>;
  if (body.status !== "approved" || body.token === undefined) {
    throw new Error(`cli poll did not issue a token: ${body.status}`);
  }
  return body as CliIssued;
}

/**
 * CLI ログインハンドオフ(実経路)で PAT 生値を得る。`tokenName` 省略時は
 * 既定名 — 同一ユーザーへの再発行は同名ローテーションで既存トークンを失効
 * させる(AUTH_SPEC §6)ため、併存させたいテストは別名を渡す。
 */
export async function cliToken(
  githubId: number,
  scopes?: readonly TokenScope[],
  tokenName?: string,
): Promise<string> {
  const issued = await cliIssue(githubId, {
    ...(scopes === undefined ? {} : { scopes }),
    ...(tokenName === undefined ? {} : { tokenName }),
  });
  return issued.token;
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
