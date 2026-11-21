import type { TokenScope } from "@maruhi/core";
import { cryptoServicesLayer } from "@maruhi/core";
import { applyD1Migrations, env, SELF } from "cloudflare:test";
import { Effect } from "effect";
import { Digest, SecureRandom } from "effect/crypto";

import { randomBase62, sha256Hex, ulid } from "../../src/ids.ts";

const runIds = (
  effect: Effect.Effect<string, never, SecureRandom.SecureRandom | Digest.Digest>,
): Promise<string> => Effect.runPromise(effect.pipe(Effect.provide(cryptoServicesLayer)));

export const BASE = "https://example.com";
export const JSON_HEADERS = { "content-type": "application/json" };
const FORM_HEADERS = { "content-type": "application/x-www-form-urlencoded" };
export const CSRF_HEADERS = { "x-maruhi-csrf": "1" };
export const SESSION_COOKIE = "__Host-maruhi_session";
export const STATE_COOKIE = "__Host-maruhi_oauth_state";
export const CLI_STATE_COOKIE = "__Host-maruhi_oauth_cli";
export const SIGNUP_CODE_COOKIE = "__Host-maruhi_signup";

const AUTH_TABLES = [
  "sessions",
  "api_tokens",
  "cli_login_flows",
  "recovery_wraps",
  "devices",
  "device_add_requests",
  "key_handoff_approvals",
  "key_handoff_requests",
  "guardian_shares",
  "guardian_groups",
  "master_key_wraps",
  "key_wrap_windows",
  "memberships",
  "project_members",
  "projects",
  "linked_identities",
  "organizations",
  "users",
  "invitations",
  "user_audit_events",
  "org_audit_events",
  "login_failed_windows",
  "flow_signing_keys",
  "signup_invites",
  "deployment_settings",
  "ops_counters",
  "ops_backups",
  "ops_state",
];

const SEED_TIME_MS = 1754006400000;

export async function resetAuthDb(): Promise<void> {
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
  for (const table of AUTH_TABLES) {
    await env.DB.prepare(`DELETE FROM ${table}`).run();
  }
}

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

export async function setSignupPolicy(value: string): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO deployment_settings (key, value, updated_at) VALUES ('signup_policy', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
  )
    .bind(value, SEED_TIME_MS)
    .run();
}

export async function seedSignupInvite(options?: {
  readonly expiresAtMs?: number;
}): Promise<{ readonly id: string; readonly code: string }> {
  const id = await runIds(ulid());
  const code = `maruhi_sgn_${await runIds(randomBase62())}`;
  const tokenHash = await runIds(Effect.orDie(sha256Hex(code)));
  await env.DB.prepare(
    "INSERT INTO signup_invites (id, token_hash, status, expires_at, created_at) VALUES (?, ?, 'pending', ?, ?)",
  )
    .bind(id, tokenHash, options?.expiresAtMs ?? Date.now() + 7 * 24 * 60 * 60 * 1000, Date.now())
    .run();
  return { id, code };
}

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

export interface CliFlowStart {
  readonly flowId: string;
  readonly flowToken: string;
  readonly userCode: string;
  readonly verificationUrl: string;
  readonly expiresInSeconds: number;
  readonly pollIntervalSeconds: number;
}

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

export function approvalTicketOf(html: string): string {
  const match = /name="ticket" value="([0-9a-f]+)"/.exec(html);
  if (match?.[1] === undefined) {
    throw new Error("approval page did not contain a ticket");
  }
  return match[1];
}

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

export function pollCliFlow(flowId: string, flowToken: string): Promise<Response> {
  return SELF.fetch(`${BASE}/auth/cli/poll`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ flowId, flowToken }),
  });
}

export interface CliIssued {
  readonly token: string;
  readonly tokenId: string;
  readonly userId: string;
  readonly expiresAtMs: number;
}

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

export async function reseedAuthDb(
  githubIds: Readonly<Record<string, number>>,
  orgMember: { readonly orgId: string; readonly userId: string },
): Promise<Record<string, string>> {
  await resetAuthDb();
  const issued = await Promise.all(
    Object.entries(githubIds).map(async ([userId, githubId]) => {
      await seedUser(userId, githubId);
      return [userId, await cliToken(githubId)] as const;
    }),
  );
  await seedOrgMember(orgMember.orgId, orgMember.userId, "member");
  return Object.fromEntries(issued);
}

export function bearer(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

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

export function readCookieValue(setCookies: readonly string[], name: string): string | null {
  const found = setCookies.find((cookie) => cookie.startsWith(`${name}=`));
  if (found === undefined) {
    return null;
  }
  const [pair] = found.split(";");
  return (pair ?? "").slice(name.length + 1);
}

export function sessionHeaders(rawSession: string): Record<string, string> {
  return { cookie: `${SESSION_COOKIE}=${rawSession}`, ...CSRF_HEADERS };
}
