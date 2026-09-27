// Shared helpers for authenticated integration tests (run inside workerd).
//
// Policy (AUTH_SPEC §11-1 ruling): sessions / tokens are always obtained via
// the real issuance path (Web OAuth callback / CLI login handoff). The only
// thing that may be stubbed is the GitHub API (the outboundService fake in
// vitest.config.ts). For vector alignment, users / linked_identities are
// seeded directly into D1 with fixed IDs (the getOrCreateUser lookup path
// resolves them as existing users).

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

// Delete in FK parent-child order (invitations and the audit tables have no FK — they can go last)
const AUTH_TABLES = [
  "sessions",
  "api_tokens",
  // CLI login handoff flow rows (AUTH_SPEC §4). Has a FK to users
  "cli_login_flows",
  "recovery_wraps",
  // Device registry and device add requests (AUTH_SPEC §13-11 — DK K3). Has a FK to users
  "devices",
  "device_add_requests",
  // master key wrap ledger (AUTH_SPEC §13-6 — KL3). Child → parent order
  "key_handoff_approvals",
  "key_handoff_requests",
  "guardian_shares",
  "guardian_groups",
  "master_key_wraps",
  "key_wrap_windows",
  "memberships",
  // membership projection (AUTH_SPEC §11-5). FK-less derived cache
  "project_members",
  "projects",
  "linked_identities",
  "organizations",
  "users",
  "invitations",
  "user_audit_events",
  "org_audit_events",
  // Window counters for login_failed / signup_denied (AUDIT_SPEC §3.1 — mutable state, not audit rows)
  "login_failed_windows",
  // Also delete the flow signing key (AUTH_SPEC §4-2) = each test goes through
  // the first-time generation path (idempotent, first-come-first-served)
  "flow_signing_keys",
  // Signup control (AUTH_SPEC §3). Default is no row = signupPolicy 'open'
  "signup_invites",
  "deployment_settings",
  // Ops infrastructure (hosted-ops.md §6) — operator-only mutable state, not audit
  "ops_counters",
  "ops_backups",
  "ops_state",
];

const SEED_TIME_MS = 1754006400000;

/** Apply migrations (idempotent) + wipe all auth tables. Called from beforeEach. */
export async function resetAuthDb(): Promise<void> {
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
  for (const table of AUTH_TABLES) {
    await env.DB.prepare(`DELETE FROM ${table}`).run();
  }
}

/** Seed a user with a fixed user_id + GitHub link (vector alignment). */
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

/** Set signupPolicy (AUTH_SPEC §3 — same upsert as the ops SQL path). */
export async function setSignupPolicy(value: string): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO deployment_settings (key, value, updated_at) VALUES ('signup_policy', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
  )
    .bind(value, SEED_TIME_MS)
    .run();
}

/**
 * Seed a signup invite code (AUTH_SPEC §3 — same row shape as the issuance
 * script. Returns the raw value; only the hash goes into the DB).
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
 * The real Web signup path (start [with optional signup_code] → callback).
 * Returns the first response that ended non-302 (start's pre-validation page /
 * 429), or the callback response (success 302 / denial guidance page).
 * `betweenSteps` is for testing acceptance-time decisions (AUTH_SPEC §3) — it
 * moves settings/rows between start and callback.
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

/** Seed an org and its membership (for init's org-member-or-higher requirements). */
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

/** Response of `POST /auth/cli/start` (AUTH_SPEC §4-1 (1)). */
export interface CliFlowStart {
  readonly flowId: string;
  readonly flowToken: string;
  readonly userCode: string;
  readonly verificationUrl: string;
  readonly expiresInSeconds: number;
  readonly pollIntervalSeconds: number;
}

/** Start a CLI login flow (§4-1 (1) — unrecorded, unauthenticated). */
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
 * Browser leg (§4-1 (3)–(4)): verify → 302 to GitHub authorize → callback.
 * Returns the callback response (the approval page on the happy path / the
 * guidance page for a missing account). Cookie values are sent back as the raw
 * Set-Cookie values (same handling as a real browser). `options.code` can
 * replace the callback code (to reproduce an exchange failure).
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

/** Extract the approval ticket (hidden input) from the approval page HTML. */
export function approvalTicketOf(html: string): string {
  const match = /name="ticket" value="([0-9a-f]+)"/.exec(html);
  if (match?.[1] === undefined) {
    throw new Error("approval page did not contain a ticket");
  }
  return match[1];
}

/** POST the approval form (§4-1 (4) — the credential is the single-use ticket only). */
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

/** poll (§4-1 (5)). Response interpretation is up to the caller (pending / approved / error). */
export function pollCliFlow(flowId: string, flowToken: string): Promise<Response> {
  return SELF.fetch(`${BASE}/auth/cli/poll`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ flowId, flowToken }),
  });
}

/** The approved poll response (§4-1 (5) — the complete issuance result). */
export interface CliIssued {
  readonly token: string;
  readonly tokenId: string;
  readonly userId: string;
  readonly expiresAtMs: number;
}

/**
 * Run the CLI login handoff (real path) to completion and get the complete
 * issuance result. The GitHub side is faked (code-<id> → gho_test<id>). CLI
 * login is for existing accounts only (ruling DH), so if there is no linked
 * identity, create the account first via Web login (get-or-create).
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
 * Get a raw PAT via the CLI login handoff (real path). When `tokenName` is
 * omitted the default name is used — reissuing for the same user under the
 * same name rotates and revokes the existing token (AUTH_SPEC §6), so tests
 * that need both to coexist should pass a different name.
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

/** Get a raw session cookie via the real Web OAuth path (start → callback). */
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

/** Extract the named cookie's value from the Set-Cookie headers (null if absent). */
export function readCookieValue(setCookies: readonly string[], name: string): string | null {
  const found = setCookies.find((cookie) => cookie.startsWith(`${name}=`));
  if (found === undefined) {
    return null;
  }
  const [pair] = found.split(";");
  return (pair ?? "").slice(name.length + 1);
}

/** Request headers for session auth (includes the CSRF header for writes). */
export function sessionHeaders(rawSession: string): Record<string, string> {
  return { cookie: `${SESSION_COOKIE}=${rawSession}`, ...CSRF_HEADERS };
}
