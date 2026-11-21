import { decodeOrgId } from "@maruhi/core";
import { testUserId } from "@maruhi/crypto/test-support";
import { env, SELF } from "cloudflare:test";
import { Cause, Context, Effect, Exit } from "effect";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import {
  D1AuditRepo,
  LOGIN_FAILED_WINDOW_LIMIT,
  LOGIN_FAILED_WINDOW_MS,
  makeDbServices,
  ProjectRepo,
  TokenRepo,
} from "../src/db.package/index.ts";
import {
  BASE,
  bearer,
  cliBrowserLeg,
  cliToken,
  JSON_HEADERS,
  loginSession,
  resetAuthDb,
  seedOrgMember,
  seedUser,
  sessionHeaders,
  startCliFlow,
  STATE_COOKIE,
} from "./support/auth.ts";
import { toWireEntry, vectorEntries, vectorProjectId } from "./support/chain-vectors.ts";
import { testProjectId } from "./support/data-crypto.ts";
import { resetProjectDo } from "./support/project-do.ts";

interface AuditRow {
  readonly seq: number;
  readonly server_ts: number;
  readonly event: string;
  readonly actor_type: string;
  readonly actor_user_id: string | null;
  readonly actor_api_token_id: string | null;
  readonly target_user_id: string | null;
  readonly org_id: string | null;
  readonly project_id: string | null;
  readonly payload: string | null;
}

async function auditRows(table: "user_audit_events" | "org_audit_events"): Promise<AuditRow[]> {
  const result = await env.DB.prepare(`SELECT * FROM ${table} ORDER BY seq`).all<AuditRow>();
  return result.results;
}

function payloadOf(row: AuditRow): Record<string, unknown> {
  return row.payload === null ? {} : (JSON.parse(row.payload) as Record<string, unknown>);
}

async function countEvent(event: string): Promise<number | undefined> {
  const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM user_audit_events WHERE event = ?")
    .bind(event)
    .first<{ n: number }>();
  return row?.n;
}

async function seedLoginFailedWindow(
  authMethod: "github_oauth" | "cli_handoff",
  reason: string,
  windowStart: number,
  recordedCount: number,
): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO login_failed_windows (bucket, window_start, recorded_count, suppressed_count) VALUES (?, ?, ?, 0) ON CONFLICT(bucket) DO UPDATE SET window_start = excluded.window_start, recorded_count = excluded.recorded_count, suppressed_count = 0",
  )
    .bind(JSON.stringify([authMethod, reason]), windowStart, recordedCount)
    .run();
}

function callbackFailure(): Promise<Response> {
  return SELF.fetch(`${BASE}/auth/github/callback?code=code-700&state=${"ab".repeat(16)}`, {
    redirect: "manual",
  });
}

beforeEach(async () => {
  await resetAuthDb();
});

describe("Web OAuth login (§3.1)", () => {
  it("records signup + login events in one flow (user_created / identity_linked / org.* / login_succeeded)", async () => {
    await loginSession(700);
    const userId = (await env.DB.prepare("SELECT id FROM users").first<{ id: string }>())?.id;
    expect(userId).toBeDefined();

    const events = await auditRows("user_audit_events");
    expect(events.map((row) => row.event)).toEqual([
      "auth.user_created",
      "auth.identity_linked",
      "auth.login_succeeded",
    ]);
    for (const row of events) {
      expect(row.actor_type).toBe("user");
      expect(row.actor_user_id).toBe(userId);
    }
    expect(payloadOf(events[1] as AuditRow)).toEqual({ provider: "github" });
    const login = payloadOf(events[2] as AuditRow);
    expect(login["authMethod"]).toBe("github_oauth");
    const sessionRow = await env.DB.prepare("SELECT id FROM sessions").first<{ id: string }>();
    expect(login["sessionId"]).toBe(sessionRow?.id);

    const orgId = (await env.DB.prepare("SELECT id FROM organizations").first<{ id: string }>())
      ?.id;
    const orgEvents = await auditRows("org_audit_events");
    expect(orgEvents.map((row) => [row.event, row.org_id, row.target_user_id])).toEqual([
      ["org.created", orgId, null],
      ["org.member_added", orgId, userId],
    ]);
    expect(payloadOf(orgEvents[0] as AuditRow)).toEqual({ personal: true });
    expect(payloadOf(orgEvents[1] as AuditRow)).toEqual({ role: "owner" });
  });

  it("records only login_succeeded on a repeat login (get-or-create resolves the same user)", async () => {
    await loginSession(700);
    await loginSession(700);
    const events = await auditRows("user_audit_events");
    expect(events.filter((row) => row.event === "auth.user_created")).toHaveLength(1);
    expect(events.filter((row) => row.event === "auth.login_succeeded")).toHaveLength(2);
    expect(await auditRows("org_audit_events")).toHaveLength(2);
  });

  it("records auth.login_failed with the reason only (state mismatch / bad code)", async () => {
    const mismatch = await SELF.fetch(
      `${BASE}/auth/github/callback?code=code-700&state=${"ab".repeat(16)}`,
      { redirect: "manual" },
    );
    expect(mismatch.status).toBe(400);
    const start = await SELF.fetch(`${BASE}/auth/github/start`, { redirect: "manual" });
    const state = new URL(start.headers.get("location") ?? "").searchParams.get("state") ?? "";
    const badCode = await SELF.fetch(
      `${BASE}/auth/github/callback?code=not-a-code&state=${state}`,
      {
        headers: { cookie: `${STATE_COOKIE}=${state}` },
        redirect: "manual",
      },
    );
    expect(badCode.status).toBe(400);

    const events = await auditRows("user_audit_events");
    expect(events.map((row) => [row.event, row.actor_user_id])).toEqual([
      ["auth.login_failed", null],
      ["auth.login_failed", null],
    ]);
    expect(payloadOf(events[0] as AuditRow)).toEqual({
      authMethod: "github_oauth",
      reason: "state-mismatch",
    });
    expect(payloadOf(events[1] as AuditRow)).toEqual({
      authMethod: "github_oauth",
      reason: "code-exchange-failed",
    });
  });

  it("caps auth.login_failed writes per fixed window (unauthenticated write amplification bound)", async () => {
    const now = Date.now();
    await seedLoginFailedWindow("github_oauth", "state-mismatch", now, LOGIN_FAILED_WINDOW_LIMIT);
    const blocked = await callbackFailure();
    expect(blocked.status).toBe(400);
    expect(await countEvent("auth.login_failed")).toBe(0);
    const suppressedOnce = await env.DB.prepare(
      "SELECT COUNT(*) AS n, MAX(actor_user_id) AS actor, MAX(payload) AS payload FROM user_audit_events WHERE event = 'auth.login_failed_suppressed'",
    ).first<{ n: number; actor: string | null; payload: string }>();
    expect(suppressedOnce?.n).toBe(1);
    expect(suppressedOnce?.actor).toBeNull();
    expect(JSON.parse(suppressedOnce?.payload ?? "{}")).toEqual({
      authMethod: "github_oauth",
      reason: "state-mismatch",
      windowMs: LOGIN_FAILED_WINDOW_MS,
      limit: LOGIN_FAILED_WINDOW_LIMIT,
      suppressedCount: 1,
    });
    for (let i = 0; i < 8; i += 1) {
      expect((await callbackFailure()).status).toBe(400);
    }
    expect(await countEvent("auth.login_failed_suppressed")).toBe(1);
    expect((await callbackFailure()).status).toBe(400);
    expect(await countEvent("auth.login_failed_suppressed")).toBe(2);
    const milestone = await env.DB.prepare(
      "SELECT payload FROM user_audit_events WHERE event = 'auth.login_failed_suppressed' ORDER BY seq DESC LIMIT 1",
    ).first<{ payload: string }>();
    expect(JSON.parse(milestone?.payload ?? "{}")).toMatchObject({ suppressedCount: 10 });

    await seedLoginFailedWindow(
      "github_oauth",
      "state-mismatch",
      now - LOGIN_FAILED_WINDOW_MS - 1000,
      LOGIN_FAILED_WINDOW_LIMIT,
    );
    expect((await callbackFailure()).status).toBe(400);
    expect(await countEvent("auth.login_failed")).toBe(1);
  });

  it("counts the cap per auth_method + reason bucket, so one path cannot blind another", async () => {
    await seedLoginFailedWindow(
      "cli_handoff",
      "state-mismatch",
      Date.now(),
      LOGIN_FAILED_WINDOW_LIMIT,
    );
    const cliBlocked = await SELF.fetch(
      `${BASE}/auth/github/callback?code=code-700&state=cli.${"ab".repeat(16)}`,
      { redirect: "manual" },
    );
    expect(cliBlocked.status).toBe(400);
    expect(await countEvent("auth.login_failed")).toBe(0);

    expect((await callbackFailure()).status).toBe(400);
    const events = await auditRows("user_audit_events");
    const recorded = events.filter((row) => row.event === "auth.login_failed");
    expect(recorded).toHaveLength(1);
    expect(payloadOf(recorded[0] as AuditRow)).toEqual({
      authMethod: "github_oauth",
      reason: "state-mismatch",
    });
  });

  it("a flood of one OAuth failure reason cannot suppress another reason", async () => {
    await seedLoginFailedWindow(
      "github_oauth",
      "state-mismatch",
      Date.now(),
      LOGIN_FAILED_WINDOW_LIMIT,
    );
    expect((await callbackFailure()).status).toBe(400);

    const start = await SELF.fetch(`${BASE}/auth/github/start`, { redirect: "manual" });
    const state = new URL(start.headers.get("location") ?? "").searchParams.get("state") ?? "";
    const badCode = await SELF.fetch(
      `${BASE}/auth/github/callback?code=not-a-code&state=${state}`,
      {
        headers: { cookie: `${STATE_COOKIE}=${state}` },
        redirect: "manual",
      },
    );
    expect(badCode.status).toBe(400);

    const events = await auditRows("user_audit_events");
    const failed = events.filter((row) => row.event === "auth.login_failed");
    expect(failed).toHaveLength(1);
    expect(payloadOf(failed[0] as AuditRow)).toEqual({
      authMethod: "github_oauth",
      reason: "code-exchange-failed",
    });
    const suppressed = events.filter((row) => row.event === "auth.login_failed_suppressed");
    expect(suppressed).toHaveLength(1);
    expect(payloadOf(suppressed[0] as AuditRow)).toMatchObject({
      authMethod: "github_oauth",
      reason: "state-mismatch",
      suppressedCount: 1,
    });
  });
});

describe("CLI login handoff (§3.1 — AUTH_SPEC §4)", () => {
  it("records login_succeeded (cli_handoff) on approval and token_created on issuance", async () => {
    await seedUser("user-cli-audit", 701);
    const token = await cliToken(701);
    const events = await auditRows("user_audit_events");
    expect(events.map((row) => row.event)).toEqual(["auth.login_succeeded", "auth.token_created"]);
    const login = events[0] as AuditRow;
    expect(login.actor_user_id).toBe("user-cli-audit");
    const loginPayload = payloadOf(login);
    expect(loginPayload["authMethod"]).toBe("cli_handoff");
    expect(loginPayload["flowId"]).toMatch(/^[0-9a-f]{32}$/);
    const tokenRow = await env.DB.prepare("SELECT id FROM api_tokens").first<{ id: string }>();
    expect(payloadOf(events[1] as AuditRow)).toEqual({
      tokenId: tokenRow?.id,
      name: "cli-login",
      scopes: [{ project: "*", permission: "admin" }],
    });
    const me = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(token) });
    expect(me.status).toBe(200);
  });

  it("records one token_created per rotation of the same (user, name)", async () => {
    await cliToken(701);
    await cliToken(701);
    const events = await auditRows("user_audit_events");
    const created = events.filter((row) => row.event === "auth.token_created");
    expect(created).toHaveLength(2);
    expect(events.filter((row) => row.event === "auth.token_revoked")).toHaveLength(0);
    const first = payloadOf(created[0] as AuditRow);
    const second = payloadOf(created[1] as AuditRow);
    expect(first["replacedTokenId"]).toBeUndefined();
    expect(second["replacedTokenId"]).toBe(first["tokenId"]);
    const surviving = await env.DB.prepare("SELECT id FROM api_tokens").first<{ id: string }>();
    expect(surviving?.id).toBe(second["tokenId"]);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM api_tokens").first<{
      n: number;
    }>();
    expect(count?.n).toBe(1);
  });

  it("records auth.login_failed (cli_handoff) when the browser leg's code exchange fails", async () => {
    const started = await startCliFlow();
    const callback = await cliBrowserLeg(started.verificationUrl, 701, { code: "not-a-code" });
    expect(callback.status).toBe(400);
    const events = await auditRows("user_audit_events");
    expect(events.map((row) => row.event)).toEqual(["auth.login_failed"]);
    expect(payloadOf(events[0] as AuditRow)).toEqual({
      authMethod: "cli_handoff",
      reason: "code-exchange-failed",
    });
  });
});

describe("session / token revocation (§3.1)", () => {
  it("records auth.session_revoked on logout with the matching session id", async () => {
    const session = await loginSession(700);
    const logout = await SELF.fetch(`${BASE}/auth/logout`, {
      method: "POST",
      headers: sessionHeaders(session),
    });
    expect(logout.status).toBe(204);
    const events = await auditRows("user_audit_events");
    const revoked = events.filter((row) => row.event === "auth.session_revoked");
    expect(revoked).toHaveLength(1);
    const succeeded = events.find((row) => row.event === "auth.login_succeeded");
    expect(payloadOf(revoked[0] as AuditRow)["sessionId"]).toBe(
      payloadOf(succeeded as AuditRow)["sessionId"],
    );
    expect((revoked[0] as AuditRow).actor_user_id).toBe((succeeded as AuditRow).actor_user_id);
    const again = await SELF.fetch(`${BASE}/auth/logout`, {
      method: "POST",
      headers: sessionHeaders(session),
    });
    expect(again.status).toBe(401);
    expect(await auditRows("user_audit_events")).toHaveLength(events.length);
  });

  it("does not record session_revoked for expiry cleanup (not an explicit revocation)", async () => {
    const session = await loginSession(700);
    await env.DB.prepare("UPDATE sessions SET expires_at = 1").run();
    const me = await SELF.fetch(`${BASE}/auth/me`, {
      headers: { cookie: `__Host-maruhi_session=${session}` },
    });
    expect(me.status).toBe(401);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM sessions").first<{ n: number }>();
    expect(count?.n).toBe(0);
    const events = await auditRows("user_audit_events");
    expect(events.filter((row) => row.event === "auth.session_revoked")).toHaveLength(0);
  });

  it("records auth.token_revoked with the token id as both actor token and target payload", async () => {
    const token = await cliToken(701);
    const tokenRow = await env.DB.prepare("SELECT id, user_id FROM api_tokens").first<{
      id: string;
      user_id: string;
    }>();
    if (tokenRow === null) {
      throw new Error("expected token row");
    }
    const revoke = await SELF.fetch(`${BASE}/auth/token/revoke`, {
      method: "POST",
      headers: bearer(token),
    });
    expect(revoke.status).toBe(204);
    const events = await auditRows("user_audit_events");
    const revoked = events.filter((row) => row.event === "auth.token_revoked");
    expect(revoked).toHaveLength(1);
    expect((revoked[0] as AuditRow).actor_api_token_id).toBe(tokenRow.id);
    expect(payloadOf(revoked[0] as AuditRow)).toEqual({ tokenId: tokenRow.id });

    const services = makeDbServices(env.DB);
    const tokens = Context.get(services, TokenRepo);
    await Effect.runPromise(
      tokens.revokeById(tokenRow.id, testUserId(tokenRow.user_id), Date.now(), {
        userId: testUserId(tokenRow.user_id),
        apiTokenId: tokenRow.id,
      }),
    );
    const after = await auditRows("user_audit_events");
    expect(after.filter((row) => row.event === "auth.token_revoked")).toHaveLength(1);
  });

  it("does not revoke or audit a token owned by another user", async () => {
    await cliToken(702);
    const tokenRow = await env.DB.prepare("SELECT id FROM api_tokens").first<{ id: string }>();
    if (tokenRow === null) {
      throw new Error("expected token row");
    }
    const tokens = Context.get(makeDbServices(env.DB), TokenRepo);
    await Effect.runPromise(
      tokens.revokeById(tokenRow.id, testUserId("user-other"), Date.now(), {
        userId: testUserId("user-other"),
        apiTokenId: tokenRow.id,
      }),
    );

    expect(
      await env.DB.prepare("SELECT id FROM api_tokens WHERE id = ?").bind(tokenRow.id).first(),
    ).not.toBeNull();
    expect(
      (await auditRows("user_audit_events")).filter((row) => row.event === "auth.token_revoked"),
    ).toHaveLength(0);
  });
});

describe("recovery (§3.1 / AUTH_SPEC §13-5)", () => {
  const wrapBody = JSON.stringify({
    suite: "maruhi/v1",
    nonceHex: "0f".repeat(12),
    ciphertextHex: "ab".repeat(64),
  });

  it("records recovery_code_reissued on PUT and recovery_blob_fetched on distributed GET only", async () => {
    const token = await cliToken(702);
    const missing = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    expect(missing.status).toBe(404);
    const put = await SELF.fetch(`${BASE}/auth/recovery`, {
      method: "PUT",
      headers: { ...JSON_HEADERS, ...bearer(token) },
      body: wrapBody,
    });
    expect(put.status).toBe(204);
    const got = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    expect(got.status).toBe(200);

    const events = await auditRows("user_audit_events");
    const recovery = events.filter((row) => row.event.startsWith("auth.recovery_"));
    expect(recovery.map((row) => row.event)).toEqual([
      "auth.recovery_code_reissued",
      "auth.recovery_blob_fetched",
    ]);
    const tokenRow = await env.DB.prepare("SELECT id FROM api_tokens").first<{ id: string }>();
    for (const row of recovery) {
      expect(row.actor_api_token_id).toBe(tokenRow?.id);
    }
  });

  it("does not record recovery_blob_fetched for a rate-limited GET (no distribution)", async () => {
    const token = await cliToken(702);
    await SELF.fetch(`${BASE}/auth/recovery`, {
      method: "PUT",
      headers: { ...JSON_HEADERS, ...bearer(token) },
      body: wrapBody,
    });
    for (let i = 0; i < 5; i += 1) {
      const ok = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
      expect(ok.status).toBe(200);
    }
    const limited = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    expect(limited.status).toBe(429);
    const events = await auditRows("user_audit_events");
    expect(events.filter((row) => row.event === "auth.recovery_blob_fetched")).toHaveLength(5);
  });
});

describe("org.project_created (§3.2) and forbidden info (§1-2)", () => {
  const VECTOR_ORG = "org-vector-0001";
  const OWNER = testUserId("user-owner-0001");
  const OWNER_GITHUB_ID = 987001;

  beforeEach(async () => {
    await resetProjectDo(vectorProjectId);
    await seedUser(OWNER, OWNER_GITHUB_ID);
    await seedOrgMember(VECTOR_ORG, OWNER, "member");
  });

  async function initGenesis(token: string): Promise<void> {
    const genesis = vectorEntries[0];
    if (genesis === undefined) {
      throw new Error("missing genesis vector");
    }
    const response = await SELF.fetch(`${BASE}/projects`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(token) },
      body: JSON.stringify({ orgId: VECTOR_ORG, entry: toWireEntry(genesis) }),
    });
    expect(response.status).toBe(200);
  }

  it("records org.project_created with org, project and the acting principal", async () => {
    const token = await cliToken(OWNER_GITHUB_ID);
    await initGenesis(token);
    const events = await auditRows("org_audit_events");
    const created = events.filter((row) => row.event === "org.project_created");
    expect(created).toHaveLength(1);
    const row = created[0] as AuditRow;
    expect(row.org_id).toBe(VECTOR_ORG);
    expect(row.project_id).toBe(vectorProjectId);
    expect(row.actor_user_id).toBe(OWNER);
    expect(row.actor_api_token_id).not.toBeNull();
  });

  it("does not record org.project_created when the insert is skipped by conflict", async () => {
    const token = await cliToken(OWNER_GITHUB_ID);
    await initGenesis(token);
    const services = makeDbServices(env.DB);
    const projects = Context.get(services, ProjectRepo);
    await Effect.runPromise(
      projects.insertIfAbsent(
        testProjectId(vectorProjectId),
        decodeOrgId(VECTOR_ORG),
        OWNER,
        Date.now(),
        { userId: OWNER },
      ),
    );
    const events = await auditRows("org_audit_events");
    expect(events.filter((row) => row.event === "org.project_created")).toHaveLength(1);
  });

  it("refuses a payload key AUDIT_SPEC does not list, writing nothing (the D1 payload check)", async () => {
    const audit = Context.get(makeDbServices(env.DB), D1AuditRepo);
    type D1Event = Parameters<typeof audit.appendUserEvent>[0];
    const typed: D1Event[] = [
      { event: "auth.identity_linked", actor: { userId: OWNER }, payload: { provider: "github" } },
      {
        event: "auth.identity_linked",
        actor: { userId: OWNER },
        // @ts-expect-error the login is never recorded (§3.1)
        payload: { provider: "github", login: "octocat" },
      },
      // @ts-expect-error a project event is not a D1 event
      { event: "var.read", actor: { userId: OWNER }, payload: { variables: [] } },
    ];
    expect(typed).toHaveLength(3);
    const before = (await auditRows("user_audit_events")).length;
    const linked = { provider: "github" as const, login: "octocat" };
    const exit = await Effect.runPromiseExit(
      audit.appendUserEvent(
        { event: "auth.identity_linked", actor: { userId: OWNER }, payload: linked },
        Date.now(),
      ),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    const defect = Exit.isFailure(exit) ? Cause.squash(exit.cause) : null;
    expect(String((defect as { readonly cause?: unknown } | null)?.cause)).toContain(
      "the auth.identity_linked payload is not the AUDIT_SPEC §3 shape",
    );
    expect(await auditRows("user_audit_events")).toHaveLength(before);
  });

  it("never records provider identifiers or emails in any row (§1-2)", async () => {
    await loginSession(987002);
    const token = await cliToken(OWNER_GITHUB_ID);
    await initGenesis(token);
    const rows = [
      ...(await auditRows("user_audit_events")),
      ...(await auditRows("org_audit_events")),
    ];
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      for (const [column, value] of Object.entries(row)) {
        if (column === "server_ts" || column === "seq" || column === "row_id" || value === null) {
          continue;
        }
        const text = String(value);
        for (const forbidden of ["987001", "987002", "user987001", "user987002", "@"]) {
          expect(text).not.toContain(forbidden);
        }
      }
    }
  });
});
