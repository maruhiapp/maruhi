// D1 側監査ログ(AUDIT_SPEC §3.1 認証系 / §3.2 org 系 / §5.2 案 A)の統合テスト。
//
// - 記録は実経路(SELF 経由の HttpApi)で発火させ、D1 のテーブルを直接読んで検証する
//   (読み取り API は Phase 2 — §6・§7 — のため v1 に存在しない)
// - 主データ書き込みと同一 batch の追記(§5.2 採用理由 (2))は、操作の成否と
//   イベントの有無が常に一致することとして観測する
// - アイデンティティ規則(§1-2): プロバイダ ID・login・メールが 1 行にも現れない

import { env, SELF } from "cloudflare:test";
import { Context, Effect } from "effect";
import { beforeEach, describe, expect, it } from "vitest";

import {
  LOGIN_FAILED_WINDOW_LIMIT,
  LOGIN_FAILED_WINDOW_MS,
  makeDbServices,
  ProjectRepo,
  TokenRepo,
} from "../src/db.package/index.ts";
import {
  BASE,
  bearer,
  deviceToken,
  JSON_HEADERS,
  loginSession,
  resetAuthDb,
  seedOrgMember,
  seedUser,
  sessionHeaders,
  STATE_COOKIE,
} from "./support/auth.ts";
import { toWireEntry, vectorEntries, vectorProjectId } from "./support/chain-vectors.ts";
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

/** login_failed の窓カウンタ(AUDIT_SPEC §3.1)を任意の状態に置く。 */
async function seedLoginFailedWindow(
  bucket: string,
  windowStart: number,
  recordedCount: number,
): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO login_failed_windows (bucket, window_start, recorded_count, suppressed_count) VALUES (?, ?, ?, 0) ON CONFLICT(bucket) DO UPDATE SET window_start = excluded.window_start, recorded_count = excluded.recorded_count, suppressed_count = 0",
  )
    .bind(bucket, windowStart, recordedCount)
    .run();
}

/** state 不一致で確実に auth.login_failed 経路へ入る callback 呼び出し。 */
function callbackFailure(): Promise<Response> {
  return SELF.fetch(`${BASE}/auth/github/callback?code=code-700&state=${"ab".repeat(16)}`, {
    redirect: "manual",
  });
}

beforeEach(async () => {
  await resetAuthDb();
});

describe("Web OAuth ログイン(§3.1)", () => {
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
    // 全行 actor = 作成されたユーザー本人(type user)
    for (const row of events) {
      expect(row.actor_type).toBe("user");
      expect(row.actor_user_id).toBe(userId);
    }
    // identity_linked は provider 種別名のみ(数値 ID・login は §1-2 で禁止)
    expect(payloadOf(events[1] as AuditRow)).toEqual({ provider: "github" });
    // login_succeeded は auth_method と対応セッション id(保存 id と同じハッシュ)
    const login = payloadOf(events[2] as AuditRow);
    expect(login["authMethod"]).toBe("github_oauth");
    const sessionRow = await env.DB.prepare("SELECT id FROM sessions").first<{ id: string }>();
    expect(login["sessionId"]).toBe(sessionRow?.id);

    // パーソナル org 自動作成も org 系イベントとして記録される(§3.2)
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
    // state 不一致(クッキーなし)
    const mismatch = await SELF.fetch(
      `${BASE}/auth/github/callback?code=code-700&state=${"ab".repeat(16)}`,
      { redirect: "manual" },
    );
    expect(mismatch.status).toBe(400);
    // 正しい state で不正 code
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
    // 窓の状態はカウンタ行が持つ(deepsec R5: 監査ログを走査しない)ので、
    // 上限到達はカウンタを直接シードして作る
    const now = Date.now();
    await seedLoginFailedWindow("github_oauth", now, LOGIN_FAILED_WINDOW_LIMIT);
    const blocked = await callbackFailure();
    // 拒否応答は変わらず、監査行だけが増えない
    expect(blocked.status).toBe(400);
    expect(await countEvent("auth.login_failed")).toBe(0);
    // 抑制は黙って行わない(deepsec M4/R4): 最初の抑制でマーカーが 1 行残る
    const suppressedOnce = await env.DB.prepare(
      "SELECT COUNT(*) AS n, MAX(actor_user_id) AS actor, MAX(payload) AS payload FROM user_audit_events WHERE event = 'auth.login_failed_suppressed'",
    ).first<{ n: number; actor: string | null; payload: string }>();
    expect(suppressedOnce?.n).toBe(1);
    // actor は個別行と同じく user_id なし(外部 ID・IP を書かない — §1-2)
    expect(suppressedOnce?.actor).toBeNull();
    // payload は auth_method・窓長・上限・抑制件数のみ(個別行の reason は運ばない)
    expect(JSON.parse(suppressedOnce?.payload ?? "{}")).toEqual({
      authMethod: "github_oauth",
      windowMs: LOGIN_FAILED_WINDOW_MS,
      limit: LOGIN_FAILED_WINDOW_LIMIT,
      suppressedCount: 1,
    });
    // マーカーは抑制ごとには増えない(10 の冪のみ)
    for (let i = 0; i < 8; i += 1) {
      expect((await callbackFailure()).status).toBe(400);
    }
    expect(await countEvent("auth.login_failed_suppressed")).toBe(1);
    // 10 件目の抑制でもう 1 行。件数から抑制の規模が読める
    expect((await callbackFailure()).status).toBe(400);
    expect(await countEvent("auth.login_failed_suppressed")).toBe(2);
    const milestone = await env.DB.prepare(
      "SELECT payload FROM user_audit_events WHERE event = 'auth.login_failed_suppressed' ORDER BY seq DESC LIMIT 1",
    ).first<{ payload: string }>();
    expect(JSON.parse(milestone?.payload ?? "{}")).toMatchObject({ suppressedCount: 10 });

    // 窓が明けたら記録が再開する
    await seedLoginFailedWindow(
      "github_oauth",
      now - LOGIN_FAILED_WINDOW_MS - 1000,
      LOGIN_FAILED_WINDOW_LIMIT,
    );
    expect((await callbackFailure()).status).toBe(400);
    expect(await countEvent("auth.login_failed")).toBe(1);
  });

  it("counts the cap per auth_method bucket, so one flooded path cannot blind the other (R4)", async () => {
    // device flow 側の窓を使い切った状態で、Web OAuth の失敗は記録され続ける
    await seedLoginFailedWindow("device_flow", Date.now(), LOGIN_FAILED_WINDOW_LIMIT);
    const deviceBlocked = await SELF.fetch(`${BASE}/auth/device/exchange`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ githubAccessToken: "gho_bogus" }),
    });
    expect(deviceBlocked.status).toBe(400);
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
});

describe("device flow(§3.1)", () => {
  it("records login_succeeded (device_flow) and token_created with token id, name and scopes", async () => {
    const token = await deviceToken(701);
    const events = await auditRows("user_audit_events");
    expect(events.map((row) => row.event)).toEqual([
      "auth.user_created",
      "auth.identity_linked",
      "auth.login_succeeded",
      "auth.token_created",
    ]);
    expect(payloadOf(events[2] as AuditRow)).toEqual({ authMethod: "device_flow" });
    const tokenRow = await env.DB.prepare("SELECT id FROM api_tokens").first<{ id: string }>();
    expect(payloadOf(events[3] as AuditRow)).toEqual({
      tokenId: tokenRow?.id,
      name: "device-flow",
      scopes: [{ project: "*", permission: "admin" }],
    });
    // 発行直後のトークンが実際に使える(イベントとトークンの整合の脇検証)
    const me = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(token) });
    expect(me.status).toBe(200);
  });

  it("records one token_created per rotation of the same (user, name)", async () => {
    await deviceToken(701);
    await deviceToken(701);
    const events = await auditRows("user_audit_events");
    const created = events.filter((row) => row.event === "auth.token_created");
    expect(created).toHaveLength(2);
    // 置換された旧行の削除はローテーションの一部であり、明示失効イベントに
    // ならない(§3.1 の線引きの否定側)
    expect(events.filter((row) => row.event === "auth.token_revoked")).toHaveLength(0);
    // が、置換されたことと対象はログから再構成できる(deepsec R6): 1 本目の
    // 発行行にはキーが無く、2 本目は 1 本目の id を replacedTokenId に持つ
    const first = payloadOf(created[0] as AuditRow);
    const second = payloadOf(created[1] as AuditRow);
    expect(first["replacedTokenId"]).toBeUndefined();
    expect(second["replacedTokenId"]).toBe(first["tokenId"]);
    // 生き残るトークンは 2 本目のもの(監査の主張と DB の状態が一致する)
    const surviving = await env.DB.prepare("SELECT id FROM api_tokens").first<{ id: string }>();
    expect(surviving?.id).toBe(second["tokenId"]);
    // ローテーションで残る実トークンは 1 本のまま
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM api_tokens").first<{
      n: number;
    }>();
    expect(count?.n).toBe(1);
  });

  it("records auth.login_failed (device_flow) for an invalid GitHub token", async () => {
    const response = await SELF.fetch(`${BASE}/auth/device/exchange`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ githubAccessToken: "gho_bogus" }),
    });
    expect(response.status).toBe(400);
    const events = await auditRows("user_audit_events");
    expect(events.map((row) => row.event)).toEqual(["auth.login_failed"]);
    expect(payloadOf(events[0] as AuditRow)).toEqual({
      authMethod: "device_flow",
      reason: "github-token-invalid",
    });
  });
});

describe("セッション / トークンの失効(§3.1)", () => {
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
    // 失効済みクッキーでの再ログアウトは 401 で、イベントを増やさない
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
    // 行は掃除されている(DB バック失効)がイベントは増えない
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM sessions").first<{ n: number }>();
    expect(count?.n).toBe(0);
    const events = await auditRows("user_audit_events");
    expect(events.filter((row) => row.event === "auth.session_revoked")).toHaveLength(0);
  });

  it("records auth.token_revoked with the token id as both actor token and target payload", async () => {
    const token = await deviceToken(701);
    const tokenRow = await env.DB.prepare("SELECT id, user_id FROM api_tokens").first<{
      id: string;
      user_id: string;
    }>();
    const revoke = await SELF.fetch(`${BASE}/auth/token/revoke`, {
      method: "POST",
      headers: bearer(token),
    });
    expect(revoke.status).toBe(204);
    const events = await auditRows("user_audit_events");
    const revoked = events.filter((row) => row.event === "auth.token_revoked");
    expect(revoked).toHaveLength(1);
    expect((revoked[0] as AuditRow).actor_api_token_id).toBe(tokenRow?.id);
    expect(payloadOf(revoked[0] as AuditRow)).toEqual({ tokenId: tokenRow?.id });

    // 削除が空振りする再失効(並行 revoke の負け側と同じ実行順)はイベントを
    // 増やさない(1 失効 = 高々 1 行)
    const services = makeDbServices(env.DB);
    const tokens = Context.get(services, TokenRepo);
    await Effect.runPromise(
      tokens.revokeById(tokenRow?.id ?? "", tokenRow?.user_id ?? "", Date.now()),
    );
    const after = await auditRows("user_audit_events");
    expect(after.filter((row) => row.event === "auth.token_revoked")).toHaveLength(1);
  });
});

describe("リカバリー(§3.1 / AUTH_SPEC §13-5)", () => {
  const wrapBody = JSON.stringify({
    suite: "maruhi/v1",
    nonceHex: "0f".repeat(12),
    ciphertextHex: "ab".repeat(64),
  });

  it("records recovery_code_reissued on PUT and recovery_blob_fetched on distributed GET only", async () => {
    const token = await deviceToken(702);
    // 未登録の GET(404)は配布なし = 記録なし
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
    // PAT 経由の操作はトークン id を actor に持つ(§2)
    const tokenRow = await env.DB.prepare("SELECT id FROM api_tokens").first<{ id: string }>();
    for (const row of recovery) {
      expect(row.actor_api_token_id).toBe(tokenRow?.id);
    }
  });

  it("does not record recovery_blob_fetched for a rate-limited GET (no distribution)", async () => {
    const token = await deviceToken(702);
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

describe("org.project_created(§3.2)と禁止情報(§1-2)", () => {
  const VECTOR_ORG = "org-vector-0001";
  const OWNER = "user-owner-0001";
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
    const token = await deviceToken(OWNER_GITHUB_ID);
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
    const token = await deviceToken(OWNER_GITHUB_ID);
    await initGenesis(token);
    // 行が既に存在する状態での冪等挿入(並行 init の競合側と同じ実行順)は
    // イベントを増やさない(偽の作成イベントを作らない)
    const services = makeDbServices(env.DB);
    const projects = Context.get(services, ProjectRepo);
    await Effect.runPromise(
      projects.insertIfAbsent(vectorProjectId, VECTOR_ORG, Date.now(), { userId: OWNER }),
    );
    const events = await auditRows("org_audit_events");
    expect(events.filter((row) => row.event === "org.project_created")).toHaveLength(1);
  });

  it("never records provider identifiers or emails in any row (§1-2)", async () => {
    // Web ログイン(verified メール保存経路)+ device flow + プロジェクト作成を
    // 通してから全行を走査する
    await loginSession(987002);
    const token = await deviceToken(OWNER_GITHUB_ID);
    await initGenesis(token);
    const rows = [
      ...(await auditRows("user_audit_events")),
      ...(await auditRows("org_audit_events")),
    ];
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      for (const [column, value] of Object.entries(row)) {
        // row_id はランダム hex — 偶然に数字列を含みうるため走査から除外する
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
