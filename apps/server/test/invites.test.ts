// 招待 API(AUTH_SPEC §15)の統合テスト。
//
// - 認可(トークンスコープ admin × チェーン role admin 以上 / role=admin は
//   owner のみ)、存在秘匿(非メンバー 404)、受諾の判定順(404 → 410 → 422 →
//   CAS)を理由コードごとに固定する
// - 受諾署名(CRYPTO_SPEC §6.5)は @maruhi/crypto の実装で実署名を作る。
//   サーバーは signed_bytes を保存行 + 呼び出し主体から再構成するため、
//   リンク改竄(別プロジェクト・別トークン)・鍵すり替え・別人の署名は
//   すべて 422 に落ちることを実データで検証する
// - invite.* 監査(AUDIT_SPEC §3.2)がレコード操作と同一 batch で書かれ、
//   CAS 敗北時に監査行が増えないこと(changes() ガード)を D1 直読で検証する

import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import {
  INVITE_ISSUE_WINDOW_LIMIT,
  INVITE_TTL_MS,
  MAX_PENDING_INVITES_PER_PROJECT,
} from "../src/db.package/index.ts";
import { BASE, bearer, cliToken, JSON_HEADERS } from "./support/auth.ts";
import {
  appendOperation,
  MEMBER,
  OWNER,
  projectId,
  READER,
  STRANGER,
  tokenOf,
} from "./support/data-fixture.ts";
import {
  errorTag,
  firstAudit,
  fixture,
  INVITE_TOKEN_PATTERN,
  inviteAuditRows,
  inviteRow,
  issueInvite,
  issueInviteRequest,
  mustRow,
  payloadOf,
  registerInviteScenario,
  seedInvitation,
  tokenHashOf,
} from "./support/invites-scenario.ts";

registerInviteScenario();

describe("invite issue", () => {
  it("owner issues an invite: raw token once, hashed row, audit in same batch", async () => {
    const before = Date.now();
    const issued = await issueInvite(fixture, OWNER, "member");
    expect(issued.token).toMatch(INVITE_TOKEN_PATTERN);
    expect(issued.expiresAtMs).toBeGreaterThanOrEqual(before + INVITE_TTL_MS);

    const row = mustRow(await inviteRow(issued.id));
    expect(row.status).toBe("pending");
    expect(row.role).toBe("member");
    // 生値は保存されない: 行にあるのは提示文字列全体の SHA-256 のみ
    expect(row.token_hash).toBe(await tokenHashOf(issued.token));
    expect(JSON.stringify(row)).not.toContain(issued.token);

    const audits = await inviteAuditRows();
    expect(audits).toHaveLength(1);
    const created = firstAudit(audits, "invite.created");
    expect(created.actor_user_id).toBe(OWNER);
    expect(created.actor_api_token_id).not.toBeNull();
    expect(created.project_id).toBe(projectId);
    // invite.* は org 軸に属さない(AUDIT_SPEC §7)
    expect(created.org_id).toBeNull();
    expect(payloadOf(created)).toMatchObject({
      inviteId: issued.id,
      role: "member",
    });
    // トークン生値を監査に写さない
    expect(String(created.payload)).not.toContain(issued.token);
  });

  it("requires chain role admin: member/reader 403, non-member 404", async () => {
    for (const [userId, expected] of [
      [MEMBER, 403],
      [READER, 403],
      [STRANGER, 404],
    ] as const) {
      const response = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
        method: "POST",
        headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, userId)) },
        body: JSON.stringify({ role: "member" }),
      });
      expect(response.status).toBe(expected);
    }
  });

  it("role=admin invites are owner-only (admin can issue member invites)", async () => {
    // owner は admin 招待を発行できる
    await issueInvite(fixture, OWNER, "admin");
    // member を admin へ昇格(change_role は owner 操作)
    await appendOperation(fixture, OWNER, {
      op: "change_role",
      payload: { targetUserId: MEMBER, newRole: "admin" },
    });
    // admin は member 招待は発行できるが admin 招待は 403
    await issueInvite(fixture, MEMBER, "member");
    const denied = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, MEMBER)) },
      body: JSON.stringify({ role: "admin" }),
    });
    expect(denied.status).toBe(403);
    expect(await errorTag(denied)).toBe("Forbidden");
  });

  it("token scope gates issuance: out-of-scope 404, low permission 403", async () => {
    const outOfScope = await cliToken(9001, [{ project: "f".repeat(64), permission: "admin" }]);
    const outResponse = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(outOfScope) },
      body: JSON.stringify({ role: "member" }),
    });
    expect(outResponse.status).toBe(404);

    const lowPermission = await cliToken(9001, [{ project: projectId, permission: "write" }]);
    const lowResponse = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(lowPermission) },
      body: JSON.stringify({ role: "member" }),
    });
    expect(lowResponse.status).toBe(403);
  });

  it("fixed-window rate limit: 31st issuance within the hour is 429", async () => {
    for (let index = 0; index < INVITE_ISSUE_WINDOW_LIMIT; index += 1) {
      await issueInvite(fixture, OWNER, "member");
    }
    const response = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, OWNER)) },
      body: JSON.stringify({ role: "member" }),
    });
    expect(response.status).toBe(429);
    const body = (await response.json()) as { _tag: string; retryAfterSeconds: number };
    expect(body["_tag"]).toBe("InviteRateLimited");
    expect(body.retryAfterSeconds).toBeGreaterThanOrEqual(1);
    expect(body.retryAfterSeconds).toBeLessThanOrEqual(3600);
  });

  it("pending cap precedes the window limit (§15-2 の記載順)", async () => {
    const now = Date.now();
    const oldCreated = now - 2 * 60 * 60 * 1000;
    // 期限内 pending を上限まで(発行窓の外の created_at)+ 窓内にも 30 行 —
    // 両条件成立時に pending-limit が先に判定されることを固定する
    for (let index = 0; index < MAX_PENDING_INVITES_PER_PROJECT - 30; index += 1) {
      await seedInvitation({
        id: `seed-old-${index}`,
        createdAt: oldCreated,
        expiresAt: now + INVITE_TTL_MS,
      });
    }
    for (let index = 0; index < 30; index += 1) {
      await seedInvitation({
        id: `seed-recent-${index}`,
        createdAt: now,
        expiresAt: now + INVITE_TTL_MS,
      });
    }
    const response = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, OWNER)) },
      body: JSON.stringify({ role: "member" }),
    });
    expect(response.status).toBe(429);
    const body = (await response.json()) as { _tag: string; limit: number };
    expect(body["_tag"]).toBe("InvitePendingLimit");
    expect(body.limit).toBe(MAX_PENDING_INVITES_PER_PROJECT);
  });

  it("concurrent issuance cannot exceed the pending cap and audits only the winner (S4)", async () => {
    const now = Date.now();
    const oldCreated = now - 2 * 60 * 60 * 1000;
    for (let index = 0; index < MAX_PENDING_INVITES_PER_PROJECT - 1; index += 1) {
      await seedInvitation({
        id: `seed-pending-race-${index}`,
        createdAt: oldCreated,
        expiresAt: now + INVITE_TTL_MS,
      });
    }

    const responses = await Promise.all(
      Array.from({ length: 8 }, () => issueInviteRequest(fixture, OWNER, "member")),
    );
    expect(responses.filter((response) => response.status === 200)).toHaveLength(1);
    const rejected = responses.filter((response) => response.status !== 200);
    expect(rejected).toHaveLength(7);
    expect(await Promise.all(rejected.map(errorTag))).toEqual(
      Array<string>(7).fill("InvitePendingLimit"),
    );

    const pending = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM invitations WHERE project_id = ? AND status = 'pending' AND expires_at > ?",
    )
      .bind(projectId, now)
      .first<{ n: number }>();
    expect(pending?.n).toBe(MAX_PENDING_INVITES_PER_PROJECT);
    expect((await inviteAuditRows()).filter((row) => row.event === "invite.created")).toHaveLength(
      1,
    );
  });

  it("concurrent issuance cannot exceed the lookback window and audits only the winner (S4)", async () => {
    const now = Date.now();
    for (let index = 0; index < INVITE_ISSUE_WINDOW_LIMIT - 1; index += 1) {
      await seedInvitation({
        id: `seed-window-race-${index}`,
        status: "completed",
        createdAt: now,
        expiresAt: now + INVITE_TTL_MS,
      });
    }

    const responses = await Promise.all(
      Array.from({ length: 8 }, () => issueInviteRequest(fixture, OWNER, "member")),
    );
    expect(responses.filter((response) => response.status === 200)).toHaveLength(1);
    const rejected = responses.filter((response) => response.status !== 200);
    expect(rejected).toHaveLength(7);
    expect(await Promise.all(rejected.map(errorTag))).toEqual(
      Array<string>(7).fill("InviteRateLimited"),
    );

    const recent = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM invitations WHERE project_id = ? AND created_at >= ?",
    )
      .bind(projectId, now - 60 * 60 * 1000)
      .first<{ n: number }>();
    expect(recent?.n).toBe(INVITE_ISSUE_WINDOW_LIMIT);
    expect((await inviteAuditRows()).filter((row) => row.event === "invite.created")).toHaveLength(
      1,
    );
  });

  it("expired pending rows do not consume the cap", async () => {
    const now = Date.now();
    for (let index = 0; index < MAX_PENDING_INVITES_PER_PROJECT; index += 1) {
      await seedInvitation({
        id: `seed-expired-${index}`,
        createdAt: now - 2 * 60 * 60 * 1000,
        expiresAt: now - 1000,
      });
    }
    await issueInvite(fixture, OWNER, "member");
  });
});
