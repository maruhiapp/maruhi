// Integration tests for the invite API (AUTH_SPEC §15).
//
// - Pins per reason code: authorization (token scope admin x chain role admin
//   or above / role=admin is owner-only), existence hiding (404 for
//   non-members), and the order of acceptance decisions (404 -> 410 -> 422 ->
//   CAS)
// - Acceptance signatures (CRYPTO_SPEC §6.5) are real signatures produced via
//   the @maruhi/crypto implementation. Since the server reconstructs
//   signed_bytes from the stored row + the calling principal, real data
//   verifies that link tampering (a different project or token), key
//   substitution, and someone else's signature all land on 422
// - Verifies by reading D1 directly that invite.* audits (AUDIT_SPEC §3.2)
//   are written in the same batch as the record operation, and that no audit
//   row is added on CAS loss (the changes() guard)

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
  inviteFixture,
  inviteAuditRows,
  inviteRow,
  issueInvite,
  issueInviteRequest,
  makeIssuePayload,
  mustRow,
  payloadOf,
  registerInviteScenario,
  seedInvitation,
  wirePayloadOf,
} from "./support/invites-scenario.ts";

registerInviteScenario();

describe("invite issue", () => {
  it("owner issues an invite: issuance statement stored, nothing secret returned, audit in same batch", async () => {
    const before = Date.now();
    const issued = await issueInvite(inviteFixture, OWNER, "member");
    expect(issued.expiresAtMs).toBeGreaterThanOrEqual(before + INVITE_TTL_MS);

    const row = mustRow(await inviteRow(issued.id));
    expect(row.status).toBe("pending");
    expect(row.role).toBe("member");
    // The issuance statement (public values) is stored as-is. The server does not verify it
    expect(row.link_pub).toBe(issued.linkPubHex);
    expect(row.head_hash).toBe(issued.headHashHex);
    expect(row.head_seq).toBe(issued.headSeq);
    expect(row.issue_signature).toBe(issued.issueSignatureHex);

    const audits = await inviteAuditRows();
    expect(audits).toHaveLength(1);
    const created = firstAudit(audits, "invite.created");
    expect(created.actor_user_id).toBe(OWNER);
    expect(created.actor_api_token_id).not.toBeNull();
    expect(created.project_id).toBe(projectId);
    // invite.* does not belong to the org axis (AUDIT_SPEC §7)
    expect(created.org_id).toBeNull();
    expect(payloadOf(created)).toMatchObject({
      inviteId: issued.id,
      role: "member",
    });
    // The issuance statement / link public key is not copied into the audit
    // (AUDIT_SPEC §3.2 — payload invariant)
    expect(String(created.payload)).not.toContain(issued.linkPubHex);
  });

  it("rejects a reused invite id or link pub with 409 (client-chosen id, UNIQUE link_pub)", async () => {
    const first = await issueInvite(inviteFixture, OWNER, "member");
    const sameId = await makeIssuePayload(inviteFixture, OWNER, "member", { id: first.id });
    const idConflict = await issueInviteRequest(inviteFixture, OWNER, "member", sameId);
    expect(idConflict.status).toBe(409);
    expect((await idConflict.json()) as object).toMatchObject({
      _tag: "InviteConflict",
      field: "id",
    });
    const sameLink = await makeIssuePayload(inviteFixture, OWNER, "member", {
      linkPubHex: first.linkPubHex,
    });
    const linkConflict = await issueInviteRequest(inviteFixture, OWNER, "member", sameLink);
    expect(linkConflict.status).toBe(409);
    expect((await linkConflict.json()) as object).toMatchObject({ field: "linkPub" });
    // A conflict writes no audit (nothing was admitted)
    expect((await inviteAuditRows()).filter((row) => row.event === "invite.created")).toHaveLength(
      1,
    );
  });

  it("rejects the pre-IV issue payload (role only) with 400 — no compatibility path", async () => {
    const response = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(tokenOf(inviteFixture.tokens, OWNER)) },
      body: JSON.stringify({ role: "member" }),
    });
    expect(response.status).toBe(400);
  });

  it("requires chain role admin: member/reader 403, non-member 404", async () => {
    for (const [userId, expected] of [
      [MEMBER, 403],
      [READER, 403],
      [STRANGER, 404],
    ] as const) {
      const response = await issueInviteRequest(inviteFixture, userId, "member");
      expect(response.status).toBe(expected);
    }
  });

  it("role=admin invites are owner-only (admin can issue member invites)", async () => {
    // The owner can issue admin invites
    await issueInvite(inviteFixture, OWNER, "admin");
    // Promote member to admin (change_role is an owner operation)
    await appendOperation(inviteFixture, OWNER, {
      op: "change_role",
      payload: {
        targetUserId: MEMBER,
        newRole: "admin",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });
    // An admin can issue member invites but an admin invite is 403
    await issueInvite(inviteFixture, MEMBER, "member");
    const denied = await issueInviteRequest(inviteFixture, MEMBER, "admin");
    expect(denied.status).toBe(403);
    expect(await errorTag(denied)).toBe("Forbidden");
  });

  it("token scope gates issuance: out-of-scope 404, low permission 403", async () => {
    const payload = wirePayloadOf(await makeIssuePayload(inviteFixture, OWNER, "member"));
    const outOfScope = await cliToken(9001, [{ project: "f".repeat(64), permission: "admin" }]);
    const outResponse = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(outOfScope) },
      body: JSON.stringify(payload),
    });
    expect(outResponse.status).toBe(404);

    const lowPermission = await cliToken(9001, [{ project: projectId, permission: "write" }]);
    const lowResponse = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(lowPermission) },
      body: JSON.stringify(payload),
    });
    expect(lowResponse.status).toBe(403);
  });

  it("fixed-window rate limit: 31st issuance within the hour is 429", async () => {
    for (let index = 0; index < INVITE_ISSUE_WINDOW_LIMIT; index += 1) {
      await issueInvite(inviteFixture, OWNER, "member");
    }
    const response = await issueInviteRequest(inviteFixture, OWNER, "member");
    expect(response.status).toBe(429);
    const body = (await response.json()) as { _tag: string; retryAfterSeconds: number };
    expect(body["_tag"]).toBe("InviteRateLimited");
    expect(body.retryAfterSeconds).toBeGreaterThanOrEqual(1);
    expect(body.retryAfterSeconds).toBeLessThanOrEqual(3600);
  });

  it("pending cap precedes the window limit (order listed in §15-2)", async () => {
    const now = Date.now();
    const oldCreated = now - 2 * 60 * 60 * 1000;
    // Fill the cap with in-period pending rows (created_at outside the
    // issue window) plus 30 rows inside the window — pins that the pending
    // limit is judged first when both conditions hold
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
    const response = await issueInviteRequest(inviteFixture, OWNER, "member");
    expect(response.status).toBe(429);
    const body = (await response.json()) as { _tag: string; limit: number };
    expect(body["_tag"]).toBe("InvitePendingLimit");
    expect(body.limit).toBe(MAX_PENDING_INVITES_PER_PROJECT);
  });

  it("concurrent issuance cannot exceed the pending cap and audits only the winner", async () => {
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
      Array.from({ length: 8 }, () => issueInviteRequest(inviteFixture, OWNER, "member")),
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

  it("concurrent issuance cannot exceed the lookback window and audits only the winner", async () => {
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
      Array.from({ length: 8 }, () => issueInviteRequest(inviteFixture, OWNER, "member")),
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
    await issueInvite(inviteFixture, OWNER, "member");
  });
});
