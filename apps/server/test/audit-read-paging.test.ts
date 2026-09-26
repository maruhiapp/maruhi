// Integration tests for the audit-event read API (AUDIT_SPEC §6 / §7).
// The visibility classes and filters live in audit-read.test.ts (the
// shared helpers in support/audit-read-scenario.ts).
//
// Properties being pinned:
//  1. Paging bounds: seq descending, limit ≤ 200 (beyond that is a Schema
//     400), advancing the before cursor. A below-admin page fills to limit
//     rows even when it straddles class-2 rows (non-leakage of counts)
//  2. invite.* (D1): the permission axis is only chain role admin of that
//     project — being an org admin grants no read access (404), and no
//     non-invite.* org events or other projects' rows leak in
//  3. self (D1): only one's own rows. The token requirement is the same
//     level as §13-2 (`*` × admin)

import { ulid } from "@maruhi/core";
import { encodeHex } from "@maruhi/crypto";
import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { INVITE_AUDIT_EVENTS } from "../src/db.package/index.ts";
import type { WireAuditEvent } from "./support/audit-read-scenario.ts";
import {
  eventNames,
  fetchEvents,
  scopedToken,
  seedProjectActivity,
} from "./support/audit-read-scenario.ts";
import { BASE, bearer, loginSession, sessionHeaders } from "./support/auth.ts";
import {
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  STRANGER,
  tokenOf,
} from "./support/data-fixture.ts";
import { fixture, registerDataScenario, token } from "./support/data-scenario.ts";

registerDataScenario();

describe("paging bounds (§7: seq descending, limit ≤ 200, cursor advance)", () => {
  it("returns seq-descending, and concatenating via the before cursor matches the full list", async () => {
    await seedProjectActivity();
    const full = await fetchEvents(token(OWNER), { limit: "200" });
    expect(full.events.length).toBeGreaterThan(8);
    const seqs = full.events.map((event) => event.seq ?? 0);
    expect(seqs.every((seq) => seq > 0)).toBe(true);
    expect(seqs).toEqual([...seqs].toSorted((a, b) => b - a));
    const paged: WireAuditEvent[] = [];
    let before: string | null = null;
    // A hard upper bound so a regression where the cursor stops advancing cannot hang (all < 4 × 50)
    for (let pages = 0; ; pages += 1) {
      expect(pages).toBeLessThan(50);
      const page = await fetchEvents(token(OWNER), {
        limit: "4",
        ...(before === null ? {} : { before }),
      });
      paged.push(...page.events);
      if (page.events.length < 4) {
        break;
      }
      before = page.events[page.events.length - 1]?.id ?? null;
    }
    expect(paged).toEqual(full.events);
  });

  it("a below-admin page fills to limit rows even when it straddles class-2 rows (non-leakage of gaps / counts)", async () => {
    await seedProjectActivity();
    const full = await fetchEvents(token(READER), { limit: "200" });
    // With class-2 rows (dek.registered ×3 + others' var.read) sandwiched
    // in the middle of the visible column, concatenating 2-row pages
    // matches the full visible column, and every page but the last holds
    // exactly 2 rows (= hidden rows do not shorten the page)
    const paged: WireAuditEvent[] = [];
    let before: string | null = null;
    // A hard upper bound so a regression where the cursor stops advancing cannot hang
    for (let pages = 0; ; pages += 1) {
      expect(pages).toBeLessThan(50);
      const page = await fetchEvents(token(READER), {
        limit: "2",
        ...(before === null ? {} : { before }),
      });
      if (paged.length + page.events.length < full.events.length) {
        expect(page.events.length).toBe(2);
      }
      paged.push(...page.events);
      if (page.events.length < 2) {
        break;
      }
      before = page.events[page.events.length - 1]?.id ?? null;
    }
    expect(paged).toEqual(full.events);
  });

  it("out-of-range limit and malformed cursors are a Schema 400", async () => {
    await seedProjectActivity();
    // before accepts only a 32-digit lowercase-hex row id (numeric seqs
    // and short/uppercase hex are rejected by Schema — the opaque cursor
    // of AUDIT_SPEC §7)
    for (const query of [
      "limit=0",
      "limit=201",
      "limit=1.5",
      "limit=abc",
      "before=0",
      "before=x",
      `before=${"a".repeat(31)}`,
      `before=${"A".repeat(32)}`,
    ]) {
      const response = await requestJson("GET", `/audit/events?${query}`, token(OWNER));
      expect(response.status, query).toBe(400);
    }
  });

  it("a cursor outside visibility or naming an unknown row id returns an empty page (no existence oracle)", async () => {
    await seedProjectActivity();
    // As OWNER, fetch the id of a row invisible to READER (a var.read
    // whose actor is someone else — class 2), then use it as READER's
    // cursor
    const admin = await fetchEvents(token(OWNER), { limit: "200" });
    const hidden = admin.events.find(
      (event) => event.event === "var.read" && event.actor.userId === MEMBER,
    );
    expect(hidden).toBeDefined();
    const probe = await fetchEvents(token(READER), { before: hidden?.id ?? "" });
    // "Exists but invisible" gets the same response as "no such id" (an
    // empty page) — a non-empty response or a 4xx difference would make it
    // an existence oracle for ids
    expect(probe.status).toBe(200);
    expect(probe.events).toEqual([]);
    const unknown = await fetchEvents(token(READER), { before: "0".repeat(32) });
    expect(unknown.status).toBe(200);
    expect(unknown.events).toEqual([]);
    // A visible row's id returns the continuation (the control showing the cursor works)
    const visible = await fetchEvents(token(READER), { limit: "1" });
    expect(visible.events.length).toBe(1);
    const rest = await fetchEvents(token(READER), { before: visible.events[0]?.id ?? "" });
    expect(rest.events.length).toBeGreaterThan(0);
  });
});

async function issueInvite(role: string): Promise<string> {
  // The server does not verify the issuance document (format check only —
  // AUTH_SPEC §15-2), so for the audit read tests we just make the id and
  // link public key unique while matching the format
  const id = ulid();
  const linkPubHex = encodeHex(crypto.getRandomValues(new Uint8Array(32)));
  const response = await requestJson("POST", "/invites", token(OWNER), {
    id,
    role,
    scopeKind: "all",
    scopeEnvironmentIds: [],
    linkPubHex,
    headHashHex: "ab".repeat(32),
    headSeq: 1,
    issueSignatureHex: "00".repeat(64),
  });
  expect(response.status).toBe(200);
  return id;
}

async function fetchInvites(
  bearerToken: string,
  query: Record<string, string> = {},
): Promise<{ status: number; events: readonly WireAuditEvent[] }> {
  const search = new URLSearchParams(query).toString();
  const response = await requestJson(
    "GET",
    `/audit/invites${search === "" ? "" : `?${search}`}`,
    bearerToken,
  );
  if (response.status !== 200) {
    return { status: response.status, events: [] };
  }
  return {
    status: 200,
    events: ((await response.json()) as { events: readonly WireAuditEvent[] }).events,
  };
}

describe("reading invite.* (the §7 exception provision — D1)", () => {
  it("a chain role admin can read the invite lifecycle newest-first", async () => {
    const inviteId = await issueInvite("member");
    const revoked = await requestJson("DELETE", `/invites/${inviteId}`, token(OWNER));
    expect(revoked.status).toBe(204);
    const { status, events } = await fetchInvites(token(OWNER));
    expect(status).toBe(200);
    expect(eventNames(events)).toEqual(["invite.revoked", "invite.created"]);
    for (const event of events) {
      expect(event.projectId).toBe(projectId);
      expect(INVITE_AUDIT_EVENTS).toContain(event.event);
      expect(event.payload?.["inviteId"]).toBe(inviteId);
    }
    // Paging (before cursor = row id). The D1 response carries no seq to
    // anyone (the global sequence is a cross-tenant ordinal — AUDIT_SPEC §7)
    for (const event of events) {
      expect(event.seq).toBeUndefined();
      expect(event.id).toMatch(/^[0-9a-f]{32}$/);
    }
    const first = await fetchInvites(token(OWNER), { limit: "1" });
    expect(eventNames(first.events)).toEqual(["invite.revoked"]);
    const second = await fetchInvites(token(OWNER), {
      limit: "1",
      before: first.events[0]?.id ?? "",
    });
    expect(eventNames(second.events)).toEqual(["invite.created"]);
  });

  it("below chain role admin is a 403, and even an org admin who is not a member gets a 404 (independence of the permission axis)", async () => {
    await issueInvite("member");
    expect((await fetchInvites(token(MEMBER))).status).toBe(403);
    expect((await fetchInvites(token(READER))).status).toBe(403);
    // Even making STRANGER an org admin leaves chain non-members of the
    // project at 404 (being an org admin grants no read access to invite.*
    // — §7)
    await env.DB.prepare(
      "INSERT INTO memberships (org_id, user_id, role) VALUES ('org-data-0001', ?, 'admin')",
    )
      .bind(STRANGER)
      .run();
    expect((await fetchInvites(token(STRANGER))).status).toBe(404);
  });

  it("a historical row without row_id (written by old code during a deploy gap) is backfilled and returned (not a 500)", async () => {
    const inviteId = await issueInvite("member");
    // Directly seed the shape old code writes between the migration's
    // application and the new worker's rollout (no row_id). Without
    // backfilling (the lazy backfill ahead of the read), the id's Schema
    // encode fails and this page stays 500/400 forever
    await env.DB.prepare(
      "INSERT INTO org_audit_events (server_ts, event, actor_type, actor_user_id, project_id, payload) VALUES (99, 'invite.created', 'user', ?, ?, '{\"inviteId\":\"legacy\"}')",
    )
      .bind(OWNER, projectId)
      .run();
    const { status, events } = await fetchInvites(token(OWNER), { limit: "200" });
    expect(status).toBe(200);
    const ids = events.map((event) => event.id);
    for (const id of ids) {
      expect(id).toMatch(/^[0-9a-f]{32}$/);
    }
    expect(new Set(ids).size).toBe(ids.length);
    const inviteIds = events.map((event) => event.payload?.["inviteId"]);
    expect(inviteIds).toEqual(expect.arrayContaining(["legacy", inviteId]));
  });

  it("row_id backfilling is limited to the rows observed on the page (no UPDATE reaching all NULL rows)", async () => {
    await issueInvite("member");
    // Seed two historical rows with NULL row_id. Only the newer one
    // (larger seq) lands on a limit=1 read page — we pin that the backfill
    // UPDATE does not spill onto NULL rows outside the page by the
    // remaining row keeping a NULL row_id
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO org_audit_events (server_ts, event, actor_type, actor_user_id, project_id, payload) VALUES (98, 'invite.created', 'user', ?, ?, '{\"inviteId\":\"legacy-old\"}')",
      ).bind(OWNER, projectId),
      env.DB.prepare(
        "INSERT INTO org_audit_events (server_ts, event, actor_type, actor_user_id, project_id, payload) VALUES (99, 'invite.created', 'user', ?, ?, '{\"inviteId\":\"legacy-new\"}')",
      ).bind(OWNER, projectId),
    ]);
    const { status, events } = await fetchInvites(token(OWNER), { limit: "1" });
    expect(status).toBe(200);
    expect(events[0]?.payload?.["inviteId"]).toBe("legacy-new");
    const rows = await env.DB.prepare(
      "SELECT row_id AS rowId, payload FROM org_audit_events WHERE row_id IS NULL",
    ).all<{ rowId: string | null; payload: string }>();
    // The off-page NULL row (legacy-old) remains unbackfilled = one
    // read's writes are bounded to the observed page. It gets backfilled
    // when a page containing it is next read
    expect(rows.results.map((row) => row.payload)).toEqual(['{"inviteId":"legacy-old"}']);
  });

  it("no non-invite.* org events or other projects' rows leak in (purity of the predicate)", async () => {
    const inviteId = await issueInvite("member");
    // Directly seed an org event with the same project_id (the org-admin
    // axis's domain) and an invite row of another project, and pin that
    // neither appears in the response
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO org_audit_events (server_ts, event, actor_type, actor_user_id, org_id, project_id) VALUES (1, 'org.project_created', 'user', ?, 'org-data-0001', ?)",
      ).bind(OWNER, projectId),
      env.DB.prepare(
        "INSERT INTO org_audit_events (server_ts, event, actor_type, actor_user_id, project_id, payload) VALUES (2, 'invite.created', 'user', ?, 'project-other', '{\"inviteId\":\"other\"}')",
      ).bind(OWNER),
    ]);
    const { events } = await fetchInvites(token(OWNER), { limit: "200" });
    expect(eventNames(events)).toEqual(["invite.created"]);
    expect(events[0]?.payload?.["inviteId"]).toBe(inviteId);
  });
});

describe("user events read by the owner (§3.1 / §6 — self)", () => {
  it("a session principal can read their own account events newest-first (other people's rows are invisible)", async () => {
    const session = await loginSession(9001);
    const response = await SELF.fetch(`${BASE}/auth/audit/events?limit=200`, {
      headers: sessionHeaders(session),
    });
    expect(response.status).toBe(200);
    const { events } = (await response.json()) as { events: readonly WireAuditEvent[] };
    expect(events.length).toBeGreaterThan(0);
    // Newest first (server_ts non-increasing). Since seq is not carried
    // in the D1 response (§7), row identity is confirmed via the opaque
    // row id
    const times = events.map((event) => event.serverTs);
    expect(times).toEqual([...times].toSorted((a, b) => b - a));
    const ids = events.map((event) => event.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const event of events) {
      expect(event.seq).toBeUndefined();
    }
    // Evidence of the real issuance paths: the CLI handoff (setup) + this Web login
    expect(eventNames(events)).toEqual(
      expect.arrayContaining(["auth.token_created", "auth.login_succeeded"]),
    );
    // Only one's own rows (§6): not a single row appears where neither the actor nor the target is the user
    for (const event of events) {
      expect(event.actor.userId === OWNER || event.targetUserId === OWNER).toBe(true);
    }
  });

  it("a scope-limited token gets a 403 (same level as §13-2); a `*` × admin token is allowed", async () => {
    const limited = await scopedToken(9001, "self-limited", [
      { project: projectId, permission: "admin" },
    ]);
    const denied = await SELF.fetch(`${BASE}/auth/audit/events`, {
      headers: bearer(limited),
    });
    expect(denied.status).toBe(403);
    const allowed = await SELF.fetch(`${BASE}/auth/audit/events`, {
      headers: bearer(tokenOf(fixture.tokens, OWNER)),
    });
    expect(allowed.status).toBe(200);
  });
});
