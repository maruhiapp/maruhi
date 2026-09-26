// Integration tests for the audit-event read API (AUDIT_SPEC §6 / §7).
//
// Properties being pinned:
//  1. Visibility classes (§6): below admin, only class-1 rows + rows
//     where the user themself is the actor. Class 2 (var.read /
//     dek.registered / dek.deleted) appears nowhere — not in results,
//     paging, or cursors ("behaves as though it did not exist"). Admin
//     visibility is "chain role admin × token scope admin" (the min
//     discipline — not disclosed even to an admin user holding a
//     read-scope token)
//  2. Specifying someone else in the actor_user_id filter is a 403 for
//     below-admin (§6: "cross-searching rows whose actor is someone else
//     is class 2"). Specifying oneself is allowed
//
// Paging bounds, invite.*, and self reads live in
// audit-read-paging.test.ts (shared helpers in
// support/audit-read-scenario.ts; see the top of
// support/membership-scenario.ts for the split's motivation).

import { auditReadVariablesOf } from "@maruhi/core";
import { describe, expect, it } from "vitest";

import { isClass1Event } from "../src/audit-store.ts";
import {
  eventNames,
  fetchEvents,
  scopedToken,
  seedProjectActivity,
} from "./support/audit-read-scenario.ts";
import {
  ALL_MEMBERS,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  STRANGER,
} from "./support/data-fixture.ts";
import { ENV, registerDataScenario, token, VAR } from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

describe("enforcing the visibility classes (§6)", () => {
  it("below admin sees only class 1 + rows where the user themself is the actor (class 2 does not leak even via counts)", async () => {
    await seedProjectActivity();
    const { status, events } = await fetchEvents(token(READER), { limit: "200" });
    expect(status).toBe(200);
    // All class-1 rows are visible
    expect(eventNames(events)).toEqual(
      expect.arrayContaining([
        "chain.genesis",
        "chain.member_added",
        "chain.environment_created",
        "env.created",
        "var.created",
      ]),
    );
    // One's own var.read is visible (self-read regardless of class)
    expect(
      events.some((event) => event.event === "var.read" && event.actor.userId === READER),
    ).toBe(true);
    // Other people's var.read / dek.registered (class 2) — not a single row appears
    expect(events.some((event) => event.event === "dek.registered")).toBe(false);
    expect(
      events.some((event) => event.event === "var.read" && event.actor.userId !== READER),
    ).toBe(false);
    // Check the visibility condition itself (allowlist ∨ self) on every
    // row. A below-admin response carries no seq (the ordinal of gapless
    // numbering); row identifiers are only the opaque row id (AUDIT_SPEC
    // §7 — blocking inference of class-2 counts from ordinals)
    for (const event of events) {
      expect(isClass1Event(event.event) || event.actor.userId === READER).toBe(true);
      expect(event.seq).toBeUndefined();
      expect(event.id).toMatch(/^[0-9a-f]{32}$/);
    }
  });

  it("chain role admin × admin scope sees every row", async () => {
    await seedProjectActivity();
    const { status, events } = await fetchEvents(token(OWNER), { limit: "200" });
    expect(status).toBe(200);
    // Class 2: dek.registered addressed to every member and both users' var.read are visible
    const dekTargets = events
      .filter((event) => event.event === "dek.registered")
      .map((event) => event.targetUserId)
      .toSorted();
    expect(dekTargets).toEqual([...ALL_MEMBERS].toSorted());
    const readActors = events
      .filter((event) => event.event === "var.read")
      .map((event) => event.actor.userId)
      .toSorted();
    expect(readActors).toEqual([MEMBER, READER].toSorted());
    // The admin-visible response carries the stored seq (material for §6's "a gap = a trace of deletion" detection)
    for (const event of events) {
      expect(event.seq).toBeGreaterThan(0);
    }
  });

  it("with a read-scope token, even an admin user does not see others' class-2 rows (min(scope, role))", async () => {
    await seedProjectActivity();
    // A read-scope-limited token for OWNER (chain role owner). Given a
    // distinct name so same-name rotation (AUTH_SPEC §6) does not revoke
    // the fixture's token
    const readToken = await scopedToken(9001, "read-only-audit", [
      { project: projectId, permission: "read" },
    ]);
    const { status, events } = await fetchEvents(readToken, { limit: "200" });
    expect(status).toBe(200);
    // Class-2 rows whose actor is someone else (READER's / MEMBER's
    // var.read) are invisible — the opposite of the admin-scope token
    // (previous test), which sees them
    expect(events.some((event) => event.event === "var.read")).toBe(false);
    // Rows where the user themself is the actor (dek.registered — the
    // signer is OWNER) stay self-readable regardless of class (§6)
    expect(
      events.some((event) => event.event === "dek.registered" && event.actor.userId === OWNER),
    ).toBe(true);
  });

  it("a non-member gets a 404 (existence hiding — §11-2)", async () => {
    await seedProjectActivity();
    const { status } = await fetchEvents(token(STRANGER));
    expect(status).toBe(404);
  });
});

describe("filters (the §7 vocabulary) and the permission of the actor filter", () => {
  it("can filter by event / environmentId / variableId / targetUserId", async () => {
    await seedProjectActivity();
    const byEvent = await fetchEvents(token(OWNER), { event: "var.created" });
    expect(eventNames(byEvent.events)).toEqual(["var.created"]);
    const byVariable = await fetchEvents(token(OWNER), {
      environmentId: ENV,
      variableId: VAR,
      limit: "200",
    });
    expect(byVariable.events.length).toBeGreaterThan(0);
    for (const event of byVariable.events) {
      expect(event.environmentId).toBe(ENV);
      if (event.event === "var.read") {
        // The aggregated form of var.read (§3.3) has no variable ID
        // column; rows whose payload enumeration contains that variable
        // match the filter (§7 / Q4)
        expect(event.variableId).toBeUndefined();
        expect(auditReadVariablesOf(event.payload)?.map((v) => v.variableId)).toContain(VAR);
      } else {
        expect(event.variableId).toBe(VAR);
      }
    }
    // Both the legacy column match (var.created etc.) and the aggregated payload match are returned
    expect(eventNames(byVariable.events)).toEqual(
      expect.arrayContaining(["var.created", "var.version_pushed", "var.read"]),
    );
    const byTarget = await fetchEvents(token(OWNER), { targetUserId: READER, limit: "200" });
    expect(eventNames(byTarget.events)).toEqual(
      expect.arrayContaining(["chain.member_added", "dek.registered"]),
    );
    for (const event of byTarget.events) {
      expect(event.targetUserId).toBe(READER);
    }
  });

  it("eventPrefix narrows to a whole namespace (full retrieval for mirror verification)", async () => {
    await seedProjectActivity();
    const { status, events } = await fetchEvents(token(OWNER), {
      eventPrefix: "chain.",
      limit: "200",
    });
    expect(status).toBe(200);
    expect(events.length).toBeGreaterThan(0);
    // Every row of the namespace is returned; no outside rows (env.* / var.* / dek.*) are mixed in
    for (const event of events) {
      expect(event.event.startsWith("chain.")).toBe(true);
    }
    const all = await fetchEvents(token(OWNER), { limit: "200" });
    expect(events.length).toBe(all.events.filter((e) => e.event.startsWith("chain.")).length);
  });

  it("a chain.* row absent from the mapping still reaches below-admin readers (§6 makes the whole namespace class 1)", async () => {
    // verify does not require admin (every member can run it). If the
    // visibility predicate admitted only mapped names, a forged row would
    // be dropped server-side and never reach a reader's verify, leaving a
    // coverage hole on the forgery side for non-admins
    await seedProjectActivity();
    await queryProjectDo(
      projectId,
      "INSERT INTO audit_events (seq, row_id, server_ts, event, actor_type, chain_seq) VALUES ((SELECT MAX(seq) + 1 FROM audit_events), ?, ?, 'chain.role_granted', 'user', 2)",
      "ab".repeat(16),
      Date.now(),
    );
    for (const viewer of [READER, MEMBER, OWNER]) {
      const { status, events } = await fetchEvents(token(viewer), {
        eventPrefix: "chain.",
        limit: "200",
      });
      expect(status).toBe(200);
      expect(eventNames(events)).toContain("chain.role_granted");
    }
    // Class 2 (others' var.read / dek.registered) stays invisible to
    // below-admin — the namespace's prefix allowance must not become a
    // class-2 hole
    const readerAll = await fetchEvents(token(READER), { limit: "200" });
    expect(readerAll.events.some((event) => event.event === "dek.registered")).toBe(false);
    for (const event of readerAll.events) {
      expect(isClass1Event(event.event) || event.actor.userId === READER).toBe(true);
    }
  });

  it("a non-chain.* row claiming a chain_seq also reaches every member's verification filter", async () => {
    await seedProjectActivity();
    await queryProjectDo(
      projectId,
      "INSERT INTO audit_events (seq, row_id, server_ts, event, actor_type, actor_user_id, chain_seq) VALUES ((SELECT MAX(seq) + 1 FROM audit_events), ?, ?, 'member.add', 'user', ?, 2)",
      "cd".repeat(16),
      Date.now(),
      OWNER,
    );
    await queryProjectDo(
      projectId,
      "INSERT INTO audit_events (seq, row_id, server_ts, event, actor_type, actor_user_id) VALUES ((SELECT MAX(seq) + 1 FROM audit_events), ?, ?, 'member.add', 'user', ?)",
      "ef".repeat(16),
      Date.now(),
      OWNER,
    );

    for (const viewer of [READER, MEMBER, OWNER]) {
      const { status, events } = await fetchEvents(token(viewer), {
        chainSeqPresent: "true",
        limit: "200",
      });
      expect(status).toBe(200);
      expect(events.length).toBeGreaterThan(0);
      expect(events.every((event) => event.chainSeq !== undefined)).toBe(true);
      expect(eventNames(events)).toContain("member.add");
    }

    const readerAll = await fetchEvents(token(READER), { limit: "200" });
    const claims = readerAll.events.filter((event) => event.event === "member.add");
    expect(claims).toHaveLength(1);
    expect(claims[0]?.chainSeq).toBe(2);
  });

  it("chainSeqPresent rejects anything but literal true via the wire schema", async () => {
    await seedProjectActivity();
    const response = await requestJson("GET", "/audit/events?chainSeqPresent=false", token(OWNER));
    expect(response.status).toBe(400);
  });

  it("eventPrefix has no wildcard semantics (a prefix comparison, not LIKE)", async () => {
    await seedProjectActivity();
    // If it were a LIKE implementation, "%" would match everything and "_" would act as a one-char wildcard
    for (const eventPrefix of ["%", "_hain.", "chain%"]) {
      const { status, events } = await fetchEvents(token(OWNER), { eventPrefix, limit: "200" });
      expect(status).toBe(200);
      expect(events).toHaveLength(0);
    }
  });

  it("a below-admin actorUserId filter is limited to oneself (naming someone else is a 403)", async () => {
    await seedProjectActivity();
    // Specifying oneself is allowed and returns only one's own rows (including the class-2 var.read)
    const self = await fetchEvents(token(MEMBER), { actorUserId: MEMBER, limit: "200" });
    expect(self.status).toBe(200);
    expect(self.events.length).toBeGreaterThan(0);
    for (const event of self.events) {
      expect(event.actor.userId).toBe(MEMBER);
    }
    expect(self.events.some((event) => event.event === "var.read")).toBe(true);
    // Specifying someone else is a data-independent 403 (§6: cross-searching rows whose actor is someone else is class 2)
    const other = await fetchEvents(token(MEMBER), { actorUserId: READER });
    expect(other.status).toBe(403);
    // An admin can cross-search by naming someone else
    const admin = await fetchEvents(token(OWNER), { actorUserId: READER, limit: "200" });
    expect(admin.status).toBe(200);
    expect(admin.events.some((event) => event.event === "var.read")).toBe(true);
    for (const event of admin.events) {
      expect(event.actor.userId).toBe(READER);
    }
  });

  it("a below-admin class-2 event-kind filter returns only one's own rows (empty is not a 403)", async () => {
    await seedProjectActivity();
    // READER has no dek.registered (the signer is OWNER) — it returns empty
    const hidden = await fetchEvents(token(READER), { event: "dek.registered" });
    expect(hidden.status).toBe(200);
    expect(hidden.events).toEqual([]);
    // One's own var.read stays visible through the event-kind filter
    const own = await fetchEvents(token(READER), { event: "var.read" });
    expect(own.status).toBe(200);
    expect(own.events.length).toBeGreaterThan(0);
    for (const event of own.events) {
      expect(event.actor.userId).toBe(READER);
    }
  });
});
