import { auditReadVariablesOf } from "@maruhi/core";
import { describe, expect, it } from "vite-plus/test";

import { isClass1Event } from "../src/audit-store-query.ts";
import {
  eventNames,
  fetchEvents,
  scopedToken,
  seedProjectActivity,
} from "./support/audit-read-scenario.ts";
import { testProjectId } from "./support/data-crypto.ts";
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
    expect(eventNames(events)).toEqual(
      expect.arrayContaining([
        "chain.genesis",
        "chain.member_added",
        "chain.environment_created",
        "env.created",
        "var.created",
      ]),
    );
    expect(
      events.some((event) => event.event === "var.read" && event.actor.userId === READER),
    ).toBe(true);
    expect(events.some((event) => event.event === "dek.registered")).toBe(false);
    expect(
      events.some((event) => event.event === "var.read" && event.actor.userId !== READER),
    ).toBe(false);
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
    for (const event of events) {
      expect(event.seq).toBeGreaterThan(0);
    }
  });

  it("with a read-scope token, even an admin user does not see others' class-2 rows (min(scope, role))", async () => {
    await seedProjectActivity();
    const readToken = await scopedToken(9001, "read-only-audit", [
      { project: testProjectId(projectId), permission: "read" },
    ]);
    const { status, events } = await fetchEvents(readToken, { limit: "200" });
    expect(status).toBe(200);
    expect(events.some((event) => event.event === "var.read")).toBe(false);
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
        expect(event.variableId).toBeUndefined();
        expect(auditReadVariablesOf(event.payload)?.map((v) => v.variableId)).toContain(VAR);
      } else {
        expect(event.variableId).toBe(VAR);
      }
    }
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
    for (const event of events) {
      expect(event.event.startsWith("chain.")).toBe(true);
    }
    const all = await fetchEvents(token(OWNER), { limit: "200" });
    expect(events.length).toBe(all.events.filter((e) => e.event.startsWith("chain.")).length);
  });

  it("a chain.* row absent from the mapping still reaches below-admin readers (§6 makes the whole namespace class 1)", async () => {
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

  it("an environmentId / variableId filter outside the §12-1 form matches verbatim (an empty page, not a 500)", async () => {
    await seedProjectActivity();
    for (const filter of [{ environmentId: "not.an.id" }, { variableId: "-leading-dash" }]) {
      const { status, events } = await fetchEvents(token(OWNER), { ...filter, limit: "200" });
      expect(status).toBe(200);
      expect(events).toHaveLength(0);
    }
  });

  it("eventPrefix has no wildcard semantics (a prefix comparison, not LIKE)", async () => {
    await seedProjectActivity();
    for (const eventPrefix of ["%", "_hain.", "chain%"]) {
      const { status, events } = await fetchEvents(token(OWNER), { eventPrefix, limit: "200" });
      expect(status).toBe(200);
      expect(events).toHaveLength(0);
    }
  });

  it("a below-admin actorUserId filter is limited to oneself (naming someone else is a 403)", async () => {
    await seedProjectActivity();
    const self = await fetchEvents(token(MEMBER), { actorUserId: MEMBER, limit: "200" });
    expect(self.status).toBe(200);
    expect(self.events.length).toBeGreaterThan(0);
    for (const event of self.events) {
      expect(event.actor.userId).toBe(MEMBER);
    }
    expect(self.events.some((event) => event.event === "var.read")).toBe(true);
    const other = await fetchEvents(token(MEMBER), { actorUserId: READER });
    expect(other.status).toBe(403);
    const admin = await fetchEvents(token(OWNER), { actorUserId: READER, limit: "200" });
    expect(admin.status).toBe(200);
    expect(admin.events.some((event) => event.event === "var.read")).toBe(true);
    for (const event of admin.events) {
      expect(event.actor.userId).toBe(READER);
    }
  });

  it("a below-admin class-2 event-kind filter returns only one's own rows (empty is not a 403)", async () => {
    await seedProjectActivity();
    const hidden = await fetchEvents(token(READER), { event: "dek.registered" });
    expect(hidden.status).toBe(200);
    expect(hidden.events).toEqual([]);
    const own = await fetchEvents(token(READER), { event: "var.read" });
    expect(own.status).toBe(200);
    expect(own.events.length).toBeGreaterThan(0);
    for (const event of own.events) {
      expect(event.actor.userId).toBe(READER);
    }
  });
});
