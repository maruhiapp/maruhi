// ES K3 — scope on invite rows (AUTH_SPEC §15 — format checking only; pins
// behavior already implemented in K2. Item 4 of the design record
// docs/notes/es-design.md §9).
//   - scope on an issue body gets format checking only (no existence check —
//   a not-yet-existing environment id still returns 200)
//   - list rows and the acceptance response carry scope
//   - Containment checking is a consensus rule at add_member admission (not
//   added here)

import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { BASE, bearer, JSON_HEADERS } from "./support/auth.ts";
import { OWNER, projectId, STRANGER, tokenOf } from "./support/data-fixture.ts";
import {
  acceptAs,
  fixture,
  inviteRow,
  issueInviteRequest,
  makeInviteeKeys,
  makeIssuePayload,
  mustRow,
  registerInviteScenario,
  wirePayloadOf,
} from "./support/invites-scenario.ts";

registerInviteScenario();

describe("scope on invite rows (§15 — format checking only)", () => {
  it("admits a listed issuance without checking environment existence, and carries scope on the list row and the acceptance response", async () => {
    const payload = await makeIssuePayload(fixture, OWNER, "member", {
      scopeKind: "listed",
      scopeEnvironmentIds: ["env-never-created-0001", "env-dev-0002"],
    });
    const issued = await issueInviteRequest(fixture, OWNER, "member", payload);
    expect(issued.status).toBe(200);
    const row = mustRow(await inviteRow(payload.id));
    expect(row.scope_kind).toBe("listed");
    expect(JSON.parse(String(row.scope_environments))).toEqual([
      "env-never-created-0001",
      "env-dev-0002",
    ]);

    const list = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      headers: bearer(tokenOf(fixture.tokens, OWNER)),
    });
    expect(list.status).toBe(200);
    const listed = (await list.json()) as {
      invitations: { id: string; scopeKind: string; scopeEnvironmentIds: string[] }[];
    };
    expect(listed.invitations.find((invite) => invite.id === payload.id)).toMatchObject({
      scopeKind: "listed",
      scopeEnvironmentIds: ["env-never-created-0001", "env-dev-0002"],
    });

    const keys = await makeInviteeKeys();
    const accepted = await acceptAs(fixture, STRANGER, keys, payload);
    expect(accepted.status).toBe(200);
    expect(await accepted.json()).toMatchObject({
      id: payload.id,
      role: "member",
      scopeKind: "listed",
      scopeEnvironmentIds: ["env-never-created-0001", "env-dev-0002"],
    });
  });

  it("attaching a non-empty scopeEnvironmentIds to an `all` issuance is a 400 format check (the §15 kind rule — before signature verification)", async () => {
    // The issue-signature producer side (@maruhi/crypto) rejects `all` +
    // non-empty as malformed, so build a valid `all` issuance first and then
    // mutate only the wire body
    const payload = await makeIssuePayload(fixture, OWNER, "member");
    const response = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, OWNER)) },
      body: JSON.stringify({ ...wirePayloadOf(payload), scopeEnvironmentIds: ["env-dev-0002"] }),
    });
    expect(response.status).toBe(400);
  });
});
