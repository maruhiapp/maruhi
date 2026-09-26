// Integration tests for the project-list API (AUTH_SPEC §11-5).
// Verifies the HttpApi and D1 / DO via SELF on
// @cloudflare/vitest-plugin (the real workerd environment).
//
// What this suite pins (session-42 ruling BL):
// - only one's own memberships (consistency with existence hiding
//   §11-2: another person's project never appears at all, not even
//   its status; a non-member gets an empty list)
// - following chain acceptance: appears on add_member (role
//   included), the role follows on change_role (behavioral proof
//   that the projection carries no role), disappears on
//   remove_member
// - ghost rows are excluded on read + deleted (the list's
//   correctness does not depend on the projection delete's success
//   — the crux of ruling BI-c)
// - lazy upsert (§11-5 (4)): a missing projection row self-heals on
//   a successful chain fetch (the same path as the unattended
//   backfill for pre-projection projects)
// - intersection with token scopes (out of scope = absent) and the
//   session principal's permission (§5)
// - cursor paging (candidate-based, ascending project_id, a
//   server-fixed page size of 100)

import { env, runInDurableObject, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { PROJECT_LIST_PAGE_SIZE } from "../src/policy.ts";
import { BASE, bearer, cliToken, loginSession, sessionHeaders } from "./support/auth.ts";
import { vectorKeyOf } from "./support/data-crypto.ts";
import {
  appendOperation,
  MEMBER,
  OWNER,
  projectId,
  READER,
  STRANGER,
} from "./support/data-fixture.ts";
import { fixture, registerDataScenario, token } from "./support/data-scenario.ts";
import { resetProjectDo } from "./support/project-do.ts";

registerDataScenario();

interface WireMembership {
  readonly projectId: string;
  readonly role: "owner" | "admin" | "member" | "reader";
}

interface WireProjectList {
  readonly projects: readonly WireMembership[];
  readonly nextAfter?: string;
}

function listRequest(headers: Record<string, string>, after?: string): Promise<Response> {
  const suffix = after === undefined ? "" : `?after=${after}`;
  return SELF.fetch(`${BASE}/projects${suffix}`, { headers });
}

async function listOk(headers: Record<string, string>, after?: string): Promise<WireProjectList> {
  const response = await listRequest(headers, after);
  expect(response.status).toBe(200);
  return (await response.json()) as WireProjectList;
}

/** Direct manipulation of projection rows (for reproducing revocation windows / paging — the implementation uses D1 as the candidate index). */
async function projectionRowsOf(userId: string): Promise<readonly string[]> {
  const rows = await env.DB.prepare(
    "SELECT project_id FROM project_members WHERE user_id = ? ORDER BY project_id",
  )
    .bind(userId)
    .all<{ project_id: string }>();
  return rows.results.map((row) => row.project_id);
}

async function insertProjectionRow(targetProjectId: string, userId: string): Promise<void> {
  await env.DB.prepare(
    "INSERT OR IGNORE INTO project_members (project_id, user_id, created_at) VALUES (?, ?, 0)",
  )
    .bind(targetProjectId, userId)
    .run();
}

async function deleteProjectionRow(targetProjectId: string, userId: string): Promise<void> {
  await env.DB.prepare("DELETE FROM project_members WHERE project_id = ? AND user_id = ?")
    .bind(targetProjectId, userId)
    .run();
}

/** A synthetic project ID matching ProjectIdSchema (64 lowercase hex chars), sortable ascending. */
function fakeProjectId(index: number): string {
  return index.toString(16).padStart(64, "0");
}

describe("the project list (AUTH_SPEC §11-5)", () => {
  it("returns only the caller's own memberships (with chain-derived role; a non-member gets an empty list)", async () => {
    const owner = await listOk(bearer(token(OWNER)));
    expect(owner.projects).toEqual([{ projectId, role: "owner" }]);
    expect(owner.nextAfter).toBeUndefined();
    const member = await listOk(bearer(token(MEMBER)));
    expect(member.projects).toEqual([{ projectId, role: "member" }]);
    const reader = await listOk(bearer(token(READER)));
    expect(reader.projects).toEqual([{ projectId, role: "reader" }]);
    // Non-member: an empty list (existence hiding §11-2 — it carries no existence information about others' projects)
    const stranger = await listOk(bearer(token(STRANGER)));
    expect(stranger.projects).toEqual([]);
  });

  it("follows chain acceptance: disappears on remove_member, appears on add_member, and the role moves on change_role", async () => {
    // remove_member → disappears from the list (the task-mandated pin)
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: READER },
    });
    expect((await listOk(bearer(token(READER)))).projects).toEqual([]);
    // The acceptance-path projection delete (§11-5 (3)) has also removed the row
    expect(await projectionRowsOf(READER)).toEqual([]);
    // add_member (re-adding under the same key) → appears (acceptance-path projection upsert — §11-5 (2))
    const keys = vectorKeyOf(READER);
    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: READER,
        encPubHex: keys.enc_pub_hex,
        sigPubHex: keys.sig_pub_hex,
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });
    expect((await listOk(bearer(token(READER)))).projects).toEqual([{ projectId, role: "member" }]);
    // change_role → the role follows (the projection holds no role; the DO's current value becomes the response)
    await appendOperation(fixture, OWNER, {
      op: "change_role",
      payload: {
        targetUserId: READER,
        newRole: "admin",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });
    expect((await listOk(bearer(token(READER)))).projects).toEqual([{ projectId, role: "admin" }]);
    // Other members' lists are unchanged
    expect((await listOk(bearer(token(OWNER)))).projects).toEqual([{ projectId, role: "owner" }]);
  });

  it("excludes a stale ghost row from the response and deletes it at read time to converge (ruling BI-c)", async () => {
    // Restoring just the projection row after remove_member is
    // accepted = reproducing a revocation window where the
    // acceptance-path delete failed. The list's correctness does not
    // depend on the delete's success
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: MEMBER },
    });
    await insertProjectionRow(projectId, MEMBER);
    const removed = await listOk(bearer(token(MEMBER)));
    expect(removed.projects).toEqual([]);
    // The read-time check has deleted the stale row (converging to chain truth)
    expect(await projectionRowsOf(MEMBER)).toEqual([]);
  });

  it("a missing projection row self-heals via lazy upsert on a successful chain fetch (§11-5 (4) — the migration path)", async () => {
    // Reproduces a D1 outage at add_member time (the missing window)
    // / a pre-projection project
    await deleteProjectionRow(projectId, MEMBER);
    expect((await listOk(bearer(token(MEMBER)))).projects).toEqual([]);
    // The chain fetch (an existing endpoint — its response is unchanged) creates the projection row
    const chain = await SELF.fetch(`${BASE}/projects/${projectId}/chain`, {
      headers: bearer(token(MEMBER)),
    });
    expect(chain.status).toBe(200);
    expect((await listOk(bearer(token(MEMBER)))).projects).toEqual([{ projectId, role: "member" }]);
  });

  it("intersects with token scopes (out of scope = absent; a read level suffices)", async () => {
    // A read scope covering the target project → it appears
    const scoped = await cliToken(9002, [{ project: projectId, permission: "read" }], "scoped-in");
    expect((await listOk(bearer(scoped))).projects).toEqual([{ projectId, role: "member" }]);
    // A scope limited to another project → absent even for a member
    // (a 200 with zero existence information)
    const other = fakeProjectId(1);
    const outOfScope = await cliToken(
      9002,
      [{ project: other, permission: "admin" }],
      "scoped-out",
    );
    expect((await listOk(bearer(outOfScope))).projects).toEqual([]);
  });

  it("nextAfter carries no out-of-scope project_id (the intersection at the candidate-index stage)", async () => {
    // Insert a full page's worth of out-of-scope synthetic candidates
    // (the path where an out-of-scope id at the candidate page's tail
    // would leak into nextAfter)
    for (let index = 1; index <= PROJECT_LIST_PAGE_SIZE; index += 1) {
      await insertProjectionRow(fakeProjectId(index), OWNER);
    }
    const scoped = await cliToken(
      9001,
      [{ project: projectId, permission: "read" }],
      "scoped-owner",
    );
    const response = await listOk(bearer(scoped));
    expect(response.projects).toEqual([{ projectId, role: "owner" }]);
    expect(response.nextAfter).toBeUndefined();
    // No field of the response shows an out-of-scope id (§11-5's invariant)
    const raw = JSON.stringify(response);
    expect(raw).not.toContain(fakeProjectId(1));
    expect(raw).not.toContain(fakeProjectId(PROJECT_LIST_PAGE_SIZE));
  });

  it("every page succeeds even with a token at the scope cap (100 entries) (D1's bound-parameter limit)", async () => {
    // 100 scopes filling the schema cap (the real project + 99
    // synthetic). As a single IN clause, together with userId / after
    // / limit it would exceed D1's 100-parameter limit and the list
    // would hard-fail (page 2 with after is worst-case 103)
    const fakes = Array.from({ length: 99 }, (_unused, index) => fakeProjectId(index + 1));
    const scopes = [
      { project: projectId, permission: "read" as const },
      ...fakes.map((project) => ({ project, permission: "read" as const })),
    ];
    expect(scopes).toHaveLength(100);
    for (const fake of fakes) {
      await insertProjectionRow(fake, OWNER);
    }
    const wide = await cliToken(9001, scopes, "scope-cap");
    // Page 1: 100 candidates (99 synthetic + 1 real = full) → a
    // nextAfter chain
    const first = await listOk(bearer(wide));
    expect(first.projects).toEqual([{ projectId, role: "owner" }]);
    expect(first.nextAfter).toBe(projectId);
    // Page 2 (the worst-case parameter count with `after` included)
    // also succeeds and terminates
    const second = await listOk(bearer(wide), first.nextAfter);
    expect(second.projects).toEqual([]);
    expect(second.nextAfter).toBeUndefined();
  });

  it("skips candidates whose DO cannot answer the check, while the rest of the enumeration still works (the row is kept)", async () => {
    // Mix in a DO with a corrupted chain (a stored row that fails
    // JSON conformance) — the shape that makes memberRoleFor a
    // defect. Use a dedicated ID that won't collide with other
    // tests, and clean it up at the end
    const broken = fakeProjectId(0xb0b);
    await insertProjectionRow(broken, OWNER);
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(broken));
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec(
        "INSERT INTO chain_entries (seq, entry_json, entry_hash_hex, canonical_bytes) VALUES (1, 'not-json', 'broken', 8)",
      );
    });
    try {
      const response = await listOk(bearer(token(OWNER)));
      // The corrupted candidate is omitted from the response, and
      // the rest (the real project) still enumerates
      expect(response.projects).toEqual([{ projectId, role: "owner" }]);
      // The row is kept (ghost deletion applies only to a definite
      // non-member answer — so it can reappear once the outage
      // clears)
      expect(await projectionRowsOf(OWNER)).toEqual([broken, projectId].toSorted());
    } finally {
      await resetProjectDo(broken);
    }
  });

  it("a session principal can list (§5's permitted set)", async () => {
    const session = await loginSession(9001);
    const viaSession = await listOk(sessionHeaders(session));
    expect(viaSession.projects).toEqual([{ projectId, role: "owner" }]);
  });

  it("candidate-based cursor paging (ascending project_id, fixed page size 100, a nextAfter chain)", async () => {
    // Insert a page's worth of synthetic IDs that sort before the
    // real project in ascending order (their DO side is
    // uninitialized = ghost — a composite check of paging plus
    // read-time convergence). Fixed IDs are used on the premise
    // that the real project ID happens not to fall in the fake
    // range
    expect(projectId > fakeProjectId(PROJECT_LIST_PAGE_SIZE)).toBe(true);
    for (let index = 1; index <= PROJECT_LIST_PAGE_SIZE; index += 1) {
      await insertProjectionRow(fakeProjectId(index), OWNER);
    }
    // Page 1: 100 candidates (all ghost) → the response is empty +
    // nextAfter = the candidate tail
    const first = await listOk(bearer(token(OWNER)));
    expect(first.projects).toEqual([]);
    expect(first.nextAfter).toBe(fakeProjectId(PROJECT_LIST_PAGE_SIZE));
    // Page 2: the real project appears and it terminates (no nextAfter)
    const second = await listOk(bearer(token(OWNER)), first.nextAfter);
    expect(second.projects).toEqual([{ projectId, role: "owner" }]);
    expect(second.nextAfter).toBeUndefined();
    // All the ghost candidates were deleted at page 1's read (only
    // the live rows remain)
    expect(await projectionRowsOf(OWNER)).toEqual([projectId]);
  });
});
