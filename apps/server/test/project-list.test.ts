import { env, runInDurableObject, SELF } from "cloudflare:test";
import { describe, expect, it, vi } from "vite-plus/test";

import { ensureProjectDoTables } from "../src/do/do-schema.ts";
import { PROJECT_LIST_PAGE_SIZE } from "../src/policy.ts";
import { BASE, bearer, cliToken, loginSession, sessionHeaders } from "./support/auth.ts";
import { vectorKeyOf } from "./support/data-crypto.ts";
import { testProjectId } from "./support/data-crypto.ts";
import {
  appendOperation,
  MEMBER,
  OWNER,
  projectId,
  READER,
  STRANGER,
} from "./support/data-fixture.ts";
import { fixture, registerDataScenario, token } from "./support/data-scenario.ts";
import { callProjectDo, resetProjectDo } from "./support/project-do.ts";

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
    const stranger = await listOk(bearer(token(STRANGER)));
    expect(stranger.projects).toEqual([]);
  });

  it("follows chain acceptance: disappears on remove_member, appears on add_member, and the role moves on change_role", async () => {
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: READER },
    });
    expect((await listOk(bearer(token(READER)))).projects).toEqual([]);
    expect(await projectionRowsOf(READER)).toEqual([]);
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
    expect((await listOk(bearer(token(OWNER)))).projects).toEqual([{ projectId, role: "owner" }]);
  });

  it("excludes a stale ghost row from the response and deletes it at read time to converge (ruling BI-c)", async () => {
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: MEMBER },
    });
    await insertProjectionRow(projectId, MEMBER);
    const removed = await listOk(bearer(token(MEMBER)));
    expect(removed.projects).toEqual([]);
    expect(await projectionRowsOf(MEMBER)).toEqual([]);
  });

  it("a missing projection row self-heals via lazy upsert on a successful chain fetch (§11-5 (4) — the migration path)", async () => {
    await deleteProjectionRow(projectId, MEMBER);
    expect((await listOk(bearer(token(MEMBER)))).projects).toEqual([]);
    const chain = await SELF.fetch(`${BASE}/projects/${projectId}/chain`, {
      headers: bearer(token(MEMBER)),
    });
    expect(chain.status).toBe(200);
    expect((await listOk(bearer(token(MEMBER)))).projects).toEqual([{ projectId, role: "member" }]);
  });

  it("intersects with token scopes (out of scope = absent; a read level suffices)", async () => {
    const scoped = await cliToken(
      9002,
      [{ project: testProjectId(projectId), permission: "read" }],
      "scoped-in",
    );
    expect((await listOk(bearer(scoped))).projects).toEqual([{ projectId, role: "member" }]);
    const other = fakeProjectId(1);
    const outOfScope = await cliToken(
      9002,
      [{ project: testProjectId(other), permission: "admin" }],
      "scoped-out",
    );
    expect((await listOk(bearer(outOfScope))).projects).toEqual([]);
  });

  it("nextAfter carries no out-of-scope project_id (the intersection at the candidate-index stage)", async () => {
    for (let index = 1; index <= PROJECT_LIST_PAGE_SIZE; index += 1) {
      await insertProjectionRow(fakeProjectId(index), OWNER);
    }
    const scoped = await cliToken(
      9001,
      [{ project: testProjectId(projectId), permission: "read" }],
      "scoped-owner",
    );
    const response = await listOk(bearer(scoped));
    expect(response.projects).toEqual([{ projectId, role: "owner" }]);
    expect(response.nextAfter).toBeUndefined();
    const raw = JSON.stringify(response);
    expect(raw).not.toContain(fakeProjectId(1));
    expect(raw).not.toContain(fakeProjectId(PROJECT_LIST_PAGE_SIZE));
  });

  it("every page succeeds even with a token at the scope cap (100 entries) (D1's bound-parameter limit)", async () => {
    const fakes = Array.from({ length: 99 }, (_unused, index) => fakeProjectId(index + 1));
    const scopes = [
      { project: testProjectId(projectId), permission: "read" as const },
      ...fakes.map((project) => ({ project: testProjectId(project), permission: "read" as const })),
    ];
    expect(scopes).toHaveLength(100);
    for (const fake of fakes) {
      await insertProjectionRow(fake, OWNER);
    }
    const wide = await cliToken(9001, scopes, "scope-cap");
    const first = await listOk(bearer(wide));
    expect(first.projects).toEqual([{ projectId, role: "owner" }]);
    expect(first.nextAfter).toBe(projectId);
    const second = await listOk(bearer(wide), first.nextAfter);
    expect(second.projects).toEqual([]);
    expect(second.nextAfter).toBeUndefined();
  });

  it("skips candidates whose DO cannot answer the check, while the rest of the enumeration still works (the row is kept)", async () => {
    const broken = fakeProjectId(0xb0b);
    await insertProjectionRow(broken, OWNER);
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(broken));
    await runInDurableObject(stub, (_instance, state) => {
      ensureProjectDoTables(state.storage);
      state.storage.sql.exec(
        "INSERT INTO chain_entries (seq, entry_json, entry_hash_hex, canonical_bytes) VALUES (1, 'not-json', 'broken', 8)",
      );
    });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const response = await listOk(bearer(token(OWNER)));
      expect(response.projects).toEqual([{ projectId, role: "owner" }]);
      expect(warn.mock.calls).toEqual([
        [
          "project list: a membership confirmation failed; omitting that project from the page (its projection row is retained)",
          "ChainInvalid",
        ],
      ]);
      expect(JSON.stringify(warn.mock.calls)).not.toContain(broken);
      await expect(
        callProjectDo(broken, (instance) => instance.memberRoleFor(OWNER)),
      ).rejects.toMatchObject({ _tag: "ChainInvalid", seq: 1, reason: "invalid-payload" });
      for (const path of ["chain", "schema-policy", "invites"]) {
        const failed = await SELF.fetch(`${BASE}/projects/${broken}/${path}`, {
          headers: bearer(token(OWNER)),
        });
        expect(failed.status, path).toBe(500);
      }
      expect(await projectionRowsOf(OWNER)).toEqual([broken, projectId].toSorted());
    } finally {
      warn.mockRestore();
      await resetProjectDo(broken);
    }
  });

  it("a session principal can list (§5's permitted set)", async () => {
    const session = await loginSession(9001);
    const viaSession = await listOk(sessionHeaders(session));
    expect(viaSession.projects).toEqual([{ projectId, role: "owner" }]);
  });

  it("candidate-based cursor paging (ascending project_id, fixed page size 100, a nextAfter chain)", async () => {
    expect(projectId > fakeProjectId(PROJECT_LIST_PAGE_SIZE)).toBe(true);
    for (let index = 1; index <= PROJECT_LIST_PAGE_SIZE; index += 1) {
      await insertProjectionRow(fakeProjectId(index), OWNER);
    }
    const first = await listOk(bearer(token(OWNER)));
    expect(first.projects).toEqual([]);
    expect(first.nextAfter).toBe(fakeProjectId(PROJECT_LIST_PAGE_SIZE));
    const second = await listOk(bearer(token(OWNER)), first.nextAfter);
    expect(second.projects).toEqual([{ projectId, role: "owner" }]);
    expect(second.nextAfter).toBeUndefined();
    expect(await projectionRowsOf(OWNER)).toEqual([projectId]);
  });
});
