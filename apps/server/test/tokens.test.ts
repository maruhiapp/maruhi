// Integration tests for the token-management API + the default TTL
// (AUTH_SPEC §6 — W3a).
//
// - the TTL is fixed at issuance (§6: deliberately asymmetric to the
//   session §5 sliding window)
// - the list returns only one's own metadata (raw values / token_hash
//   are never returned — not even the fields)
// - targeted-revocation judgment order (ruling CG): 401 → 403 (from
//   caller qualification alone) → uniform 404
// - a legacy no-expiry row (expires_at NULL) is fail-closed 401 at
//   verification (ruling CE). The migration SQL (token_ttl_reanchor)
//   is verified by re-running the real thing from TEST_MIGRATIONS

import { applyD1Migrations, env, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import {
  BASE,
  bearer,
  cliIssue,
  cliToken,
  JSON_HEADERS,
  loginSession,
  resetAuthDb,
  sessionHeaders,
} from "./support/auth.ts";

const DAY_MS = 24 * 60 * 60 * 1000;
const SESSION_COOKIE = "__Host-maruhi_session";

/** The full issuance response via the CLI handoff (the real path) — an alias of support's cliIssue. */
const exchange = cliIssue;

interface TokenRow {
  readonly id: string;
  readonly expires_at: number | null;
  readonly created_at: number;
}

async function tokenRow(id: string): Promise<TokenRow> {
  const row = await env.DB.prepare("SELECT id, expires_at, created_at FROM api_tokens WHERE id = ?")
    .bind(id)
    .first<TokenRow>();
  if (row === null) {
    throw new Error("expected token row");
  }
  return row;
}

beforeEach(async () => {
  await resetAuthDb();
});

describe("the default TTL (AUTH_SPEC §6)", () => {
  it("fixes expires_at to created_at + 90 days at issuance and reports it in the response", async () => {
    const issued = await exchange(801);
    const row = await tokenRow(issued.tokenId);
    expect(row.expires_at).toBe(row.created_at + 90 * DAY_MS);
    expect(issued.expiresAtMs).toBe(row.expires_at);
  });

  it("honors an explicit expiresInDays within 1..365 (ruling CF)", async () => {
    const one = await exchange(802, { tokenName: "short", expiresInDays: 1 });
    const oneRow = await tokenRow(one.tokenId);
    expect(oneRow.expires_at).toBe(oneRow.created_at + DAY_MS);

    const max = await exchange(802, { tokenName: "long", expiresInDays: 365 });
    const maxRow = await tokenRow(max.tokenId);
    expect(maxRow.expires_at).toBe(maxRow.created_at + 365 * DAY_MS);
  });

  it("rejects out-of-range or non-integer expiresInDays at the wire schema", async () => {
    for (const expiresInDays of [0, 366, 1.5, -1]) {
      const response = await SELF.fetch(`${BASE}/auth/cli/start`, {
        method: "POST",
        headers: JSON_HEADERS,
        body: JSON.stringify({ expiresInDays }),
      });
      expect(response.status, `expiresInDays=${expiresInDays}`).toBe(400);
    }
    // A malformed value never reaches flow start = never reaches token issuance
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM api_tokens").first<{
      n: number;
    }>();
    expect(count?.n).toBe(0);
  });

  it("treats a legacy NULL expires_at as expired (fail-closed) and re-login self-heals (ruling CE)", async () => {
    const issued = await exchange(804);
    await env.DB.prepare("UPDATE api_tokens SET expires_at = NULL WHERE id = ?")
      .bind(issued.tokenId)
      .run();
    const denied = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(issued.token) });
    expect(denied.status).toBe(401);

    // Re-login (same-name rotation) recovers by issuing a row with expires_at
    const reissued = await exchange(804);
    const row = await tokenRow(reissued.tokenId);
    expect(row.expires_at).not.toBeNull();
    const ok = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(reissued.token) });
    expect(ok.status).toBe(200);
  });

  it("self-discloses the presented token's expiry on /auth/me (ruling CI — a self-credential attribute)", async () => {
    // The path by which unattended use (a PAT on a lease-less
    // environment — ruling CF) observes its own expiry. Even a
    // scope-limited token can see just its own expiry (without
    // opening the list — ruling CH's `*` × admin condition). The
    // session principal is absent (it presented no token)
    const issued = await exchange(806);
    const viaToken = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(issued.token) });
    expect(viaToken.status).toBe(200);
    const tokenMe = (await viaToken.json()) as { tokenExpiresAtMs?: number };
    expect(tokenMe.tokenExpiresAtMs).toBe(issued.expiresAtMs);

    const scoped = await cliToken(
      806,
      [{ project: "ef".repeat(32), permission: "read" }],
      "scoped",
    );
    const viaScoped = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(scoped) });
    expect(viaScoped.status).toBe(200);
    expect(((await viaScoped.json()) as { tokenExpiresAtMs?: number }).tokenExpiresAtMs).toBeTypeOf(
      "number",
    );

    const session = await loginSession(806);
    const viaSession = await SELF.fetch(`${BASE}/auth/me`, {
      headers: { cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(viaSession.status).toBe(200);
    expect(Object.hasOwn((await viaSession.json()) as object, "tokenExpiresAtMs")).toBe(false);
  });

  it("re-anchors legacy NULL rows to apply-time + 90 days (migration token_ttl_reanchor)", async () => {
    const issued = await exchange(805);
    await env.DB.prepare("UPDATE api_tokens SET expires_at = NULL WHERE id = ?")
      .bind(issued.tokenId)
      .run();
    // Re-run the real migration SQL taken from TEST_MIGRATIONS (no
    // SQL copies in the test). As an UPDATE statement it applies
    // idempotently regardless of the already-applied record
    const migration = env.TEST_MIGRATIONS.find((entry) =>
      entry.name.includes("token_ttl_reanchor"),
    );
    if (migration === undefined) {
      throw new Error("expected the token_ttl_reanchor migration in TEST_MIGRATIONS");
    }
    const before = Date.now();
    for (const query of migration.queries) {
      await env.DB.prepare(query).run();
    }
    const row = await tokenRow(issued.tokenId);
    expect(row.expires_at).not.toBeNull();
    // unixepoch() is second-precision, so allow ±1s of rounding
    expect(row.expires_at ?? 0).toBeGreaterThanOrEqual(before - 1000 + 90 * DAY_MS);
    expect(row.expires_at ?? 0).toBeLessThanOrEqual(Date.now() + 1000 + 90 * DAY_MS);
    // The re-anchored token works again (a 90-day re-login grace)
    const ok = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(issued.token) });
    expect(ok.status).toBe(200);
  });
});

describe("GET /auth/tokens (listing — AUTH_SPEC §6)", () => {
  it("returns the caller's own token metadata for a session principal, without raw values or hashes", async () => {
    const session = await loginSession(811);
    const issued = await exchange(811, { tokenName: "inventory" });
    // Another user's token does not appear
    await exchange(812, { tokenName: "someone-else" });

    const response = await SELF.fetch(`${BASE}/auth/tokens`, {
      headers: { cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { tokens: Record<string, unknown>[] };
    expect(body.tokens).toHaveLength(1);
    const entry = body.tokens[0] as Record<string, unknown>;
    expect(entry["id"]).toBe(issued.tokenId);
    expect(entry["name"]).toBe("inventory");
    expect(entry["tokenPrefix"]).toBe(issued.token.slice(0, "maruhi_pat_".length + 4));
    expect(entry["scopes"]).toEqual([{ project: "*", permission: "admin" }]);
    expect(typeof entry["createdAtMs"]).toBe("number");
    expect(entry["expiresAtMs"]).toBe(issued.expiresAtMs);
    // Raw values / hashes do not exist even as fields (§6: not returned)
    expect(Object.keys(entry).toSorted()).toEqual([
      "createdAtMs",
      "expiresAtMs",
      "id",
      "lastUsedAtMs",
      "name",
      "scopes",
      "tokenPrefix",
    ]);
    expect(JSON.stringify(body)).not.toContain(issued.token);
  });

  it("lists expired tokens too (inventory view — only verification rejects them)", async () => {
    const session = await loginSession(813);
    const issued = await exchange(813, { tokenName: "expired" });
    await env.DB.prepare("UPDATE api_tokens SET expires_at = 1 WHERE id = ?")
      .bind(issued.tokenId)
      .run();
    const response = await SELF.fetch(`${BASE}/auth/tokens`, {
      headers: { cookie: `${SESSION_COOKIE}=${session}` },
    });
    const body = (await response.json()) as { tokens: { id: string; expiresAtMs: number }[] };
    expect(body.tokens.map((token) => token.id)).toContain(issued.tokenId);
  });

  it("allows a token principal only with a * × admin scope (ruling CH)", async () => {
    const wildcard = await cliToken(814, undefined, "wildcard");
    const allowed = await SELF.fetch(`${BASE}/auth/tokens`, { headers: bearer(wildcard) });
    expect(allowed.status).toBe(200);

    const scoped = await cliToken(
      814,
      [{ project: "ab".repeat(32), permission: "admin" }],
      "scoped",
    );
    const denied = await SELF.fetch(`${BASE}/auth/tokens`, { headers: bearer(scoped) });
    expect(denied.status).toBe(403);
    const body = (await denied.json()) as { reason?: string };
    expect(body.reason).toBe("insufficient-permission");
  });
});

describe("DELETE /auth/tokens/:tokenId (targeted revocation — AUTH_SPEC §6)", () => {
  it("lets a session principal revoke an owned token (with CSRF) and records the audit event", async () => {
    const session = await loginSession(821);
    const issued = await exchange(821, { tokenName: "target" });
    const response = await SELF.fetch(`${BASE}/auth/tokens/${issued.tokenId}`, {
      method: "DELETE",
      headers: sessionHeaders(session),
    });
    expect(response.status).toBe(204);
    // The revocation takes effect: the target token is 401 thereafter
    const denied = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(issued.token) });
    expect(denied.status).toBe(401);
    // Audit (AUDIT_SPEC §3.1): actor = the acting principal (a
    // session — no token id); payload.tokenId = the revoked target
    const audit = await env.DB.prepare(
      "SELECT actor_user_id, actor_api_token_id, payload FROM user_audit_events WHERE event = 'auth.token_revoked'",
    ).first<{ actor_user_id: string; actor_api_token_id: string | null; payload: string }>();
    expect(audit?.actor_user_id).toBe(issued.userId);
    expect(audit?.actor_api_token_id).toBeNull();
    expect(JSON.parse(audit?.payload ?? "{}")).toEqual({
      tokenId: issued.tokenId,
      authMethod: "github_oauth",
    });
  });

  it("requires the CSRF header for a session principal (write via cookie)", async () => {
    const session = await loginSession(822);
    const issued = await exchange(822, { tokenName: "target" });
    const response = await SELF.fetch(`${BASE}/auth/tokens/${issued.tokenId}`, {
      method: "DELETE",
      headers: { cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason?: string };
    expect(body.reason).toBe("csrf-header-required");
  });

  it("returns a uniform 404 for another user's and a nonexistent token id (existence hiding)", async () => {
    const session = await loginSession(823);
    const foreign = await exchange(824, { tokenName: "foreign" });

    const foreignResponse = await SELF.fetch(`${BASE}/auth/tokens/${foreign.tokenId}`, {
      method: "DELETE",
      headers: sessionHeaders(session),
    });
    const missingResponse = await SELF.fetch(`${BASE}/auth/tokens/01ARZ3NDEKTSV4RRFFQ69G5FAV`, {
      method: "DELETE",
      headers: sessionHeaders(session),
    });
    expect(foreignResponse.status).toBe(404);
    expect(missingResponse.status).toBe(404);
    // Even the response body is uniform (cannot distinguish whether the id exists)
    expect(await foreignResponse.json()).toEqual(await missingResponse.json());
    // The other user's token is not deleted and no audit is recorded
    // (the discipline of not letting it silently succeed)
    const row = await env.DB.prepare("SELECT id FROM api_tokens WHERE id = ?")
      .bind(foreign.tokenId)
      .first();
    expect(row).not.toBeNull();
    const audits = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM user_audit_events WHERE event = 'auth.token_revoked'",
    ).first<{ n: number }>();
    expect(audits?.n).toBe(0);
  });

  it("allows a * × admin token to revoke a sibling token, and denies a scoped token before target resolution (ruling CG)", async () => {
    const wildcard = await cliToken(825, undefined, "wildcard");
    const sibling = await exchange(825, { tokenName: "sibling" });
    const scoped = await cliToken(
      825,
      [{ project: "cd".repeat(32), permission: "admin" }],
      "scoped",
    );

    // A scope-limited token is 403 regardless of the target's existence (computed from caller qualification alone)
    const deniedExisting = await SELF.fetch(`${BASE}/auth/tokens/${sibling.tokenId}`, {
      method: "DELETE",
      headers: bearer(scoped),
    });
    const deniedMissing = await SELF.fetch(`${BASE}/auth/tokens/no-such-token`, {
      method: "DELETE",
      headers: bearer(scoped),
    });
    expect(deniedExisting.status).toBe(403);
    expect(deniedMissing.status).toBe(403);
    expect(await deniedExisting.json()).toEqual(await deniedMissing.json());

    const revoked = await SELF.fetch(`${BASE}/auth/tokens/${sibling.tokenId}`, {
      method: "DELETE",
      headers: bearer(wildcard),
    });
    expect(revoked.status).toBe(204);
    // The audit actor is the wildcard token (the acting principal); the target is payload.tokenId
    const audit = await env.DB.prepare(
      "SELECT actor_api_token_id, payload FROM user_audit_events WHERE event = 'auth.token_revoked'",
    ).first<{ actor_api_token_id: string | null; payload: string }>();
    expect(audit?.actor_api_token_id).not.toBeNull();
    expect(audit?.actor_api_token_id).not.toBe(sibling.tokenId);
    expect(JSON.parse(audit?.payload ?? "{}")).toEqual({ tokenId: sibling.tokenId });
  });
});

// Make explicit that beforeEach's resetAuthDb has applied the
// migrations (the response's precondition is not left implicit —
// applyD1Migrations is idempotent)
it("keeps migrations idempotent for this suite", async () => {
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
});
