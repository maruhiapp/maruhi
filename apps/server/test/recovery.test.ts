// Integration tests for the recovery-blob API (AUTH_SPEC §13; the
// server side of CRYPTO_SPEC §8).
// Verifies the real path via SELF on @cloudflare/vitest-plugin (real
// workerd environment).
//
// The blob is opaque ciphertext to the server, so any hex fixture
// suffices for the content (decryptability is the client side's job —
// covered by the CLI tests).

import { env, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { RECOVERY_FETCH_LIMIT } from "../src/db.package/index.ts";
import {
  BASE,
  bearer,
  cliToken,
  JSON_HEADERS,
  loginSession,
  resetAuthDb,
  sessionHeaders,
} from "./support/auth.ts";

beforeEach(async () => {
  await resetAuthDb();
});

const NONCE_HEX = "0f".repeat(12);
const CIPHERTEXT_HEX = "ab".repeat(64);

function wrapBody(ciphertextHex: string = CIPHERTEXT_HEX): string {
  return JSON.stringify({ suite: "maruhi/v1", nonceHex: NONCE_HEX, ciphertextHex });
}

async function putWrap(headers: Record<string, string>, ciphertextHex?: string): Promise<Response> {
  return SELF.fetch(`${BASE}/auth/recovery`, {
    method: "PUT",
    headers: { ...JSON_HEADERS, ...headers },
    body: wrapBody(ciphertextHex),
  });
}

describe("PUT /auth/recovery(§13-1 / §13-2)", () => {
  it("registers a blob for a device-flow token (default * × admin scope)", async () => {
    const token = await cliToken(501);
    const put = await putWrap(bearer(token));
    expect(put.status).toBe(204);

    const get = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    expect(get.status).toBe(200);
    const body = (await get.json()) as Record<string, unknown>;
    expect(body["suite"]).toBe("maruhi/v1");
    expect(body["nonceHex"]).toBe(NONCE_HEX);
    expect(body["ciphertextHex"]).toBe(CIPHERTEXT_HEX);
    expect(typeof body["updatedAtMs"]).toBe("number");
  });

  it("rejects a session principal for both PUT and GET (the §5 capability restriction — the §13-2 table = tokens only)", async () => {
    const session = await loginSession(502);
    // Neither registration nor fetch has a legitimate path from a
    // session (W0 ruling). Even with the CSRF header it is 403
    // session-not-allowed
    const put = await putWrap(sessionHeaders(session));
    expect(put.status).toBe(403);
    expect(((await put.json()) as Record<string, unknown>)["reason"]).toBe("session-not-allowed");
    const get = await SELF.fetch(`${BASE}/auth/recovery`, {
      headers: sessionHeaders(session),
    });
    expect(get.status).toBe(403);
    expect(((await get.json()) as Record<string, unknown>)["reason"]).toBe("session-not-allowed");
  });

  it("session GET is rejected before the CSRF check and does not consume the window", async () => {
    const token = await cliToken(507);
    expect((await putWrap(bearer(token))).status).toBe(204);
    const session = await loginSession(507);
    // The shape of a cross-site navigation where only the Lax cookie
    // rides along (no custom header). The capability judgment (§5)
    // precedes the CSRF check, so the rejection reason does not vary
    // with the header's presence
    const get = await SELF.fetch(`${BASE}/auth/recovery`, {
      headers: { cookie: sessionHeaders(session)["cookie"] ?? "" },
    });
    expect(get.status).toBe(403);
    const body = (await get.json()) as Record<string, unknown>;
    expect(body["reason"]).toBe("session-not-allowed");
    // Since KL3 (AUTH_SPEC §13-8), the fetch count lives in the
    // kind-aggregated window key_wrap_windows
    const row = await env.DB.prepare(
      "SELECT count AS fetch_count FROM key_wrap_windows WHERE kind = 'blob-fetch'",
    ).first<{ fetch_count: number }>();
    expect(row?.fetch_count ?? 0).toBe(0);
  });

  it("re-registration replaces the previous blob (re-issuance = replacement; §13-1)", async () => {
    const token = await cliToken(503);
    expect((await putWrap(bearer(token))).status).toBe(204);
    const reissued = "cd".repeat(64);
    expect((await putWrap(bearer(token), reissued)).status).toBe(204);

    const get = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    const body = (await get.json()) as Record<string, unknown>;
    // The old blob does not survive (at most one row per user)
    expect(body["ciphertextHex"]).toBe(reissued);
  });

  it("rejects a project-scoped admin token with 403 (§13-2's key-material management condition)", async () => {
    const token = await cliToken(504, [{ project: "f0".repeat(32), permission: "admin" }]);
    const put = await putWrap(bearer(token));
    expect(put.status).toBe(403);
  });

  it("rejects a * × write token with 403 (below admin)", async () => {
    const token = await cliToken(505, [{ project: "*", permission: "write" }]);
    const put = await putWrap(bearer(token));
    expect(put.status).toBe(403);
  });

  it("rejects malformed wraps with 400 (nonce length and hex format are Schema-validated)", async () => {
    const token = await cliToken(506);
    const bad = await SELF.fetch(`${BASE}/auth/recovery`, {
      method: "PUT",
      headers: { ...JSON_HEADERS, ...bearer(token) },
      body: JSON.stringify({ suite: "maruhi/v1", nonceHex: "0f", ciphertextHex: CIPHERTEXT_HEX }),
    });
    expect(bad.status).toBe(400);
  });

  it("requires authentication (401)", async () => {
    const put = await SELF.fetch(`${BASE}/auth/recovery`, {
      method: "PUT",
      headers: JSON_HEADERS,
      body: wrapBody(),
    });
    expect(put.status).toBe(401);
  });
});

describe("GET /auth/recovery(§13-2 / §13-3)", () => {
  it("returns 404 when no blob is registered", async () => {
    const token = await cliToken(511);
    const get = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    expect(get.status).toBe(404);
  });

  it("rejects a scope-limited token with 403 (blocks a watched operation)", async () => {
    const token = await cliToken(512, [{ project: "*", permission: "read" }]);
    const get = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    expect(get.status).toBe(403);
  });

  it("rate-limits blob fetches per fixed window and reissue resets it (§13-3)", async () => {
    const token = await cliToken(513);
    expect((await putWrap(bearer(token))).status).toBe(204);

    for (let i = 0; i < RECOVERY_FETCH_LIMIT; i += 1) {
      const ok = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
      expect(ok.status).toBe(200);
    }
    const limited = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    expect(limited.status).toBe(429);
    const body = (await limited.json()) as Record<string, unknown>;
    expect(body["_tag"]).toBe("RecoveryRateLimited");
    expect(typeof body["retryAfterSeconds"]).toBe("number");
    expect(body["retryAfterSeconds"] as number).toBeGreaterThan(0);

    // Re-issuance (replacement) resets the fetch window (the new blob does not inherit old attempt history)
    expect((await putWrap(bearer(token), "ef".repeat(64))).status).toBe(204);
    const afterReissue = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    expect(afterReissue.status).toBe(200);
  });

  it("counts concurrent fetches atomically: exactly the limit succeeds and the count matches", async () => {
    const token = await cliToken(516);
    expect((await putWrap(bearer(token))).status).toBe(204);
    // Over-limit concurrent requests: since counting is a
    // conditional relative UPDATE (a single statement), exactly the
    // limit succeeds under any interleaving and the stored count
    // stops at the limit
    const responses = await Promise.all(
      Array.from({ length: RECOVERY_FETCH_LIMIT + 3 }, () =>
        SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) }),
      ),
    );
    const succeeded = responses.filter((response) => response.status === 200).length;
    const limited = responses.filter((response) => response.status === 429).length;
    expect(succeeded).toBe(RECOVERY_FETCH_LIMIT);
    expect(limited).toBe(3);
    // Since KL3 (AUTH_SPEC §13-8), the fetch count lives in the
    // kind-aggregated window key_wrap_windows
    const row = await env.DB.prepare(
      "SELECT count AS fetch_count FROM key_wrap_windows WHERE kind = 'blob-fetch'",
    ).first<{ fetch_count: number }>();
    expect(row?.fetch_count).toBe(RECOVERY_FETCH_LIMIT);
    // The audit rows (auth.recovery_blob_fetched) are 1:1 with
    // permitted fetches (the §5.2 same-transaction principle
    // preserved)
    const audit = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM user_audit_events WHERE event = 'auth.recovery_blob_fetched'",
    ).first<{ n: number }>();
    expect(audit?.n).toBe(RECOVERY_FETCH_LIMIT);
  });

  it("rejects an unknown stored suite without consuming the fetch window", async () => {
    const token = await cliToken(515);
    expect((await putWrap(bearer(token))).status).toBe(204);
    // Create a row the v1 write path cannot produce, directly (the
    // assumption of a future-version write / DB corruption). It must
    // not be silently distributed as v1 (500) and must not consume
    // the window
    await env.DB.prepare("UPDATE recovery_wraps SET suite = 'maruhi/v2'").run();
    const broken = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    expect(broken.status).toBe(500);
    // Since KL3 (AUTH_SPEC §13-8), the fetch count lives in the
    // kind-aggregated window key_wrap_windows
    const row = await env.DB.prepare(
      "SELECT count AS fetch_count FROM key_wrap_windows WHERE kind = 'blob-fetch'",
    ).first<{ fetch_count: number }>();
    expect(row?.fetch_count ?? 0).toBe(0);
  });

  it("does not count 404s toward the fetch window (unregistered does not count)", async () => {
    const token = await cliToken(514);
    for (let i = 0; i < RECOVERY_FETCH_LIMIT + 2; i += 1) {
      const notFound = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
      expect(notFound.status).toBe(404);
    }
    // After registration the fetches run to the limit (the 404s did not consume the window)
    expect((await putWrap(bearer(token))).status).toBe(204);
    const first = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    expect(first.status).toBe(200);
  });
});

describe("GET /auth/recovery/status(§13-2)", () => {
  it("reports registration state to any authenticated principal (the blob is not carried)", async () => {
    const token = await cliToken(521, [{ project: "*", permission: "read" }]);
    const before = await SELF.fetch(`${BASE}/auth/recovery/status`, { headers: bearer(token) });
    expect(before.status).toBe(200);
    expect(await before.json()).toEqual({ registered: false, updatedAtMs: null });

    // Registration is done under a differently-named token for the
    // same user (a session cannot register under §5's capability
    // restriction. Re-issuing a same-named token would revoke the
    // existing token on rotation, so a different name keeps both
    // alive)
    const adminToken = await cliToken(521, undefined, "recovery-secondary");
    expect((await putWrap(bearer(adminToken))).status).toBe(204);

    const after = await SELF.fetch(`${BASE}/auth/recovery/status`, { headers: bearer(token) });
    expect(after.status).toBe(200);
    const body = (await after.json()) as Record<string, unknown>;
    expect(body["registered"]).toBe(true);
    expect(typeof body["updatedAtMs"]).toBe("number");
    expect(Object.keys(body).toSorted()).toEqual(["registered", "updatedAtMs"]);
  });

  it("requires authentication (401)", async () => {
    const get = await SELF.fetch(`${BASE}/auth/recovery/status`);
    expect(get.status).toBe(401);
  });
});
