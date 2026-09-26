// Integration tests for the master-key wrap ledger API (AUTH_SPEC
// §13-6–13-10 — KL3; the server side of CRYPTO_SPEC §8's classes S /
// G / H). Verifies the real path via SELF on
// @cloudflare/vitest-plugin (real workerd environment).
//
// Wraps, shares, and approvals are opaque ciphertext to the server,
// so hex fixtures that merely have the right format suffice
// (decryptability is covered by packages/crypto's vectors and the
// CLI-side tests). What is pinned here is authorization, the
// acceptance policy, the fixed windows, existence hiding, and the
// 1:1 with audit.

import { env, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import {
  APPROVAL_LIMIT,
  HANDOFF_REQUEST_LIMIT,
  KEY_BLOB_FETCH_LIMIT,
} from "../src/db.package/index.ts";
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

const WRAP = { suite: "maruhi/v1", nonceHex: "0f".repeat(12), ciphertextHex: "ab".repeat(64) };
const ENC_PUB = "11".repeat(32);
const FP = "22".repeat(16);
const HPKE_ENC = "33".repeat(32);
const SHARE_CT = "44".repeat(48);

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/** A client-assigned ledger id (ULID shape — 26 characters). */
const ledgerId = () =>
  Array.from(
    crypto.getRandomValues(new Uint8Array(26)),
    (byte) => CROCKFORD[byte % 32] ?? "0",
  ).join("");

const passkeyBody = (label?: string) =>
  JSON.stringify({
    wrapId: ledgerId(),
    wrap: WRAP,
    credentialIdHex: "55".repeat(16),
    prfSaltHex: "66".repeat(32),
    rpId: "localhost",
    ...(label === undefined ? {} : { label }),
  });

/** The group-creation body (groupId is client-assigned). */
const guardianBody = (mode: "any" | "all", shares: readonly unknown[], groupId = ledgerId()) => ({
  groupId,
  mode,
  wrap: WRAP,
  shares,
});

const share = (shareIndex: number, guardianUserId: string) => ({
  shareIndex,
  guardianUserId,
  guardianEncPubHex: ENC_PUB,
  guardianKeyFingerprintHex: FP,
  encHex: HPKE_ENC,
  ciphertextHex: SHARE_CT,
});

async function userIdOf(token: string): Promise<string> {
  const me = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(token) });
  expect(me.status).toBe(200);
  return ((await me.json()) as { userId: string }).userId;
}

const post = (path: string, token: string, body: unknown) =>
  SELF.fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...bearer(token) },
    body: JSON.stringify(body),
  });
const get = (path: string, token: string) =>
  SELF.fetch(`${BASE}${path}`, { headers: bearer(token) });
const del = (path: string, token: string) =>
  SELF.fetch(`${BASE}${path}`, { method: "DELETE", headers: bearer(token) });

async function json<T = Record<string, unknown>>(response: Response): Promise<T> {
  return (await response.json()) as T;
}

async function auditCount(event: string): Promise<number> {
  const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM user_audit_events WHERE event = ?")
    .bind(event)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

const requestIdOf = (seed: number) => seed.toString(16).padStart(2, "0").repeat(32);

/** Create a ward (A) and guardians (B, C), and register one `all` group for A. */
async function guardianFixture() {
  const a = await cliToken(701);
  const b = await cliToken(702);
  const c = await cliToken(703);
  const [aId, bId, cId] = await Promise.all([userIdOf(a), userIdOf(b), userIdOf(c)]);
  const body = guardianBody("all", [share(1, bId), share(2, cId)]);
  const created = await post("/auth/key-wraps/guardians", a, body);
  expect(created.status).toBe(200);
  const { groupId } = await json<{ groupId: string }>(created);
  // The server uses the client-assigned id as-is
  expect(groupId).toBe(body.groupId);
  return { a, b, c, aId, bId, cId, groupId };
}

describe("GET /auth/key-wraps(§13-7 status)", () => {
  it("returns an empty ledger for a fresh user and is readable by a session principal", async () => {
    const token = await cliToken(601);
    const status = await get("/auth/key-wraps", token);
    expect(status.status).toBe(200);
    expect(await json(status)).toEqual({
      recoveryCode: { registered: false, updatedAtMs: null },
      passkeys: [],
      guardianGroups: [],
    });
    const session = await loginSession(601);
    const viaSession = await SELF.fetch(`${BASE}/auth/key-wraps`, {
      headers: sessionHeaders(session),
    });
    expect(viaSession.status).toBe(200);
  });

  it("rejects a session principal for every mutation / fetch face (§5 — only status is allowed)", async () => {
    const session = await loginSession(602);
    const register = await SELF.fetch(`${BASE}/auth/key-wraps/passkey`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...sessionHeaders(session) },
      body: passkeyBody(),
    });
    expect(register.status).toBe(403);
    expect((await json(register))["reason"]).toBe("session-not-allowed");
    const wards = await SELF.fetch(`${BASE}/auth/guardian/wards`, {
      headers: sessionHeaders(session),
    });
    expect(wards.status).toBe(403);
  });
});

describe("passkey-prf wraps (class S — §13-7)", () => {
  it("registers, fetches (with params) and deletes a passkey wrap, recording audit 1:1", async () => {
    const token = await cliToken(611);
    const registered = await SELF.fetch(`${BASE}/auth/key-wraps/passkey`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(token) },
      body: passkeyBody("MacBook Touch ID"),
    });
    expect(registered.status).toBe(200);
    const { wrapId } = await json<{ wrapId: string }>(registered);
    expect(wrapId).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);

    const status = await json<{ passkeys: { wrapId: string; label: string | null }[] }>(
      await get("/auth/key-wraps", token),
    );
    expect(status.passkeys).toEqual([
      expect.objectContaining({
        wrapId,
        label: "MacBook Touch ID",
        credentialIdHex: "55".repeat(16),
        // Public parameters (the §13-7 2026-09-13 revision): the
        // restoring client reads them before the ceremony
        prfSaltHex: "66".repeat(32),
      }),
    ]);

    const fetched = await get(`/auth/key-wraps/passkey/${wrapId}`, token);
    expect(fetched.status).toBe(200);
    const body = await json(fetched);
    expect(body["wrap"]).toEqual(WRAP);
    expect(body["prfSaltHex"]).toBe("66".repeat(32));
    expect(body["rpId"]).toBe("localhost");
    expect(body["label"]).toBe("MacBook Touch ID");

    expect((await del(`/auth/key-wraps/passkey/${wrapId}`, token)).status).toBe(204);
    expect((await get(`/auth/key-wraps/passkey/${wrapId}`, token)).status).toBe(404);
    expect((await del(`/auth/key-wraps/passkey/${wrapId}`, token)).status).toBe(404);

    expect(await auditCount("auth.key_wrap_registered")).toBe(1);
    expect(await auditCount("auth.key_wrap_fetched")).toBe(1);
    expect(await auditCount("auth.key_wrap_removed")).toBe(1);
  });

  it("rejects a project-scoped token (§13-2's key-material condition) and unknown fields (strict)", async () => {
    const scoped = await cliToken(612, [{ project: "f0".repeat(32), permission: "admin" }]);
    const forbidden = await SELF.fetch(`${BASE}/auth/key-wraps/passkey`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(scoped) },
      body: passkeyBody(),
    });
    expect(forbidden.status).toBe(403);
    const token = await cliToken(613);
    const probe = await post("/auth/key-wraps/passkey", token, {
      ...JSON.parse(passkeyBody()),
      __probe: true,
    });
    expect(probe.status).toBe(400);
  });

  it("caps passkey wraps per user (§13-8: 5)", async () => {
    const token = await cliToken(614);
    for (let i = 0; i < 5; i += 1) {
      const ok = await SELF.fetch(`${BASE}/auth/key-wraps/passkey`, {
        method: "POST",
        headers: { ...JSON_HEADERS, ...bearer(token) },
        body: passkeyBody(),
      });
      expect(ok.status).toBe(200);
    }
    const sixth = await SELF.fetch(`${BASE}/auth/key-wraps/passkey`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(token) },
      body: passkeyBody(),
    });
    expect(sixth.status).toBe(422);
    expect((await json(sixth))["reason"]).toBe("too-many-passkeys");
    expect(await auditCount("auth.key_wrap_registered")).toBe(5);
  });

  it("shares one blob-fetch window with the recovery-code blob (the §13-8 combined window)", async () => {
    const token = await cliToken(615);
    expect(
      (
        await SELF.fetch(`${BASE}/auth/recovery`, {
          method: "PUT",
          headers: { ...JSON_HEADERS, ...bearer(token) },
          body: JSON.stringify(WRAP),
        })
      ).status,
    ).toBe(204);
    const registered = await SELF.fetch(`${BASE}/auth/key-wraps/passkey`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(token) },
      body: passkeyBody(),
    });
    const { wrapId } = await json<{ wrapId: string }>(registered);
    // recovery ×2 + passkey ×3 = the limit of 5. The 6th is 429 on either path
    expect((await get("/auth/recovery", token)).status).toBe(200);
    expect((await get("/auth/recovery", token)).status).toBe(200);
    for (let i = 2; i < KEY_BLOB_FETCH_LIMIT; i += 1) {
      expect((await get(`/auth/key-wraps/passkey/${wrapId}`, token)).status).toBe(200);
    }
    const limited = await get(`/auth/key-wraps/passkey/${wrapId}`, token);
    expect(limited.status).toBe(429);
    const body = await json(limited);
    expect(body["_tag"]).toBe("KeyWrapRateLimited");
    expect(body["window"]).toBe("blob-fetch");
    expect((await get("/auth/recovery", token)).status).toBe(429);
    // Audit is 1:1 with permitted fetches
    expect(await auditCount("auth.recovery_blob_fetched")).toBe(2);
    expect(await auditCount("auth.key_wrap_fetched")).toBe(3);
  });
});

describe("guardian groups (class G — §13-7)", () => {
  it("creates a group, lists it for the guardians, serves the share and the blob, and deletes it", async () => {
    const { a, b, aId, bId, cId, groupId } = await guardianFixture();

    const status = await json<{
      guardianGroups: { groupId: string; mode: string; guardians: { guardianUserId: string }[] }[];
    }>(await get("/auth/key-wraps", a));
    expect(status.guardianGroups).toHaveLength(1);
    expect(status.guardianGroups[0]?.groupId).toBe(groupId);
    expect(status.guardianGroups[0]?.guardians.map((g) => g.guardianUserId)).toEqual([bId, cId]);

    const wards = await json<{
      wards: { wardUserId: string; wardLogin: string | null; shareIndex: number }[];
    }>(await get("/auth/guardian/wards", b));
    expect(wards.wards).toEqual([
      expect.objectContaining({
        wardUserId: aId,
        wardLogin: "user701",
        groupId,
        mode: "all",
        shareIndex: 1,
      }),
    ]);

    const myShare = await get(`/auth/guardian/shares/${groupId}`, b);
    expect(myShare.status).toBe(200);
    expect(await json(myShare)).toEqual(
      expect.objectContaining({
        groupId,
        wardUserId: aId,
        mode: "all",
        shareIndex: 1,
        encHex: HPKE_ENC,
        ciphertextHex: SHARE_CT,
      }),
    );
    // The share is 404 to anyone but that guardian (the ward included)
    expect((await get(`/auth/guardian/shares/${groupId}`, a)).status).toBe(404);

    const blob = await get(`/auth/key-wraps/guardians/${groupId}`, a);
    expect(blob.status).toBe(200);
    expect((await json(blob))["wrap"]).toEqual(WRAP);
    // The group's blob is 404 to anyone but the ward (guardians included)
    expect((await get(`/auth/key-wraps/guardians/${groupId}`, b)).status).toBe(404);

    expect(await auditCount("auth.key_wrap_registered")).toBe(1);
    expect(await auditCount("auth.guardian_designated")).toBe(2);
    expect(await auditCount("auth.guardian_share_fetched")).toBe(1);
    expect(await auditCount("auth.key_wrap_fetched")).toBe(1);
    const designated = await env.DB.prepare(
      "SELECT target_user_id FROM user_audit_events WHERE event = 'auth.guardian_designated' ORDER BY seq",
    ).all<{ target_user_id: string }>();
    expect(designated.results.map((r) => r.target_user_id)).toEqual([bId, cId]);

    expect((await del(`/auth/key-wraps/guardians/${groupId}`, b)).status).toBe(404);
    expect((await del(`/auth/key-wraps/guardians/${groupId}`, a)).status).toBe(204);
    expect((await json<{ wards: unknown[] }>(await get("/auth/guardian/wards", b))).wards).toEqual(
      [],
    );
    expect(await auditCount("auth.key_wrap_removed")).toBe(1);
    expect(await auditCount("auth.guardian_released")).toBe(2);
  });

  it("rejects policy violations with 422 reasons (§13-7 / §13-8)", async () => {
    const a = await cliToken(721);
    const b = await cliToken(722);
    const [aId, bId] = await Promise.all([userIdOf(a), userIdOf(b)]);
    const cases: readonly [string, unknown][] = [
      ["share-count", guardianBody("all", [share(1, bId)])],
      ["share-count", guardianBody("any", [share(2, bId)])],
      ["self-guardian", guardianBody("any", [share(1, aId)])],
      ["duplicate-guardian", guardianBody("all", [share(1, bId), share(2, bId)])],
      ["unknown-guardian", guardianBody("any", [share(1, "01ARZ3NDEKTSV4RRFFQ69G5FAV")])],
    ];
    for (const [reason, body] of cases) {
      const response = await post("/auth/key-wraps/guardians", a, body);
      expect(response.status, reason).toBe(422);
      expect((await json(response))["reason"]).toBe(reason);
    }
    // Rejections write no audit
    expect(await auditCount("auth.key_wrap_registered")).toBe(0);
    expect(await auditCount("auth.guardian_designated")).toBe(0);
  });

  it("caps guardian groups per user (§13-8: 5)", async () => {
    const a = await cliToken(731);
    const b = await cliToken(732);
    const bId = await userIdOf(b);
    const first = guardianBody("any", [share(1, bId)]);
    expect((await post("/auth/key-wraps/guardians", a, first)).status).toBe(200);
    // Re-registering the same id is 422 duplicate-id (judged before the limit)
    const duplicate = await post("/auth/key-wraps/guardians", a, first);
    expect(duplicate.status).toBe(422);
    expect((await json(duplicate))["reason"]).toBe("duplicate-id");
    // Rejections that reach the DB (collisions) also write no audit:
    // the audit rows are conditioned on a chain of `changes() = 1`
    // checks at the batch's end (only the one accepted registration
    // remains)
    expect(await auditCount("auth.key_wrap_registered")).toBe(1);
    expect(await auditCount("auth.guardian_designated")).toBe(1);
    for (let i = 1; i < 5; i += 1) {
      const ok = await post("/auth/key-wraps/guardians", a, guardianBody("any", [share(1, bId)]));
      expect(ok.status).toBe(200);
    }
    const sixth = await post("/auth/key-wraps/guardians", a, guardianBody("any", [share(1, bId)]));
    expect(sixth.status).toBe(422);
    expect((await json(sixth))["reason"]).toBe("too-many-groups");
    // Same for the limit rejection: only the 5 accepted groups' worth
    // (1 + share count = one row each) remains
    expect(await auditCount("auth.key_wrap_registered")).toBe(5);
    expect(await auditCount("auth.guardian_designated")).toBe(5);
  });

  it("counts share fetches against the approval window (§13-8: 20)", async () => {
    const { b, groupId } = await guardianFixture();
    for (let i = 0; i < APPROVAL_LIMIT; i += 1) {
      expect((await get(`/auth/guardian/shares/${groupId}`, b)).status).toBe(200);
    }
    const limited = await get(`/auth/guardian/shares/${groupId}`, b);
    expect(limited.status).toBe(429);
    expect((await json(limited))["window"]).toBe("approval");
    expect(await auditCount("auth.guardian_share_fetched")).toBe(APPROVAL_LIMIT);
  });
});

describe("handoff (class H — §13-7)", () => {
  it("runs the guardian approval flow end to end with uniform 404 for strangers (the ward has no approval role — DK K4)", async () => {
    const { a, b, aId, groupId } = await guardianFixture();
    const stranger = await cliToken(704);
    const requestId = requestIdOf(0xa1);

    const created = await post("/auth/handoff", a, { requestId });
    expect(created.status).toBe(200);
    expect(typeof (await json(created))["expiresAtMs"]).toBe("number");
    const duplicate = await post("/auth/handoff", a, { requestId });
    expect(duplicate.status).toBe(409);
    expect((await json(duplicate))["reason"]).toBe("request-exists");

    // Lookup: the ward = no roles (but can look up), a guardian =
    // their own share, a stranger = uniform 404
    const byWard = await json<{ roles: unknown[]; wardUserId: string; wardLogin: string }>(
      await get(`/auth/handoff/${requestId}`, a),
    );
    expect(byWard.roles).toEqual([]);
    expect(byWard.wardUserId).toBe(aId);
    expect(byWard.wardLogin).toBe("user701");
    const byGuardian = await json<{ roles: unknown[] }>(await get(`/auth/handoff/${requestId}`, b));
    expect(byGuardian.roles).toEqual([{ groupId, mode: "all", shareIndex: 1 }]);
    expect((await get(`/auth/handoff/${requestId}`, stranger)).status).toBe(404);
    expect((await get(`/auth/handoff/${requestIdOf(0xa2)}`, a)).status).toBe(404);

    // A guardian's approval (only their own share). A different
    // share_index or another's group id is 422
    const guardianApproval = {
      source: groupId,
      shareIndex: 1,
      approverKeyFingerprintHex: FP,
      encHex: HPKE_ENC,
      ciphertextHex: SHARE_CT,
    };
    expect((await post(`/auth/handoff/${requestId}/approvals`, b, guardianApproval)).status).toBe(
      204,
    );
    const again = await post(`/auth/handoff/${requestId}/approvals`, b, guardianApproval);
    expect(again.status).toBe(409);
    expect((await json(again))["reason"]).toBe("already-approved");
    const wrongIndex = await post(`/auth/handoff/${requestId}/approvals`, b, {
      ...guardianApproval,
      shareIndex: 2,
    });
    expect(wrongIndex.status).toBe(422);
    expect((await json(wrongIndex))["reason"]).toBe("source-mismatch");
    // A stranger's approval is a uniform 404
    expect(
      (await post(`/auth/handoff/${requestId}/approvals`, stranger, guardianApproval)).status,
    ).toBe(404);

    // The ward themself cannot approve their own request (the legacy
    // device path was removed): 422 even with their own group id; the
    // old wire's `source: "device"` + `blob` is a strict-acceptance
    // 400
    const byWardApproval = await post(`/auth/handoff/${requestId}/approvals`, a, guardianApproval);
    expect(byWardApproval.status).toBe(422);
    expect((await json(byWardApproval))["reason"]).toBe("source-mismatch");
    const legacyDevice = await post(`/auth/handoff/${requestId}/approvals`, a, {
      source: "device",
      shareIndex: 0,
      approverKeyFingerprintHex: FP,
      encHex: HPKE_ENC,
      ciphertextHex: SHARE_CT,
      blob: WRAP,
    });
    expect(legacyDevice.status).toBe(400);

    // Only the ward fetches. One approval from the guardian arrives
    // (no blob column) and collected is recorded exactly once
    expect((await get(`/auth/handoff/${requestId}/approvals`, b)).status).toBe(404);
    const first = await json<{ approvals: Record<string, unknown>[] }>(
      await get(`/auth/handoff/${requestId}/approvals`, a),
    );
    expect(first.approvals.map((x) => x["source"])).toEqual([groupId]);
    expect(first.approvals[0]).not.toHaveProperty("blob");
    await get(`/auth/handoff/${requestId}/approvals`, a);
    expect(await auditCount("auth.key_handoff_collected")).toBe(1);
    expect(await auditCount("auth.key_handoff_approved")).toBe(1);
    expect(await auditCount("auth.key_handoff_requested")).toBe(1);
    const approvedTargets = await env.DB.prepare(
      "SELECT target_user_id FROM user_audit_events WHERE event = 'auth.key_handoff_approved'",
    ).all<{ target_user_id: string }>();
    expect(approvedTargets.results.every((r) => r.target_user_id === aId)).toBe(true);

    // After cancellation (ward only) everything is a uniform 404
    expect((await del(`/auth/handoff/${requestId}`, b)).status).toBe(404);
    expect((await del(`/auth/handoff/${requestId}`, a)).status).toBe(204);
    expect((await get(`/auth/handoff/${requestId}`, a)).status).toBe(404);
    expect((await get(`/auth/handoff/${requestId}`, b)).status).toBe(404);
  });

  it("rate-limits request creation per ward (§13-8: 5 / h) and rejects the excess with 429", async () => {
    const a = await cliToken(741);
    for (let i = 0; i < HANDOFF_REQUEST_LIMIT; i += 1) {
      expect((await post("/auth/handoff", a, { requestId: requestIdOf(0x10 + i) })).status).toBe(
        200,
      );
    }
    const limited = await post("/auth/handoff", a, { requestId: requestIdOf(0x20) });
    expect(limited.status).toBe(429);
    expect((await json(limited))["window"]).toBe("handoff-request");
    expect(await auditCount("auth.key_handoff_requested")).toBe(HANDOFF_REQUEST_LIMIT);
  });

  it("treats an expired request as absent (§13-8: TTL 15 minutes)", async () => {
    const a = await cliToken(751);
    const requestId = requestIdOf(0xb1);
    expect((await post("/auth/handoff", a, { requestId })).status).toBe(200);
    await env.DB.prepare("UPDATE key_handoff_requests SET expires_at = ?")
      .bind(Date.now() - 1000)
      .run();
    expect((await get(`/auth/handoff/${requestId}`, a)).status).toBe(404);
    expect((await get(`/auth/handoff/${requestId}/approvals`, a)).status).toBe(404);
    const approve = await post(`/auth/handoff/${requestId}/approvals`, a, {
      source: ledgerId(),
      shareIndex: 1,
      approverKeyFingerprintHex: FP,
      encHex: HPKE_ENC,
      ciphertextHex: SHARE_CT,
    });
    expect(approve.status).toBe(404);
  });
});
