// 招待 API(AUTH_SPEC §15)の統合テスト。
//
// - 認可(トークンスコープ admin × チェーン role admin 以上 / role=admin は
//   owner のみ)、存在秘匿(非メンバー 404)、受諾の判定順(404 → 410 → 422 →
//   CAS)を理由コードごとに固定する
// - 受諾署名(CRYPTO_SPEC §6.5)は @maruhi/crypto の実装で実署名を作る。
//   サーバーは signed_bytes を保存行 + 呼び出し主体から再構成するため、
//   リンク改竄(別プロジェクト・別トークン)・鍵すり替え・別人の署名は
//   すべて 422 に落ちることを実データで検証する
// - invite.* 監査(AUDIT_SPEC §3.2)がレコード操作と同一 batch で書かれ、
//   CAS 敗北時に監査行が増えないこと(changes() ガード)を D1 直読で検証する

import type { InviteAcceptSignatureContext } from "@maruhi/crypto";
import {
  computeUserKeyFingerprint,
  encodeHex,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  signInviteAccept,
  SUITE_ID,
  verifyInviteAcceptSignature,
} from "@maruhi/crypto";
import { env, SELF } from "cloudflare:test";
import { Context, Effect } from "effect";
import { beforeEach, describe, expect, it } from "vitest";

import {
  INVITE_ISSUE_WINDOW_LIMIT,
  INVITE_TTL_MS,
  InviteRepo,
  makeDbServices,
  MAX_PENDING_INVITES_PER_PROJECT,
} from "../src/db.package/index.ts";
import {
  BASE,
  bearer,
  cliToken,
  JSON_HEADERS,
  loginSession,
  sessionHeaders,
} from "./support/auth.ts";
import type { DataFixture } from "./support/data-fixture.ts";
import {
  appendOperation,
  MEMBER,
  OWNER,
  projectId,
  READER,
  setupDataProject,
  STRANGER,
  tokenOf,
} from "./support/data-fixture.ts";

const INVITE_TOKEN_PATTERN = /^maruhi_inv_[0-9A-Za-z]{43}$/;

/** 提示トークン文字列全体の SHA-256(サーバー・CLI と同じハッシュ入力定義)。 */
async function tokenHashOf(rawToken: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawToken));
  return encodeHex(new Uint8Array(digest));
}

/** 受諾者のテスト鍵ペア(未登録ユーザーの新規生成を模す)。 */
async function makeInviteeKeys() {
  const enc = await generateEncryptionKeyPair();
  const sig = await generateSigningKeyPair();
  const encPub = await exportEncryptionPublicKey(enc.publicKey);
  const sigPub = await exportSigningPublicKey(sig.publicKey);
  const fingerprint = await computeUserKeyFingerprint(encPub, sigPub);
  if (!fingerprint.ok) {
    throw new Error("fingerprint computation failed");
  }
  return {
    signingKey: sig.privateKey,
    encPubHex: encodeHex(encPub),
    sigPubHex: encodeHex(sigPub),
    fingerprintHex: encodeHex(fingerprint.value),
  };
}

type InviteeKeys = Awaited<ReturnType<typeof makeInviteeKeys>>;

/** 受諾署名(CRYPTO_SPEC §6.5)を作る。context の上書きでリンク改竄等を模す。 */
async function signAcceptance(
  keys: InviteeKeys,
  rawToken: string,
  inviteeUserId: string,
  overrides?: Partial<InviteAcceptSignatureContext>,
): Promise<string> {
  const context: InviteAcceptSignatureContext = {
    suite: SUITE_ID,
    projectId,
    inviteTokenHashHex: await tokenHashOf(rawToken),
    inviteeUserId,
    inviteeEncPubHex: keys.encPubHex,
    inviteeSigPubHex: keys.sigPubHex,
    ...overrides,
  };
  const signed = await signInviteAccept({ context, signingKey: keys.signingKey });
  if (!signed.ok) {
    throw new Error("acceptance signing failed");
  }
  return signed.value;
}

async function issueInvite(
  fixture: DataFixture,
  actorUserId: string,
  role: "reader" | "member" | "admin",
): Promise<{ id: string; token: string; expiresAtMs: number }> {
  const response = await issueInviteRequest(fixture, actorUserId, role);
  expect(response.status).toBe(200);
  return (await response.json()) as { id: string; token: string; expiresAtMs: number };
}

function issueInviteRequest(
  fixture: DataFixture,
  actorUserId: string,
  role: "reader" | "member" | "admin",
): Promise<Response> {
  return SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, actorUserId)) },
    body: JSON.stringify({ role }),
  });
}

function acceptRequest(
  authHeaders: Record<string, string>,
  body: Record<string, unknown>,
): Promise<Response> {
  return SELF.fetch(`${BASE}/invites/accept`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...authHeaders },
    body: JSON.stringify(body),
  });
}

async function acceptAs(
  fixture: DataFixture,
  userId: string,
  keys: InviteeKeys,
  rawToken: string,
  overrides?: Partial<InviteAcceptSignatureContext>,
): Promise<Response> {
  const signatureHex = await signAcceptance(keys, rawToken, userId, overrides);
  return acceptRequest(bearer(tokenOf(fixture.tokens, userId)), {
    token: rawToken,
    encPubHex: keys.encPubHex,
    sigPubHex: keys.sigPubHex,
    signatureHex,
  });
}

interface InviteRow {
  readonly id: string;
  readonly project_id: string;
  readonly token_hash: string;
  readonly role: string;
  readonly status: string;
  readonly invitee_user_id: string | null;
  readonly invitee_enc_pub: string | null;
  readonly invitee_sig_pub: string | null;
  readonly accept_signature: string | null;
  readonly expires_at: number;
  readonly created_at: number;
}

async function inviteRow(id: string): Promise<InviteRow | null> {
  const row = await env.DB.prepare("SELECT * FROM invitations WHERE id = ?")
    .bind(id)
    .first<InviteRow>();
  return row;
}

interface AuditRow {
  readonly event: string;
  readonly actor_user_id: string | null;
  readonly actor_api_token_id: string | null;
  readonly target_user_id: string | null;
  readonly org_id: string | null;
  readonly project_id: string | null;
  readonly payload: string | null;
}

async function inviteAuditRows(): Promise<AuditRow[]> {
  const result = await env.DB.prepare(
    "SELECT * FROM org_audit_events WHERE event LIKE 'invite.%' ORDER BY seq",
  ).all<AuditRow>();
  return result.results;
}

function payloadOf(row: AuditRow): Record<string, unknown> {
  return row.payload === null ? {} : (JSON.parse(row.payload) as Record<string, unknown>);
}

/** テスト用の招待行の直接シード(受理ポリシー・状態遷移の前提状態を作る)。 */
async function seedInvitation(input: {
  readonly id: string;
  readonly status?: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO invitations (id, project_id, token_hash, role, inviter_user_id, status, expires_at, created_at) VALUES (?, ?, ?, 'member', ?, ?, ?, ?)",
  )
    .bind(
      input.id,
      projectId,
      `seed-hash-${input.id}`,
      OWNER,
      input.status ?? "pending",
      input.expiresAt,
      input.createdAt,
    )
    .run();
}

async function errorTag(response: Response): Promise<string> {
  const body = (await response.json()) as { _tag?: string };
  return body["_tag"] ?? "";
}

/** 存在を検証済みの行の non-null 化(以降のフィールド検証を素の参照にする)。 */
function mustRow(row: InviteRow | null): InviteRow {
  if (row === null) {
    throw new Error("invitation row missing");
  }
  return row;
}

function firstAudit(rows: readonly AuditRow[], event: string): AuditRow {
  const found = rows.find((row) => row.event === event);
  if (found === undefined) {
    throw new Error(`audit row missing: ${event}`);
  }
  return found;
}

let fixture: DataFixture;

beforeEach(async () => {
  fixture = await setupDataProject();
});

describe("invite issue", () => {
  it("owner issues an invite: raw token once, hashed row, audit in same batch", async () => {
    const before = Date.now();
    const issued = await issueInvite(fixture, OWNER, "member");
    expect(issued.token).toMatch(INVITE_TOKEN_PATTERN);
    expect(issued.expiresAtMs).toBeGreaterThanOrEqual(before + INVITE_TTL_MS);

    const row = mustRow(await inviteRow(issued.id));
    expect(row.status).toBe("pending");
    expect(row.role).toBe("member");
    // 生値は保存されない: 行にあるのは提示文字列全体の SHA-256 のみ
    expect(row.token_hash).toBe(await tokenHashOf(issued.token));
    expect(JSON.stringify(row)).not.toContain(issued.token);

    const audits = await inviteAuditRows();
    expect(audits).toHaveLength(1);
    const created = firstAudit(audits, "invite.created");
    expect(created.actor_user_id).toBe(OWNER);
    expect(created.actor_api_token_id).not.toBeNull();
    expect(created.project_id).toBe(projectId);
    // invite.* は org 軸に属さない(AUDIT_SPEC §7)
    expect(created.org_id).toBeNull();
    expect(payloadOf(created)).toMatchObject({
      inviteId: issued.id,
      role: "member",
    });
    // トークン生値を監査に写さない
    expect(String(created.payload)).not.toContain(issued.token);
  });

  it("requires chain role admin: member/reader 403, non-member 404", async () => {
    for (const [userId, expected] of [
      [MEMBER, 403],
      [READER, 403],
      [STRANGER, 404],
    ] as const) {
      const response = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
        method: "POST",
        headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, userId)) },
        body: JSON.stringify({ role: "member" }),
      });
      expect(response.status).toBe(expected);
    }
  });

  it("role=admin invites are owner-only (admin can issue member invites)", async () => {
    // owner は admin 招待を発行できる
    await issueInvite(fixture, OWNER, "admin");
    // member を admin へ昇格(change_role は owner 操作)
    await appendOperation(fixture, OWNER, {
      op: "change_role",
      payload: { targetUserId: MEMBER, newRole: "admin" },
    });
    // admin は member 招待は発行できるが admin 招待は 403
    await issueInvite(fixture, MEMBER, "member");
    const denied = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, MEMBER)) },
      body: JSON.stringify({ role: "admin" }),
    });
    expect(denied.status).toBe(403);
    expect(await errorTag(denied)).toBe("Forbidden");
  });

  it("token scope gates issuance: out-of-scope 404, low permission 403", async () => {
    const outOfScope = await cliToken(9001, [{ project: "f".repeat(64), permission: "admin" }]);
    const outResponse = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(outOfScope) },
      body: JSON.stringify({ role: "member" }),
    });
    expect(outResponse.status).toBe(404);

    const lowPermission = await cliToken(9001, [{ project: projectId, permission: "write" }]);
    const lowResponse = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(lowPermission) },
      body: JSON.stringify({ role: "member" }),
    });
    expect(lowResponse.status).toBe(403);
  });

  it("fixed-window rate limit: 31st issuance within the hour is 429", async () => {
    for (let index = 0; index < INVITE_ISSUE_WINDOW_LIMIT; index += 1) {
      await issueInvite(fixture, OWNER, "member");
    }
    const response = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, OWNER)) },
      body: JSON.stringify({ role: "member" }),
    });
    expect(response.status).toBe(429);
    const body = (await response.json()) as { _tag: string; retryAfterSeconds: number };
    expect(body["_tag"]).toBe("InviteRateLimited");
    expect(body.retryAfterSeconds).toBeGreaterThanOrEqual(1);
    expect(body.retryAfterSeconds).toBeLessThanOrEqual(3600);
  });

  it("pending cap precedes the window limit (§15-2 の記載順)", async () => {
    const now = Date.now();
    const oldCreated = now - 2 * 60 * 60 * 1000;
    // 期限内 pending を上限まで(発行窓の外の created_at)+ 窓内にも 30 行 —
    // 両条件成立時に pending-limit が先に判定されることを固定する
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
    const response = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, OWNER)) },
      body: JSON.stringify({ role: "member" }),
    });
    expect(response.status).toBe(429);
    const body = (await response.json()) as { _tag: string; limit: number };
    expect(body["_tag"]).toBe("InvitePendingLimit");
    expect(body.limit).toBe(MAX_PENDING_INVITES_PER_PROJECT);
  });

  it("concurrent issuance cannot exceed the pending cap and audits only the winner (S4)", async () => {
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
      Array.from({ length: 8 }, () => issueInviteRequest(fixture, OWNER, "member")),
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

  it("concurrent issuance cannot exceed the lookback window and audits only the winner (S4)", async () => {
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
      Array.from({ length: 8 }, () => issueInviteRequest(fixture, OWNER, "member")),
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
    await issueInvite(fixture, OWNER, "member");
  });
});

describe("invite accept", () => {
  it("accepts with a valid signature and records invite.accepted in the same batch", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    const response = await acceptAs(fixture, STRANGER, keys, issued.token);
    expect(response.status).toBe(200);
    const body = (await response.json()) as { id: string; projectId: string; role: string };
    expect(body).toEqual({ id: issued.id, projectId, role: "member" });

    const row = mustRow(await inviteRow(issued.id));
    expect(row.status).toBe("accepted");
    expect(row.invitee_user_id).toBe(STRANGER);
    expect(row.invitee_enc_pub).toBe(keys.encPubHex);
    expect(row.invitee_sig_pub).toBe(keys.sigPubHex);
    expect(row.accept_signature).not.toBeNull();

    const accepted = (await inviteAuditRows()).filter((r) => r.event === "invite.accepted");
    expect(accepted).toHaveLength(1);
    const audit = firstAudit(accepted, "invite.accepted");
    expect(audit.actor_user_id).toBe(STRANGER);
    expect(audit.target_user_id).toBe(STRANGER);
    expect(audit.project_id).toBe(projectId);
    expect(payloadOf(audit)).toMatchObject({
      inviteId: issued.id,
      inviteeKeyFingerprintHex: keys.fingerprintHex,
    });
  });

  it("is single-use: the losing accept gets 410 accepted and no extra audit row", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, keys, issued.token)).status).toBe(200);
    // 正規受諾者の再試行も、別人の後着も同じ 410 accepted(うるさい競合の顕在化)
    const retry = await acceptAs(fixture, STRANGER, keys, issued.token);
    expect(retry.status).toBe(410);
    expect((await retry.json()) as object).toMatchObject({ reason: "accepted" });
    const memberKeys = await makeInviteeKeys();
    const late = await acceptAs(fixture, MEMBER, memberKeys, issued.token);
    expect(late.status).toBe(410);
    // CAS 敗北で監査行は増えない(changes() ガード)
    const accepted = (await inviteAuditRows()).filter((r) => r.event === "invite.accepted");
    expect(accepted).toHaveLength(1);
  });

  it("a lost CAS writes no audit row (changes() guard)", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, keys, issued.token)).status).toBe(200);
    // 「pending を読んでから CAS までの間に他者の受諾が確定した」並行敗者は、
    // HTTP 経路では事前読みの 410 が先に立つため、リポジトリ直呼びで決定的に
    // 再現する(同一 batch 内の changes() ガードそのものの検証)
    const invites = Context.get(makeDbServices(env.DB), InviteRepo);
    const lateKeys = await makeInviteeKeys();
    const won = await Effect.runPromise(
      invites.acceptCas(
        {
          inviteId: issued.id,
          inviteeUserId: MEMBER,
          inviteeEncPubHex: lateKeys.encPubHex,
          inviteeSigPubHex: lateKeys.sigPubHex,
          acceptSignatureHex: "ab".repeat(64),
          inviteeKeyFingerprintHex: lateKeys.fingerprintHex,
        },
        Date.now(),
        { userId: MEMBER },
      ),
    );
    expect(won).toBe(false);
    // 敗者の監査行は書かれず、行は勝者の受諾内容のまま
    expect((await inviteAuditRows()).filter((r) => r.event === "invite.accepted")).toHaveLength(1);
    expect(mustRow(await inviteRow(issued.id)).invitee_user_id).toBe(STRANGER);

    // revoke 側の CAS 敗北も同じガード: completed 行への失効は監査を書かない
    const completed = await issueInvite(fixture, OWNER, "member");
    await env.DB.prepare("UPDATE invitations SET status = 'completed' WHERE id = ?")
      .bind(completed.id)
      .run();
    const revoked = await Effect.runPromise(
      invites.revokeCas(projectId, completed.id, { role: "member" }, Date.now(), {
        userId: OWNER,
      }),
    );
    expect(revoked).toBe(false);
    expect((await inviteAuditRows()).filter((r) => r.event === "invite.revoked")).toHaveLength(0);
  });

  it("unknown token is 404 InviteNotFound; malformed token is schema 400", async () => {
    const keys = await makeInviteeKeys();
    const unknownToken = `maruhi_inv_${"A".repeat(43)}`;
    const unknown = await acceptAs(fixture, STRANGER, keys, unknownToken);
    expect(unknown.status).toBe(404);
    expect(await errorTag(unknown)).toBe("InviteNotFound");

    const malformed = await acceptRequest(bearer(tokenOf(fixture.tokens, STRANGER)), {
      token: "not-a-token",
      encPubHex: keys.encPubHex,
      sigPubHex: keys.sigPubHex,
      signatureHex: "ab".repeat(64),
    });
    expect(malformed.status).toBe(400);
  });

  it("unusable invites are 410 with a reason (status precedes expiry)", async () => {
    const keys = await makeInviteeKeys();
    // revoked(かつ期限切れ)→ revoked が先(判定順の固定)
    const revoked = await issueInvite(fixture, OWNER, "member");
    await env.DB.prepare("UPDATE invitations SET status = 'revoked', expires_at = ? WHERE id = ?")
      .bind(Date.now() - 1000, revoked.id)
      .run();
    const revokedResponse = await acceptAs(fixture, STRANGER, keys, revoked.token);
    expect(revokedResponse.status).toBe(410);
    expect((await revokedResponse.json()) as object).toMatchObject({ reason: "revoked" });

    // completed → completed
    const completed = await issueInvite(fixture, OWNER, "member");
    await env.DB.prepare("UPDATE invitations SET status = 'completed' WHERE id = ?")
      .bind(completed.id)
      .run();
    const completedResponse = await acceptAs(fixture, STRANGER, keys, completed.token);
    expect(completedResponse.status).toBe(410);
    expect((await completedResponse.json()) as object).toMatchObject({ reason: "completed" });

    // pending のまま期限切れ → expired
    const expired = await issueInvite(fixture, OWNER, "member");
    await env.DB.prepare("UPDATE invitations SET expires_at = ? WHERE id = ?")
      .bind(Date.now() - 1000, expired.id)
      .run();
    const expiredResponse = await acceptAs(fixture, STRANGER, keys, expired.token);
    expect(expiredResponse.status).toBe(410);
    expect((await expiredResponse.json()) as object).toMatchObject({ reason: "expired" });
  });

  it("rejects invalid signatures with 422 (tamper / transplant / actor / key swap)", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    const otherKeys = await makeInviteeKeys();

    // (a) 署名バイトの改竄
    const validSignature = await signAcceptance(keys, issued.token, STRANGER);
    const tampered = `${validSignature.slice(0, -1)}${validSignature.endsWith("0") ? "1" : "0"}`;
    const tamperedResponse = await acceptRequest(bearer(tokenOf(fixture.tokens, STRANGER)), {
      token: issued.token,
      encPubHex: keys.encPubHex,
      sigPubHex: keys.sigPubHex,
      signatureHex: tampered,
    });
    expect(tamperedResponse.status).toBe(422);
    expect(await errorTag(tamperedResponse)).toBe("InviteSignatureInvalid");

    // (b) リンク改竄: 別プロジェクトの座標で署名(サーバーは保存行から再構成)
    const wrongProject = await acceptAs(fixture, STRANGER, keys, issued.token, {
      projectId: "0".repeat(64),
    });
    expect(wrongProject.status).toBe(422);

    // (c) 別トークンハッシュへの署名(別招待への移植)
    const wrongToken = await acceptAs(fixture, STRANGER, keys, issued.token, {
      inviteTokenHashHex: await tokenHashOf(`maruhi_inv_${"B".repeat(43)}`),
    });
    expect(wrongToken.status).toBe(422);

    // (d) 別人向けに署名した受諾の持ち込み(呼び出し主体 = 署名対象の invitee)
    const wrongInvitee = await acceptAs(fixture, STRANGER, keys, issued.token, {
      inviteeUserId: MEMBER,
    });
    expect(wrongInvitee.status).toBe(422);

    // (e) 宣言 sig 鍵と署名鍵の不一致(鍵すり替え)
    const swappedSignature = await signAcceptance(keys, issued.token, STRANGER, {
      inviteeSigPubHex: otherKeys.sigPubHex,
    });
    const swappedResponse = await acceptRequest(bearer(tokenOf(fixture.tokens, STRANGER)), {
      token: issued.token,
      encPubHex: keys.encPubHex,
      sigPubHex: otherKeys.sigPubHex,
      signatureHex: swappedSignature,
    });
    expect(swappedResponse.status).toBe(422);

    // どの失敗経路でも行は pending のまま・監査は invite.created のみ
    const row = await inviteRow(issued.id);
    expect(row?.status).toBe("pending");
    expect((await inviteAuditRows()).filter((r) => r.event === "invite.accepted")).toHaveLength(0);
  });

  it("requires the key-material token condition (§13-2 と同水準)", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    const narrow = await cliToken(9009, [{ project: projectId, permission: "admin" }]);
    const signatureHex = await signAcceptance(keys, issued.token, STRANGER);
    const response = await acceptRequest(bearer(narrow), {
      token: issued.token,
      encPubHex: keys.encPubHex,
      sigPubHex: keys.sigPubHex,
      signatureHex,
    });
    expect(response.status).toBe(403);
    expect((await response.json()) as object).toMatchObject({
      reason: "insufficient-permission",
    });
  });

  it("rejects a session principal even with the CSRF header (§5 能力制限 — §15-2 の反転。W2b)", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    const session = await loginSession(9009);
    const signatureHex = await signAcceptance(keys, issued.token, STRANGER);
    const body = {
      token: issued.token,
      encPubHex: keys.encPubHex,
      sigPubHex: keys.sigPubHex,
      signatureHex,
    };
    // 受諾は CLI のみ(§15-3)でセッションの正当な導線がなく、セッション XSS +
    // 漏洩招待リンクで攻撃者鍵を被害者 user_id に束縛する複合を FP 相互確認の
    // 手前で塞ぐ(§15-2)。CSRF ヘッダーの有無によらず一様に拒否
    const noCsrf = await acceptRequest({ cookie: `__Host-maruhi_session=${session}` }, body);
    expect(noCsrf.status).toBe(403);
    expect(((await noCsrf.json()) as { reason: string }).reason).toBe("session-not-allowed");
    const withCsrf = await acceptRequest(sessionHeaders(session), body);
    expect(withCsrf.status).toBe(403);
    expect(((await withCsrf.json()) as { reason: string }).reason).toBe("session-not-allowed");
    // 行は pending のまま(拒否が受諾 CAS より前に確定している)
    expect((await inviteRow(issued.id))?.status).toBe("pending");
  });
});

describe("invite list / revoke", () => {
  it("lists invitations with the acceptance block; inviter client re-verifies §6.5", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, keys, issued.token)).status).toBe(200);

    const response = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      headers: bearer(tokenOf(fixture.tokens, OWNER)),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      invitations: readonly {
        id: string;
        projectId: string;
        tokenHashHex: string;
        status: string;
        acceptance: {
          inviteeUserId: string;
          inviteeEncPubHex: string;
          inviteeSigPubHex: string;
          signatureHex: string;
        } | null;
      }[];
    };
    const listed = body.invitations.find((entry) => entry.id === issued.id);
    expect(listed?.status).toBe("accepted");
    expect(listed?.tokenHashHex).toBe(await tokenHashOf(issued.token));
    const acceptance = listed?.acceptance;
    expect(acceptance).not.toBeNull();
    if (listed === undefined || acceptance === null || acceptance === undefined) {
      throw new Error("accepted invitation missing from list");
    }
    // 招待者クライアントの独立検証(CRYPTO_SPEC §6.5): 一覧の材料だけで
    // signed_bytes を再構成し、宣言鍵で検証が通る
    const verified = await verifyInviteAcceptSignature({
      context: {
        suite: SUITE_ID,
        projectId: listed.projectId,
        inviteTokenHashHex: listed.tokenHashHex,
        inviteeUserId: acceptance.inviteeUserId,
        inviteeEncPubHex: acceptance.inviteeEncPubHex,
        inviteeSigPubHex: acceptance.inviteeSigPubHex,
      },
      signatureHex: acceptance.signatureHex,
    });
    expect(verified.ok).toBe(true);
  });

  it("list requires chain role admin: member 403, non-member 404", async () => {
    const member = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      headers: bearer(tokenOf(fixture.tokens, MEMBER)),
    });
    expect(member.status).toBe(403);
    const stranger = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      headers: bearer(tokenOf(fixture.tokens, STRANGER)),
    });
    expect(stranger.status).toBe(404);
  });

  it("revokes pending and accepted invites; terminal states are 410 / unknown 404", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const revoke = (id: string) =>
      SELF.fetch(`${BASE}/projects/${projectId}/invites/${id}`, {
        method: "DELETE",
        headers: bearer(tokenOf(fixture.tokens, OWNER)),
      });

    const first = await revoke(issued.id);
    expect(first.status).toBe(204);
    expect((await inviteRow(issued.id))?.status).toBe("revoked");
    const revokedAudits = (await inviteAuditRows()).filter((r) => r.event === "invite.revoked");
    expect(revokedAudits).toHaveLength(1);
    expect(payloadOf(revokedAudits[0] ?? ({} as AuditRow))).toMatchObject({
      inviteId: issued.id,
      role: "member",
    });

    // 受諾は 410 revoked
    const keys = await makeInviteeKeys();
    const late = await acceptAs(fixture, STRANGER, keys, issued.token);
    expect(late.status).toBe(410);
    expect((await late.json()) as object).toMatchObject({ reason: "revoked" });

    // 再失効は 410 revoked(黙って成功させない)+ 監査は増えない
    const again = await revoke(issued.id);
    expect(again.status).toBe(410);
    expect((await inviteAuditRows()).filter((r) => r.event === "invite.revoked")).toHaveLength(1);

    // accepted の失効は可(FP 不一致の発見時に殺す経路)
    const accepted = await issueInvite(fixture, OWNER, "member");
    const acceptedKeys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, acceptedKeys, accepted.token)).status).toBe(200);
    expect((await revoke(accepted.id)).status).toBe(204);

    // completed は 410 completed
    const completed = await issueInvite(fixture, OWNER, "member");
    await env.DB.prepare("UPDATE invitations SET status = 'completed' WHERE id = ?")
      .bind(completed.id)
      .run();
    const completedResponse = await revoke(completed.id);
    expect(completedResponse.status).toBe(410);
    expect((await completedResponse.json()) as object).toMatchObject({ reason: "completed" });

    // 未知 id は 404
    expect((await revoke("01ARZ3NDEKTSV4RRFFQ69G5FAV")).status).toBe(404);
  });

  it("session principals can list and revoke (§5 の許可列挙 — 読み取り + 失効系。W2b)", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const session = await loginSession(9001);

    // 一覧(読み取り)— チェーン role admin 以上のセッションは可(§15-2)
    const listed = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      headers: sessionHeaders(session),
    });
    expect(listed.status).toBe(200);

    // 失効(資格を減らす方向の mutation — ADR-0018 改訂 2 の境界原則)。
    // セッション actor の監査帰属は auth_method(トークン id なし — AUDIT_SPEC §2)
    const revoked = await SELF.fetch(`${BASE}/projects/${projectId}/invites/${issued.id}`, {
      method: "DELETE",
      headers: sessionHeaders(session),
    });
    expect(revoked.status).toBe(204);
    expect((await inviteRow(issued.id))?.status).toBe("revoked");
    const audits = (await inviteAuditRows()).filter((r) => r.event === "invite.revoked");
    expect(audits).toHaveLength(1);
    const audit = audits[0] ?? ({} as AuditRow);
    expect(audit.actor_user_id).toBe(OWNER);
    expect(audit.actor_api_token_id).toBeNull();
    expect(payloadOf(audit)).toMatchObject({ authMethod: "github_oauth" });
  });

  it("marks the key-matched accepted invite completed when add_member is accepted", async () => {
    const matched = await issueInvite(fixture, OWNER, "member");
    const otherPending = await issueInvite(fixture, OWNER, "reader");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, keys, matched.token)).status).toBe(200);

    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex: keys.encPubHex,
        sigPubHex: keys.sigPubHex,
        role: "member",
      },
    });

    // 鍵一致の accepted 招待だけが completed へ突合される(§15-2)
    expect((await inviteRow(matched.id))?.status).toBe("completed");
    // 受諾されていない招待は据え置き
    expect((await inviteRow(otherPending.id))?.status).toBe("pending");
    // completed への更新は独立イベントを書かない(§15-4 — chain.member_added が証跡)
    const audits = await inviteAuditRows();
    expect(audits.filter((r) => r.event === "invite.completed")).toHaveLength(0);
  });

  it("add_member still succeeds when the reconciliation write fails (catchDefect guard)", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, keys, issued.token)).status).toBe(200);
    // 突合の D1 書き込みを決定的に失敗させる(テーブルを一時退避)。ガードを
    // 外すと確定済み append が 500 になり appendOperation 内の 200 expect が落ちる
    await env.DB.prepare("ALTER TABLE invitations RENAME TO invitations_hidden").run();
    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex: keys.encPubHex,
        sigPubHex: keys.sigPubHex,
        role: "member",
      },
    });
    await env.DB.prepare("ALTER TABLE invitations_hidden RENAME TO invitations").run();
    // 突合は欠落し、招待は accepted のまま残る(可視・失効で修復できる状態 —
    // handlers-membership.ts のコメントが宣言する「欠落側に倒す」の実挙動)
    expect(mustRow(await inviteRow(issued.id)).status).toBe("accepted");
  });

  it("leaves an accepted invite untouched when add_member carries different keys", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    const differentKeys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, keys, issued.token)).status).toBe(200);

    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex: differentKeys.encPubHex,
        sigPubHex: differentKeys.sigPubHex,
        role: "member",
      },
    });

    // 別鍵での add_member はこの受諾を成就させない — accepted のまま一覧に残り、
    // 管理者の失効対象として可視
    expect((await inviteRow(issued.id))?.status).toBe("accepted");
  });
});
