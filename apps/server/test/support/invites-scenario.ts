// 招待 API(AUTH_SPEC §15)統合テストの共有ヘルパ(旧 invites.test.ts の冒頭
// ヘルパの分割先 — 分割の動機は membership-scenario.ts 冒頭を参照)。
//
// 受諾署名(CRYPTO_SPEC §6.5)は @maruhi/crypto の実装で実署名を作る。fixture
// は data-fixture の setupDataProject(ベースチェーン再生込み)を register 形
// (data-scenario.ts と同じ live binding パターン)で提供する。

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
} from "@maruhi/crypto";
import { env, SELF } from "cloudflare:test";
import { beforeEach, expect } from "vitest";

import { BASE, bearer, JSON_HEADERS } from "./auth.ts";
import type { DataFixture } from "./data-fixture.ts";
import { OWNER, projectId, setupDataProject, tokenOf } from "./data-fixture.ts";

export const INVITE_TOKEN_PATTERN = /^maruhi_inv_[0-9A-Za-z]{43}$/;
/** 提示トークン文字列全体の SHA-256(サーバー・CLI と同じハッシュ入力定義)。 */
export async function tokenHashOf(rawToken: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawToken));
  return encodeHex(new Uint8Array(digest));
}

/** 受諾者のテスト鍵ペア(未登録ユーザーの新規生成を模す)。 */
export async function makeInviteeKeys() {
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

export type InviteeKeys = Awaited<ReturnType<typeof makeInviteeKeys>>;

/** 受諾署名(CRYPTO_SPEC §6.5)を作る。context の上書きでリンク改竄等を模す。 */
export async function signAcceptance(
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

export async function issueInvite(
  fixture: DataFixture,
  actorUserId: string,
  role: "reader" | "member" | "admin",
): Promise<{ id: string; token: string; expiresAtMs: number }> {
  const response = await issueInviteRequest(fixture, actorUserId, role);
  expect(response.status).toBe(200);
  return (await response.json()) as { id: string; token: string; expiresAtMs: number };
}

export function issueInviteRequest(
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

export function acceptRequest(
  authHeaders: Record<string, string>,
  body: Record<string, unknown>,
): Promise<Response> {
  return SELF.fetch(`${BASE}/invites/accept`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...authHeaders },
    body: JSON.stringify(body),
  });
}

export async function acceptAs(
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

export interface InviteRow {
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

export async function inviteRow(id: string): Promise<InviteRow | null> {
  const row = await env.DB.prepare("SELECT * FROM invitations WHERE id = ?")
    .bind(id)
    .first<InviteRow>();
  return row;
}

export interface AuditRow {
  readonly event: string;
  readonly actor_user_id: string | null;
  readonly actor_api_token_id: string | null;
  readonly target_user_id: string | null;
  readonly org_id: string | null;
  readonly project_id: string | null;
  readonly payload: string | null;
}

export async function inviteAuditRows(): Promise<AuditRow[]> {
  const result = await env.DB.prepare(
    "SELECT * FROM org_audit_events WHERE event LIKE 'invite.%' ORDER BY seq",
  ).all<AuditRow>();
  return result.results;
}

export function payloadOf(row: AuditRow): Record<string, unknown> {
  return row.payload === null ? {} : (JSON.parse(row.payload) as Record<string, unknown>);
}

/** テスト用の招待行の直接シード(受理ポリシー・状態遷移の前提状態を作る)。 */
export async function seedInvitation(input: {
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

export async function errorTag(response: Response): Promise<string> {
  const body = (await response.json()) as { _tag?: string };
  return body["_tag"] ?? "";
}

/** 存在を検証済みの行の non-null 化(以降のフィールド検証を素の参照にする)。 */
export function mustRow(row: InviteRow | null): InviteRow {
  if (row === null) {
    throw new Error("invitation row missing");
  }
  return row;
}

export function firstAudit(rows: readonly AuditRow[], event: string): AuditRow {
  const found = rows.find((row) => row.event === event);
  if (found === undefined) {
    throw new Error(`audit row missing: ${event}`);
  }
  return found;
}

export let fixture: DataFixture;

/** 各テストファイルの冒頭で 1 回呼ぶ: フィクスチャの beforeEach を登録する。 */
export function registerInviteScenario(): void {
  beforeEach(async () => {
    fixture = await setupDataProject();
  });
}
