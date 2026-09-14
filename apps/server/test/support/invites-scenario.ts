// 招待 API(AUTH_SPEC §15 — IV 改訂)統合テストの共有ヘルパ。
//
// 発行文(発行署名)・受諾の共同署名(受諾署名 + リンク署名 — CRYPTO_SPEC §6.5)は
// @maruhi/crypto の実装で実署名を作る。招待者の署名鍵はベクター固定鍵
// (data-crypto.ts の vectorKeyOf)、リンク鍵は種から導出する。fixture は
// data-fixture の setupDataProject(ベースチェーン再生込み)を register 形
// (data-scenario.ts と同じ live binding パターン)で提供する。

import { ulid } from "@maruhi/core";
import type {
  InviteAcceptSignatureContext,
  InviteIssueContext,
  InviteLinkKeyPair,
} from "@maruhi/crypto";
import {
  computeUserKeyFingerprint,
  deriveInviteLinkKeyPair,
  encodeHex,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateInviteLinkSeed,
  generateSigningKeyPair,
  importSigningKeyPair,
  signInviteAccept,
  signInviteIssue,
  signInviteLink,
  SUITE_ID,
} from "@maruhi/crypto";
import { env, SELF } from "cloudflare:test";
import { beforeEach, expect } from "vitest";

import { BASE, bearer, JSON_HEADERS } from "./auth.ts";
import { hexBytes, vectorKeyOf } from "./data-crypto.ts";
import type { DataFixture } from "./data-fixture.ts";
import { OWNER, projectId, setupDataProject, tokenOf } from "./data-fixture.ts";

/**
 * ユーザーの署名鍵ペア(発行署名の署名者)。ベクター固定鍵を持つユーザーは
 * その鍵、持たないユーザー(STRANGER 等 — 認可で落ちる経路の主体)は使い捨ての
 * 生成鍵(サーバーは発行署名を検証しないので形式が揃えば足りる)。
 */
export async function signingKeyPairOf(userId: string) {
  let vector: ReturnType<typeof vectorKeyOf> | null;
  try {
    vector = vectorKeyOf(userId);
  } catch {
    vector = null;
  }
  if (vector === null) {
    const enc = await generateEncryptionKeyPair();
    const sig = await generateSigningKeyPair();
    return {
      pair: sig,
      encPubHex: encodeHex(await exportEncryptionPublicKey(enc.publicKey)),
      sigPubHex: encodeHex(await exportSigningPublicKey(sig.publicKey)),
    };
  }
  const pair = await importSigningKeyPair({
    publicKey: hexBytes(vector.sig_pub_hex),
    privateSeed: hexBytes(vector.sig_sk_seed_hex),
  });
  if (!pair.ok) {
    throw new Error("signing key import failed");
  }
  return { pair: pair.value, encPubHex: vector.enc_pub_hex, sigPubHex: vector.sig_pub_hex };
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

/** 発行の要求 body(§15-2)+ クライアント側の材料(リンク鍵ペア)。 */
export interface IssuePayload {
  readonly id: string;
  readonly role: "reader" | "member" | "admin";
  /** 付与予定 scope(AUTH_SPEC §15-2 — 2026-09-14 ES)。 */
  readonly scopeKind: "all" | "listed";
  readonly scopeEnvironmentIds: readonly string[];
  readonly linkPubHex: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly issueSignatureHex: string;
}

export interface IssuedInvite extends IssuePayload {
  readonly linkKey: InviteLinkKeyPair;
  readonly expiresAtMs: number;
}

/** 招待 id の採番 + リンク鍵の生成 + 発行署名(招待者 = actor のベクター鍵)。 */
export async function makeIssuePayload(
  fixture: DataFixture,
  actorUserId: string,
  role: "reader" | "member" | "admin",
  overrides?: Partial<InviteIssueContext> & { readonly id?: string },
): Promise<IssuePayload & { readonly linkKey: InviteLinkKeyPair }> {
  const linkKey = await deriveInviteLinkKeyPair(generateInviteLinkSeed());
  if (!linkKey.ok) {
    throw new Error("link key derivation failed");
  }
  const inviter = await signingKeyPairOf(actorUserId);
  const context: InviteIssueContext = {
    suite: SUITE_ID,
    inviteId: overrides?.id ?? ulid(),
    projectId,
    linkPubHex: encodeHex(linkKey.value.publicKeyRaw),
    headHashHex: fixture.head.hashHex,
    headSeq: fixture.head.seq,
    role,
    inviterUserId: actorUserId,
    inviterEncPubHex: inviter.encPubHex,
    inviterSigPubHex: inviter.sigPubHex,
    scopeKind: "all",
    scopeEnvironmentIds: [],
    ...overrides,
  };
  const signed = await signInviteIssue({ context, signingKey: inviter.pair.privateKey });
  if (!signed.ok) {
    throw new Error("issue signing failed");
  }
  return {
    id: context.inviteId,
    role,
    scopeKind: context.scopeKind,
    scopeEnvironmentIds: context.scopeEnvironmentIds,
    linkPubHex: context.linkPubHex,
    headHashHex: context.headHashHex,
    headSeq: context.headSeq,
    issueSignatureHex: signed.value,
    linkKey: linkKey.value,
  };
}

/** 発行 body のワイヤ部分だけ(リンク鍵ペアを落とす)。 */
export function wirePayloadOf(payload: IssuePayload): Record<string, unknown> {
  return {
    id: payload.id,
    role: payload.role,
    scopeKind: payload.scopeKind,
    scopeEnvironmentIds: payload.scopeEnvironmentIds,
    linkPubHex: payload.linkPubHex,
    headHashHex: payload.headHashHex,
    headSeq: payload.headSeq,
    issueSignatureHex: payload.issueSignatureHex,
  };
}

export async function issueInvite(
  fixture: DataFixture,
  actorUserId: string,
  role: "reader" | "member" | "admin",
): Promise<IssuedInvite> {
  const payload = await makeIssuePayload(fixture, actorUserId, role);
  const response = await issueInviteRequest(fixture, actorUserId, role, payload);
  expect(response.status).toBe(200);
  const body = (await response.json()) as { expiresAtMs: number };
  return { ...payload, expiresAtMs: body.expiresAtMs };
}

export async function issueInviteRequest(
  fixture: DataFixture,
  actorUserId: string,
  role: "reader" | "member" | "admin",
  payload?: IssuePayload,
): Promise<Response> {
  const body = payload ?? (await makeIssuePayload(fixture, actorUserId, role));
  return SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, actorUserId)) },
    body: JSON.stringify(wirePayloadOf(body)),
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

/** 受諾の共同署名(CRYPTO_SPEC §6.5)を作る。context の上書きでリンク改竄等を模す。 */
export async function signAcceptance(
  keys: InviteeKeys,
  issued: { readonly linkPubHex: string; readonly linkKey: InviteLinkKeyPair },
  inviteeUserId: string,
  overrides?: Partial<InviteAcceptSignatureContext>,
): Promise<{ readonly acceptSignatureHex: string; readonly linkSignatureHex: string }> {
  const context: InviteAcceptSignatureContext = {
    suite: SUITE_ID,
    projectId,
    linkPubHex: issued.linkPubHex,
    inviteeUserId,
    inviteeEncPubHex: keys.encPubHex,
    inviteeSigPubHex: keys.sigPubHex,
    ...overrides,
  };
  const signed = await signInviteAccept({ context, signingKey: keys.signingKey });
  const linkSigned = await signInviteLink({ context, linkPrivateKey: issued.linkKey.privateKey });
  if (!signed.ok || !linkSigned.ok) {
    throw new Error("acceptance signing failed");
  }
  return { acceptSignatureHex: signed.value, linkSignatureHex: linkSigned.value };
}

export async function acceptAs(
  fixture: DataFixture,
  userId: string,
  keys: InviteeKeys,
  issued: { readonly linkPubHex: string; readonly linkKey: InviteLinkKeyPair },
  overrides?: Partial<InviteAcceptSignatureContext>,
): Promise<Response> {
  const signatures = await signAcceptance(keys, issued, userId, overrides);
  return acceptRequest(bearer(tokenOf(fixture.tokens, userId)), {
    linkPubHex: issued.linkPubHex,
    encPubHex: keys.encPubHex,
    sigPubHex: keys.sigPubHex,
    ...signatures,
  });
}

export interface InviteRow {
  readonly id: string;
  readonly project_id: string;
  readonly link_pub: string;
  readonly head_hash: string;
  readonly head_seq: number;
  readonly issue_signature: string;
  readonly role: string;
  readonly status: string;
  readonly invitee_user_id: string | null;
  readonly invitee_enc_pub: string | null;
  readonly invitee_sig_pub: string | null;
  readonly accept_signature: string | null;
  readonly link_signature: string | null;
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

/**
 * テスト用の招待行の直接シード(受理ポリシー・状態遷移の前提状態を作る)。
 * 発行文は形だけ整えたダミー(link_pub は id から決定的に導く = UNIQUE を満たす。
 * 発行署名はサーバーが検証しないので固定値)。
 */
export async function seedInvitation(input: {
  readonly id: string;
  readonly status?: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}): Promise<void> {
  const linkPub = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input.id));
  await env.DB.prepare(
    "INSERT INTO invitations (id, project_id, link_pub, head_hash, head_seq, issue_signature, role, scope_kind, scope_environments, inviter_user_id, status, expires_at, created_at) VALUES (?, ?, ?, ?, 1, ?, 'member', 'all', '[]', ?, ?, ?, ?)",
  )
    .bind(
      input.id,
      projectId,
      encodeHex(new Uint8Array(linkPub)),
      "ab".repeat(32),
      "00".repeat(64),
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
