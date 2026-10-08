// Shared helpers for the invite API (AUTH_SPEC §15 — IV revision)
// integration tests.
//
// The issuance statement (issue signature) and the acceptance joint
// signature (accept signature + link signature — CRYPTO_SPEC §6.5) are real
// signatures produced via the @maruhi/crypto implementation. The inviter's
// signing key is the fixed vector key (data-crypto.ts vectorKeyOf); the link
// key is derived from a seed. The fixture provides data-fixture's
// setupDataProject (base-chain replay included) in register form (the same
// live-binding pattern as data-scenario.ts).

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
import { testKeyFingerprintHex } from "@maruhi/crypto/test-support";
import { env, SELF } from "cloudflare:test";
import { beforeEach, expect } from "vitest";

import { BASE, bearer, JSON_HEADERS } from "./auth.ts";
import { hexBytes, vectorKeyOf } from "./data-crypto.ts";
import { testProjectId, testUserId } from "./data-crypto.ts";
import type { DataFixture } from "./data-fixture.ts";
import { OWNER, projectId, setupDataProject, tokenOf } from "./data-fixture.ts";

/**
 * A user's signing key pair (the signer of issue signatures). Users with a
 * fixed vector key get that key; users without one (STRANGER etc. —
 * principals on paths that fail at authorization) get a disposable generated
 * key (the server does not verify issue signatures, so well-formed is
 * enough).
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

/** The invitee's test key pair (simulates fresh generation by an
 * unregistered user). */
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
    fingerprintHex: testKeyFingerprintHex(encodeHex(fingerprint.value)),
  };
}

export type InviteeKeys = Awaited<ReturnType<typeof makeInviteeKeys>>;

/** The issue request body (§15-2) plus client-side material (the link key
 * pair). */
export interface IssuePayload {
  readonly id: string;
  readonly role: "reader" | "member" | "admin";
  /** Scope to be granted (AUTH_SPEC §15-2 — 2026-09-14 ES). */
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

/** Assigns the invite id, generates the link key, and produces the issue
 * signature (inviter = the actor's vector key). */
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
    projectId: testProjectId(projectId),
    linkPubHex: encodeHex(linkKey.value.publicKeyRaw),
    headHashHex: fixture.head.hashHex,
    headSeq: fixture.head.seq,
    role,
    inviterUserId: testUserId(actorUserId),
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

/** Only the wire part of an issue body (drops the link key pair). */
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

/** Produces the acceptance joint signature (CRYPTO_SPEC §6.5). Overrides on
 * context simulate link tampering etc. */
export async function signAcceptance(
  keys: InviteeKeys,
  issued: { readonly linkPubHex: string; readonly linkKey: InviteLinkKeyPair },
  inviteeUserId: string,
  overrides?: Partial<InviteAcceptSignatureContext>,
): Promise<{ readonly acceptSignatureHex: string; readonly linkSignatureHex: string }> {
  const context: InviteAcceptSignatureContext = {
    suite: SUITE_ID,
    projectId: testProjectId(projectId),
    linkPubHex: issued.linkPubHex,
    inviteeUserId: testUserId(inviteeUserId),
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
  /** Scope to be granted (AUTH_SPEC §15-1 — 2026-09-14 ES).
   * scope_environments is a JSON array. */
  readonly scope_kind: string;
  readonly scope_environments: string;
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
 * Directly seeds an invitation row for tests (builds the precondition state
 * for admission-policy / state-transition tests). The issuance statement is
 * a shape-only dummy (link_pub is derived deterministically from the id =
 * satisfies UNIQUE; the issue signature is a fixed value because the server
 * does not verify it).
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

/** Non-null-ifies a row whose existence was verified (lets later field
 * checks use plain references). */
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

export let inviteFixture: DataFixture;

/** Called once at the top of each test file: registers the fixture's
 * beforeEach. */
export function registerInviteScenario(): void {
  beforeEach(async () => {
    inviteFixture = await setupDataProject();
  });
}
