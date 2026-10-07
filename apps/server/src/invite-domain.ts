// Server-side domain types for invites (AUTH_SPEC §15 — 2026-09-13 IV
// revision).
//
// Shared by db.package (the repository) and the handlers. No Drizzle
// types appear here (ADR-0006: confined inside the service boundary).
// The invite's secret (the link key's seed) never passes through the
// server, so it appears in no type. Only public values sit on the row
// (issue document, signatures).

import type { KeyFingerprintHex, UserId } from "@maruhi/core";

/** Chain roles grantable via an invite (owner is never granted through invites — §15-1). */
export type InviteRole = "reader" | "member" | "admin";

/** The to-be-granted scope (AUTH_SPEC §15-2 — 2026-09-14 ES; same shape as CRYPTO_SPEC §6.2). */
export interface InviteScope {
  readonly scopeKind: "all" | "listed";
  readonly scopeEnvironmentIds: readonly string[];
}

/** The stored invite state (expiry is derived from expires_at, not a stored state). */
export type InviteStatus = "pending" | "accepted" | "completed" | "revoked";

/**
 * The issue document (CRYPTO_SPEC §6.5): the client-generated link
 * public key, the inviter's verified head at issuance, and the issue
 * signature. The server stores and distributes it without verifying.
 */
export interface InviteIssuance {
  readonly linkPubHex: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly issueSignatureHex: string;
}

/** The acceptance block (status accepted and onward — §15-1). */
export interface InviteAcceptance {
  readonly inviteeUserId: UserId;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
  /** The §6.5 accept signature (the acceptor's chain sig key) — material for the inviter client's independent verification */
  readonly acceptSignatureHex: string;
  /** The §6.5 link signature (link key) — same material */
  readonly linkSignatureHex: string;
  readonly acceptedAtMs: number;
}

/** Domain representation of an invite row. */
export interface InvitationRecord {
  readonly id: string;
  readonly projectId: string;
  readonly role: InviteRole;
  /** The to-be-granted scope (part of the issue document — covered by the issue signature. §15-2) */
  readonly scope: InviteScope;
  readonly inviterUserId: string;
  readonly status: InviteStatus;
  readonly expiresAtMs: number;
  readonly createdAtMs: number;
  readonly issuance: InviteIssuance;
  readonly acceptance: InviteAcceptance | null;
}

/** The acceptance decision for issuance (§15-2's acceptance policy. Check order: UNIQUE → pending cap → fixed window). */
export type InviteIssueDecision =
  | { readonly kind: "created" }
  | { readonly kind: "conflict"; readonly field: "id" | "linkPub" }
  | { readonly kind: "pending-limit"; readonly limit: number }
  | { readonly kind: "rate-limited"; readonly retryAfterSeconds: number };

/**
 * The committed values passed to the accept CAS (pending → accepted).
 * Both signatures are already verified by the handler (CRYPTO_SPEC
 * §6.5 — project_id / link_pub are reconstructed from the stored
 * row).
 */
export interface InviteAcceptInput {
  readonly inviteId: string;
  readonly inviteeUserId: UserId;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
  readonly acceptSignatureHex: string;
  readonly linkSignatureHex: string;
  /** The acceptor key FP copied into the audit payload (AUDIT_SPEC §3.2), computed from the accepting keys. */
  readonly inviteeKeyFingerprintHex: KeyFingerprintHex;
}

/** The target of the accepted → completed comparison at add_member acceptance (§15-2). */
export interface InviteCompletionTarget {
  readonly projectId: string;
  readonly inviteeUserId: UserId;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
}
