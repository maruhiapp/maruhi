import type { EnvironmentId, KeyFingerprintHex, ProjectId, UserId } from "@maruhi/core";

export type InviteRole = "reader" | "member" | "admin";

export interface InviteScope {
  readonly scopeKind: "all" | "listed";
  readonly scopeEnvironmentIds: readonly EnvironmentId[];
}

export type InviteStatus = "pending" | "accepted" | "completed" | "revoked";

export interface InviteIssuance {
  readonly linkPubHex: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly issueSignatureHex: string;
}

export interface InviteAcceptance {
  readonly inviteeUserId: UserId;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
  readonly acceptSignatureHex: string;
  readonly linkSignatureHex: string;
  readonly acceptedAtMs: number;
}

export interface InvitationRecord {
  readonly id: string;
  readonly projectId: ProjectId;
  readonly role: InviteRole;
  readonly scope: InviteScope;
  readonly inviterUserId: UserId;
  readonly status: InviteStatus;
  readonly expiresAtMs: number;
  readonly createdAtMs: number;
  readonly issuance: InviteIssuance;
  readonly acceptance: InviteAcceptance | null;
}

export type InviteIssueDecision =
  | { readonly kind: "created" }
  | { readonly kind: "conflict"; readonly field: "id" | "linkPub" }
  | { readonly kind: "pending-limit"; readonly limit: number }
  | { readonly kind: "rate-limited"; readonly retryAfterSeconds: number };

export interface InviteAcceptInput {
  readonly inviteId: string;
  readonly inviteeUserId: UserId;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
  readonly acceptSignatureHex: string;
  readonly linkSignatureHex: string;
  readonly inviteeKeyFingerprintHex: KeyFingerprintHex;
}

export interface InviteCompletionTarget {
  readonly projectId: ProjectId;
  readonly inviteeUserId: UserId;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
  readonly role: InviteRole | "owner";
  readonly scopeKind: InviteScope["scopeKind"];
  readonly scopeEnvironmentIds: readonly EnvironmentId[];
}
