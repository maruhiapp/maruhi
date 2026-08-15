// 招待のサーバー内ドメイン型(AUTH_SPEC §15)。
//
// db.package(リポジトリ)とハンドラが共有する。Drizzle の型はここに現れない
// (ADR-0006: サービス境界内に隔離)。トークン生値はどの型にも現れない
// (発行応答のワイヤ型 — api-schema — にのみ一度だけ現れる)。

/** 招待で付与できるチェーン role(owner は招待経由で付与しない — §15-1)。 */
export type InviteRole = "reader" | "member" | "admin";

/** 保存上の招待状態(期限切れは expires_at からの導出で、保存状態ではない)。 */
export type InviteStatus = "pending" | "accepted" | "completed" | "revoked";

/** 受諾ブロック(status が accepted 以降 — §15-1)。 */
export interface InviteAcceptance {
  readonly inviteeUserId: string;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
  /** CRYPTO_SPEC §6.5 の受諾署名。招待者クライアントの独立検証の材料 */
  readonly acceptSignatureHex: string;
  readonly acceptedAtMs: number;
}

/** 招待行のドメイン表現(トークンはハッシュのみ)。 */
export interface InvitationRecord {
  readonly id: string;
  readonly projectId: string;
  readonly tokenHashHex: string;
  readonly role: InviteRole;
  readonly inviterUserId: string;
  readonly status: InviteStatus;
  readonly expiresAtMs: number;
  readonly createdAtMs: number;
  readonly acceptance: InviteAcceptance | null;
}

/** 発行の受理判定(§15-2 の受理ポリシー。判定順: pending 上限 → 固定窓)。 */
export type InviteIssueDecision =
  | { readonly kind: "created" }
  | { readonly kind: "pending-limit"; readonly limit: number }
  | { readonly kind: "rate-limited"; readonly retryAfterSeconds: number };

/**
 * 受諾 CAS(pending → accepted)へ渡す確定値。署名はハンドラが検証済み
 * (CRYPTO_SPEC §6.5 — project_id / token_hash は保存行から再構成)。
 */
export interface InviteAcceptInput {
  readonly inviteId: string;
  readonly inviteeUserId: string;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
  readonly acceptSignatureHex: string;
  /** 監査 payload に写す受諾鍵 FP(AUDIT_SPEC §3.2)。 */
  readonly inviteeKeyFingerprintHex: string;
}

/** add_member 受理時の accepted → completed 突合の対象(§15-2)。 */
export interface InviteCompletionTarget {
  readonly projectId: string;
  readonly inviteeUserId: string;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
}
