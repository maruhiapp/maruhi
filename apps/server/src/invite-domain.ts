// 招待のサーバー内ドメイン型(AUTH_SPEC §15 — 2026-09-13 IV 改訂)。
//
// db.package(リポジトリ)とハンドラが共有する。Drizzle の型はここに現れない
// (ADR-0006: サービス境界内に隔離)。招待の秘密(リンク鍵の種)はサーバーを
// 通らないため、どの型にも現れない。行に載るのは公開値だけ(発行文・署名)。

/** 招待で付与できるチェーン role(owner は招待経由で付与しない — §15-1)。 */
export type InviteRole = "reader" | "member" | "admin";

/** 付与予定 scope(AUTH_SPEC §15-2 — 2026-09-14 ES。CRYPTO_SPEC §6.2 と同じ形)。 */
export interface InviteScope {
  readonly scopeKind: "all" | "listed";
  readonly scopeEnvironmentIds: readonly string[];
}

/** 保存上の招待状態(期限切れは expires_at からの導出で、保存状態ではない)。 */
export type InviteStatus = "pending" | "accepted" | "completed" | "revoked";

/**
 * 発行文(CRYPTO_SPEC §6.5): クライアント生成のリンク公開鍵・発行時点の招待者の
 * 検証済みヘッド・発行署名。サーバーは検証せず保存・配布する。
 */
export interface InviteIssuance {
  readonly linkPubHex: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly issueSignatureHex: string;
}

/** 受諾ブロック(status が accepted 以降 — §15-1)。 */
export interface InviteAcceptance {
  readonly inviteeUserId: string;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
  /** CRYPTO_SPEC §6.5 の受諾署名(受諾者のチェーン sig 鍵)。招待者クライアントの独立検証の材料 */
  readonly acceptSignatureHex: string;
  /** CRYPTO_SPEC §6.5 のリンク署名(リンク鍵)。同じ材料 */
  readonly linkSignatureHex: string;
  readonly acceptedAtMs: number;
}

/** 招待行のドメイン表現。 */
export interface InvitationRecord {
  readonly id: string;
  readonly projectId: string;
  readonly role: InviteRole;
  /** 付与予定 scope(発行文の一部 — 発行署名が覆う。§15-2) */
  readonly scope: InviteScope;
  readonly inviterUserId: string;
  readonly status: InviteStatus;
  readonly expiresAtMs: number;
  readonly createdAtMs: number;
  readonly issuance: InviteIssuance;
  readonly acceptance: InviteAcceptance | null;
}

/** 発行の受理判定(§15-2 の受理ポリシー。判定順: UNIQUE → pending 上限 → 固定窓)。 */
export type InviteIssueDecision =
  | { readonly kind: "created" }
  | { readonly kind: "conflict"; readonly field: "id" | "linkPub" }
  | { readonly kind: "pending-limit"; readonly limit: number }
  | { readonly kind: "rate-limited"; readonly retryAfterSeconds: number };

/**
 * 受諾 CAS(pending → accepted)へ渡す確定値。両署名はハンドラが検証済み
 * (CRYPTO_SPEC §6.5 — project_id / link_pub は保存行から再構成)。
 */
export interface InviteAcceptInput {
  readonly inviteId: string;
  readonly inviteeUserId: string;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
  readonly acceptSignatureHex: string;
  readonly linkSignatureHex: string;
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
