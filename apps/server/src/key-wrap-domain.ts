// master 鍵ラップ台帳のドメイン型(AUTH_SPEC §13-6〜13-10 — KL3)。
// db.package の外へ出す公開シェイプ(Drizzle の型は出さない — ADR-0006)。
// どの型もラップ・分片はサーバーから見て不透明な暗号文(hex 文字列)であり、
// KEK の素材・平文の分片は現れない。

/** 保護者グループの閾値モード(CRYPTO_SPEC §8.3)。 */
export type GuardianMode = "any" | "all";

/** B(master 鍵ブロブ)のラップ(AES-256-GCM。§13-9 MasterKeyWrap)。 */
export interface MasterKeyWrapBlob {
  readonly suite: string;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
}

/** クラス S(passkey-prf)の台帳行。`params` は公開パラメータの JSON 文字列。 */
export interface PasskeyWrapRecord {
  readonly wrapId: string;
  readonly params: string;
  readonly wrap: MasterKeyWrapBlob;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}

/** クラス G の分片行(保護者の enc 公開鍵への HPKE Seal)。 */
export interface GuardianShareRecord {
  readonly shareIndex: number;
  readonly guardianUserId: string;
  readonly guardianEncPubHex: string;
  readonly guardianKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

/** クラス G のグループ行(分片込み)。 */
export interface GuardianGroupRecord {
  readonly groupId: string;
  readonly userId: string;
  readonly mode: GuardianMode;
  readonly wrap: MasterKeyWrapBlob;
  readonly createdAtMs: number;
  readonly shares: readonly GuardianShareRecord[];
}

/** 保護者から見た自分の分片(ward 情報つき)。 */
export interface WardShareRecord {
  readonly wardUserId: string;
  /** linked_identities.provider_login の表示用スナップショット(識別子ではない) */
  readonly wardLogin: string | null;
  readonly groupId: string;
  readonly mode: GuardianMode;
  readonly shareIndex: number;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly createdAtMs: number;
}

/** クラス H のハンドオフ要求(E.pub は持たない — request_id はその導出値)。 */
export interface HandoffRequestRecord {
  readonly requestId: string;
  readonly userId: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly collectedAtMs: number | null;
}

/** クラス H の承認(応答スコープ — 要求とともに消える)。 */
export interface HandoffApprovalRecord {
  readonly source: string;
  readonly shareIndex: number;
  readonly approverUserId: string;
  readonly approverKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly blob: MasterKeyWrapBlob | null;
  readonly createdAtMs: number;
}

/** §13-8 の固定窓の種別。 */
export type KeyWrapWindowKind = "blob-fetch" | "handoff-request" | "approval";

/** 固定窓の消費結果。 */
export type KeyWrapWindowDecision =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly retryAfterSeconds: number };
