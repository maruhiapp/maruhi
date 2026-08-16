// AUTH_SPEC §2 の D1 スキーマ(Drizzle。ADR-0006)。
//
// この境界(db.package)の外に Drizzle の型を出さない: テーブル定義・select 結果型は
// リポジトリサービスの実装専用で、公開 API はドメイン型と Effect 型のみ(index.ts 参照)。
//
// 規則(AUTH_SPEC §2):
// - 他のあらゆる構造からの参照は users.id(内部 ULID)のみ。provider_user_id を
//   外部キーとして使用禁止
// - ルックアップは (provider, provider_user_id) でのみ行う。メールでの検索を作らない
// - memberships.role(org ロール)はプロジェクトアクセスに関与しない(§9-2)
// - projects は org 帰属のメタデータであり、プロジェクト内権限の真実源ではない
//   (真実源はメンバーシップチェーン。CRYPTO_SPEC §6.4 の 2 つの真実源の禁止)
//
// 時刻はすべて unix ms の INTEGER。

import {
  index,
  integer,
  primaryKey,
  sqliteTable,
  text,
  uniqueIndex,
} from "drizzle-orm/sqlite-core";

export const users = sqliteTable("users", {
  /** 内部 user_id(ULID)。全システムの主体識別子 */
  id: text("id").primaryKey(),
  /** 表示・通知用。識別子として使用禁止。GitHub 側で verified なもののみ保存 */
  email: text("email"),
  emailVerified: integer("email_verified").notNull().default(0),
  createdAt: integer("created_at").notNull(),
  updatedAt: integer("updated_at").notNull(),
});

export const linkedIdentities = sqliteTable(
  "linked_identities",
  {
    userId: text("user_id")
      .notNull()
      .references(() => users.id),
    /** 'github'(将来: 'workos' 等) */
    provider: text("provider").notNull(),
    /** GitHub の数値 ID の文字列化(login 名ではない。login は変更可能) */
    providerUserId: text("provider_user_id").notNull(),
    /** 表示用スナップショット */
    providerLogin: text("provider_login"),
    linkedAt: integer("linked_at").notNull(),
  },
  (t) => [primaryKey({ columns: [t.provider, t.providerUserId] }), index("li_user").on(t.userId)],
);

export const organizations = sqliteTable(
  "organizations",
  {
    id: text("id").primaryKey(),
    slug: text("slug").notNull(),
    name: text("name").notNull(),
    createdAt: integer("created_at").notNull(),
    // 将来カラム(今は作らない): sso_connection_id, allowed_domains, enforce_sso
  },
  (t) => [uniqueIndex("org_slug").on(t.slug)],
);

export const memberships = sqliteTable(
  "memberships",
  {
    orgId: text("org_id")
      .notNull()
      .references(() => organizations.id),
    userId: text("user_id")
      .notNull()
      .references(() => users.id),
    /** org ロール: 'owner' | 'admin' | 'member'(プロジェクトアクセスには関与しない) */
    role: text("role").notNull(),
  },
  (t) => [primaryKey({ columns: [t.orgId, t.userId] }), index("mem_user").on(t.userId)],
);

export const sessions = sqliteTable(
  "sessions",
  {
    /** ランダム 256-bit セッション値の SHA-256(hex)。生値は保存しない */
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id),
    /** 'github_oauth'(将来: 'sso' 等)。SSO 強制ポリシーに必要 */
    authMethod: text("auth_method").notNull(),
    createdAt: integer("created_at").notNull(),
    expiresAt: integer("expires_at").notNull(),
    lastUsedAt: integer("last_used_at").notNull(),
  },
  (t) => [index("sess_user").on(t.userId), index("sess_expires").on(t.expiresAt)],
);

export const apiTokens = sqliteTable(
  "api_tokens",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id),
    name: text("name").notNull(),
    /** SHA-256(hex)。生トークンは発行時に一度だけ返す */
    tokenHash: text("token_hash").notNull(),
    /** 表示用(例: maruhi_pat_Ab12…) */
    tokenPrefix: text("token_prefix").notNull(),
    /** TokenScope の JSON 配列(AUTH_SPEC §6 のスコープ表現) */
    scopes: text("scopes").notNull(),
    expiresAt: integer("expires_at"),
    createdAt: integer("created_at").notNull(),
    lastUsedAt: integer("last_used_at"),
  },
  (t) => [
    uniqueIndex("tok_hash").on(t.tokenHash),
    index("tok_user").on(t.userId),
    // 同名トークンはローテーション(AUTH_SPEC §6)。並行発行でも 1 本を DB 制約で保証
    uniqueIndex("tok_user_name").on(t.userId, t.name),
  ],
);

export const recoveryWraps = sqliteTable("recovery_wraps", {
  /** user 単位で高々 1 つ(AUTH_SPEC §13-1) */
  userId: text("user_id")
    .primaryKey()
    .references(() => users.id),
  /** スイート識別子(CRYPTO_SPEC §2 設計原則 4) */
  suite: text("suite").notNull(),
  /** 96-bit nonce(hex 小文字 24 文字) */
  nonceHex: text("nonce_hex").notNull(),
  /** AES-256-GCM の ct || tag(hex 小文字)。サーバーは復号・解釈しない */
  ciphertextHex: text("ciphertext_hex").notNull(),
  createdAt: integer("created_at").notNull(),
  updatedAt: integer("updated_at").notNull(),
  /** ブロブ取得の固定窓レート制限(AUTH_SPEC §13-3)。未取得は 0 / null */
  fetchWindowStart: integer("fetch_window_start"),
  fetchCount: integer("fetch_count").notNull().default(0),
});

export const projects = sqliteTable(
  "projects",
  {
    /** プロジェクト ID = genesis エントリハッシュ(hex 小文字 64。CRYPTO_SPEC §6.4) */
    id: text("id").primaryKey(),
    /** org 帰属(AUTH_SPEC §11-3。NOT NULL = org なしプロジェクトは存在しない) */
    orgId: text("org_id")
      .notNull()
      .references(() => organizations.id),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("proj_org").on(t.orgId)],
);

export const invitations = sqliteTable(
  "invitations",
  {
    /** ULID */
    id: text("id").primaryKey(),
    /**
     * genesis ハッシュ(AUTH_SPEC §15-1)。projects への FK は張らない: 招待は
     * チェーン(DO)の role で認可され、projects 行は org 帰属メタデータに
     * すぎない(§11-3 の部分失敗修復中でも招待は成立してよい)
     */
    projectId: text("project_id").notNull(),
    /**
     * 招待トークン(提示文字列全体 `maruhi_inv_…`)の SHA-256(hex)。生値は
     * 発行応答で一度だけ返す(§5 / §6 の PAT と同じ規律。CRYPTO_SPEC §6.5 の
     * 「256-bit 乱数」はエントロピーの規定であり、ハッシュ入力は PAT と同じく
     * 提示文字列の UTF-8 バイト)
     */
    tokenHash: text("token_hash").notNull(),
    /** 'reader' | 'member' | 'admin'(招待経由で owner は付与しない — §15-1) */
    role: text("role").notNull(),
    inviterUserId: text("inviter_user_id").notNull(),
    /** 'pending' | 'accepted' | 'completed' | 'revoked'(期限切れは expires_at からの導出) */
    status: text("status").notNull(),
    /** 発行 + 7 日(§15-1 起草値) */
    expiresAt: integer("expires_at").notNull(),
    // 受諾ブロック(status が accepted 以降 — §15-1)
    inviteeUserId: text("invitee_user_id"),
    inviteeEncPub: text("invitee_enc_pub"),
    inviteeSigPub: text("invitee_sig_pub"),
    /** CRYPTO_SPEC §6.5 の受諾署名(hex)。招待者クライアントの独立検証の材料 */
    acceptSignature: text("accept_signature"),
    acceptedAt: integer("accepted_at"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [
    uniqueIndex("inv_token_hash").on(t.tokenHash),
    // pending 上限(status 条件)と一覧
    index("inv_project_status").on(t.projectId, t.status),
    // 発行の固定窓レート制限(created_at 範囲)
    index("inv_project_created").on(t.projectId, t.createdAt),
  ],
);

// ---------------------------------------------------------------------------
// D1 側監査イベント(AUDIT_SPEC §3.1〜§3.2。保存先の裁定は §5.2 案 A)
//
// - 列構成は project DO の audit_events(§5.1)と同じ設計(頻出属性の列昇格 +
//   payload JSON)。DO 専用列(チェーン・変数座標・鍵 FP)は D1 側イベントに
//   現れないため持たず、org 系の横断クエリ用に org_id / project_id を昇格する
// - seq は autoincrement(§5.2。DO の無欠番保証はない — D1 で実用上足りる)
// - append-only(§1-4): このテーブルへ UPDATE / DELETE を発行するコードを
//   書かない。読み取り API は Phase 2 の監査ログ UI と同時に設計する(§6)
// - users への FK を張らない: 監査行は記録対象の行より長生きし、参照整合で
//   追記が阻害されてはならない(§1-4 の append-only を守る側に倒す)
// ---------------------------------------------------------------------------

/** user / org 監査テーブルの共通列(Drizzle の列オブジェクト共有パターン)。 */
const auditEventColumns = {
  seq: integer("seq").primaryKey({ autoIncrement: true }),
  /** サーバー受理時刻(unix ms) */
  serverTs: integer("server_ts").notNull(),
  /** AUDIT_SPEC §3 のイベント名(`領域.動詞`) */
  event: text("event").notNull(),
  /** §2 アクター種別。D1 側は現状 'user' のみ(login_failed は user_id なしの user) */
  actorType: text("actor_type").notNull(),
  actorUserId: text("actor_user_id"),
  actorApiTokenId: text("actor_api_token_id"),
  /** メンバー操作の対象 */
  targetUserId: text("target_user_id"),
  orgId: text("org_id"),
  projectId: text("project_id"),
  /** JSON。auth_method・スナップショット等の補足。§1-2/1-3 の禁止情報を含めない */
  payload: text("payload"),
};

/** 認証系イベント(AUDIT_SPEC §3.1)。 */
export const userAuditEvents = sqliteTable("user_audit_events", auditEventColumns, (t) => [
  index("uae_actor").on(t.actorUserId, t.seq),
  index("uae_target").on(t.targetUserId, t.seq),
  index("uae_event").on(t.event, t.seq),
]);

/** org 系イベント(AUDIT_SPEC §3.2)。 */
export const orgAuditEvents = sqliteTable("org_audit_events", auditEventColumns, (t) => [
  index("oae_actor").on(t.actorUserId, t.seq),
  index("oae_target").on(t.targetUserId, t.seq),
  index("oae_event").on(t.event, t.seq),
  index("oae_org").on(t.orgId, t.seq),
  // invite.* の project_id スコープ読み取り(AUDIT_SPEC §7 — C1)のページング用
  index("oae_project").on(t.projectId, t.seq),
]);
