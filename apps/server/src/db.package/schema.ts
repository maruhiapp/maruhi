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
