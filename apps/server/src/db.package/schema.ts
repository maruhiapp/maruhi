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

/**
 * デプロイメント単位のサーバー設定(AUTH_SPEC §3 — 2026-09-01 H1)。現状の
 * キーは `signup_policy`('open' | 'invite' | 'closed'。行なし = 'open')のみ。
 * 書き込み経路はコードに存在しない — 変更は運営の wrangler / SQL 経路のみ
 * (docs/SELF_HOSTING.md。管理 UI・設定 API は作らない)。読み手は未知の値を
 * 'closed' として扱う(fail-closed — repos.ts の readSignupPolicy)。
 */
export const deploymentSettings = sqliteTable("deployment_settings", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
  updatedAt: integer("updated_at").notNull(),
});

/**
 * サインアップ招待コード(AUTH_SPEC §3 — 2026-09-01 H1)。256-bit 乱数 bearer
 * (`maruhi_sgn_` + Base62)の SHA-256 ハッシュのみ保存・単回(消費 CAS)・
 * 期限つき(§15 invitations の型の踏襲)。コードはアカウント作成の許可だけを
 * 運ぶ — プロジェクト・org・role・プロバイダ識別子と結びつけない。
 *
 * - 発行は運営操作(scripts/issue-signup-invite.ts + wrangler d1)— サーバーに
 *   発行経路はない
 * - 消費(status 'pending' → 'used')はアカウント作成と同一 D1 batch 内の
 *   CAS(repos.ts — 作成失敗でコードだけ燃える形・作成成功でコードが残る形の
 *   両方を排除)
 * - used_by_user_id に FK を張らない: 消費 UPDATE は同一 batch 内で users 行の
 *   挿入**より前**に実行される(CAS の changes() を作成側の条件が読む)ため、
 *   参照整合は構造的に張れない(invitations と同じ「FK なし」判断)
 */
export const signupInvites = sqliteTable(
  "signup_invites",
  {
    /** ULID(発行スクリプトが採番)。監査 payload の signupInviteId と同じ値 */
    id: text("id").primaryKey(),
    /** 提示文字列全体(maruhi_sgn_…)の SHA-256(hex)。生値は発行時のみ */
    tokenHash: text("token_hash").notNull(),
    /** 'pending' | 'used'(期限切れは expires_at からの導出 — §15 と同じ) */
    status: text("status").notNull(),
    /** 発行 + 7 日(起草値 — 発行スクリプトが計算) */
    expiresAt: integer("expires_at").notNull(),
    createdAt: integer("created_at").notNull(),
    usedByUserId: text("used_by_user_id"),
    usedAt: integer("used_at"),
  },
  (t) => [uniqueIndex("sgn_token_hash").on(t.tokenHash)],
);

/**
 * フロー署名鍵(AUTH_SPEC §4-2)。CLI ログインの flowToken / vsig を検証する
 * HMAC-SHA-256 鍵で、初回使用時に自動生成して保存する(冪等 — insert の先勝ち +
 * 読み戻し)。auth 層の資格情報保護であり CRYPTO_SPEC の対象外(E2EE 特性に
 * 一切依拠されない)。行は固定 id の高々 1 行。
 */
export const flowSigningKeys = sqliteTable("flow_signing_keys", {
  /** 固定識別子(現状 'v1' の 1 行のみ) */
  id: text("id").primaryKey(),
  /** HMAC-SHA-256 鍵(256-bit、hex 小文字 64 文字) */
  keyHex: text("key_hex").notNull(),
  createdAt: integer("created_at").notNull(),
});

/**
 * CLI ログインのフロー行(AUTH_SPEC §4-1 (4) (iii))。start は無記録(裁定 DH)
 * で、行は callback の create-or-match CAS で**初めて**生まれる — 生まれた時点で
 * 認証済み user_id・発行パラメータ(vsig 済み URL 由来)・期限・承認チケットが
 * 確定している(中間状態が存在しない)。
 *
 * - status: 'awaiting' | 'approved' | 'denied' | 'consumed'。承認 / 拒否は
 *   awaiting からの CAS、PAT 発行は approved → consumed の CAS 勝者のみ(§4-1 (5))
 * - ticket_hash: 承認チケット(256-bit 乱数)の SHA-256(hex)。生値はページに
 *   のみ埋め、常に最新 1 枚(同一 user_id の再到達で置換)
 * - consumed / denied の行も期限 + 余裕までは削除しない(先に消すと poll が
 *   「行なし = pending」と誤読する — §4-1 (5))。掃除は期限経過後の日和見削除のみ
 */
export const cliLoginFlows = sqliteTable(
  "cli_login_flows",
  {
    /** 公開相関子 flowId(128-bit 乱数 hex 小文字 32 文字) */
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id),
    status: text("status").notNull(),
    /** 発行パラメータ(start で既定値を解決済み — vsig が覆う確定値) */
    tokenName: text("token_name").notNull(),
    /** TokenScope の JSON 配列(api_tokens.scopes と同じ表現) */
    scopes: text("scopes").notNull(),
    expiresInDays: integer("expires_in_days").notNull(),
    /** 照合用の短い表示コード(秘密ではない — §4-1 (2)) */
    userCode: text("user_code").notNull(),
    /** 承認チケット(生値 256-bit 乱数)の SHA-256(hex)。 */
    ticketHash: text("ticket_hash").notNull(),
    /** フローの期限(unix ms — flowToken / vsig の署名済み期限と同値) */
    expiresAt: integer("expires_at").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  // 日和見削除(期限 + 余裕を過ぎた行の掃除)用
  (t) => [index("clf_expires").on(t.expiresAt)],
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

/**
 * チェーン導出 membership の D1 投影(AUTH_SPEC §11-5 — W2a)。
 *
 * **発見(discovery)専用の候補索引**であり、いかなる認可判定にも使わない
 * (プロジェクトアクセスの真実源はメンバーシップチェーン — CRYPTO_SPEC §6.4 の
 * 「2 つの真実源の禁止」。一覧応答は読取時に各プロジェクト DO の membership
 * 確認を通過した行のみで、stale 行は読取時に削除されて収束する)。role・状態
 * 列を意図的に持たない: role は読取時確認が返す現在値を使うため、change_role の
 * 投影追随が構造的に不要(session-42 裁定 BI 第 2 周)。
 *
 * FK を張らない(invitations と同じ理由: 導出キャッシュは参照整合で受理・修復を
 * 阻害しない — §11-3 の部分失敗窓とも干渉させない)。
 */
export const projectMembers = sqliteTable(
  "project_members",
  {
    /** genesis ハッシュ(hex 小文字 64) */
    projectId: text("project_id").notNull(),
    /** 内部 user_id(ULID) */
    userId: text("user_id").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [
    primaryKey({ columns: [t.projectId, t.userId] }),
    // 一覧の候補列挙(user 軸・project_id 昇順のカーソルページング — §11-5)
    index("pm_user_project").on(t.userId, t.projectId),
  ],
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
  /** ワイヤ行識別子(16 バイト乱数 hex — AUDIT_SPEC §5.1 / §7。seq はワイヤに出さない) */
  rowId: text("row_id"),
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

/**
 * `auth.login_failed` の記録窓カウンタ(AUDIT_SPEC §3.1 — deepsec R4/R5)。
 *
 * 監査行ではなく可変のカウンタ状態(§1-4 の append-only は監査テーブルの規律)。
 * 窓内件数を監査ログの走査で求めると、append-only で伸び続けるテーブルを未認証
 * 経路の追記ごとに走査することになり、有界にしたい洪水がコスト増幅器になる。
 *
 * 行の粒度 = バケット(現状 `auth_method`)。発信元識別子は**持たない**
 * (§1-2 の線引き — 発信元単位の別枠計数を採らない理由は §3.1)。
 */
export const loginFailedWindows = sqliteTable("login_failed_windows", {
  /** 計数バケット。現状は auth_method 種別名(github_oauth / cli_handoff) */
  bucket: text("bucket").primaryKey(),
  /** 固定窓の開始(unix ms) */
  windowStart: integer("window_start").notNull(),
  /** この窓で監査行として記録した件数(上限まで) */
  recordedCount: integer("recorded_count").notNull().default(0),
  /** この窓で上限により落とした件数(抑制マーカーの根拠) */
  suppressedCount: integer("suppressed_count").notNull().default(0),
});

/** 認証系イベント(AUDIT_SPEC §3.1)。 */
export const userAuditEvents = sqliteTable("user_audit_events", auditEventColumns, (t) => [
  uniqueIndex("uae_row_id").on(t.rowId),
  index("uae_actor").on(t.actorUserId, t.seq),
  index("uae_target").on(t.targetUserId, t.seq),
  index("uae_event").on(t.event, t.seq),
]);

/** org 系イベント(AUDIT_SPEC §3.2)。 */
export const orgAuditEvents = sqliteTable("org_audit_events", auditEventColumns, (t) => [
  uniqueIndex("oae_row_id").on(t.rowId),
  index("oae_actor").on(t.actorUserId, t.seq),
  index("oae_target").on(t.targetUserId, t.seq),
  index("oae_event").on(t.event, t.seq),
  index("oae_org").on(t.orgId, t.seq),
  // invite.* の project_id スコープ読み取り(AUDIT_SPEC §7 — C1)のページング用
  index("oae_project").on(t.projectId, t.seq),
]);

// ---------------------------------------------------------------------------
// 運用(H3 — docs/notes/hosted-ops.md §6)。監査ログではない**運営限定の可変状態**
// (hosted-design.md §5-5 — 監査と運用ログを混ぜない)。いずれの表もリクエスト
// 由来の識別子のうちプロジェクト ID 以外を持たない(ops_backups の project_id は
// `projects` 表と同じ運営ストア内の参照で、退避オブジェクトのキーには載せない)。
// ---------------------------------------------------------------------------

/**
 * 運用カウンタ(固定窓 — hosted-ops.md §2-A)。metric = `github_token_requests`
 * (GitHub token 請求の自前計数)/ `cli_flow_capacity`(ログインフロー行の作成
 * 上限到達)。窓は 1 時間、行は評価時に 7 日超を削除する(有界)。
 */
export const opsCounters = sqliteTable(
  "ops_counters",
  {
    metric: text("metric").notNull(),
    /** 固定窓の開始(unix ms、1 時間境界) */
    windowStart: integer("window_start").notNull(),
    count: integer("count").notNull().default(0),
  },
  (t) => [primaryKey({ columns: [t.metric, t.windowStart] })],
);

/**
 * DO → R2 退避の記録(hosted-ops.md §4-2)。プロジェクトごと 1 行。do_id_hex は
 * `idFromName(projectId)` の像(一方向)で、R2 のキーと突合するために持つ。
 * storage_level は退避時の census(AUTH_SPEC §12-8 の判定 — admit / warn / reject)。
 */
export const opsBackups = sqliteTable("ops_backups", {
  projectId: text("project_id").primaryKey(),
  doIdHex: text("do_id_hex").notNull(),
  lastAttemptAt: integer("last_attempt_at").notNull(),
  lastSuccessAt: integer("last_success_at"),
  lastObjectKey: text("last_object_key"),
  lastBytes: integer("last_bytes"),
  lastAuditSeq: integer("last_audit_seq"),
  lastChainSeq: integer("last_chain_seq"),
  /** ヘッド申告の最新受理時刻(skip 規則の第三成分 — do-snapshot.ts readWatermarks) */
  lastAttestationMark: integer("last_attestation_mark"),
  storageLevel: text("storage_level"),
  consecutiveFailures: integer("consecutive_failures").notNull().default(0),
  /** 静的な失敗コードのみ(エラーメッセージ本文は書かない) */
  lastFailureCode: text("last_failure_code"),
});

/** 運用の小さな状態 kv(スイープのカーソル・アラート状態 — JSON 文字列)。 */
export const opsState = sqliteTable("ops_state", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
  updatedAt: integer("updated_at").notNull(),
});
