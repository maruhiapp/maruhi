// プロジェクト DO(SQLite)のテーブル定義とマイグレーション機構。
//
// - chain_entries: メンバーシップチェーンの append-only 保存(CRYPTO_SPEC §6.4)
// - environments / variables / variable_versions / dek_wraps: データプレーン
//   (AUTH_SPEC §12)。environments / variables の削除は tombstone(deleted_at)で
//   表現し、ID の再利用を禁止する(§12-1)。暗号文・ラップは即時削除する
// - audit_events: 監査ログ(AUDIT_SPEC §5.1 のスキーマそのまま)。seq は
//   INSERT ... SELECT MAX(seq)+1 による単調・無欠番の採番
// - schema_meta: 適用済みマイグレーションの version(1 行)。maruhi はセルフ
//   ホスト配布物のため、公開後は既存 DO のスキーマ変更を順序付きステップとして
//   PROJECT_DO_MIGRATIONS に追記する(IF NOT EXISTS の DDL 再適用では既存
//   テーブルに列を追加できない)
//
// Drizzle(drizzle-orm/durable-sqlite)は今回も見送り(セッション 05 の判断を
// 継続。裁定は docs/notes/session-07.md): クエリは単純なキー参照のみで、依存を
// 増やさず素の SQL を Store サービス境界内に閉じる。D1 側(db.package)は
// 引き続き Drizzle。

const PROJECT_DO_DDL = [
  `CREATE TABLE IF NOT EXISTS chain_entries (
     seq INTEGER PRIMARY KEY,
     entry_json TEXT NOT NULL,
     entry_hash_hex TEXT NOT NULL,
     canonical_bytes INTEGER NOT NULL
   )`,
  // name / latest_meta_version は最新ステートメント(*_meta_statements)の
  // 導出キャッシュ(名前一意性クエリと metaVersion CAS 用)。真実源は
  // ステートメント行で、書き込みフェーズで同期更新する(2026-08-04 PR-3)
  `CREATE TABLE IF NOT EXISTS environments (
     environment_id TEXT PRIMARY KEY,
     name TEXT NOT NULL,
     latest_meta_version INTEGER NOT NULL,
     created_at INTEGER NOT NULL,
     deleted_at INTEGER
   )`,
  `CREATE TABLE IF NOT EXISTS variables (
     environment_id TEXT NOT NULL,
     variable_id TEXT NOT NULL,
     name TEXT NOT NULL,
     latest_meta_version INTEGER NOT NULL,
     latest_version INTEGER NOT NULL,
     created_at INTEGER NOT NULL,
     deleted_at INTEGER,
     PRIMARY KEY (environment_id, variable_id)
   )`,
  // メタデータステートメント(CRYPTO_SPEC §4.2 / AUTH_SPEC §12-5。2026-08-04
  // PR-3): metaVersion ごとに signed_bytes ハッシュ(サーバー再計算 — prev
  // 検査・409 再試行の検証材料。配布しない)・署名・author(user_id + 受理
  // 時点のチェーン導出鍵 FP)・name・status・prev・宣言ヘッドを保存する。
  // 削除ステートメント(status deleted)も保存・配布し続ける(§12-4/-5 —
  // 削除の否認・無断復活の検出材料)
  `CREATE TABLE IF NOT EXISTS variable_meta_statements (
     environment_id TEXT NOT NULL,
     variable_id TEXT NOT NULL,
     meta_version INTEGER NOT NULL,
     suite TEXT NOT NULL,
     name TEXT NOT NULL,
     status TEXT NOT NULL,
     prev_meta_sig_hash_hex TEXT NOT NULL,
     chain_head_hash_hex TEXT NOT NULL,
     chain_head_seq INTEGER NOT NULL,
     signature_hex TEXT NOT NULL,
     signed_bytes_hash_hex TEXT NOT NULL,
     author_user_id TEXT NOT NULL,
     author_key_fingerprint TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     PRIMARY KEY (environment_id, variable_id, meta_version)
   )`,
  `CREATE TABLE IF NOT EXISTS environment_meta_statements (
     environment_id TEXT NOT NULL,
     meta_version INTEGER NOT NULL,
     suite TEXT NOT NULL,
     name TEXT NOT NULL,
     status TEXT NOT NULL,
     prev_meta_sig_hash_hex TEXT NOT NULL,
     chain_head_hash_hex TEXT NOT NULL,
     chain_head_seq INTEGER NOT NULL,
     signature_hex TEXT NOT NULL,
     signed_bytes_hash_hex TEXT NOT NULL,
     author_user_id TEXT NOT NULL,
     author_key_fingerprint TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     PRIMARY KEY (environment_id, meta_version)
   )`,
  // suite 列: すべての永続データ構造はスイート識別子を持つ(CRYPTO_SPEC §2
  // 設計原則 4 / AUTH_SPEC §12-2。将来のアルゴリズム移行時に行単位で判別する)
  //
  // 値の書き込み署名列(CRYPTO_SPEC §4.1 / AUTH_SPEC §12-5。2026-08-04 PR-2):
  // prev_value_sig_hash_hex(version 1 は空文字列)/ 宣言ヘッド(hash + seq)/
  // 署名 / サーバー再計算の signed_bytes ハッシュ(prev 検査と 409 再試行の
  // 検証材料 — 配布はしない)/ 受理時点の writer(user_id + チェーン導出鍵 FP)。
  // signed bytes 本体・公開鍵は保存しない(座標とチェーンから再構成できる)
  `CREATE TABLE IF NOT EXISTS variable_versions (
     environment_id TEXT NOT NULL,
     variable_id TEXT NOT NULL,
     version INTEGER NOT NULL,
     suite TEXT NOT NULL,
     epoch INTEGER NOT NULL,
     nonce_hex TEXT NOT NULL,
     ciphertext_hex TEXT NOT NULL,
     ciphertext_bytes INTEGER NOT NULL,
     prev_value_sig_hash_hex TEXT NOT NULL,
     chain_head_hash_hex TEXT NOT NULL,
     chain_head_seq INTEGER NOT NULL,
     signature_hex TEXT NOT NULL,
     signed_bytes_hash_hex TEXT NOT NULL,
     writer_user_id TEXT NOT NULL,
     writer_key_fingerprint TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     PRIMARY KEY (environment_id, variable_id, version)
   )`,
  // signature_hex / signer_*: DEK ラップの登録署名(CRYPTO_SPEC §5.1)と署名者。
  // 配布時のクライアント検証(署名者のチェーン履歴上の鍵と突合)を可能にする
  `CREATE TABLE IF NOT EXISTS dek_wraps (
     environment_id TEXT NOT NULL,
     epoch INTEGER NOT NULL,
     recipient_user_id TEXT NOT NULL,
     suite TEXT NOT NULL,
     recipient_enc_pub_hex TEXT NOT NULL,
     enc_hex TEXT NOT NULL,
     ciphertext_hex TEXT NOT NULL,
     signature_hex TEXT NOT NULL,
     signer_user_id TEXT NOT NULL,
     signer_key_fingerprint TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     PRIMARY KEY (environment_id, epoch, recipient_user_id)
   )`,
  // AUDIT_SPEC §5.1 のスキーマ(列名・索引とも仕様どおり)
  `CREATE TABLE IF NOT EXISTS audit_events (
     seq INTEGER PRIMARY KEY,
     server_ts INTEGER NOT NULL,
     client_ts INTEGER,
     event TEXT NOT NULL,
     actor_type TEXT NOT NULL,
     actor_user_id TEXT,
     actor_key_fingerprint TEXT,
     actor_api_token_id TEXT,
     target_user_id TEXT,
     target_key_fingerprint TEXT,
     environment_id TEXT,
     variable_id TEXT,
     epoch INTEGER,
     version INTEGER,
     chain_seq INTEGER,
     payload TEXT
   )`,
  `CREATE INDEX IF NOT EXISTS ae_var ON audit_events (variable_id, environment_id, seq)`,
  `CREATE INDEX IF NOT EXISTS ae_actor ON audit_events (actor_user_id, seq)`,
  `CREATE INDEX IF NOT EXISTS ae_target ON audit_events (target_user_id, seq)`,
  `CREATE INDEX IF NOT EXISTS ae_target_fp ON audit_events (target_key_fingerprint, seq)`,
  `CREATE INDEX IF NOT EXISTS ae_actor_fp ON audit_events (actor_key_fingerprint, seq)`,
  `CREATE INDEX IF NOT EXISTS ae_event ON audit_events (event, seq)`,
];

/**
 * A single ordered migration step for the project DO's SQLite schema.
 *
 * `tables` lists the tables this step introduces — the test reset helper
 * derives its DELETE targets from these, so declare every new table here.
 */
export interface ProjectDoMigration {
  readonly tables: readonly string[];
  readonly apply: (sql: SqlStorage) => void;
}

// 順序付きマイグレーションステップ。**末尾への追記のみ可**(適用済みステップの
// 編集・並べ替え・削除は、外部にデプロイ済みの DO と不整合になるため禁止)。
// 各ステップは「前ステップまで適用済みの DB」を前提に書いてよい(ALTER TABLE 等)。
// 適用は 1 ステップずつ version を進めるため、途中で失敗しても次回コンストラクタ
// 実行時に失敗したステップから再開される(ステップ内は再実行安全に書くこと —
// step 1 は IF NOT EXISTS でこれを満たす)。
export const PROJECT_DO_MIGRATIONS: readonly ProjectDoMigration[] = [
  {
    tables: [
      "chain_entries",
      "environments",
      "variables",
      "variable_meta_statements",
      "environment_meta_statements",
      "variable_versions",
      "dek_wraps",
      "audit_events",
    ],
    apply(sql) {
      for (const statement of PROJECT_DO_DDL) {
        sql.exec(statement);
      }
    },
  },
];

/**
 * All project-DO table names, derived from the migration steps. The test
 * reset helper (test/support/project-do.ts) uses this as its DELETE list.
 * `schema_meta` is intentionally excluded: the applied-version row must
 * survive test resets so migrations are not re-applied to a populated schema.
 */
export const PROJECT_DO_TABLES: readonly string[] = PROJECT_DO_MIGRATIONS.flatMap(
  (migration) => migration.tables,
);

// version は「適用済みステップ数」(0 = 未適用、PROJECT_DO_MIGRATIONS.length = 最新)
const SCHEMA_META_DDL = `CREATE TABLE IF NOT EXISTS schema_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL
)`;

/** Read the number of applied migration steps (0 for a fresh database). */
export function readProjectDoSchemaVersion(sql: SqlStorage): number {
  sql.exec(SCHEMA_META_DDL);
  const rows = sql.exec("SELECT version FROM schema_meta WHERE id = 1").toArray();
  const row = rows[0];
  return row === undefined ? 0 : Number(row.version);
}

/**
 * Apply the not-yet-applied migration steps in order, advancing the stored
 * version after each step. Already-applied steps are skipped, so calling this
 * on an up-to-date database is a no-op.
 */
export function applyProjectDoMigrations(
  sql: SqlStorage,
  migrations: readonly ProjectDoMigration[],
): void {
  const current = readProjectDoSchemaVersion(sql);
  for (const [index, migration] of migrations.entries()) {
    if (index < current) {
      continue;
    }
    migration.apply(sql);
    sql.exec(
      `INSERT INTO schema_meta (id, version) VALUES (1, ?)
       ON CONFLICT (id) DO UPDATE SET version = excluded.version`,
      index + 1,
    );
  }
}

/** DO コンストラクタから呼ぶ(冪等)。未適用ステップだけを順に適用する。 */
export function ensureProjectDoTables(sql: SqlStorage): void {
  applyProjectDoMigrations(sql, PROJECT_DO_MIGRATIONS);
}
