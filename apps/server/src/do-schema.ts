// プロジェクト DO(SQLite)のテーブル定義。
//
// - chain_entries: メンバーシップチェーンの append-only 保存(CRYPTO_SPEC §6.4)
// - environments / variables / variable_versions / dek_wraps: データプレーン
//   (AUTH_SPEC §12)。environments / variables の削除は tombstone(deleted_at)で
//   表現し、ID の再利用を禁止する(§12-1)。暗号文・ラップは即時削除する
// - audit_events: 監査ログ(AUDIT_SPEC §5.1 のスキーマそのまま)。seq は
//   INSERT ... SELECT MAX(seq)+1 による単調・無欠番の採番
//
// Drizzle(drizzle-orm/durable-sqlite)は今回も見送り(セッション 05 の判断を
// 継続。裁定は docs/notes/session-07.md): クエリは単純なキー参照のみで、DO の
// マイグレーションはコンストラクタでの DDL 適用と等価になるため、依存を増やさず
// 素の SQL を Store サービス境界内に閉じる。D1 側(db.package)は引き続き Drizzle。

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
  // 削除の否認・無断復活の検出材料)。すべて NOT NULL — backfill・nullable
  // 遷移は作らない(公開前・適用済み環境なしの DDL 直接変更。古い
  // .wrangler/state は破棄が必要 — session-15.md)
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
  // signed bytes 本体・公開鍵は保存しない(座標とチェーンから再構成できる)。
  // すべて NOT NULL — backfill・nullable 遷移は作らない(公開前・適用済み環境
  // なしの DDL 直接変更。古い .wrangler/state は破棄が必要 — session-14.md)
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
  // 配布時のクライアント検証(署名者のチェーン履歴上の鍵と突合)を可能にする。
  // DDL 直接変更(公開前・適用済み環境なし。ローカル dev の .wrangler/state は
  // このブランチで動かす前に破棄が必要 — session-08.md §3 と同じ注意)
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
 * プロジェクト DO の全テーブル名。テストの beforeEach リセット(名指しの DELETE
 * 一覧)がここを参照する — テーブルを追加したら必ずこの配列にも追加すること。
 */
export const PROJECT_DO_TABLES = [
  "chain_entries",
  "environments",
  "variables",
  "variable_meta_statements",
  "environment_meta_statements",
  "variable_versions",
  "dek_wraps",
  "audit_events",
] as const;

/** DO コンストラクタから呼ぶ(冪等)。全テーブル・索引を作成する。 */
export function ensureProjectDoTables(sql: SqlStorage): void {
  for (const statement of PROJECT_DO_DDL) {
    sql.exec(statement);
  }
}
