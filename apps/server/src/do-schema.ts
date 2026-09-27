// プロジェクト DO(SQLite)のテーブル定義とマイグレーション機構。
//
// - chain_entries: メンバーシップチェーンの append-only 保存(CRYPTO_SPEC §6.4)
// - environments / variables / variable_versions / dek_wraps: データプレーン
//   (AUTH_SPEC §12)。environments / variables の削除は tombstone(deleted_at)で
//   表現し、ID の再利用を禁止する(§12-1)。暗号文・ラップは即時削除する
// - audit_events: 監査ログ(AUDIT_SPEC §5.1 のスキーマそのまま)。seq は
//   単調・無欠番(採番は audit-store.ts — DO メモリ保持の next seq)
// - schema_meta: 適用済みマイグレーションの version(1 行)。以後の既存 DO の
//   スキーマ変更は順序付きステップとして PROJECT_DO_MIGRATIONS に追記する
//   (CREATE の再適用では既存テーブルに列を追加できない)
//
// Drizzle(drizzle-orm/durable-sqlite)は今回も見送り(セッション 05 の判断を
// 継続。裁定は docs/notes/session-07.md): クエリは単純なキー参照のみで、依存を
// 増やさず素の SQL を Store サービス境界内に閉じる。D1 側(db.package)は
// 引き続き Drizzle。

// 現行スキーマ(2026-09-26 に全ステップを 1 本へ畳んだ — 設計録 dk-design.md §22-4。
// 畳む前の DO は運営のデプロイごと作り直した)。
const PROJECT_DO_DDL = [
  `CREATE TABLE chain_entries (
     seq INTEGER PRIMARY KEY,
     entry_json TEXT NOT NULL,
     entry_hash_hex TEXT NOT NULL,
     canonical_bytes INTEGER NOT NULL
   )`,
  // name / latest_meta_version は最新ステートメント(*_meta_statements)の
  // 導出キャッシュ(名前一意性クエリと metaVersion CAS 用)。真実源は
  // ステートメント行で、書き込みフェーズで同期更新する
  `CREATE TABLE environments (
     environment_id TEXT PRIMARY KEY,
     name TEXT NOT NULL,
     latest_meta_version INTEGER NOT NULL,
     created_at INTEGER NOT NULL,
     deleted_at INTEGER
   )`,
  `CREATE TABLE variables (
     environment_id TEXT NOT NULL,
     variable_id TEXT NOT NULL,
     name TEXT NOT NULL,
     latest_meta_version INTEGER NOT NULL,
     latest_version INTEGER NOT NULL,
     created_at INTEGER NOT NULL,
     deleted_at INTEGER,
     PRIMARY KEY (environment_id, variable_id)
   )`,
  // メタデータステートメント(CRYPTO_SPEC §4.2 / AUTH_SPEC §12-5):
  // metaVersion ごとに signed_bytes ハッシュ(サーバー再計算 — prev
  // 検査・409 再試行の検証材料。配布しない)・署名・author(user_id + 受理
  // 時点のチェーン導出鍵 FP)・name・status・prev・宣言ヘッドを保存する。
  // 削除ステートメント(status deleted)も保存・配布し続ける(§12-4/-5 —
  // 削除の否認・無断復活の検出材料)。
  // layout_version: ワイヤレイアウト(次ステートメントのレイアウト単調性検査の
  // アンカー)。var_type / required / description: v2 のスキーマ欄(v1 行は NULL。
  // required は署名対象の "true" / "false" 文字列表現のまま保存する)
  `CREATE TABLE variable_meta_statements (
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
     layout_version INTEGER NOT NULL DEFAULT 1,
     var_type TEXT,
     required TEXT,
     description TEXT,
     PRIMARY KEY (environment_id, variable_id, meta_version)
   )`,
  `CREATE TABLE environment_meta_statements (
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
  // 値の書き込み署名列(CRYPTO_SPEC §4.1 / AUTH_SPEC §12-5):
  // prev_value_sig_hash_hex(version 1 は空文字列)/ 宣言ヘッド(hash + seq)/
  // 署名 / サーバー再計算の signed_bytes ハッシュ(prev 検査と 409 再試行の
  // 検証材料 — 配布はしない)/ 受理時点の writer(user_id + チェーン導出鍵 FP)。
  // signed bytes 本体・公開鍵は保存しない(座標とチェーンから再構成できる)
  `CREATE TABLE variable_versions (
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
  // DEK ラップ(AUTH_SPEC §12-6)。スロット = (環境, エポック, 受信者, 受信者の端末
  // enc 公開鍵) — 同じ人の端末ごとに 1 スロット(R(E) の端末展開 — CRYPTO_SPEC §6.2)。
  // signature_hex / signer_*: 登録署名(CRYPTO_SPEC §5.1)と署名者。
  // recipient_class = server の行の recipient_user_id にはサーバー鍵 FP(hex 小文字
  // 32 文字)が入る(列名は歴史的経緯で user_id のまま)。member の user_id との
  // クラス跨ぎ衝突は受理段が守る(dek-wraps.ts の wrapStorageKey = 422、既存エポック
  // への追記はクラス無視の保存存在検査 = 409 — A-1)
  `CREATE TABLE dek_wraps (
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
     recipient_class TEXT NOT NULL DEFAULT 'member',
     PRIMARY KEY (environment_id, epoch, recipient_user_id, recipient_enc_pub_hex)
   )`,
  // 受信者索引: §12-6 の再追加受理時掃除(data-store.ts の deleteStaleMemberWraps)は
  // `recipient_user_id = ? AND recipient_class = 'member'` で引く(主キーの第 3 成分は
  // 前方一致を使えない)
  `CREATE INDEX dw_recipient ON dek_wraps (recipient_user_id, recipient_class)`,
  // AUDIT_SPEC §5.1 のスキーマ。row_id はワイヤ行識別子(16 バイト乱数 hex —
  // §7 C1 裁定: 無欠番の seq をワイヤに出さない)で、追記経路(audit-store.ts)が
  // 常に生成する
  `CREATE TABLE audit_events (
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
     payload TEXT,
     row_id TEXT NOT NULL
   )`,
  `CREATE INDEX ae_var ON audit_events (variable_id, environment_id, seq)`,
  `CREATE INDEX ae_actor ON audit_events (actor_user_id, seq)`,
  `CREATE INDEX ae_event ON audit_events (event, seq)`,
  `CREATE UNIQUE INDEX ae_row_id ON audit_events (row_id)`,
  // 対象・鍵 FP 索引は部分索引(監査ログの成長密度対策 ①): 支配的な行種 `var.read`
  // で常に NULL の列なので、NULL 行を索引に入れない。読み手はすべて等値条件
  // (等値は IS NOT NULL を含意)なので選択される(test/audit-index.test.ts が
  // EXPLAIN QUERY PLAN で固定)
  `CREATE INDEX ae_target ON audit_events (target_user_id, seq) WHERE target_user_id IS NOT NULL`,
  `CREATE INDEX ae_target_fp ON audit_events (target_key_fingerprint, seq) WHERE target_key_fingerprint IS NOT NULL`,
  `CREATE INDEX ae_actor_fp ON audit_events (actor_key_fingerprint, seq) WHERE actor_key_fingerprint IS NOT NULL`,
  // ワークロードリースの固定窓カウンタ(AUTH_SPEC §14-3 / AUDIT_SPEC §3.5)。
  // `kind` は "issued"(発行の窓)/ "denied"(拒否記録の窓)の 2 行だけ。窓は
  // 「開始時刻 + 件数」のベストエフォート方式(§13-3 の先例と同型)。窓の状態は
  // 上書き更新が要るので監査ログ(append-only)には置けない
  `CREATE TABLE lease_windows (
     kind TEXT PRIMARY KEY,
     window_start INTEGER NOT NULL,
     count INTEGER NOT NULL
   )`,
  // ワークロードリースの先着束縛(AUTH_SPEC §14-1 の裁定 — docs/notes/session-24.md)。
  // 発行時に「束縛キー → 一時公開鍵」を記録し、同一キー + 別鍵の再要求を拒否する。
  // `binding_key_hex` は **JWS signing input(`header.payload`)の SHA-256** で
  // あって、生トークンのハッシュ**ではない**(生トークンの署名セグメントは可鍛 —
  // verifier.ts の signingInputHashHex の doc)。`expires_at` は「時刻検証が当該
  // トークンを受理しうる最終時刻 + 余裕」(policy.ts の LEASE_BINDING_RETENTION_MARGIN_MS)で、
  // 行数は発行レート窓と GC(data-store.ts — 記録時に期限切れを削除)で有界。
  // トークン本体・claim は保存しない(ハッシュと公開鍵のみ — どちらも非機密)
  `CREATE TABLE lease_bindings (
     binding_key_hex TEXT PRIMARY KEY,
     ephemeral_pub_hex TEXT NOT NULL,
     expires_at INTEGER NOT NULL
   )`,
  // 環境マニフェスト(CRYPTO_SPEC §4.3 / AUTH_SPEC §12-5)。**保持は環境ごとに最新
  // 1 通のみ**(PRIMARY KEY = environment_id の upsert)。signed_bytes_hash_hex は
  // サーバー再計算(次の manifestVersion の prev 照合材料。配布しない)。issuer は
  // 受理時点のチェーン導出メンバー(user_id + 鍵 FP)。環境削除のカスケード対象
  // (§12-4 — retireEnvironment が行を消す)
  `CREATE TABLE environment_manifests (
     environment_id TEXT PRIMARY KEY,
     manifest_version INTEGER NOT NULL,
     suite TEXT NOT NULL,
     epoch INTEGER NOT NULL,
     variables_digest_hex TEXT NOT NULL,
     env_meta_version INTEGER NOT NULL,
     env_meta_sig_hash_hex TEXT NOT NULL,
     prev_manifest_sig_hash_hex TEXT NOT NULL,
     chain_head_hash_hex TEXT NOT NULL,
     chain_head_seq INTEGER NOT NULL,
     signature_hex TEXT NOT NULL,
     signed_bytes_hash_hex TEXT NOT NULL,
     issuer_user_id TEXT NOT NULL,
     issuer_key_fingerprint TEXT NOT NULL,
     created_at INTEGER NOT NULL
   )`,
  // チェックポイントの値スナップショット(CRYPTO_SPEC §6.4 / AUTH_SPEC §16-2)。
  // 環境ごとの**最新包含 checkpoint** のタプル(upsert)と、その時点の値スナップ
  // ショット列挙(環境単位の全置換)。payload に含まれない環境の既存スナップショットは
  // 変更しない(§6.4)。環境削除のカスケード対象(retireEnvironment が両表を消す)
  `CREATE TABLE environment_checkpoints (
     environment_id TEXT PRIMARY KEY,
     chain_seq INTEGER NOT NULL,
     entry_hash_hex TEXT NOT NULL,
     epoch INTEGER NOT NULL,
     manifest_version INTEGER NOT NULL,
     manifest_sig_hash_hex TEXT NOT NULL,
     values_digest_hex TEXT NOT NULL,
     updated_at INTEGER NOT NULL
   )`,
  `CREATE TABLE checkpoint_snapshot_values (
     environment_id TEXT NOT NULL,
     variable_id TEXT NOT NULL,
     version INTEGER NOT NULL,
     value_sig_hash_hex TEXT NOT NULL,
     PRIMARY KEY (environment_id, variable_id)
   )`,
  // 監査ヘッド累積ハッシュの計算列(AUDIT_SPEC §5.1)。audit_events の決定論的な
  // 導出値(append-only の行が真実源)で、materialize は遅延拡張(audit-store.ts の
  // ensureHeadCurrent — 監査ヘッド読み取り・checkpoint 受理の前に MAX(seq) まで伸ばす)。
  // 接頭辞連続(seq 1..k の完全な前置)を不変条件とし、書き直し・削除をしない。
  // head_hash_hex の索引は checkpoint 受理の所属・位置検査(CRYPTO_SPEC §6.4)用
  `CREATE TABLE audit_head_hashes (
     seq INTEGER PRIMARY KEY,
     head_hash_hex TEXT NOT NULL
   )`,
  `CREATE INDEX ahh_hash ON audit_head_hashes (head_hash_hex)`,
  // ヘッド申告(CRYPTO_SPEC §6.6 / AUTH_SPEC §16-1)。**端末ごとに最新 1 行**
  // (PK = (attester_user_id, attester_key_fingerprint) の upsert — チェーンに載せない
  // 可変データ)。端末は独立に同期するため端末を跨いだ seq 単調性は課さない。
  // accepted_at は保存するが**配布しない**。`remove_member` 受理時に行を削除する
  // (chain-accept.ts の受理副作用)。attestation_windows はメンバー単位の固定窓
  // カウンタ(1 時間 60 回 — §16-1。remove 時に申告行と一緒に削除)
  `CREATE TABLE head_attestations (
     attester_user_id TEXT NOT NULL,
     attester_key_fingerprint TEXT NOT NULL,
     suite TEXT NOT NULL,
     chain_head_seq INTEGER NOT NULL,
     chain_head_hash_hex TEXT NOT NULL,
     signature_hex TEXT NOT NULL,
     accepted_at INTEGER NOT NULL,
     PRIMARY KEY (attester_user_id, attester_key_fingerprint)
   )`,
  `CREATE TABLE attestation_windows (
     attester_user_id TEXT PRIMARY KEY,
     window_start INTEGER NOT NULL,
     count INTEGER NOT NULL
   )`,
  // プロジェクト設定(1 行)。行なし = schemaPolicy 'disabled'(既定 — AUTH_SPEC
  // §12-11)。監査は project.schema_policy_changed(AUDIT_SPEC §3.3)
  `CREATE TABLE project_settings (
     id INTEGER PRIMARY KEY CHECK (id = 1),
     schema_policy TEXT NOT NULL
   )`,
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
// 各ステップは「本体 + version 進め」を 1 トランザクション(transactionSync)で
// 適用するため、途中で例外が起きてもステップ全体がロールバックされ、次回
// コンストラクタ実行時に失敗したステップの先頭から再実行される(部分適用の
// DDL は残らないので、ステップ自体を冪等に書く必要はない)。
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
      "lease_windows",
      "lease_bindings",
      "environment_manifests",
      "environment_checkpoints",
      "checkpoint_snapshot_values",
      "audit_head_hashes",
      "head_attestations",
      "attestation_windows",
      "project_settings",
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
  if (row === undefined) {
    return 0;
  }
  const version = Number(row.version);
  if (!Number.isInteger(version) || version < 0) {
    // 破損値を 0 扱いにすると全ステップが再実行されてしまう(step 2 以降は
    // 冪等でない)ため、明示的に失敗させて人間の調査へ回す
    throw new Error(`project DO schema_meta.version is corrupt: ${String(row.version)}`);
  }
  return version;
}

/**
 * Apply the not-yet-applied migration steps in order. Each step and its
 * version bump run in one synchronous transaction, so a failing step rolls
 * back entirely and is retried from its start on the next call. Applied steps
 * are skipped, so calling this on an up-to-date database is a no-op.
 *
 * Refuses to run when the stored version is newer than this deployment's step
 * count: after a rollback deploy the old code cannot know the newer schema's
 * shape, and continuing silently risks writing through stale assumptions.
 */
export function applyProjectDoMigrations(
  storage: DurableObjectStorage,
  migrations: readonly ProjectDoMigration[],
): void {
  const sql = storage.sql;
  const current = readProjectDoSchemaVersion(sql);
  if (current > migrations.length) {
    // セルフホスト配布物では旧バージョンへのロールバックデプロイが現実に起こる。
    // 新スキーマの DB 上で旧コードを黙って動かさない(§運用: 前進のみ)。
    // 影響範囲に注意: この throw は DO コンストラクタで起きるため、ロールバック中は
    // 適用済みプロジェクトの DO が一切開けなくなる(整合性 > 可用性の意図的選択。
    // 復旧は前方デプロイ)。ステップを追加する際はこの爆風半径を前提に置くこと
    throw new Error(
      `project DO schema version ${current} is newer than this deployment supports ` +
        `(max ${migrations.length}); refusing to run older code on a newer schema`,
    );
  }
  for (const [index, migration] of migrations.entries()) {
    if (index < current) {
      continue;
    }
    storage.transactionSync(() => {
      migration.apply(sql);
      sql.exec(
        `INSERT INTO schema_meta (id, version) VALUES (1, ?)
         ON CONFLICT (id) DO UPDATE SET version = excluded.version`,
        index + 1,
      );
    });
  }
}

/** DO コンストラクタから呼ぶ(冪等)。未適用ステップだけを順に適用する。 */
export function ensureProjectDoTables(storage: DurableObjectStorage): void {
  applyProjectDoMigrations(storage, PROJECT_DO_MIGRATIONS);
}
