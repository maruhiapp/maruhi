// プロジェクト DO(SQLite)のテーブル定義とマイグレーション機構。
//
// - chain_entries: メンバーシップチェーンの append-only 保存(CRYPTO_SPEC §6.4)
// - environments / variables / variable_versions / dek_wraps: データプレーン
//   (AUTH_SPEC §12)。environments / variables の削除は tombstone(deleted_at)で
//   表現し、ID の再利用を禁止する(§12-1)。暗号文・ラップは即時削除する
// - audit_events: 監査ログ(AUDIT_SPEC §5.1 のスキーマそのまま)。seq は
//   単調・無欠番(採番は audit-store.ts — DO メモリ保持の next seq)
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
 * ワークロードリースの固定窓カウンタ(AUTH_SPEC §14-3 / AUDIT_SPEC §3.5)。
 * `kind` は "issued"(発行の窓)/ "denied"(拒否記録の窓)の 2 行だけ。
 * 窓は「開始時刻 + 件数」のベストエフォート方式(§13-3 の先例と同型)。
 */
const LEASE_WINDOWS_DDL = `CREATE TABLE IF NOT EXISTS lease_windows (
     kind TEXT PRIMARY KEY,
     window_start INTEGER NOT NULL,
     count INTEGER NOT NULL
   )`;

/**
 * ワークロードリースの先着束縛(AUTH_SPEC §14-1。2026-08-15 裁定 —
 * docs/notes/session-24.md)。発行時に「束縛キー → 一時公開鍵」を記録し、
 * 同一キー + 別鍵の再要求を拒否する材料にする。
 *
 * `binding_key_hex` は **JWS signing input(`header.payload`)の SHA-256** で
 * あって、生トークンのハッシュ**ではない**: 生トークンの署名セグメントは署名の
 * 保護外で可鍛(base64url 末尾ビット / ES256 s-malleability)であり、それを
 * キーにすると 1 文字編集で束縛を素通りできる(verifier.ts の
 * signingInputHashHex の doc — 2026-08-15 pullfrog レビュー)。列名を
 * token_hash ではなく binding_key にしているのは、この「何をハッシュするか」の
 * 取り違えを名前の段階で防ぐため。
 *
 * `expires_at` は「時刻検証が当該トークンを受理しうる最終時刻 + 余裕」
 * (policy.ts の LEASE_BINDING_RETENTION_MARGIN_MS)で、行数は発行レート窓
 * (300 回/時)と GC(data-store.ts — 記録時に期限切れを削除)で有界。
 * トークン本体・claim は保存しない(ハッシュと公開鍵のみ — どちらも非機密)。
 */
const LEASE_BINDINGS_DDL = `CREATE TABLE IF NOT EXISTS lease_bindings (
     binding_key_hex TEXT PRIMARY KEY,
     ephemeral_pub_hex TEXT NOT NULL,
     expires_at INTEGER NOT NULL
   )`;

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
// 例外: 本機構導入(step 1)以前にデプロイされた DO は「テーブルあり・version
// 行なし」で version 0 と読まれるため、step 1 に限り IF NOT EXISTS で既存
// テーブルと共存できる形を維持すること。
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
  {
    // 受信者クラス server(AUTH_SPEC §12-6。2026-08-12): dek_wraps に受信者
    // クラス列を追加する。server 行の recipient_user_id 列にはサーバー鍵 FP
    // (hex 小文字 32 文字)が入る(列名は歴史的経緯で user_id のまま。意味は
    // 「受信者クラス内の受信者識別子」)。member の user_id と「実際上形式が
    // 交わらない」ことは型でも合意規則でも保証されない(add_member の対象
    // user_id は自由文字列 — AUTH_SPEC §11-1)ため、主キー
    // (environment_id, epoch, recipient_user_id) のクラス跨ぎ衝突は受理段が
    // 守る: 初回登録はリクエスト内の保存粒度重複検出(dek-wraps.ts の
    // wrapStorageKey = 422)、既存エポックへの追記はクラス無視の保存存在検査
    // (= 409)(セキュリティレビュー 2026-08-14 A-1)
    tables: [],
    apply(sql) {
      sql.exec("ALTER TABLE dek_wraps ADD COLUMN recipient_class TEXT NOT NULL DEFAULT 'member'");
    },
  },
  {
    // ワークロードリースの固定窓カウンタ(AUTH_SPEC §14-3。2026-08-15)。
    // 発行(1 時間 300 回 / プロジェクト)と拒否記録(同 100 行 — AUDIT_SPEC
    // §3.5 の lease_denied の上限)を 1 テーブルの 2 行で持つ。窓の状態は
    // 監査ログ(append-only)には置けない — 上書き更新が必要なため
    tables: ["lease_windows"],
    apply(sql) {
      sql.exec(LEASE_WINDOWS_DDL);
    },
  },
  {
    // ワークロードリースの先着束縛(AUTH_SPEC §14-1。2026-08-15 裁定)。
    // 注: このステップの DDL 列名は同 PR 内で token_hash_hex → binding_key_hex に
    // 修正した(pullfrog レビュー — 生トークンではなく signing input をハッシュ
    // する変更に伴う改名)。末尾追記のみの規則の例外だが、本ステップは未マージ・
    // 未デプロイで適用済みの外部 DO が存在しないため in-place 編集が正しい
    // (rename ステップの追記は誰も持たないテーブルに恒久ノイズを残す)。
    // ローカル wrangler dev で中間コミットを適用済みの場合のみ永続ストレージの
    // 破棄が必要(詳細は docs/notes/session-24.md §9)
    tables: ["lease_bindings"],
    apply(sql) {
      sql.exec(LEASE_BINDINGS_DDL);
    },
  },

  {
    // 監査行のワイヤ識別子 row_id(AUDIT_SPEC §5.1 / §7 — 2026-08-16 C1 裁定)。
    // 16 バイト乱数 hex。無欠番採番 seq をワイヤに出すと admin 未満が可視行の
    // seq 差分からクラス 2 の件数・時刻窓を推論できるため、行識別子・カーソルは
    // この乱数を使う(seq は admin 可視の応答にのみ載る)。既存行は SQLite の
    // randomblob で backfill する(randomblob は行ごとに評価される)。UNIQUE
    // 索引は NULL を重複可とするため作成順は backfill の前後どちらでもよいが、
    // 追記経路(audit-store.ts)は常に値を生成するので NULL は残らない
    tables: [],
    apply(sql) {
      sql.exec("ALTER TABLE audit_events ADD COLUMN row_id TEXT");
      sql.exec("UPDATE audit_events SET row_id = lower(hex(randomblob(16))) WHERE row_id IS NULL");
      sql.exec("CREATE UNIQUE INDEX IF NOT EXISTS ae_row_id ON audit_events (row_id)");
    },
  },

  {
    // 環境マニフェスト(CRYPTO_SPEC §4.3 / AUTH_SPEC §12-5。2026-08-18 PR-M1)。
    // **保持は環境ごとに最新 1 通のみ**(PRIMARY KEY = environment_id の upsert —
    // §12-5: prev 検査・配布・チェックポイント受理のすべてが最新しか参照せず、
    // 行が蓄積しないため行数上限も置かない — §12-8)。signed_bytes_hash_hex は
    // サーバー再計算(prev 検査 = 次の manifestVersion の prev 照合材料。配布
    // しない)。issuer は受理時点のチェーン導出メンバー(user_id + 鍵 FP)。
    // 環境削除のカスケード対象(§12-4 — retireEnvironment が行を消す)。
    // マニフェスト導入前に作成された環境は行なしで始まり、最初のメタ操作 /
    // rotate が manifest_version 1 を確立する(移行手順 — session-27 §14 PR-M1)
    tables: ["environment_manifests"],
    apply(sql) {
      sql.exec(
        `CREATE TABLE IF NOT EXISTS environment_manifests (
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
      );
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
