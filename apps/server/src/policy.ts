// CRYPTO_SPEC §6.4 のサーバー受理ポリシー(2026-08-02 追加)。
//
// これらは「チェーン有効性の合意規則」ではない: §6.1 のフィールド上限(合意規則)が
// 仕様適合エントリの正規化サイズを最大約 516 KiB に束縛するため、この受理ポリシーが
// 仕様適合エントリを拒否することはない(チェーン分裂を生まない)。値の引き上げは
// 過去チェーンの有効性に影響しない。

/** §6.4: 1 エントリの正規化バイト列(entry_bytes)の受理上限。 */
export const MAX_ENTRY_CANONICAL_BYTES = 1 * 1024 * 1024;

/** §6.4: チェーン全体のエントリ数の受理上限。 */
export const MAX_CHAIN_ENTRIES = 10_000;

/** §6.4: チェーン全体の正規化バイト列の累積受理上限。 */
export const MAX_CHAIN_TOTAL_CANONICAL_BYTES = 32 * 1024 * 1024;

/**
 * HTTP 境界の生ボディ上限(実装詳細。仕様は正規化バイト列基準のみを規定)。
 * JSON エスケープによる膨張(最悪 6 倍近く)を見込んで正規化上限より大きく取る。
 * 超過は JSON パースに入る前に素の 413 で拒否する(メモリ DoS の前段防御)。
 */
export const MAX_REQUEST_BODY_BYTES = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// データプレーンの受理ポリシー(AUTH_SPEC §12-8。合意規則ではない — セルフ
// ホストでの引き上げは自由)。表示名の 256 文字上限は api-schema の Schema が
// 強制する(値と違い専用の検証層がないため)。
// ---------------------------------------------------------------------------

/** §12-8: 値の暗号文(ct || tag)の受理上限。 */
export const MAX_VALUE_CIPHERTEXT_BYTES = 64 * 1024;

/** §12-8: プロジェクトあたりのアクティブ環境数。 */
export const MAX_ACTIVE_ENVIRONMENTS = 100;

/** §12-8: プロジェクトあたりの環境行数(tombstone 込み。ID 焼却の資源保護)。 */
export const MAX_ENVIRONMENT_ROWS = 1_000;

/** §12-8: 環境あたりのアクティブ変数数。 */
export const MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT = 1_000;

/** §12-8: 環境あたりの変数行数(tombstone 込み)。 */
export const MAX_VARIABLE_ROWS_PER_ENVIRONMENT = 5_000;

/** §12-8: 変数あたりのバージョン数。 */
export const MAX_VERSIONS_PER_VARIABLE = 1_000;

/** §12-8: プロジェクトの累積暗号文バイト(現在保存中の量。削除で解放される)。 */
export const MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES = 1024 * 1024 * 1024;

/**
 * §12-8: 1 リクエストの DEK ラップ数。チェーン受理ポリシー(10,000 エントリ)が
 * 束縛するメンバー数上限以上に取り、初回登録の完全一致要件(§12-6)と両立させる。
 */
export const MAX_DEK_WRAPS_PER_REQUEST = 10_000;
