// 識別子の表示形(部品ファイルの外に置く — React Doctor の only-export-components)。

/** 識別子の短縮形(先頭・末尾 6 桁 — 見出し・サイドバーの子項目・スコープの chip 用。全文は HexText 等で並記する)。 */
export function shortId(id: string): string {
  return `${id.slice(0, 6)}…${id.slice(-6)}`;
}

// プロジェクト ID の形式(genesis エントリの SHA-256 hex — CRYPTO_SPEC §6.4)。
// @maruhi/core の isProjectId と同形だが、実行コードを bundle に持ち込まない
// 方針(裁定 BR)のためリテラルで持つ。判定はここ 1 か所(入力・ルート・サイドバーで共用)
const PROJECT_ID_PATTERN = /^[0-9a-f]{64}$/;

/** 64 桁の小文字 hex か(サーバーに問い合わせる前のクライアント側の形式判定)。 */
export function isProjectId(value: string): boolean {
  return PROJECT_ID_PATTERN.test(value);
}
