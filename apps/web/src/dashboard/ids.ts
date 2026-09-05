// 識別子の表示形(部品ファイルの外に置く — React Doctor の only-export-components)。

/** 識別子の短縮形(先頭・末尾 6 桁 — 見出し・サイドバーの子項目・スコープの chip 用。全文は HexText 等で並記する)。 */
export function shortId(id: string): string {
  return `${id.slice(0, 6)}…${id.slice(-6)}`;
}
