// 端末出力のサニタイズ。
//
// 変数の表示名・user_id 等はサーバー配布の非認証メタデータ(自由文字列)で、
// 改行・ANSI エスケープを含められる。生のまま端末へ流すと偽行・誘導文の
// 混入(端末インジェクション)になるため、制御文字を可視の代替文字に置換
// してから表示する。値(--show)は対象外: 値はメンバーが E2EE で書いた
// データでサーバーには偽造できず、改変すれば復号失敗に落ちる。

const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/g;

/** Replaces control characters (C0 / C1 / DEL) for safe terminal display. */
export function displayText(value: string): string {
  return value.replace(CONTROL_CHARS, "\uFFFD");
}
