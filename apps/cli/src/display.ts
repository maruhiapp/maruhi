// 端末出力のサニタイズ。
//
// 変数の表示名・user_id 等はサーバー配布の非認証メタデータ(自由文字列)で、
// 改行・ANSI エスケープを含められる。生のまま端末へ流すと偽行・誘導文の
// 混入(端末インジェクション)になるため、制御文字を可視の代替文字に置換
// してから表示する。値(--show)は対象外: 値はメンバーが E2EE で書いた
// データでサーバーには偽造できず、改変すれば復号失敗に落ちる。

// Unicode カテゴリ Cc = C0 制御(NUL〜US)+ DEL + C1 制御(ANSI CSI を含む)
const CONTROL_CHARS = /\p{Cc}/gu;

/** Replaces control characters (C0 / C1 / DEL) for safe terminal display. */
export function displayText(value: string): string {
  return value.replace(CONTROL_CHARS, "\uFFFD");
}

// 値の表示(pull --show)用: 端末インジェクションの媒介(ESC・BEL・C1・
// CR 等)は中和しつつ、正当なシークレット(複数行 PEM 鍵など)を壊さないよう
// タブ(\t)と改行(\n)だけは残す。値は共同編集者(正当な書き手)が保存する
// ため、悪意ある値による他メンバーの端末改ざんを防ぐ(サーバー偽造とは別脅威)
const VALUE_CONTROL_CHARS = /[^\P{Cc}\t\n]/gu;

/** Neutralizes injection-capable control chars in a secret value, keeping \t and \n. */
export function displayValue(value: string): string {
  return value.replace(VALUE_CONTROL_CHARS, "\uFFFD");
}
