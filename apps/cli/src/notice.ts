// stderr へ出す通知(Note / Warning / 失敗)の語彙と描画(DP5 裁定 A / B)。
//
// 語彙(用途で使い分ける — 混ぜない):
//   - `Note:`     情報。コマンドは成功しており、書かれているのは任意の次の一手か
//                 状況の説明。見逃しても安全性は下がらない
//   - `Warning:`  劣化・要注意。コマンドは続行(または成功)したが、利用者が
//                 確認すべき状態がある。見逃すと安全性が下がりうるものは常に
//                 こちら(床の破損・アンカー不一致・署名検証失敗など)
//   - `maruhi:`   失敗(終了コード ≠ 0)。文面は「何が起きたか。次の一手」
//
// 宛先はすべて stderr(ADR-0016 決定 9 — stdout はコマンドの出力だけ)。文字列
// 連結 `\`Note: ${…}\`` を各所に散らさず、接頭辞の描画をここ 1 か所に寄せる。
//
// 色の規律(裁定 A): 色を付けるのは**接頭辞だけ**。本文(値・識別子・URL を
// 含みうる)には一切付けない — 付けるものを定数の接頭辞に限ることで、識別子や
// 値に色が混ざる形を構造的に作らない。記号(✓ / ⚠ 等)は使わない(Windows の
// 端末・非 UTF-8 ロケールでの化けを避け、接頭辞の語がその役を担う)。色の
// 可否は `CliIo.colorEnabled()` — 本番は {@link shouldUseColor}(stderr が端末か
// + NO_COLOR / FORCE_COLOR / TERM=dumb)、テストは既定で無色。判定材料は
// サービス経由で取り、ここでは `process.*` を読まない(ADR-0016 決定 5)。

import { Context, Effect, Option } from "effect";

import { CliIo } from "./io.ts";

/**
 * 1 回のコマンド実行の中で出した Note / Warning の文面(裁定 C の規則
 * 「同一文面の通知は 1 コマンド実行あたり 1 回」)。同期 → 再同期のように同じ
 * 経路を 2 度通る実行で、同じ 1 行(例: ヘッド申告の送信失敗)が 2 度並ぶのを
 * 防ぐ。差し替え対象の**状態**なのでサービスにし、runEffectCli が実行ごとに
 * 新しい台帳を供給する(台帳が無い文脈 — 単体テストなど — では抑制しない)。
 */
export class NoticeLedger extends Context.Service<NoticeLedger, Set<string>>()(
  "cli/NoticeLedger",
) {}

/** Kind of a stderr notice (decides the prefix and its color). */
export type NoticeKind = "note" | "warning" | "error";

const RESET = "\u001B[0m";
const PREFIXES: Readonly<Record<NoticeKind, { readonly label: string; readonly color: string }>> = {
  // 情報 = シアン(端末 16 色で「情報」の慣用。朱 accent の模倣はしない —
  // 端末の赤は danger の意味を持つ)
  note: { label: "Note:", color: "\u001B[36m" },
  warning: { label: "Warning:", color: "\u001B[33m" },
  error: { label: "maruhi:", color: "\u001B[31m" },
};

/**
 * Decides whether stderr decorations (ANSI colors) may be used.
 *
 * 優先順: `FORCE_COLOR`(非空。`0` は無効化)> `NO_COLOR`(非空なら無効 —
 * no-color.org の規約: 値は問わない)> `TERM=dumb` > stderr が端末か。stdout は
 * 判定に使わない(色を付けるのは stderr の通知だけで、stdout はデータ)。
 */
export function shouldUseColor(input: {
  readonly stderrIsTerminal: boolean;
  readonly envVar: (name: string) => string | undefined;
}): boolean {
  const force = input.envVar("FORCE_COLOR");
  if (force !== undefined && force !== "") {
    return force !== "0";
  }
  const noColor = input.envVar("NO_COLOR");
  if (noColor !== undefined && noColor !== "") {
    return false;
  }
  if (input.envVar("TERM") === "dumb") {
    return false;
  }
  return input.stderrIsTerminal;
}

/**
 * Renders one notice line: the prefix (optionally colored) and the text.
 *
 * 本文は呼び出し側が `displayText` で中和済みの文字列を渡す(サーバー由来の
 * 文字列を素通しにしない規律はそのまま — ここでは装飾だけを足す)。
 */
export function formatNotice(kind: NoticeKind, text: string, color: boolean): string {
  const prefix = PREFIXES[kind];
  const label = color ? `${prefix.color}${prefix.label}${RESET}` : prefix.label;
  return `${label} ${text}`;
}

/**
 * Where a notice belongs. `run` (default): a run-level fact, printed at most
 * once per command execution. `prompt`: attached to the interactive item
 * printed just above it (a candidate in `schema import`), so it repeats on
 * every retry of that item and is indented under it — never deduplicated.
 */
export interface NoticeOptions {
  readonly scope?: "run" | "prompt";
}

/** Writes a notice to stderr (dedupe by exact text within one run — `run` scope only). */
function logNotice(
  kind: NoticeKind,
  text: string,
  options: NoticeOptions,
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const scope = options.scope ?? "run";
    const ledger = yield* Effect.serviceOption(NoticeLedger);
    if (kind !== "error" && scope === "run" && Option.isSome(ledger)) {
      const key = `${kind}\u0000${text}`;
      if (ledger.value.has(key)) {
        return;
      }
      ledger.value.add(key);
    }
    const line = formatNotice(kind, text, io.colorEnabled());
    yield* io.logError(scope === "prompt" ? `  ${line}` : line);
  });
}

/** Writes `Note: <text>` to stderr (information — the command succeeded). */
export function logNote(text: string, options: NoticeOptions = {}) {
  return logNotice("note", text, options);
}

/** Writes `Warning: <text>` to stderr (degraded or suspicious state — the command continued). */
export function logWarning(text: string, options: NoticeOptions = {}) {
  return logNotice("warning", text, options);
}

/** Writes `maruhi: <message>` to stderr (the command failed). */
export function logFailure(message: string) {
  return logNotice("error", message, {});
}
