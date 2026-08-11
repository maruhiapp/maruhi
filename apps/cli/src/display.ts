// 端末出力のサニタイズと表示整形。
//
// 変数の表示名・user_id 等はサーバー配布の非認証メタデータ(自由文字列)で、
// 改行・ANSI エスケープを含められる。生のまま端末へ流すと偽行・誘導文の
// 混入(端末インジェクション)になるため、制御文字を可視の代替文字に置換
// してから表示する。値(--show)は対象外: 値はメンバーが E2EE で書いた
// データでサーバーには偽造できず、改変すれば復号失敗に落ちる。

import { Effect } from "effect";

import { ensureValueDisplayAllowed } from "./agent.ts";
import type { CliError } from "./errors.ts";
import { CliIo } from "./io.ts";

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

// ---------------------------------------------------------------------------
// \u30B3\u30DE\u30F3\u30C9\u51FA\u529B\u306E\u6574\u5F62\u30D8\u30EB\u30D1(\u65E7 cli.ts \u304B\u3089\u79FB\u52D5)
// ---------------------------------------------------------------------------

/** pull \u4E00\u89A7\u884C\u306E\u5BFE\u8C61(pull.ts \u306E DecryptedVariable \u306E\u8868\u793A\u90E8\u5206)\u3002 */
export interface DisplayableVariable {
  readonly name: string;
  readonly version: number;
  readonly epoch: number;
  readonly value: Uint8Array;
}

/** pull \u306E\u30E1\u30BF\u30C7\u30FC\u30BF\u4E00\u89A7 1 \u884C\u3002 */
export function formatPulledLine(variable: DisplayableVariable): string {
  return `${displayText(variable.name)}\tversion=${variable.version}\tepoch=${variable.epoch}\t(${variable.value.byteLength} bytes)`;
}

/** \u691C\u8A3C\u4E2D\u306B\u53CE\u96C6\u3057\u305F SHOULD \u8B66\u544A(\u975E NFC \u540D\u306E\u914D\u5E03\u7B49 \u2014 \u00A712-1)\u3092\u8868\u793A\u3059\u308B\u3002 */
export function logWarnings(warnings: readonly string[]): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    for (const warning of warnings) {
      yield* io.logError(`\u8B66\u544A: ${warning}`);
    }
  });
}

const displayDecoder = new TextDecoder("utf-8", { fatal: false });

/** \u5024\u306E\u7AEF\u672B\u8868\u793A(pull --show)\u3002\u30A8\u30FC\u30B8\u30A7\u30F3\u30C8\u691C\u51FA\u6642\u306F agent.ts \u304C\u62D2\u5426\u3059\u308B\u3002 */
export function showValues(
  variables: readonly DisplayableVariable[],
): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensureValueDisplayAllowed(io.agentProfile());
    for (const variable of variables) {
      yield* io.log(
        `${displayText(variable.name)}=${displayValue(displayDecoder.decode(variable.value))}`,
      );
    }
  });
}
