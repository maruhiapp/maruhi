// 端末出力のサニタイズと表示整形。
//
// 変数の表示名・user_id 等はサーバー配布の非認証メタデータ(自由文字列)で、
// 改行・ANSI エスケープを含められる。生のまま端末へ流すと偽行・誘導文の
// 混入(端末インジェクション)になるため、制御文字を可視の代替文字に置換
// してから表示する。値(--show)は対象外: 値はメンバーが E2EE で書いた
// データでサーバーには偽造できず、改変すれば復号失敗に落ちる。

import { Effect } from "effect";

import { ensureValueDisplayAllowed } from "./agent.ts";
import { cliError, type CliError } from "./errors.ts";
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
function displayValue(value: string): string {
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

const strictValueDecoder = new TextDecoder("utf-8", { fatal: true });

/**
 * \u5024\u30D0\u30A4\u30C8\u5217 \u2192 \u30C6\u30AD\u30B9\u30C8\u306E\u552F\u4E00\u306E\u30C7\u30B3\u30FC\u30C9\u65B9\u91DD(fatal)\u3002\u4E0D\u6B63 UTF-8 \u306F null
 * (\u547C\u3073\u51FA\u3057\u5074\u304C\u5909\u6570\u540D\u4ED8\u304D\u306E\u660E\u793A\u30A8\u30E9\u30FC\u306B\u3059\u308B)\u3002
 *
 * \u65B9\u91DD\u306E\u9078\u5B9A: run(\u74B0\u5883\u5909\u6570\u6CE8\u5165)\u306F fatal \u5FC5\u9808\u3067\u3042\u308A\u3001\u8868\u793A\u5074\u3060\u3051\u7F6E\u63DB\u6587\u5B57\u3067
 * \u901A\u3059\u3068\u300C--show \u3067\u306F\u8868\u793A\u3067\u304D\u308B\u306E\u306B run \u3067\u306F\u5931\u6557\u3059\u308B\u300D\u975E\u5BFE\u79F0\u3068\u3001\u7F6E\u63DB\u6587\u5B57\u3067
 * \u9759\u304B\u306B\u58CA\u308C\u305F\u5024\u306E\u30B3\u30D4\u30FC\u4E8B\u6545\u3092\u751F\u3080\u3002\u4E21\u7D4C\u8DEF\u3068\u3082 fatal \u306B\u7D71\u4E00\u3059\u308B(pull --show \u306E
 * \u4E0D\u6B63 UTF-8 \u5024\u306F\u7F6E\u63DB\u8868\u793A\u304B\u3089\u30CF\u30FC\u30C9\u30A8\u30E9\u30FC\u3078\u306E\u6319\u52D5\u5909\u66F4)\u3002
 */
export function decodeValueText(value: Uint8Array): string | null {
  try {
    return strictValueDecoder.decode(value);
  } catch {
    // fatal \u30C7\u30B3\u30FC\u30C0\u306E\u4F8B\u5916\u306F\u300C\u4E0D\u6B63 UTF-8\u300D\u306E\u5224\u5B9A\u5024\u3068\u3057\u3066\u6271\u3046(\u5024\u306F\u904B\u3070\u306A\u3044)
    return null;
  }
}

/** \u5024\u306E\u7AEF\u672B\u8868\u793A(pull --show)\u3002\u30A8\u30FC\u30B8\u30A7\u30F3\u30C8\u691C\u51FA\u6642\u306F agent.ts \u304C\u62D2\u5426\u3059\u308B\u3002 */
export function showValues(
  variables: readonly DisplayableVariable[],
): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // \u30B3\u30DE\u30F3\u30C9\u5165\u53E3(\u5FA9\u53F7\u524D)\u306E\u691C\u67FB\u304C\u672C\u7DDA\u3002\u5FA9\u53F7\u5F8C\u306E\u3053\u306E\u691C\u67FB\u306F\u3001showValues \u3092
    // \u76F4\u63A5\u547C\u3076\u5C06\u6765\u306E\u7D4C\u8DEF\u304C\u5165\u53E3\u691C\u67FB\u3092\u6B20\u3044\u3066\u3082\u8868\u793A\u306B\u81F3\u3089\u305B\u306A\u3044\u9632\u885B\u7DDA
    yield* ensureValueDisplayAllowed(io.agentProfile());
    // \u5168\u5024\u306E\u30C7\u30B3\u30FC\u30C9\u3092\u51FA\u529B\u3088\u308A\u524D\u306B\u5B8C\u4E86\u3055\u305B\u308B(all-or-nothing)\u30021 \u5024\u3067\u3082\u4E0D\u6B63
    // UTF-8 \u306A\u3089\u4F55\u3082\u8868\u793A\u305B\u305A\u5931\u6557\u3057\u3001\u90E8\u5206\u51FA\u529B(\u524D\u534A\u306E\u5024\u3060\u3051\u753B\u9762\u306B\u6B8B\u308B)\u3092\u4F5C\u3089\u306A\u3044
    const lines: string[] = [];
    for (const variable of variables) {
      const text = decodeValueText(variable.value);
      if (text === null) {
        return yield* Effect.fail(
          cliError(
            `\u5909\u6570 ${displayText(variable.name)} \u306E\u5024\u306F UTF-8 \u3068\u3057\u3066\u4E0D\u6B63\u306E\u305F\u3081\u8868\u793A\u3067\u304D\u307E\u305B\u3093(\u30D0\u30A4\u30CA\u30EA\u5024\u306F --show \u306E\u5BFE\u8C61\u5916\u3067\u3059)`,
          ),
        );
      }
      lines.push(`${displayText(variable.name)}=${displayValue(text)}`);
    }
    for (const line of lines) {
      yield* io.log(line);
    }
  });
}
