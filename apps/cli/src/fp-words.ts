// フィンガープリントのワード表示(BIP39 英語 12 語 — CRYPTO_SPEC §3)と、
// 帯域外照合の明示確認の儀式(最終語の再入力)の共有実装。
//
// 使い手はサーバー鍵確認(server-grant — §9)、招待の相互確認(invite accept /
// member add — §6.5)、`maruhi key show` の自 FP 表示。儀式の文言は操作ごとに
// 異なる(照合の相手・対象が違う)ため呼び出し側が与え、再入力ループの形
// (3 回試行・最終語一致)だけをここで固定する。
//
// FP は公開情報であり、ワード列の表示・ログ出力は平文値・鍵素材の禁止規則に
// 抵触しない。

import { decodeHex, fingerprintToWords } from "@maruhi/crypto";
import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";

/** 再入力の試行回数(server-grant の CONFIRM_ATTEMPTS を共有化)。 */
const CONFIRM_ATTEMPTS = 3;

/** FP hex(16 バイト)を BIP39 12 語へ(§3)。`invalidMessage` は形式不正時の文言。 */
export function fingerprintWords(
  fingerprintHex: string,
  invalidMessage: string,
): Effect.Effect<readonly string[], CliError> {
  return Effect.gen(function* () {
    const bytes = decodeHex(fingerprintHex);
    if (bytes === null) {
      return yield* Effect.fail(cliError(invalidMessage));
    }
    const words = yield* Effect.tryPromise({
      try: () => fingerprintToWords(bytes),
      catch: () => cliError("FP ワード表示の計算に失敗しました(暗号処理エラー)"),
    });
    if (!words.ok) {
      return yield* Effect.fail(cliError("FP ワード表示の計算に失敗しました"));
    }
    return words.value;
  });
}

/** 12 語の番号付き 1 行表示(server-grant の表示形式を共有化)。 */
export function formatWordList(words: readonly string[]): string {
  return words.map((word, index) => `${String(index + 1).padStart(2)}.${word}`).join(" ");
}

/**
 * 最終語の再入力による明示確認(ADR-0014 の儀式)。表示済みの語列を読まずに
 * 進む形を塞ぐ。プロンプト・不一致・失敗の文言は操作ごとに与える(server-grant
 * の既存文言は呼び出し側がそのまま渡す — 挙動・文言の互換を保つ)。
 */
export function confirmByLastWord(input: {
  readonly words: readonly string[];
  /** `(n/3): ` の直前までのプロンプト本文。 */
  readonly promptText: string;
  readonly mismatchText: string;
  readonly exhaustedText: string;
}): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const lastWord = input.words[input.words.length - 1];
    if (lastWord === undefined) {
      return yield* Effect.fail(cliError("FP ワード表示の計算に失敗しました"));
    }
    for (let attempt = 1; attempt <= CONFIRM_ATTEMPTS; attempt += 1) {
      const answer = yield* io.promptLine({
        prompt: `${input.promptText}(${attempt}/${CONFIRM_ATTEMPTS}): `,
      });
      if (answer.trim() === lastWord) {
        return;
      }
      yield* io.logError(input.mismatchText);
    }
    return yield* Effect.fail(cliError(input.exhaustedText));
  });
}
