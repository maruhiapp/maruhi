import { cryptoEffect } from "@maruhi/core";
import { decodeHex, fingerprintToWords } from "@maruhi/crypto";
import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";

const CONFIRM_ATTEMPTS = 3;

export const fingerprintWords = Effect.fnUntraced(function* (
  fingerprintHex: string,
  invalidMessage: string,
): Effect.fn.Return<readonly string[], CliError> {
  const bytes = decodeHex(fingerprintHex);
  if (bytes === null) {
    return yield* Effect.fail(cliError(invalidMessage));
  }
  return yield* cryptoEffect(() => fingerprintToWords(bytes)).pipe(
    Effect.mapError(() => cliError("Failed to compute the fingerprint word list")),
  );
});

export function formatWordList(words: readonly string[]): string {
  return words.map((word, index) => `${String(index + 1).padStart(2)}.${word}`).join(" ");
}

export const confirmByLastWord = Effect.fn("fp-words.confirmByLastWord")(function* (input: {
  readonly words: readonly string[];
  readonly promptText: string;
  readonly mismatchText: string;
  readonly exhaustedText: string;
}): Effect.fn.Return<void, CliError, CliIo> {
  const io = yield* CliIo;
  const lastWord = input.words[input.words.length - 1];
  if (lastWord === undefined) {
    return yield* Effect.fail(cliError("Failed to compute the fingerprint word list"));
  }
  for (let attempt = 1; attempt <= CONFIRM_ATTEMPTS; attempt += 1) {
    const answer = yield* io.promptLine({
      prompt: `${input.promptText} (${attempt}/${CONFIRM_ATTEMPTS}): `,
    });
    if (answer.trim() === lastWord) {
      return;
    }
    yield* io.logError(input.mismatchText);
  }
  return yield* Effect.fail(cliError(input.exhaustedText));
});
