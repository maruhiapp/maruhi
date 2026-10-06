// Word display of a fingerprint (BIP39 English 12 words — CRYPTO_SPEC
// §3) and the shared implementation of the explicit out-of-band
// confirmation ceremony (re-entering the last word).
//
// Users: server-key confirmation (server-grant — §9), invite mutual
// confirmation (invite accept / member add — §6.5), `maruhi key
// show`'s own-FP display. The ceremony wording differs per operation
// (the comparison's peer and target differ), so the caller supplies
// it; only the shape of the re-entry loop (3 attempts, last-word
// match) is fixed here.
//
// The FP is public information; displaying or logging the word list
// does not violate the no-plaintext-values / no-key-material rule.

import { cryptoEffect } from "@maruhi/core";
import { decodeHex, fingerprintToWords } from "@maruhi/crypto";
import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";

/** Number of re-entry attempts (shared from server-grant's CONFIRM_ATTEMPTS). */
const CONFIRM_ATTEMPTS = 3;

/** FP hex (16 bytes) to BIP39 12 words (§3). `invalidMessage` is the wording for malformed input. */
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

/** One-line numbered display of the 12 words (shared from server-grant's display format). */
export function formatWordList(words: readonly string[]): string {
  return words.map((word, index) => `${String(index + 1).padStart(2)}.${word}`).join(" ");
}

/**
 * Explicit confirmation by re-entering the last word (the ADR-0014
 * ceremony). Blocks the form where the user proceeds without reading
 * the displayed word list. The prompt, mismatch, and failure wording
 * are supplied per operation (the caller passes server-grant's
 * existing wording verbatim — behavior and wording stay compatible).
 */
export const confirmByLastWord = Effect.fn("fp-words.confirmByLastWord")(function* (input: {
  readonly words: readonly string[];
  /** The prompt body up to just before `(n/3): `. */
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
