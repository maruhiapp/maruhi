// The human-readable representation of the recovery code
// (CRYPTO_SPEC §8: a 256-bit random value as a grouped Base32
// (RFC 4648) string).
//
// This is a display encoding, not a crypto primitive (key derivation
// and wrapping are owned by packages/crypto's §8 implementation).
// 32 bytes = 256 bit → 52 symbols (260 bit; the last 4 bits are
// zero-padded) → 4 chars × 13 groups joined by hyphens.
//
// Input acceptance is lenient: lowercase, hyphens, and spaces are
// absorbed. Characters outside the Base32 alphabet (0 / 1 / 8 / 9
// etc.) are refused without guesswork substitution — 0→O / 1→I|L
// interpretations are not unique, and a mistranscribed 256-bit value
// just silently fails decryption without the user reaching the
// cause.

import { Redacted } from "effect";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const SECRET_BYTES = 32;
const SYMBOL_COUNT = Math.ceil((SECRET_BYTES * 8) / 5); // 52
const GROUP_SIZE = 4;

/**
 * Formats a 256-bit recovery secret as grouped Base32 (`XXXX-XXXX-…`).
 *
 * Why it is unwrapped: input for Base32 encoding. The formatted
 * code is another representation of the secret itself, so it is
 * wrapped in `Redacted` again on return, keeping the raw string
 * inside this function (unwrapping is the display side's — behind
 * recovery.ts's agent gate).
 */
export function formatRecoveryCode(
  redactedSecret: Redacted.Redacted<Uint8Array>,
): Redacted.Redacted<string> {
  const secret = Redacted.value(redactedSecret);
  if (secret.length !== SECRET_BYTES) {
    throw new Error("recovery secret must be 32 bytes");
  }
  let bits = 0;
  let acc = 0;
  let symbols = "";
  for (const byte of secret) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      symbols += ALPHABET[(acc >> bits) & 0b11111];
      acc &= (1 << bits) - 1;
    }
  }
  if (bits > 0) {
    symbols += ALPHABET[(acc << (5 - bits)) & 0b11111];
  }
  const groups: string[] = [];
  for (let i = 0; i < symbols.length; i += GROUP_SIZE) {
    groups.push(symbols.slice(i, i + GROUP_SIZE));
  }
  return Redacted.make(groups.join("-"), { label: "recovery-code" });
}

/**
 * Parses a recovery code back into its 32-byte secret. Case-insensitive;
 * hyphens and whitespace are ignored. Returns null for anything that is not
 * exactly a 52-symbol Base32 string with zeroed padding bits.
 */
export function parseRecoveryCode(text: string): Redacted.Redacted<Uint8Array> | null {
  const symbols = text.replace(/[\s-]/g, "").toUpperCase();
  if (symbols.length !== SYMBOL_COUNT) {
    return null;
  }
  const out = new Uint8Array(SECRET_BYTES);
  let bits = 0;
  let acc = 0;
  let offset = 0;
  for (const symbol of symbols) {
    const value = ALPHABET.indexOf(symbol);
    if (value < 0) {
      return null;
    }
    acc = (acc << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[offset] = (acc >> bits) & 0xff;
      offset += 1;
      acc &= (1 << bits) - 1;
    }
  }
  // Zero-padding check of the last 4 bits: non-zero is a
  // transcription error (not identified with another code one symbol
  // away)
  if (acc !== 0) {
    return null;
  }
  return Redacted.make(out, { label: "recovery-secret" });
}
