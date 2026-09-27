// CRYPTO_SPEC §3: word display of fingerprints — mnemonic encoding of a 16-byte
// FP via the BIP39 English word list (12 words = 128-bit entropy + the first
// 4 bits of SHA-256 as checksum). Used for human out-of-band comparison (the
// §6.5 mutual check, the §9 server-key check at grant time). Always the single
// English list regardless of display language or locale (verbal comparison
// only works if both sides see the same rendering). No truncation to short
// codes (one side of the comparison may be attacker-chosen, so truncation =
// weakened resistance to second-preimage search). This is a display encoding,
// not a new cryptographic primitive (SHA-256 + a fixed dictionary; the encoding
// is identical to BIP39's 128-bit-entropy form, and the official test vectors
// pin it in a unit test — test/checks/fingerprint-words.ts).

import { BIP39_ENGLISH_WORDS } from "./bip39-english.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";

const FINGERPRINT_BYTES = 16;
/** Words in the §3 fingerprint display (128-bit entropy + 4-bit checksum = 12 × 11 bit). */
export const FINGERPRINT_WORD_COUNT = 12;
const INDEX_BITS = 11;

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

/**
 * Encodes a 16-byte key fingerprint as its BIP39 English 12-word display form
 * (CRYPTO_SPEC §3): the 128 fingerprint bits followed by the first 4 bits of
 * `SHA-256(fingerprint)` are split into twelve 11-bit indexes into the fixed
 * English word list. Works for both user fingerprints (§3) and server key
 * fingerprints (§9) — any 16-byte fingerprint value.
 */
export async function fingerprintToWords(
  fingerprint: Uint8Array,
): Promise<CryptoResult<readonly string[]>> {
  if (fingerprint.length !== FINGERPRINT_BYTES) {
    return invalidInput("fingerprint length");
  }
  const digest = await sha256(fingerprint);
  // 132-bit stream = FP 128 bits || checksum 4 bits (the upper 4 bits of byte 17)
  const stream = new Uint8Array(FINGERPRINT_BYTES + 1);
  stream.set(fingerprint, 0);
  stream[FINGERPRINT_BYTES] = (digest[0] ?? 0) & 0xf0;
  const bitAt = (position: number): number =>
    ((stream[position >> 3] ?? 0) >> (7 - (position & 7))) & 1;
  const words: string[] = [];
  for (let word = 0; word < FINGERPRINT_WORD_COUNT; word += 1) {
    let index = 0;
    for (let bit = 0; bit < INDEX_BITS; bit += 1) {
      index = (index << 1) | bitAt(word * INDEX_BITS + bit);
    }
    const entry = BIP39_ENGLISH_WORDS[index];
    if (entry === undefined) {
      // unreachable since an 11-bit index is always 0..2047 (defense against a corrupted dictionary)
      return invalidInput("word index");
    }
    words.push(entry);
  }
  return { ok: true, value: words };
}
