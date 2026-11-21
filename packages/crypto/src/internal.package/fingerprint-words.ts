import { BIP39_ENGLISH_WORDS } from "./bip39-english.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";

const FINGERPRINT_BYTES = 16;
export const FINGERPRINT_WORD_COUNT = 12;
const INDEX_BITS = 11;

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

export async function fingerprintToWords(
  fingerprint: Uint8Array,
): Promise<CryptoResult<readonly string[]>> {
  if (fingerprint.length !== FINGERPRINT_BYTES) {
    return invalidInput("fingerprint length");
  }
  const digest = await sha256(fingerprint);
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
      return invalidInput("word index");
    }
    words.push(entry);
  }
  return { ok: true, value: words };
}
