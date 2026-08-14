// CRYPTO_SPEC §3: フィンガープリントのワード表示 — 16 バイト FP の BIP39 英語
// ワードリストによるニーモニック符号化(12 語 = エントロピー 128 bit + SHA-256
// 先頭 4 bit チェックサム)。人間の帯域外照合(§6.5 の相互確認・§9 の grant 時
// サーバー鍵確認)に用いる。表示言語・ロケールに依らず常に英語リスト 1 本
// (両者の表示が一致しなければ口頭照合が成立しない)。短縮コードへの切り詰めは
// 行わない(照合の一方の鍵は攻撃者が選べるため、切り詰め = 第二原像探索への
// 強度低下)。これは表示符号化であり新しい暗号プリミティブではない
// (SHA-256 + 固定辞書。符号化は BIP39 の 128-bit エントロピー形と同一で、
// 公式テストベクターが単体テストで固定する — test/checks/fingerprint-words.ts)。

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
  // 132 bit ストリーム = FP 128 bit || チェックサム 4 bit(17 バイト目の上位 4 bit)
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
      // 11 bit インデックスは常に 0..2047 なので到達しない(辞書破損の防衛)
      return invalidInput("word index");
    }
    words.push(entry);
  }
  return { ok: true, value: words };
}
