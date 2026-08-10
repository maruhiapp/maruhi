// リカバリーコードの人間可読表現(CRYPTO_SPEC §8: 256-bit ランダム値を
// Base32(RFC 4648)でグループ化した文字列)。
//
// これは表示エンコーディングであり暗号プリミティブではない(鍵導出・ラップは
// packages/crypto の §8 実装が担う)。32 バイト = 256 bit → 52 シンボル
// (260 bit。末尾 4 bit はゼロ詰め)→ 4 文字 × 13 グループをハイフンで結ぶ。
//
// 入力の受理は寛容にする: 小文字・ハイフン・空白は吸収する。ただし Base32
// アルファベット外の文字(0 / 1 / 8 / 9 等)は推測置換せずに拒否する —
// 0→O / 1→I|L の解釈は一意でなく、誤変換した 256-bit 値は黙って復号失敗に
// なるだけで利用者が原因へ辿り着けない。

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const SECRET_BYTES = 32;
const SYMBOL_COUNT = Math.ceil((SECRET_BYTES * 8) / 5); // 52
const GROUP_SIZE = 4;

/** Formats a 256-bit recovery secret as grouped Base32 (`XXXX-XXXX-…`). */
export function formatRecoveryCode(secret: Uint8Array): string {
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
  return groups.join("-");
}

/**
 * Parses a recovery code back into its 32-byte secret. Case-insensitive;
 * hyphens and whitespace are ignored. Returns null for anything that is not
 * exactly a 52-symbol Base32 string with zeroed padding bits.
 */
export function parseRecoveryCode(text: string): Uint8Array | null {
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
  // 末尾 4 bit のゼロ詰め検査: 非ゼロは転記ミス(1 シンボル違いの別コードと
  // 同一視しない)
  if (acc !== 0) {
    return null;
  }
  return out;
}
