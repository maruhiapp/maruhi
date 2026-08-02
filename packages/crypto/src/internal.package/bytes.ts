// バイト列ユーティリティ。hex は小文字固定
// (チェーン正規化の binary_encoding 規約が hex 小文字文字列のため)。

const textEncoder = new TextEncoder();

export function utf8Encode(s: string): Uint8Array {
  return textEncoder.encode(s);
}

/**
 * Encodes bytes as a lowercase hex string — the canonical text form for all
 * binary values in maruhi data structures (hashes, public keys, signatures).
 */
export function encodeHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * Decodes a lowercase hex string. Returns null for malformed input (odd
 * length, non-hex characters — and, defensively, non-string runtime values
 * from untrusted JSON). Uppercase is rejected: the canonical form of chain
 * entries and fingerprints is lowercase only.
 */
export function decodeHex(s: string): Uint8Array | null {
  // 不信データの検証境界から呼ばれるため、実行時型が string でない場合も
  // throw せず null を返す(TS 型より実行時の防御を優先)
  if (typeof s !== "string" || s.length % 2 !== 0 || !/^[0-9a-f]*$/.test(s)) {
    return null;
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) {
    total += p.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}
