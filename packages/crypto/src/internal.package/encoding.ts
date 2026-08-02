// CRYPTO_SPEC §2.1: 長さプレフィックス付き決定論的エンコーディング。
// AAD / HPKE info / チェーン正規化のすべてがこの 1 実装を共有する(仕様の必須要件)。
// テストベクター: test-vectors/encoding.json

import { concatBytes, utf8Encode } from "./bytes.ts";

/**
 * A field of the length-prefixed encoding: strings are UTF-8 encoded, numbers
 * are converted to their decimal string form, byte arrays are used as-is.
 */
export type LengthPrefixedField = string | number | Uint8Array;

const UINT32_MAX = 0xffffffff;

/**
 * Encodes fields as `uint32-BE length || body` concatenation (CRYPTO_SPEC §2.1).
 *
 * This is the single shared encoder for AADs, HPKE info strings and chain entry
 * canonicalization. It removes the concatenation ambiguity of plain string
 * joins: `("ab","c")` and `("a","bc")` produce distinct byte strings.
 *
 * @throws {TypeError} if a number field is not a non-negative safe integer,
 *   or a field body exceeds 2^32 - 1 bytes. These are programmer errors, not
 *   runtime conditions, so they throw instead of returning a typed error.
 */
export function encodeLengthPrefixed(fields: readonly LengthPrefixedField[]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const field of fields) {
    let body: Uint8Array;
    if (typeof field === "number") {
      if (!Number.isSafeInteger(field) || field < 0) {
        throw new TypeError("length-prefixed number fields must be non-negative safe integers");
      }
      body = utf8Encode(String(field));
    } else if (typeof field === "string") {
      body = utf8Encode(field);
    } else {
      body = field;
    }
    if (body.length > UINT32_MAX) {
      throw new TypeError("length-prefixed field exceeds uint32 length");
    }
    const prefix = new Uint8Array(4);
    new DataView(prefix.buffer).setUint32(0, body.length, false);
    parts.push(prefix, body);
  }
  return concatBytes(...parts);
}
