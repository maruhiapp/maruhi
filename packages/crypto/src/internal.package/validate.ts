// 署名系モジュール共通の入力検証ヘルパ(dek-wrap-sign.ts / value-sign.ts /
// value-verify.ts)。hex は小文字・固定長のみを正規形とする(大文字 hex を
// 許すと同一データに複数の正規形が生まれ、署名・照合の一意性が壊れる)。

import { decodeHex } from "./bytes.ts";
import type { CryptoError } from "./errors.ts";

/** InvalidInput エラー値(フィールド名のみ — 秘密・入力断片を載せない)。 */
export function invalidInput(field: string): {
  readonly ok: false;
  readonly error: CryptoError;
} {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

/** 指定文字数の hex 小文字文字列か(decodeHex は小文字のみ受理)。 */
export function isLowercaseHexOfLength(value: string, length: number): boolean {
  return value.length === length && decodeHex(value) !== null;
}
