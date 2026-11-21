import { concatBytes, utf8Encode } from "./bytes.ts";

export type LengthPrefixedField = string | number | Uint8Array;

const UINT32_MAX = 0xffffffff;

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
