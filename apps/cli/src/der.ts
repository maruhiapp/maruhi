// A minimal DER writer (ITU-T X.690) for the two places the CLI has to
// *produce* ASN.1: the ephemeral certificates of `maruhi proxy run`
// (proxy-cert.ts) and wrapping a PKCS#1 RSA key as PKCS#8 for WebCrypto
// (proxy-connector.ts — GitHub hands App keys out in PKCS#1). Encoding
// only; nothing here parses, and no cryptographic operation happens here.

const encoder = new TextEncoder();

/** Concatenates byte arrays into one fresh buffer. */
function concatBytes(parts: readonly Uint8Array[]): Uint8Array<ArrayBuffer> {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(new ArrayBuffer(total));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function derLength(length: number): Uint8Array {
  if (length < 0x80) {
    return new Uint8Array([length]);
  }
  const bytes: number[] = [];
  let rest = length;
  while (rest > 0) {
    bytes.unshift(rest & 0xff);
    rest >>>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

/** One tag-length-value. */
export function tlv(tag: number, content: Uint8Array): Uint8Array<ArrayBuffer> {
  return concatBytes([new Uint8Array([tag]), derLength(content.length), content]);
}

export const seq = (...parts: Uint8Array[]) => tlv(0x30, concatBytes(parts));
export const set = (...parts: Uint8Array[]) => tlv(0x31, concatBytes(parts));
export const octetString = (bytes: Uint8Array) => tlv(0x04, bytes);
export const boolTrue = () => tlv(0x01, new Uint8Array([0xff]));
const asn1Null = () => tlv(0x05, new Uint8Array(0));
export const utf8String = (text: string) => tlv(0x0c, encoder.encode(text));
export const ia5String = (text: string) => tlv(0x16, encoder.encode(text));
/** `[n] EXPLICIT` context tag (constructed). */
export const explicit = (n: number, content: Uint8Array) => tlv(0xa0 | n, content);

/** A BIT STRING with no unused bits. */
export function bitString(bytes: Uint8Array): Uint8Array {
  return tlv(0x03, concatBytes([new Uint8Array([0]), bytes]));
}

/** An unsigned big-endian INTEGER (minimal encoding, always positive). */
export function unsignedInteger(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start++;
  }
  const trimmed = bytes.subarray(start);
  // A leading 0x00 keeps the value positive when the high bit is set
  const body = (trimmed[0] ?? 0) & 0x80 ? concatBytes([new Uint8Array([0]), trimmed]) : trimmed;
  return tlv(0x02, body);
}

export function smallInteger(value: number): Uint8Array {
  return unsignedInteger(new Uint8Array([value]));
}

/** OBJECT IDENTIFIER from dotted text. */
export function oid(dotted: string): Uint8Array {
  const arcs = dotted.split(".").map(Number);
  const [first = 0, second = 0, ...rest] = arcs;
  const bytes: number[] = [first * 40 + second];
  for (const arc of rest) {
    const chunk: number[] = [arc & 0x7f];
    let remaining = arc >>> 7;
    while (remaining > 0) {
      chunk.unshift((remaining & 0x7f) | 0x80);
      remaining >>>= 7;
    }
    bytes.push(...chunk);
  }
  return tlv(0x06, new Uint8Array(bytes));
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/** PEM armour (64-column base64). */
export function pem(label: string, der: Uint8Array): string {
  const lines = toBase64(der).match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

/** The DER body of a PEM block (null when the text is not a PEM block of `label`). */
export function pemBody(text: string, label: string): Uint8Array<ArrayBuffer> | null {
  const match = new RegExp(
    `-----BEGIN ${label}-----([A-Za-z0-9+/=\\s]+)-----END ${label}-----`,
  ).exec(text);
  if (match === null) {
    return null;
  }
  const base64 = (match[1] ?? "").replace(/\s+/g, "");
  const binary = atob(base64);
  const out = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

const RSA_ENCRYPTION = "1.2.840.113549.1.1.1";

/**
 * Wraps a PKCS#1 `RSAPrivateKey` as PKCS#8 `PrivateKeyInfo` (RFC 5208) —
 * the one form WebCrypto's `importKey` accepts.
 */
export function pkcs1ToPkcs8(pkcs1: Uint8Array): Uint8Array<ArrayBuffer> {
  return seq(smallInteger(0), seq(oid(RSA_ENCRYPTION), asn1Null()), octetString(pkcs1));
}
