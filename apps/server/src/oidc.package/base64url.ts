// base64url decoding for the JWS compact serialization (RFC 7515
// Appendix C).
//
// Since atob accepts only base64 (`+` / `/` / `=`), the base64url
// 62nd/63rd characters are replaced and padding restored before
// handing off. **Validated strictly**: characters outside the alphabet
// and invalid lengths (mod 4 == 1) return null — a lenient decode must
// not create a path that "passes as different bytes" (the signed
// content is the raw segment strings, and lenient decoding would
// create a gap between the verified bytes and the restored value).

const BASE64URL = /^[A-Za-z0-9_-]*$/;

/** Decodes one base64url segment. Returns null for anything malformed. */
export function decodeBase64Url(segment: string): Uint8Array | null {
  if (!BASE64URL.test(segment) || segment.length % 4 === 1) {
    return null;
  }
  const padded = segment
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(segment.length + ((4 - (segment.length % 4)) % 4), "=");
  try {
    const binary = atob(padded);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
}

/** Decodes one base64url segment as UTF-8 JSON. Returns null for anything malformed. */
export function decodeBase64UrlJson(segment: string): unknown {
  const bytes = decodeBase64Url(segment);
  if (bytes === null) {
    return null;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch {
    return null;
  }
}
