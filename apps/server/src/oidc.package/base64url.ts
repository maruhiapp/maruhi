// JWS compact serialization の base64url デコード(RFC 7515 Appendix C)。
//
// atob は base64(`+` / `/` / `=`)しか受けないため、base64url の 62/63 文字を
// 置換しパディングを補ってから渡す。**厳格に検査する**: 文字集合外・不正な長さ
// (mod 4 == 1)は null を返し、寛容なデコードで「別のバイト列として通る」経路を
// 作らない(署名対象は生の segment 文字列であり、デコードの寛容さは検証対象
// バイト列と復元値のズレを生む)。

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
