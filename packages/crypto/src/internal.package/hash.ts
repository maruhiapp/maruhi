// SHA-256(WebCrypto)。チェーンハッシュ・鍵フィンガープリントで共用。

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
}
