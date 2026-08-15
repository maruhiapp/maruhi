// JWKS の鍵 → WebCrypto 検証鍵(AUTH_SPEC §14-1 の署名検証)。
//
// **alg 混同を構造的に閉じる設計**: 使用するアルゴリズムは常に **JWK 側の
// kty / crv** から決め、トークンヘッダーの `alg` はそこから導かれる期待値との
// 一致検査にしか使わない。ヘッダーの `alg` で分岐する実装は、攻撃者が選べる
// 値で検証経路を選ばせることになる(`none`・HMAC への差し替え)。ここでは
// 分岐の入力がサーバーが取得した JWKS だけなので、その経路が存在しない。
//
// 許可アルゴリズムは RS256 / ES256 のみ(§14-1)。対称鍵 alg・`none` は
// そもそも JWK 側に対応する kty がなく、到達しない。

/** JWS `alg` values this deployment accepts (AUTH_SPEC §14-1). */
export type AllowedAlg = "RS256" | "ES256";

/** One JWKS entry, narrowed to the fields the lease path reads. */
export interface Jwk {
  readonly kty?: unknown;
  readonly kid?: unknown;
  readonly use?: unknown;
  readonly alg?: unknown;
  readonly crv?: unknown;
}

interface AlgorithmBinding {
  /** The `alg` a token must declare to be verified with this key. */
  readonly headerAlg: AllowedAlg;
  readonly importParams: RsaHashedImportParams | EcKeyImportParams;
  readonly verifyParams: AlgorithmIdentifier | EcdsaParams;
}

const RS256: AlgorithmBinding = {
  headerAlg: "RS256",
  importParams: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
  verifyParams: { name: "RSASSA-PKCS1-v1_5" },
};

const ES256: AlgorithmBinding = {
  headerAlg: "ES256",
  importParams: { name: "ECDSA", namedCurve: "P-256" },
  verifyParams: { name: "ECDSA", hash: "SHA-256" },
};

/**
 * Derives the verification algorithm from the JWK itself. Returns null when
 * the key is not one this deployment can use — an unusable key is skipped
 * during selection rather than making the whole JWKS unusable (issuers may
 * publish keys for algorithms we do not accept).
 */
export function algorithmForJwk(jwk: Jwk): AlgorithmBinding | null {
  // `use` は任意だが、宣言されているなら署名用であること
  if (jwk.use !== undefined && jwk.use !== "sig") {
    return null;
  }
  if (jwk.kty === "RSA") {
    // JWK 側が alg を宣言しているなら、それも許可リスト内で一致すること
    return jwk.alg === undefined || jwk.alg === "RS256" ? RS256 : null;
  }
  if (jwk.kty === "EC" && jwk.crv === "P-256") {
    return jwk.alg === undefined || jwk.alg === "ES256" ? ES256 : null;
  }
  return null;
}

/**
 * Imports a JWKS key for verification. The algorithm comes from
 * {@link algorithmForJwk}; the caller must have already checked that the
 * token's declared `alg` equals `binding.headerAlg`.
 */
export async function importJwk(jwk: Jwk, binding: AlgorithmBinding): Promise<CryptoKey | null> {
  try {
    return await crypto.subtle.importKey(
      "jwk",
      // WebCrypto は JWK を JsonWebKey として受ける。ここへ渡すのは取得済みの
      // JWKS のエントリそのもの(改変しない)
      jwk as JsonWebKey,
      binding.importParams,
      false,
      ["verify"],
    );
  } catch {
    return null;
  }
}

/**
 * Verifies a JWS signature over `signingInput`. ES256 の JWS 署名は生の
 * `r || s`(64 バイト)であり、WebCrypto の ECDSA がそのまま受ける形なので
 * DER 変換は要らない(不要な変換層を置かない)。
 */
export async function verifyJwsSignature(input: {
  readonly key: CryptoKey;
  readonly binding: AlgorithmBinding;
  readonly signature: Uint8Array;
  readonly signingInput: Uint8Array;
}): Promise<boolean> {
  try {
    return await crypto.subtle.verify(
      input.binding.verifyParams,
      input.key,
      input.signature as BufferSource,
      input.signingInput as BufferSource,
    );
  } catch {
    return false;
  }
}
