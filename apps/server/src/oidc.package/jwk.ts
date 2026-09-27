// JWKS key → WebCrypto verification key (AUTH_SPEC §14-1's signature
// verification).
//
// **A design that structurally closes off alg confusion**: the
// algorithm used is always decided from **the JWK side's kty / crv**,
// and the token header's `alg` is used only for a match check against
// the expectation derived from them. An implementation that branches
// on the header's `alg` lets an attacker-chosen value pick the
// verification path (`none`, substitution to HMAC). Here the branch
// input is only the server-fetched JWKS, so that path does not exist.
//
// The allowed algorithms are RS256 / ES256 only (§14-1). Symmetric-key
// algs and `none` have no corresponding JWK-side kty and are
// unreachable.

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
  // `use` is optional, but when declared it must be "sig"
  if (jwk.use !== undefined && jwk.use !== "sig") {
    return null;
  }
  if (jwk.kty === "RSA") {
    // When the JWK side declares an alg, it must also match inside the allowlist
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
      // WebCrypto takes the JWK as a JsonWebKey. What is passed here
      // is the fetched JWKS entry itself (unmodified)
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
 * Verifies a JWS signature over `signingInput`. An ES256 JWS
 * signature is raw `r || s` (64 bytes), the form WebCrypto's ECDSA
 * takes directly, so no DER conversion is needed (no unnecessary
 * conversion layer).
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
