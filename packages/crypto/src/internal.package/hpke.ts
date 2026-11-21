import * as HPKE from "hpke";

let cached: HPKE.CipherSuite | undefined;

export function hpkeSuite(): HPKE.CipherSuite {
  cached ??= new HPKE.CipherSuite(
    HPKE.KEM_DHKEM_X25519_HKDF_SHA256,
    HPKE.KDF_HKDF_SHA256,
    HPKE.AEAD_AES_256_GCM,
  );
  return cached;
}
