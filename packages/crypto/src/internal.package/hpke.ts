// The single construction point of the HPKE suite (CRYPTO_SPEC §2).
// DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM, Base-mode single-shot Seal/Open only.
// The library is panva hpke (exact pin; the selection history is docs/notes/spike-c.md).

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
