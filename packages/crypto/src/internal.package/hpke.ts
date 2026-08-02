// HPKE スイートの単一構築点(CRYPTO_SPEC §2)。
// DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM、Base mode 単発 Seal/Open のみ。
// ライブラリは panva hpke(2026-08-01 決定・厳密ピン。選定経緯は docs/notes/spike-c.md)。

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
