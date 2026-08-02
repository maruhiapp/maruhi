// @maruhi/crypto — E2EE コア(WebCrypto + HPKE)。
// 暗号仕様は docs/CRYPTO_SPEC.md が唯一の正。このパッケージへの変更は人間レビュー必須。
// 実装は test-vectors/ の全ベクターを通ることを必須とする。
//
// 全環境(ブラウザ / Bun / workerd)で動く: WebCrypto + panva hpke 以外のプリミティブ禁止。
// エラーは型付きエラー値(CryptoResult)で返し、Effect ラップは packages/core 側で行う。

export {
  buildDekWrapInfo,
  buildVariableAad,
  type ChainInvalidReason,
  computeServerKeyFingerprint,
  computeUserKeyFingerprint,
  type CryptoError,
  type CryptoResult,
  decodeHex,
  decryptVariable,
  type DekWrapContext,
  encodeHex,
  encodeLengthPrefixed,
  type EncryptedVariable,
  type EncryptionKey,
  type EncryptionKeyPair,
  encryptVariable,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateDek,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  importEncryptionKeyPair,
  importEncryptionPublicKey,
  importSigningKeyPair,
  importSigningPublicKey,
  type LengthPrefixedField,
  type SigningKeyPair,
  SUITE_ID,
  unwrapDek,
  type VariableContext,
  wrapDek,
  type WrappedDek,
} from "./internal.package/index.ts";
