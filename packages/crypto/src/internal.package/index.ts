// internal.package の公開面。ここから再輸出したものだけが境界の外(src/index.ts)へ出る。
// 公開 API は最小に保つ(CLAUDE.md)。

export { decodeHex, encodeHex } from "./bytes.ts";
export {
  buildDekWrapInfo,
  type DekWrapContext,
  unwrapDek,
  wrapDek,
  type WrappedDek,
} from "./dek-wrap.ts";
export { SUITE_ID } from "./suite.ts";
export {
  buildVariableAad,
  decryptVariable,
  type EncryptedVariable,
  encryptVariable,
  type VariableContext,
} from "./variable.ts";
export { encodeLengthPrefixed, type LengthPrefixedField } from "./encoding.ts";
export { type ChainInvalidReason, type CryptoError, type CryptoResult } from "./errors.ts";
export {
  computeServerKeyFingerprint,
  computeUserKeyFingerprint,
  type EncryptionKey,
  type EncryptionKeyPair,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateDek,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  importEncryptionKeyPair,
  importEncryptionPublicKey,
  importSigningKeyPair,
  importSigningPublicKey,
  type SigningKeyPair,
} from "./keys.ts";
