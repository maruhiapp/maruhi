// internal.package の公開面。ここから再輸出したものだけが境界の外(src/index.ts)へ出る。
// 公開 API は最小に保つ(CLAUDE.md)。

export { decodeHex, encodeHex } from "./bytes.ts";
export {
  canonicalChainEntryBytes,
  canonicalChainPayloadBytes,
  canonicalChainSignedBytes,
  computeChainEntryHash,
} from "./chain-canonical.ts";
export { signChainEntry } from "./chain-sign.ts";
export {
  type AddMemberPayload,
  type ChainActor,
  type ChainEntry,
  type ChainMember,
  type ChainOp,
  type ChainOperation,
  type ChainState,
  type ChangeRolePayload,
  type GenesisPayload,
  type GrantServerPayload,
  type RemoveMemberPayload,
  type RevokeServerPayload,
  type Role,
  type RotateEpochPayload,
  type ServerGrant,
  type UnsignedChainEntry,
} from "./chain-types.ts";
export { verifyChain } from "./chain-verify.ts";
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
