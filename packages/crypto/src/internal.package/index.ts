// internal.package の公開面。ここから再輸出したものだけが境界の外(src/index.ts)へ出る。
// 公開 API は最小に保つ(CLAUDE.md)。

export { decodeHex, encodeHex } from "./bytes.ts";
export {
  canonicalChainEntryBytes,
  canonicalChainPayloadBytes,
  canonicalChainSignedBytes,
  computeChainEntryHash,
} from "./chain-canonical.ts";
export {
  type ChainHistoryIndex,
  type CheckpointTupleLookup,
  type EnvironmentStateAtSeq,
  type MemberStateAtSeq,
} from "./chain-history.ts";
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
  type CheckpointEnvironmentEntry,
  type CheckpointPayload,
  type CreateEnvironmentPayload,
  type EnvironmentChainState,
  type EnvironmentCheckpointState,
  type GenesisPayload,
  type GrantServerPayload,
  type LeaseClaimConstraint,
  type LeasePolicyIssuer,
  type RemoveMemberPayload,
  type RevokeServerPayload,
  type Role,
  type RotateEpochPayload,
  type ServerGrant,
  type UnsignedChainEntry,
} from "./chain-types.ts";
export { verifyChain, verifyChainWithHistory } from "./chain-verify.ts";
export {
  computeEnvValuesDigest,
  type EnvValuesDigestEntry,
  type EnvValuesDigestSource,
  selectEnvValuesDigestEntries,
} from "./values-digest.ts";
export { type AuditHeadRow, computeAuditHeadHash, computeAuditRowDigest } from "./audit-head.ts";
export {
  buildDekCommitmentBytes,
  computeDekCommitment,
  type DekCommitmentContext,
  verifyDekCommitment,
} from "./dek-commitment.ts";
export {
  buildDekWrapInfo,
  type DekWrapContext,
  unwrapDek,
  wrapDek,
  type WrappedDek,
} from "./dek-wrap.ts";
export {
  buildDekWrapSignatureBytes,
  type DekWrapSignatureContext,
  signDekWrap,
  verifyDekWrapSignature,
} from "./dek-wrap-sign.ts";
export {
  buildInviteAcceptSignedBytes,
  type InviteAcceptSignatureContext,
  signInviteAccept,
  verifyInviteAcceptSignature,
} from "./invite-accept-sign.ts";
export {
  buildLeaseClaimsBytes,
  buildLeaseWrapInfo,
  computeLeaseClaimsDigest,
  type LeaseClaims,
  type LeaseWrapContext,
  unwrapLeaseDek,
  wrapLeaseDek,
} from "./lease-wrap.ts";
export {
  generateRecoverySecret,
  unwrapMasterSecret,
  type WrappedMasterSecret,
  wrapMasterSecret,
} from "./recovery.ts";
export { SUITE_ID } from "./suite.ts";
export {
  buildVariableAad,
  decryptVariable,
  type EncryptedVariable,
  encryptVariable,
  type VariableContext,
} from "./variable.ts";
export { encodeLengthPrefixed, type LengthPrefixedField } from "./encoding.ts";
export {
  type AttestationInvalidReason,
  type ChainInvalidReason,
  type CryptoError,
  type CryptoResult,
  type ManifestInvalidReason,
  type MetaInvalidReason,
  type ValueInvalidReason,
} from "./errors.ts";
export {
  buildHeadAttestationSignedBytes,
  computeHeadAttestationSignedBytesHash,
  type DistributedHeadAttestationInput,
  type HeadAttestationContext,
  signHeadAttestation,
  verifyDistributedHeadAttestation,
  verifyHeadAttestationSignature,
} from "./head-attestation.ts";
export {
  buildEnvManifestSignedBytes,
  computeEnvManifestSignedBytesHash,
  computeVariablesDigest,
  type EnvManifestContext,
  manifestContextInvalidField,
  signEnvManifest,
  type VariablesDigestEntry,
  verifyEnvManifestSignature,
} from "./manifest-sign.ts";
export {
  type DistributedEnvManifestInput,
  type EnvManifestEnvMeta,
  type EnvManifestPredecessor,
  verifyDistributedEnvManifest,
} from "./manifest-verify.ts";
export {
  buildMetaSignedBytes,
  computeMetaSignedBytesHash,
  metaLayoutVersionOf,
  type MetaStatementContext,
  type MetaStatementStatus,
  type MetaStatementTarget,
  type MetaVariableSchema,
  type MetaVarType,
  signMetaStatement,
  SUPPORTED_META_LAYOUT_VERSIONS,
  verifyMetaStatementSignature,
} from "./meta-sign.ts";
export {
  type DistributedMetaStatementInput,
  type MetaPredecessor,
  verifyDistributedMetaStatement,
} from "./meta-verify.ts";
export {
  buildValueSignedBytes,
  computeValueSignedBytesHash,
  signValue,
  type ValueSignatureContext,
  verifyValueSignature,
} from "./value-sign.ts";
export {
  type DistributedValueInput,
  type ValuePredecessor,
  verifyDistributedValue,
} from "./value-verify.ts";
export { BIP39_ENGLISH_WORDS } from "./bip39-english.ts";
export { FINGERPRINT_WORD_COUNT, fingerprintToWords } from "./fingerprint-words.ts";
export {
  computeServerKeyFingerprint,
  computeUserKeyFingerprint,
  deriveEncryptionKeyPair,
  type EncryptionKey,
  type EncryptionKeyPair,
  exportEncryptionPrivateKey,
  exportEncryptionPublicKey,
  exportSigningPrivateSeed,
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
