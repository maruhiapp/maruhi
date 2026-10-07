// @maruhi/crypto — the E2EE core (WebCrypto + HPKE).
// docs/CRYPTO_SPEC.md is the sole source of truth for the crypto spec. Changes to
// this package require human review.
// Implementations must pass every vector in test-vectors/.
//
// Runs in every environment (browser / Bun / workerd): no primitives other than
// WebCrypto + panva hpke.
// Errors are returned as typed error values (CryptoResult); Effect wrapping is
// done on the packages/core side.
//
// Exports are grouped by CRYPTO_SPEC section (the grouping does not change the set).

// §1-§2: common — suite identifier, encoding conventions (§2.1), result types
export {
  type AeadOperation,
  type CryptoError,
  type CryptoResult,
  decodeHex,
  encodeHex,
  encodeLengthPrefixed,
  type LengthPrefixedField,
  SUITE_ID,
} from "./internal.package/index.ts";

// §3: key hierarchy — master key pair / DEK generation, key import/export,
// user key fingerprints, FP word rendering (BIP39 English 12 words — the
// display encoding for out-of-band reconciliation. The dictionary is
// published as §3's fixed dictionary — completeness is pinned by a test
// against a known upstream hash)
export {
  BIP39_ENGLISH_WORDS,
  computeUserKeyFingerprint,
  deriveEncryptionKeyPair,
  FINGERPRINT_WORD_COUNT,
  fingerprintToWords,
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
} from "./internal.package/index.ts";

// §4: variable encryption — AES-GCM with coordinate-bound AAD
export {
  buildVariableAad,
  decryptVariable,
  type EncryptedVariable,
  encryptVariable,
  type VariableContext,
} from "./internal.package/index.ts";

// §4.1: value write signatures
export {
  buildValueSignedBytes,
  computeValueSignedBytesHash,
  type DistributedValueInput,
  signValue,
  type ValueInvalidReason,
  type ValuePredecessor,
  type ValueSignatureContext,
  verifyDistributedValue,
  verifyValueSignature,
} from "./internal.package/index.ts";

// §4.2: signed statements of variable / environment metadata (including
// layout v3 — schema columns, declared, max age, layout selection)
export {
  buildMetaSignedBytes,
  computeMetaSignedBytesHash,
  type DistributedMetaStatementInput,
  metaLayoutVersionOf,
  type MetaInvalidReason,
  type MetaPredecessor,
  type MetaStatementContext,
  type MetaStatementStatus,
  type MetaStatementTarget,
  type MetaVariableSchema,
  type MetaVarType,
  signMetaStatement,
  isMetaMaxAgeDays,
  MAX_META_MAX_AGE_DAYS,
  SUPPORTED_META_LAYOUT_VERSIONS,
  verifyDistributedMetaStatement,
  verifyMetaStatementSignature,
} from "./internal.package/index.ts";

// §4.3: environment manifest (the freshness anchor of the meta layer —
// epoch baking + variable-set digest. The canonical implementation lives
// exactly here, shared by server / CLI)
export {
  buildEnvManifestSignedBytes,
  computeEnvManifestSignedBytesHash,
  computeVariablesDigest,
  type DistributedEnvManifestInput,
  type EnvManifestContext,
  type EnvManifestEnvMeta,
  type EnvManifestPredecessor,
  manifestContextInvalidField,
  type ManifestInvalidReason,
  signEnvManifest,
  type VariablesDigestEntry,
  verifyDistributedEnvManifest,
  verifyEnvManifestSignature,
} from "./internal.package/index.ts";

// §5: key wrap (HPKE)
export {
  buildDekWrapInfo,
  type DekWrapContext,
  unwrapDek,
  wrapDek,
  type WrappedDek,
} from "./internal.package/index.ts";

// §5.1: registration signature of DEK wraps
export {
  buildDekWrapSignatureBytes,
  type DekWrapSignatureContext,
  signDekWrap,
  verifyDekWrapSignature,
} from "./internal.package/index.ts";

// §5.2: the epoch DEK commitment (authenticity bound by the chain)
export {
  buildDekCommitmentBytes,
  computeDekCommitment,
  type DekCommitmentContext,
  verifyDekCommitment,
} from "./internal.package/index.ts";

// §6: membership log (signed hash chain) — entry format (§6.1), roles and
// operation kinds (§6.2 — including 2026-09-14 ES's environment scope and
// PF1's four-eyes), verification (§6.3 / §6.4), derived state
export {
  type AddDevicePayload,
  type AddMemberPayload,
  ALL_SCOPE,
  APPROVAL_TARGET_OPS,
  type ApprovalPolicy,
  type ApprovalTargetOp,
  approvalSignersOf,
  type ApprovalVote,
  type ApprovePayload,
  canonicalChainEntryBytes,
  canonicalChainPayloadBytes,
  canonicalChainSignedBytes,
  type ChainActor,
  type ChainDevice,
  type ChainEntry,
  type ChainHistoryIndex,
  type ChainInvalidReason,
  type ChainMember,
  type ChainOp,
  type ChainOperation,
  type ChainState,
  type ChangeRolePayload,
  type CheckpointEnvironmentEntry,
  type CheckpointPayload,
  type CheckpointTupleLookup,
  computeChainEntryHash,
  computeEnvValuesDigest,
  type CreateEnvironmentPayload,
  type DeleteEnvironmentPayload,
  type DeviceCap,
  type DeviceStateAtSeq,
  type EffectivePermission,
  effectivePermissionOf,
  type EnvironmentChainState,
  type EnvironmentCheckpointState,
  type EnvironmentStateAtSeq,
  type EnvValuesDigestEntry,
  type EnvValuesDigestSource,
  type GenesisPayload,
  type GrantServerPayload,
  isApprovalTarget,
  isApprovalTargetOp,
  ownerVotersOf,
  type LeaseClaimConstraint,
  type LeasePolicyIssuer,
  MAX_SCOPE_ENVIRONMENTS,
  type MemberScope,
  memberScopeOf,
  type MemberStateAtSeq,
  type PendingProposal,
  type ProposableOperation,
  type ProposePayload,
  type RemoveMemberPayload,
  type RevokeDevicePayload,
  type RevokeServerPayload,
  type Role,
  type RotateEpochPayload,
  type ScopeKind,
  type ScopePayloadFields,
  scopeIncludesEnvironment,
  scopePayloadFieldsOf,
  selectEnvValuesDigestEntries,
  type ServerGrant,
  type SetApprovalPolicyPayload,
  signChainEntry,
  soleDeviceOf,
  type UnsignedChainEntry,
  type UserId,
  verifyChain,
  verifyChainWithHistory,
  type WithdrawPayload,
} from "./internal.package/index.ts";

// AUDIT_SPEC §5.1: the audit-head rolling hash (the input of checkpoint's
// audit_head_hash — §6.2). Generation = the project DO's acceptance side;
// verification = the admin cross-check (AUDIT_SPEC §6) share this one
// implementation
export {
  type AuditHeadRow,
  computeAuditHeadHash,
  computeAuditRowDigest,
} from "./internal.package/index.ts";

// §6.5: the crypto side of invites (2026-09-13 IV) — link keys, issuance
// signatures, acceptance co-signatures, the OpenSSH public-key line
// (interoperability with the backing source; additional evidence outside the
// chain. Mutual-confirmation display uses §3's fingerprintToWords, the link
// anchor §6.3 — both existing exports)
export {
  buildInviteAcceptSignedBytes,
  buildInviteIssueSignedBytes,
  deriveInviteLinkKeyPair,
  encodeOpenSshEd25519PublicKey,
  generateInviteLinkSeed,
  INVITE_LINK_SEED_BYTES,
  type InviteAcceptSignatureContext,
  type InviteIssueContext,
  type InviteLinkKeyPair,
  parseOpenSshEd25519PublicKey,
  signInviteAccept,
  signInviteIssue,
  signInviteLink,
  verifyInviteAcceptSignature,
  verifyInviteIssueSignature,
  verifyInviteLinkSignature,
} from "./internal.package/index.ts";

// §6.6: head attestation (the attestation form of §6.3 head gossip — a
// signed declaration outside the chain. Submission side = AUTH_SPEC §16-1,
// server verification = §6.4, reconciliation rules = §6.3)
export {
  type AttestationInvalidReason,
  buildHeadAttestationSignedBytes,
  computeHeadAttestationSignedBytesHash,
  type DistributedHeadAttestationInput,
  type HeadAttestationContext,
  signHeadAttestation,
  verifyDistributedHeadAttestation,
  verifyHeadAttestationSignature,
} from "./internal.package/index.ts";

// §7: epoch and membership changes — no export surface (workflow rules only)

// §8: master-key wrap ledger — the recovery-code path (unchanged)
export {
  generateRecoverySecret,
  unwrapMasterSecret,
  type WrappedMasterSecret,
  wrapMasterSecret,
} from "./internal.package/index.ts";

// §8.1-8.4 (0.9-draft / KL3): the ledger's new recipient classes —
// passkey-prf KEK derivation, wrapping B under the master-wrap AAD,
// guardian groups (XOR split + HPKE Seal of shares), handoff (Seal to an
// ephemeral key, request_id, handoff code)
export {
  buildGuardianWrapInfo,
  buildHandoffWrapInfo,
  buildMasterWrapAad,
  computeHandoffRequestId,
  decodeHandoffCode,
  derivePasskeyKek,
  encodeHandoffCode,
  generateMasterWrapKek,
  type GuardianMode,
  type GuardianWrapContext,
  type HandoffWrapContext,
  joinGuardianShares,
  type MasterWrapContext,
  type MasterWrapKind,
  openGuardianShare,
  openHandoffValue,
  sealGuardianShare,
  sealHandoffValue,
  splitGuardianKek,
  unwrapMasterBlob,
  wrapMasterBlob,
} from "./internal.package/index.ts";

// §5.3: sealed value proposals (the same primitive as §5; the info binds
// the proposal and variable ids — a workload's proposed value, stored
// sealed to the accepting members' device keys)
export {
  buildSealedValueInfo,
  isProposalId,
  MAX_SEALED_VALUE_BYTES,
  openProposedValue,
  PROPOSAL_ID_BYTES,
  type SealedValue,
  type SealedValueContext,
  sealProposedValue,
} from "./internal.package/index.ts";

// §9: selective disclosure (server keys)
export { computeServerKeyFingerprint } from "./internal.package/index.ts";

// §9.1: workload leases — the lease wrap (the same primitive as §5; the
// info binds claims_digest). Wraps are response-scoped and never persisted
export {
  buildLeaseClaimsBytes,
  buildLeaseWrapInfo,
  computeLeaseClaimsDigest,
  type LeaseClaims,
  type LeaseWrapContext,
  unwrapLeaseDek,
  wrapLeaseDek,
} from "./internal.package/index.ts";
