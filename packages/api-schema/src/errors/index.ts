// Barrel of API errors by domain (re-exports only — definitions live in
// the per-domain files).
//
// - auth.ts: authentication / identity (AUTH_SPEC §3-§6 / §13)
// - chain.ts: membership log (CRYPTO_SPEC §6.4; the runtime mirror of
//   ChainInvalidReason lives here too)
// - data.ts: data plane (AUTH_SPEC §12)
// - deks.ts: DEK-wrap registration / repair (AUTH_SPEC §12-6)
// - invites.ts: invites (AUTH_SPEC §15)
// - lease.ts: workload leases (AUTH_SPEC §14)
// - rotation.ts: rotation-required flags (AUDIT_SPEC §4.1 / §7)

export {
  AuthFlowError,
  AuthFlowFailureReasonSchema,
  AuthRateLimitedError,
  CliFlowExpiredError,
  CliFlowRejectedError,
  ForbiddenError,
  ForbiddenReasonSchema,
  RecoveryRateLimitedError,
  RecoveryWrapNotFoundError,
  SetupIncompleteError,
  SetupIncompleteReasonSchema,
  TokenLimitError,
  TokenNotFoundError,
  UnauthorizedError,
} from "./auth.ts";
export {
  DeviceFingerprintMismatchError,
  DeviceNotFoundError,
  DeviceRegistryConflictError,
  DeviceRegistryConflictReasonSchema,
  DeviceRegistryLimitError,
  DeviceRegistryLimitReasonSchema,
} from "./devices.ts";
export {
  HandoffConflictError,
  HandoffConflictReasonSchema,
  HandoffNotFoundError,
  KeyWrapNotFoundError,
  KeyWrapPolicyError,
  KeyWrapPolicyReasonSchema,
  KeyWrapRateLimitedError,
  KeyWrapWindowSchema,
} from "./key-wraps.ts";
export {
  AttestationRateLimitedError,
  AttestationRegressionError,
  AttestationRejectedError,
  AttestationRejectReasonSchema,
} from "./attestation.ts";
export {
  ChainCapacityExceededError,
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  ChainHeadConflictError,
  ChainInvalidReasonSchema,
  CompositeRequiredError,
  DeviceLimitError,
  ProjectAlreadyInitializedError,
  ProjectLimitError,
  ProjectNotFoundError,
  ProposalLimitError,
  ProposalLimitReasonSchema,
} from "./chain.ts";
export {
  ActivationRequiredError,
  AuditHeadNotReadyError,
  CheckpointMismatchReasonSchema,
  CheckpointStateMismatchError,
  DataLimitExceededError,
  DataLimitResourceSchema,
  EnvironmentConflictError,
  EnvironmentConflictReasonSchema,
  EnvironmentNotFoundError,
  EpochConflictError,
  ManifestRejectedError,
  ManifestRejectReasonSchema,
  ManifestVersionConflictError,
  MetaStatementRejectedError,
  MetaStatementRejectReasonSchema,
  MetaVersionConflictError,
  NameNotNfcError,
  PayloadMismatchError,
  ResourceConflictReasonSchema,
  SchemaDescriptionRejectedError,
  SchemaDescriptionRejectReasonSchema,
  SchemaPolicyRejectedError,
  SchemaPolicyRejectReasonSchema,
  ValueSignatureRejectedError,
  ValueSignatureRejectReasonSchema,
  ValueTooLargeError,
  VariableConflictError,
  VariableNotFoundError,
  VersionConflictError,
} from "./data.ts";
export {
  DekWrapExistsError,
  DekWrapNotFoundError,
  DekWrapRejectedError,
  DekWrapRejectReasonSchema,
} from "./deks.ts";
export { ExportChangedError, ExportRateLimitedError } from "./export.ts";
export {
  InviteConflictError,
  InviteGoneError,
  InviteGoneReasonSchema,
  InviteNotFoundError,
  InvitePendingLimitError,
  InviteRateLimitedError,
  InviteSignatureInvalidError,
} from "./invites.ts";
export {
  LeaseRateLimitedError,
  LeaseRateLimitScopeSchema,
  LeaseUnauthorizedError,
  LeaseUnauthorizedReasonSchema,
  LeaseUnavailableError,
  LeaseUnavailableReasonSchema,
} from "./lease.ts";
export {
  RotationFlagNotFoundError,
  RotationProposalNotFoundError,
  RotationProposalRejectedError,
  RotationProposalRejectReasonSchema,
} from "./rotation.ts";
