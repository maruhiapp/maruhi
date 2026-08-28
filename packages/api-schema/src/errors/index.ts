// API エラーのドメイン別バレル(再エクスポートのみ — 定義は各ドメインファイル)。
//
// - auth.ts: 認証・アイデンティティ(AUTH_SPEC §3-§6 / §13)
// - chain.ts: メンバーシップログ(CRYPTO_SPEC §6.4。ChainInvalidReason の
//   実行時ミラーもここ)
// - data.ts: データプレーン(AUTH_SPEC §12)
// - deks.ts: DEK ラップ登録・修復(AUTH_SPEC §12-6)
// - invites.ts: 招待(AUTH_SPEC §15)
// - lease.ts: ワークロードリース(AUTH_SPEC §14)
// - rotation.ts: 要ローテーションフラグ(AUDIT_SPEC §4.1 / §7)

export {
  AuthFlowError,
  AuthFlowFailureReasonSchema,
  AuthRateLimitedError,
  ForbiddenError,
  ForbiddenReasonSchema,
  RecoveryRateLimitedError,
  RecoveryWrapNotFoundError,
  SetupIncompleteError,
  SetupIncompleteReasonSchema,
  TokenLimitError,
  UnauthorizedError,
} from "./auth.ts";
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
  ProjectAlreadyInitializedError,
  ProjectNotFoundError,
} from "./chain.ts";
export {
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
  MetaVersionConflictError,
  NameNotNfcError,
  PayloadMismatchError,
  ResourceConflictReasonSchema,
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
export {
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
export { RotationFlagNotFoundError } from "./rotation.ts";
