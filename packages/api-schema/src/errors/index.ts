// API エラーのドメイン別バレル(再エクスポートのみ — 定義は各ドメインファイル)。
//
// - auth.ts: 認証・アイデンティティ(AUTH_SPEC §3-§6 / §13)
// - chain.ts: メンバーシップログ(CRYPTO_SPEC §6.4。ChainInvalidReason の
//   実行時ミラーもここ)
// - data.ts: データプレーン(AUTH_SPEC §12)
// - deks.ts: DEK ラップ登録・修復(AUTH_SPEC §12-6)

export {
  AuthFlowError,
  AuthFlowFailureReasonSchema,
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
  DataLimitExceededError,
  DataLimitResourceSchema,
  EnvironmentConflictError,
  EnvironmentConflictReasonSchema,
  EnvironmentNotFoundError,
  EpochConflictError,
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
