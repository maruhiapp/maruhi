// メンバーシップログ API の型付きエラー(CRYPTO_SPEC §6.4)。
//
// エラーには識別子・カウンタしか載せない(平文値・鍵素材の断片を運ばない)。

import type { ChainInvalidReason } from "@maruhi/crypto";
import { Schema } from "effect";

// crypto の ChainInvalidReason と同期する理由コード一覧(satisfies で静的検査)。
// 値の実体をここに持つのは、api-schema をランタイムで crypto に依存させないため。
const CHAIN_INVALID_REASONS = [
  "empty-chain",
  "bad-suite",
  "bad-seq",
  "bad-prev-hash",
  "bad-genesis",
  "bad-signature",
  "invalid-payload",
  "insufficient-role",
  "actor-not-member",
  "actor-key-mismatch",
  "last-owner-protected",
  "unknown-target",
  "duplicate-member",
  "unknown-server-grant",
  "grant-scope-narrowed",
  "epoch-out-of-sequence",
] as const satisfies readonly ChainInvalidReason[];

// 逆方向の静的検査: crypto 側に理由コードが追加されたらここがコンパイルエラーになる
type AllReasonsListed = ChainInvalidReason extends (typeof CHAIN_INVALID_REASONS)[number]
  ? true
  : never;
const allReasonsListed: AllReasonsListed = true;
void allReasonsListed;

/** Reason codes a server-side chain verification can reject an entry with. */
export const ChainInvalidReasonSchema = Schema.Literals(CHAIN_INVALID_REASONS);

/** 401: the request presented no valid session cookie or API token. */
export class UnauthorizedError extends Schema.TaggedErrorClass<UnauthorizedError>()(
  "Unauthorized",
  {},
  { httpApiStatus: 401 },
) {}

/** Reason codes for a 403 (AUTH_SPEC §5 CSRF / §9-2 実効権限 / §11-1 / §11-3 / §12-3). */
export const ForbiddenReasonSchema = Schema.Literals([
  "csrf-header-required",
  "insufficient-permission",
  "actor-mismatch",
  "org-membership-required",
  "insufficient-role",
]);

/** 403: the authenticated principal may not perform this operation. */
export class ForbiddenError extends Schema.TaggedErrorClass<ForbiddenError>()(
  "Forbidden",
  { reason: ForbiddenReasonSchema },
  { httpApiStatus: 403 },
) {}

/** Reason codes for a failed authentication flow (AUTH_SPEC §3 / §4). */
export const AuthFlowFailureReasonSchema = Schema.Literals([
  "state-mismatch",
  "code-exchange-failed",
  "github-token-invalid",
]);

/**
 * 400: the OAuth / device-flow dance failed (state mismatch, code exchange
 * rejection, or an invalid GitHub token presented to the device exchange).
 * 提示された外部 ID・トークン値は運ばない(理由コードのみ)。
 */
export class AuthFlowError extends Schema.TaggedErrorClass<AuthFlowError>()(
  "AuthFlow",
  { reason: AuthFlowFailureReasonSchema },
  { httpApiStatus: 400 },
) {}

/** 429: the per-user API token limit has been reached (AUTH_SPEC §6). */
export class TokenLimitError extends Schema.TaggedErrorClass<TokenLimitError>()(
  "TokenLimit",
  { limit: Schema.Number },
  { httpApiStatus: 429 },
) {}

/** 404: no chain has been initialized under this project id. */
export class ProjectNotFoundError extends Schema.TaggedErrorClass<ProjectNotFoundError>()(
  "ProjectNotFound",
  { projectId: Schema.String },
  { httpApiStatus: 404 },
) {}

/** 409: a chain already exists under this project id (duplicate genesis submission). */
export class ProjectAlreadyInitializedError extends Schema.TaggedErrorClass<ProjectAlreadyInitializedError>()(
  "ProjectAlreadyInitialized",
  { projectId: Schema.String },
  { httpApiStatus: 409 },
) {}

/**
 * 409: compare-and-swap failure (CRYPTO_SPEC §6.4) — the append named a parent
 * head that is no longer the current head. The current head is returned so the
 * client can fetch, re-verify, and retry.
 */
export class ChainHeadConflictError extends Schema.TaggedErrorClass<ChainHeadConflictError>()(
  "ChainHeadConflict",
  { currentHeadSeq: Schema.Number, currentHeadHashHex: Schema.String },
  { httpApiStatus: 409 },
) {}

/**
 * 422: server-side chain verification (CRYPTO_SPEC §6.4 = verifyChain の再実行)
 * rejected the entry at `seq` for `reason`.
 */
export class ChainEntryInvalidError extends Schema.TaggedErrorClass<ChainEntryInvalidError>()(
  "ChainEntryInvalid",
  { seq: Schema.Number, reason: ChainInvalidReasonSchema },
  { httpApiStatus: 422 },
) {}

/** 413: the entry's canonical byte length exceeds the §6.4 acceptance policy (1 MiB). */
export class ChainEntryTooLargeError extends Schema.TaggedErrorClass<ChainEntryTooLargeError>()(
  "ChainEntryTooLarge",
  { limitBytes: Schema.Number },
  { httpApiStatus: 413 },
) {}

/**
 * 422: accepting the entry would exceed the §6.4 chain-wide acceptance policy
 * (10,000 entries / 32 MiB cumulative canonical bytes).
 */
export class ChainCapacityExceededError extends Schema.TaggedErrorClass<ChainCapacityExceededError>()(
  "ChainCapacityExceeded",
  { maxEntries: Schema.Number, maxTotalBytes: Schema.Number },
  { httpApiStatus: 422 },
) {}

// ---------------------------------------------------------------------------
// データプレーン API の型付きエラー(AUTH_SPEC §12)。
// チェーン API と同じく、エラーは識別子・カウンタのみを運ぶ(平文値・鍵素材なし)。
// EnvironmentNotFound / VariableNotFound が返るのはチェーン導出メンバーに対して
// のみ(プロジェクト自体の存在秘匿 §11-2 が先行する — §12-3)。
// ---------------------------------------------------------------------------

/** 404: no active environment under this id (returned to chain members only). */
export class EnvironmentNotFoundError extends Schema.TaggedErrorClass<EnvironmentNotFoundError>()(
  "EnvironmentNotFound",
  { environmentId: Schema.String },
  { httpApiStatus: 404 },
) {}

/** 404: no active variable under this id (returned to chain members only). */
export class VariableNotFoundError extends Schema.TaggedErrorClass<VariableNotFoundError>()(
  "VariableNotFound",
  { variableId: Schema.String },
  { httpApiStatus: 404 },
) {}

/**
 * Reason codes for a 409 on environment / variable creation or rename
 * (AUTH_SPEC §12-1): `exists` = the id is in use, `retired` = the id was used
 * before (tombstone or chain-observed epoch) and may not be reused,
 * `duplicate-name` = the display name is taken within the uniqueness scope.
 */
export const ResourceConflictReasonSchema = Schema.Literals([
  "exists",
  "retired",
  "duplicate-name",
]);

/** 409: the environment id or display name conflicts (AUTH_SPEC §12-1 / §12-4). */
export class EnvironmentConflictError extends Schema.TaggedErrorClass<EnvironmentConflictError>()(
  "EnvironmentConflict",
  { environmentId: Schema.String, reason: ResourceConflictReasonSchema },
  { httpApiStatus: 409 },
) {}

/** 409: the variable id or display name conflicts (AUTH_SPEC §12-1 / §12-5). */
export class VariableConflictError extends Schema.TaggedErrorClass<VariableConflictError>()(
  "VariableConflict",
  { variableId: Schema.String, reason: ResourceConflictReasonSchema },
  { httpApiStatus: 409 },
) {}

/**
 * 409: push CAS failure (AUTH_SPEC §12-5) — the declared AAD version is not
 * `currentVersion + 1`. The client re-encrypts under the next version and
 * retries (the version is part of the AAD, so the server cannot renumber).
 */
export class VersionConflictError extends Schema.TaggedErrorClass<VersionConflictError>()(
  "VersionConflict",
  { currentVersion: Schema.Number },
  { httpApiStatus: 409 },
) {}

/**
 * 409: the declared AAD epoch is not the current chain epoch (AUTH_SPEC
 * §12-5). After a rotation the client fetches the new DEK, re-encrypts and
 * retries under `currentEpoch`.
 */
export class EpochConflictError extends Schema.TaggedErrorClass<EpochConflictError>()(
  "EpochConflict",
  { currentEpoch: Schema.Number },
  { httpApiStatus: 409 },
) {}

/**
 * 422: a declared AAD component does not match the storage coordinates named
 * by the request (AUTH_SPEC §12-2). `field` names the mismatching component.
 */
export class PayloadMismatchError extends Schema.TaggedErrorClass<PayloadMismatchError>()(
  "PayloadMismatch",
  { field: Schema.String },
  { httpApiStatus: 422 },
) {}

/** Reason codes for rejecting a DEK-wrap registration (AUTH_SPEC §12-6). */
export const DekWrapRejectReasonSchema = Schema.Literals([
  "recipient-not-member",
  "recipient-key-mismatch",
  "recipient-missing",
  "duplicate-recipient",
  "epoch-out-of-range",
  "signature-invalid",
]);

/**
 * 422: the wrap set violates §12-6 — a recipient is not a current chain
 * member / has a different chain key, the initial registration for an epoch
 * does not cover the member set exactly, a recipient is duplicated, the
 * epoch is outside 1..currentEpoch, or a registration signature does not
 * verify under the caller's chain signing key (CRYPTO_SPEC §5.1).
 */
export class DekWrapRejectedError extends Schema.TaggedErrorClass<DekWrapRejectedError>()(
  "DekWrapRejected",
  { reason: DekWrapRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

/**
 * 409: a wrap for this (environment, epoch, recipient) already exists.
 * Overwriting is forbidden (§12-6: replacing a valid wrap with an
 * undecryptable blob would be an availability attack the server cannot
 * detect).
 */
export class DekWrapExistsError extends Schema.TaggedErrorClass<DekWrapExistsError>()(
  "DekWrapExists",
  { epoch: Schema.Number, recipientUserId: Schema.String },
  { httpApiStatus: 409 },
) {}

/**
 * 404: no wrap is stored for this (environment, epoch, recipient). Returned by
 * the §12-6 repair path (deletion targets must exist — silently succeeding
 * would let an admin believe a poisoned wrap was removed when it was not).
 */
export class DekWrapNotFoundError extends Schema.TaggedErrorClass<DekWrapNotFoundError>()(
  "DekWrapNotFound",
  { epoch: Schema.Number, recipientUserId: Schema.String },
  { httpApiStatus: 404 },
) {}

/** 413: the value ciphertext exceeds the §12-8 acceptance policy (64 KiB). */
export class ValueTooLargeError extends Schema.TaggedErrorClass<ValueTooLargeError>()(
  "ValueTooLarge",
  { limitBytes: Schema.Number },
  { httpApiStatus: 413 },
) {}

/** Resources bounded by the §12-8 count / cumulative-size acceptance policy. */
export const DataLimitResourceSchema = Schema.Literals([
  "environments",
  "environment-rows",
  "variables",
  "variable-rows",
  "versions",
  "project-ciphertext-bytes",
  "dek-wraps-per-request",
  "dek-wrap-rows",
]);

/** 422: accepting the request would exceed a §12-8 count / size limit. */
export class DataLimitExceededError extends Schema.TaggedErrorClass<DataLimitExceededError>()(
  "DataLimitExceeded",
  { resource: DataLimitResourceSchema, limit: Schema.Number },
  { httpApiStatus: 422 },
) {}
