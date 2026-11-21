import { AUTH_FLOW_FAILURE_REASONS } from "@maruhi/core";
import { Schema } from "effect";

export class UnauthorizedError extends Schema.TaggedError<UnauthorizedError>()(
  "Unauthorized",
  {},
  { httpApiStatus: 401 },
) {}

export const ForbiddenReasonSchema = Schema.Literals([
  "csrf-header-required",
  "session-not-allowed",
  "insufficient-permission",
  "actor-mismatch",
  "org-membership-required",
  "insufficient-role",
  "insufficient-scope",
  "mirror-read-only",
]);

export class ForbiddenError extends Schema.TaggedError<ForbiddenError>()(
  "Forbidden",
  { reason: ForbiddenReasonSchema },
  { httpApiStatus: 403 },
) {}

export const AuthFlowFailureReasonSchema = Schema.Literals(AUTH_FLOW_FAILURE_REASONS);

export class AuthFlowError extends Schema.TaggedError<AuthFlowError>()(
  "AuthFlow",
  { reason: AuthFlowFailureReasonSchema },
  { httpApiStatus: 400 },
) {}

export const SetupIncompleteReasonSchema = Schema.Literals([
  "github-oauth-unconfigured",
  "rate-limit-unconfigured",
]);

export class SetupIncompleteError extends Schema.TaggedError<SetupIncompleteError>()(
  "SetupIncomplete",
  { reason: SetupIncompleteReasonSchema },
  { httpApiStatus: 503 },
) {}

export class AuthRateLimitedError extends Schema.TaggedError<AuthRateLimitedError>()(
  "AuthRateLimited",
  { retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}

export class CliFlowExpiredError extends Schema.TaggedError<CliFlowExpiredError>()(
  "CliFlowExpired",
  {},
  { httpApiStatus: 410 },
) {}

export class CliFlowRejectedError extends Schema.TaggedError<CliFlowRejectedError>()(
  "CliFlowRejected",
  {},
  { httpApiStatus: 400 },
) {}

export class TokenLimitError extends Schema.TaggedError<TokenLimitError>()(
  "TokenLimit",
  { limit: Schema.Number },
  { httpApiStatus: 429 },
) {}

export class TokenNotFoundError extends Schema.TaggedError<TokenNotFoundError>()(
  "TokenNotFound",
  {},
  { httpApiStatus: 404 },
) {}

export class RecoveryWrapNotFoundError extends Schema.TaggedError<RecoveryWrapNotFoundError>()(
  "RecoveryWrapNotFound",
  {},
  { httpApiStatus: 404 },
) {}

export class RecoveryRateLimitedError extends Schema.TaggedError<RecoveryRateLimitedError>()(
  "RecoveryRateLimited",
  { retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}
