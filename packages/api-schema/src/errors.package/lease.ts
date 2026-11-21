import { Schema } from "effect";

export const LeaseUnauthorizedReasonSchema = Schema.Literals([
  "malformed-token",
  "unsupported-alg",
  "unsupported-crit",
  "unsupported-issuer",
  "unknown-key",
  "signature-invalid",
  "token-expired",
  "token-not-yet-valid",
  "missing-claim",
  "ambiguous-audience",
  "token-replayed",
]);

export class LeaseUnauthorizedError extends Schema.TaggedError<LeaseUnauthorizedError>()(
  "LeaseUnauthorized",
  { reason: LeaseUnauthorizedReasonSchema },
  { httpApiStatus: 401 },
) {}

export const LeaseUnavailableReasonSchema = Schema.Literals([
  "server-wraps-missing",
  "oidc-jwks-unavailable",
  "server-key-unconfigured",
]);

export class LeaseUnavailableError extends Schema.TaggedError<LeaseUnavailableError>()(
  "LeaseUnavailable",
  { reason: LeaseUnavailableReasonSchema },
  { httpApiStatus: 503 },
) {}

export const LeaseRateLimitScopeSchema = Schema.Literals(["project-window", "source-address"]);

export class LeaseRateLimitedError extends Schema.TaggedError<LeaseRateLimitedError>()(
  "LeaseRateLimited",
  {
    retryAfterSeconds: Schema.Number,
    scope: LeaseRateLimitScopeSchema,
  },
  { httpApiStatus: 429 },
) {}
