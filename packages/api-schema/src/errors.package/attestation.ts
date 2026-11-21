import { Schema } from "effect";

export const AttestationRejectReasonSchema = Schema.Literals([
  "signature-invalid",
  "chain-head-unknown",
  "chain-head-state-mismatch",
]);

export class AttestationRejectedError extends Schema.TaggedError<AttestationRejectedError>()(
  "AttestationRejected",
  { reason: AttestationRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

export class AttestationRegressionError extends Schema.TaggedError<AttestationRegressionError>()(
  "AttestationRegression",
  { storedSeq: Schema.Number },
  { httpApiStatus: 409 },
) {}

export class AttestationRateLimitedError extends Schema.TaggedError<AttestationRateLimitedError>()(
  "AttestationRateLimited",
  { retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}
