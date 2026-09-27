// Typed errors of the head-attestation API (CRYPTO_SPEC §6.6 / AUTH_SPEC
// §16-1).
//
// Errors carry only identifiers and counters (no fragments of plaintext
// values or key material).

import { Schema } from "effect";

/**
 * Refusal reasons of the attestation's acceptance verification
 * (CRYPTO_SPEC §6.4). The mapping from crypto's detailed reasons folds
 * the same way as value signatures (ValueSignatureRejectReason):
 *
 * - `signature-invalid` — signature verification failed under the
 *   calling principal's chain-derived sig key at acceptance time
 * - `chain-head-unknown` — the declared head's (hash + seq) exact pair
 *   does not exist on the server's own chain (including the case where
 *   the seq is ahead of the current head — the client-side re-sync
 *   branch does not exist on the server)
 * - `chain-head-state-mismatch` — mismatch of membership / key binding
 *   at the declared head (includes refusing a head declaration for a
 *   stale membership interval after remove → re-add under a different
 *   key)
 */
export const AttestationRejectReasonSchema = Schema.Literals([
  "signature-invalid",
  "chain-head-unknown",
  "chain-head-state-mismatch",
]);

/** 422: the head-attestation acceptance verification rejected the submission. */
export class AttestationRejectedError extends Schema.TaggedError<AttestationRejectedError>()(
  "AttestationRejected",
  { reason: AttestationRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

/**
 * 409: seq regression against the stored attestation (CRYPTO_SPEC §6.4 /
 * AUTH_SPEC §16-1 — the "don't silently succeed" discipline). The stored seq is returned: an
 * honest client hitting this indicates floor damage or a concurrent CLI whose
 * view regressed, which must surface instead of being silently swallowed.
 * Resubmitting the same seq is idempotent (204), so this only fires on a
 * strict regression.
 */
export class AttestationRegressionError extends Schema.TaggedError<AttestationRegressionError>()(
  "AttestationRegression",
  { storedSeq: Schema.Number },
  { httpApiStatus: 409 },
) {}

/**
 * 429: the per-member fixed-window submission limit is exhausted
 * (AUTH_SPEC §16-1 — drafted value: 60 per hour).
 */
export class AttestationRateLimitedError extends Schema.TaggedError<AttestationRateLimitedError>()(
  "AttestationRateLimited",
  { retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}
