// Typed errors of the device-registry / device-add-request API
// (AUTH_SPEC §13-11 — 2026-09-19 DK K3).
//
// The registry is advisory (never an input to verification or
// authorization). Errors carry only identifiers, reason codes, and
// counters (public keys and FPs are values the requester sent and are
// not copied into the error — the discipline of not reflecting the
// caller's values into errors is the same as TokenNotFound).

import { Schema } from "effect";

/**
 * 404: no registry row / add request is addressable by the caller under this
 * fingerprint (AUTH_SPEC §13-11). Uniform for "absent" and "expired" — the
 * registry is per-user, so no other user's rows are ever reachable.
 */
export class DeviceNotFoundError extends Schema.TaggedError<DeviceNotFoundError>()(
  "DeviceNotFound",
  {},
  { httpApiStatus: 404 },
) {}

/**
 * 400: the `:fp` path parameter does not equal the fingerprint recomputed from
 * the body's public keys (CRYPTO_SPEC §3 — SHA-256(enc ‖ sig)[:16]). The
 * registry never stores a fingerprint the server did not derive itself.
 */
export class DeviceFingerprintMismatchError extends Schema.TaggedError<DeviceFingerprintMismatchError>()(
  "DeviceFingerprintMismatch",
  {},
  { httpApiStatus: 400 },
) {}

/**
 * 409 reasons (AUTH_SPEC §13-11): `request-exists` = an unexpired add request
 * with the same fingerprint is already pending; `device-registered` = the
 * registry already holds this fingerprint (approve or delete it first).
 */
export const DeviceRegistryConflictReasonSchema = Schema.Literals([
  "request-exists",
  "device-registered",
]);

/** 409: the add request collides with a pending request or a registered device. */
export class DeviceRegistryConflictError extends Schema.TaggedError<DeviceRegistryConflictError>()(
  "DeviceRegistryConflict",
  { reason: DeviceRegistryConflictReasonSchema },
  { httpApiStatus: 409 },
) {}

/**
 * 429 reasons (AUTH_SPEC §13-11 — acceptance policy, not a consensus rule):
 * `device-rows` = the registry already holds the per-user maximum (32);
 * `add-requests` = the per-user fixed window for add requests (5 per hour) is
 * exhausted (`retryAfterSeconds` = remaining window).
 */
export const DeviceRegistryLimitReasonSchema = Schema.Literals(["device-rows", "add-requests"]);

/** 429: a §13-11 registry limit or request window is exhausted. */
export class DeviceRegistryLimitError extends Schema.TaggedError<DeviceRegistryLimitError>()(
  "DeviceRegistryLimit",
  {
    reason: DeviceRegistryLimitReasonSchema,
    limit: Schema.Number,
    retryAfterSeconds: Schema.optionalKey(Schema.Number),
  },
  { httpApiStatus: 429 },
) {}
