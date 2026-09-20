// 端末登録簿・端末追加要求 API の型付きエラー(AUTH_SPEC §13-11 — 2026-09-19 DK K3)。
//
// 登録簿は advisory(検証・認可の入力にならない)。エラーには識別子・理由コード・
// カウンタしか載せない(公開鍵・FP は要求側が送った値であり、エラーに写さない —
// 呼び出し側の値をエラーに映さない規律は TokenNotFound と同じ)。

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
