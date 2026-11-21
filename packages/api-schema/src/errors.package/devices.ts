import { Schema } from "effect";

export class DeviceNotFoundError extends Schema.TaggedError<DeviceNotFoundError>()(
  "DeviceNotFound",
  {},
  { httpApiStatus: 404 },
) {}

export class DeviceFingerprintMismatchError extends Schema.TaggedError<DeviceFingerprintMismatchError>()(
  "DeviceFingerprintMismatch",
  {},
  { httpApiStatus: 400 },
) {}

export const DeviceRegistryConflictReasonSchema = Schema.Literals([
  "request-exists",
  "device-registered",
]);

export class DeviceRegistryConflictError extends Schema.TaggedError<DeviceRegistryConflictError>()(
  "DeviceRegistryConflict",
  { reason: DeviceRegistryConflictReasonSchema },
  { httpApiStatus: 409 },
) {}

export const DeviceRegistryLimitReasonSchema = Schema.Literals(["device-rows", "add-requests"]);

export class DeviceRegistryLimitError extends Schema.TaggedError<DeviceRegistryLimitError>()(
  "DeviceRegistryLimit",
  {
    reason: DeviceRegistryLimitReasonSchema,
    limit: Schema.Number,
    retryAfterSeconds: Schema.optionalKey(Schema.Number),
  },
  { httpApiStatus: 429 },
) {}
