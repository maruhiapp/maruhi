import { KeyFingerprintHexSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/http-api";

import { TokenNameSchema } from "./auth-api.ts";
import { AuthMiddleware } from "./auth-middleware.ts";
import {
  DeviceFingerprintMismatchError,
  DeviceNotFoundError,
  DeviceRegistryConflictError,
  DeviceRegistryLimitError,
  ForbiddenError,
} from "./errors.package/index.ts";
import { EncPubHex, PublicKeyHex } from "./hex.ts";
import { strictPayload } from "./strict.ts";

export const MAX_DEVICE_REGISTRY_ROWS_PER_USER = 32;
export const MAX_DEVICE_ADD_REQUESTS_PER_HOUR = 5;
export const DEVICE_ADD_REQUEST_TTL_MS = 15 * 60 * 1000;

export const DeviceLabelSchema = TokenNameSchema.check(Schema.isMinLength(1));

export const DeviceSummarySchema = Schema.Struct({
  keyFingerprintHex: KeyFingerprintHexSchema,
  encPubHex: EncPubHex,
  sigPubHex: PublicKeyHex,
  label: DeviceLabelSchema,
  tokenId: Schema.optionalKey(Schema.String),
  createdAtMs: Schema.Number,
});

export const DeviceRegistrationSchema = Schema.Struct({
  encPubHex: EncPubHex,
  sigPubHex: PublicKeyHex,
  label: DeviceLabelSchema,
  tokenId: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(128))),
});

export const DeviceAddRequestSchema = Schema.Struct({
  encPubHex: EncPubHex,
  sigPubHex: PublicKeyHex,
  label: DeviceLabelSchema,
});

export const DeviceAddRequestSummarySchema = Schema.Struct({
  keyFingerprintHex: KeyFingerprintHexSchema,
  encPubHex: EncPubHex,
  sigPubHex: PublicKeyHex,
  label: DeviceLabelSchema,
  expiresAtMs: Schema.Number,
});

export const DeviceListSchema = Schema.Struct({ devices: Schema.Array(DeviceSummarySchema) });

export const DeviceAddRequestCreateResultSchema = Schema.Struct({ expiresAtMs: Schema.Number });

export const DeviceAddRequestListSchema = Schema.Struct({
  requests: Schema.Array(DeviceAddRequestSummarySchema),
});

const fingerprintParams = { fp: KeyFingerprintHexSchema };

export const devicesGroup = HttpApiGroup.make("devices")
  .add(
    HttpApiEndpoint.get("list", "/auth/devices", {
      success: DeviceListSchema,
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.put("register", "/auth/devices/:fp", {
      params: fingerprintParams,
      payload: strictPayload(DeviceRegistrationSchema),
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, DeviceFingerprintMismatchError, DeviceRegistryLimitError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.delete("remove", "/auth/devices/:fp", {
      params: fingerprintParams,
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, DeviceNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("requestCreate", "/auth/devices/requests", {
      payload: strictPayload(DeviceAddRequestSchema),
      success: DeviceAddRequestCreateResultSchema,
      error: [ForbiddenError, DeviceRegistryConflictError, DeviceRegistryLimitError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("requestList", "/auth/devices/requests", {
      success: DeviceAddRequestListSchema,
      error: [ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("requestGet", "/auth/devices/requests/:fp", {
      params: fingerprintParams,
      success: DeviceAddRequestSummarySchema,
      error: [ForbiddenError, DeviceNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.delete("requestCancel", "/auth/devices/requests/:fp", {
      params: fingerprintParams,
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, DeviceNotFoundError],
    }).middleware(AuthMiddleware),
  );
