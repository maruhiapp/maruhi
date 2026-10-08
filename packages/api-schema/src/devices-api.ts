// HttpApi definition of the device registry and device-add requests
// (AUTH_SPEC §13-11 — 2026-09-19 DK K3).
//
// - The source of truth for device keys is each project's chain
//   (CRYPTO_SPEC §6.2 — `add_device` / `revoke_device`). This group's
//   registry is **a place for display names, token associations, and the
//   public keys of add requests**; it is **never an input to any
//   verification or authorization** (advisory). A server inserting a row
//   does not add a device on the client
// - Authorization (§13-11 / §5): `list` (reading the registry) is open to
//   every authenticated principal (session principals too —
//   SESSION_ALLOWED_ENDPOINTS). Writes and requests are `*` × admin
//   tokens only (same level as the §13-2 key-material condition; session
//   principals are refused)
// - "Approval" is not an API: the approving device recomputes the FP
//   from the request's public key and `add_device`s to each project's
//   chain only the one that matches the FP a human carried over
// - Carries no secrets (public keys, FPs, display names, token ids only).
//   Has no audit events (the same discipline as the §6 token list —
//   device additions and revocations are recorded by the chain's mirror
//   rows)

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
} from "./errors/index.ts";
import { EncPubHex, PublicKeyHex } from "./hex.ts";
import { strictPayload } from "./strict.ts";

/** Device-registry acceptance policy (AUTH_SPEC §13-11 — not a consensus rule). */
export const MAX_DEVICE_REGISTRY_ROWS_PER_USER = 32;
/** Device-add requests: a fixed window of 5 per hour per user. */
export const MAX_DEVICE_ADD_REQUESTS_PER_HOUR = 5;
/** Lifetime of a device-add request (15 minutes). */
export const DEVICE_ADD_REQUEST_TTL_MS = 15 * 60 * 1000;

/**
 * Display name of a device (§13-11 — same acceptance discipline as the
 * §6 token name: no control or bidi control characters, 128 characters
 * or fewer). Empty is not allowed (a registry row carries the name a
 * human chose).
 */
export const DeviceLabelSchema = TokenNameSchema.check(Schema.isMinLength(1));

/** One registry row (`GET /auth/devices`). Carries no secrets. */
export const DeviceSummarySchema = Schema.Struct({
  keyFingerprintHex: KeyFingerprintHexSchema,
  encPubHex: EncPubHex,
  sigPubHex: PublicKeyHex,
  label: DeviceLabelSchema,
  /** Optional: the API token id of this device (§6 — advisory; never an input to authorization). */
  tokenId: Schema.optionalKey(Schema.String),
  createdAtMs: Schema.Number,
});

/** Body of registry registration / display-name update (`PUT /auth/devices/:fp`). */
export const DeviceRegistrationSchema = Schema.Struct({
  encPubHex: EncPubHex,
  sigPubHex: PublicKeyHex,
  label: DeviceLabelSchema,
  tokenId: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(128))),
});

/** Body of device-add request creation (`POST /auth/devices/requests`). */
export const DeviceAddRequestSchema = Schema.Struct({
  encPubHex: EncPubHex,
  sigPubHex: PublicKeyHex,
  label: DeviceLabelSchema,
});

/**
 * One device-add request row (for the approving device). **The approving
 * client recomputes the FP from the response's public key and ignores
 * anything that does not match the FP a human carried over** (a server
 * swapping the public key is caught by the FP comparison — §13-11).
 */
export const DeviceAddRequestSummarySchema = Schema.Struct({
  keyFingerprintHex: KeyFingerprintHexSchema,
  encPubHex: EncPubHex,
  sigPubHex: PublicKeyHex,
  label: DeviceLabelSchema,
  expiresAtMs: Schema.Number,
});

/** Response envelope of the registry listing (`GET /auth/devices`) (K5 follow-up (0) — the web reads it via the derived type). */
export const DeviceListSchema = Schema.Struct({ devices: Schema.Array(DeviceSummarySchema) });

/**
 * Response of request creation (`POST /auth/devices/requests`): the
 * request's expiry (`DEVICE_ADD_REQUEST_TTL_MS` later). Not shared with
 * the guardian handoff's `HandoffCreateResultSchema` because the
 * expiry's meaning differs (DK K9-4).
 */
export const DeviceAddRequestCreateResultSchema = Schema.Struct({ expiresAtMs: Schema.Number });

/** Response envelope of the request listing (`GET /auth/devices/requests` — the caller's own unexpired requests). */
export const DeviceAddRequestListSchema = Schema.Struct({
  requests: Schema.Array(DeviceAddRequestSummarySchema),
});

const fingerprintParams = { fp: KeyFingerprintHexSchema };

/**
 * Device registry and device-add request endpoints (AUTH_SPEC §13-11 — DK K3).
 * HTTP statuses follow the §13-11 table: reads and request creation / listing
 * return 200; registry writes, deletions and request cancellation return 204.
 */
export const devicesGroup = HttpApiGroup.make("devices")
  .add(
    // Reading the registry: every authenticated principal (session principals too — the §5 allowlist)
    HttpApiEndpoint.get("list", "/auth/devices", {
      success: DeviceListSchema,
    }).middleware(AuthMiddleware),
  )
  .add(
    // Registry registration / display-name update (upsert). `fp` must
    // equal the value recomputed from the body's public key (400). Rows
    // are capped at 32 per user (429 — updates do not count toward the
    // cap)
    HttpApiEndpoint.put("register", "/auth/devices/:fp", {
      params: fingerprintParams,
      // strict acceptance (§12-10 (1) — registering a public key = the
      // key-declaration class; unknown fields are not silently dropped)
      payload: strictPayload(DeviceRegistrationSchema),
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, DeviceFingerprintMismatchError, DeviceRegistryLimitError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // Deletion from the registry (deleting an advisory — independent of
    // chain revocation). 404 when absent
    HttpApiEndpoint.delete("remove", "/auth/devices/:fp", {
      params: fingerprintParams,
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, DeviceNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // Creating an add request (the new device itself — it has already
    // logged in via §4). A creation's success is the HttpApi default 200
    // (same as §13-7). A conflict with an existing request of the same FP
    // or an existing registry row is 409
    HttpApiEndpoint.post("requestCreate", "/auth/devices/requests", {
      payload: strictPayload(DeviceAddRequestSchema),
      success: DeviceAddRequestCreateResultSchema,
      error: [ForbiddenError, DeviceRegistryConflictError, DeviceRegistryLimitError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // Listing add requests (for the approving device — the caller only).
    // Expired rows are not included
    HttpApiEndpoint.get("requestList", "/auth/devices/requests", {
      success: DeviceAddRequestListSchema,
      error: [ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // Fetching an add request (the caller only). Unknown and expired
    // requests are a uniform 404
    HttpApiEndpoint.get("requestGet", "/auth/devices/requests/:fp", {
      params: fingerprintParams,
      success: DeviceAddRequestSummarySchema,
      error: [ForbiddenError, DeviceNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // Cancelling an add request (the caller only). The client removes it
    // after approval. 404 when absent
    HttpApiEndpoint.delete("requestCancel", "/auth/devices/requests/:fp", {
      params: fingerprintParams,
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, DeviceNotFoundError],
    }).middleware(AuthMiddleware),
  );
