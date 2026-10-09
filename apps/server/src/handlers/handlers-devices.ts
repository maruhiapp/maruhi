// Handlers for the device registry and device-add requests
// (AUTH_SPEC §13-11 — 2026-09-19 DK K3).
//
// - The registry is advisory: where display labels, token associations,
//   and request public keys live — never an input to verification or
//   authorization (the source of truth is each project's chain). The
//   server does not touch this ledger on `add_device` /
//   `revoke_device` acceptance, and `revoke_device` does not revoke the
//   token (§6 / design record dk-design.md §6 K1-15)
// - Authorization (§13-11 / §5): `list` is open to every authenticated
//   principal (session principals included —
//   SESSION_ALLOWED_ENDPOINTS). Everything else requires a `*` × admin
//   token only (ensureKeyMaterialAccess — same level as §13-2; session
//   principals are refused)
// - The FP is **recomputed by the server** from the body's public keys
//   and must match the path's `:fp` or 400 (the registry and request
//   rows never get an FP the server did not derive itself). The
//   approving client also recomputes the FP from the response's public
//   keys and compares it against the human-carried FP (anti-swap)
// - No audit events (same discipline as §6's token listing)

import {
  DEVICE_ADD_REQUEST_TTL_MS,
  DeviceFingerprintMismatchError,
  DeviceNotFoundError,
  DeviceRegistryConflictError,
  DeviceRegistryLimitError,
  MAX_DEVICE_ADD_REQUESTS_PER_HOUR,
  MAX_DEVICE_REGISTRY_ROWS_PER_USER,
  maruhiApi,
} from "@maruhi/api-schema";
import { type KeyFingerprintHex, RequestAuth, userKeyFingerprintHex } from "@maruhi/core";
import { decodeHex } from "@maruhi/crypto";
import { Clock, Effect } from "effect";
import { HttpServerResponse } from "effect/http";
import { HttpApiBuilder } from "effect/http-api";

import { ensureKeyMaterialAccess } from "../authz.ts";
import type { DeviceAddRequestRecord, DeviceRecord } from "../db.package/index.ts";
import { DeviceRepo, KeyWrapRepo } from "../db.package/index.ts";

const noContent = HttpServerResponse.empty({ status: 204 });

/**
 * Recomputation of the device-key FP (CRYPTO_SPEC §3 — first 16 bytes
 * of SHA-256(enc ‖ sig)). Since the wire Schema guarantees fixed-length
 * hex, decode / computation failures are defects.
 */
const fingerprintOf = Effect.fn("handlers-devices.fingerprintOf")(function* (
  encPubHex: string,
  sigPubHex: string,
) {
  const enc = decodeHex(encPubHex);
  const sig = decodeHex(sigPubHex);
  if (enc === null || sig === null) {
    return yield* Effect.die(new Error("device public keys are not valid hex"));
  }
  // A wrapped crypto failure stays a defect, like the die the
  // pre-bridge code raised on a failed fingerprint computation
  return yield* userKeyFingerprintHex(enc, sig).pipe(Effect.orDie);
});

/** Match between the path's `:fp` and the FP recomputed from the body's public keys (mismatch = 400). */
const ensureFingerprintMatches = Effect.fn("handlers-devices.ensureFingerprintMatches")(function* (
  fp: KeyFingerprintHex,
  encPubHex: string,
  sigPubHex: string,
) {
  const computed = yield* fingerprintOf(encPubHex, sigPubHex);
  if (computed !== fp) {
    return yield* Effect.fail(new DeviceFingerprintMismatchError());
  }
});

function toSummary(record: DeviceRecord) {
  return {
    keyFingerprintHex: record.keyFingerprintHex,
    encPubHex: record.encPubHex,
    sigPubHex: record.sigPubHex,
    label: record.label,
    ...(record.tokenId === null ? {} : { tokenId: record.tokenId }),
    createdAtMs: record.createdAtMs,
  };
}

function toRequestSummary(record: DeviceAddRequestRecord) {
  return {
    keyFingerprintHex: record.keyFingerprintHex,
    encPubHex: record.encPubHex,
    sigPubHex: record.sigPubHex,
    label: record.label,
    expiresAtMs: record.expiresAtMs,
  };
}

export const devicesLive = HttpApiBuilder.group(maruhiApi, "devices", (handlers) =>
  handlers
    .handle(
      "list",
      Effect.fn("handlers-devices.list")(function* () {
        // Every authenticated principal (session principals have
        // already passed §5's allowed enumeration). The response is the
        // caller's own rows only (userId is server-derived — there is
        // structurally no surface to probe someone else's registry)
        const principal = yield* (yield* RequestAuth).principal;
        const repo = yield* DeviceRepo;
        const rows = yield* repo.list(principal.userId);
        return { devices: rows.map(toSummary) };
      }),
    )
    .handle(
      "register",
      Effect.fn("handlers-devices.register")(function* ({ params, payload }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        yield* ensureFingerprintMatches(params.fp, payload.encPubHex, payload.sigPubHex);
        const repo = yield* DeviceRepo;
        const admitted = yield* repo.upsert({
          userId: principal.userId,
          keyFingerprintHex: params.fp,
          encPubHex: payload.encPubHex,
          sigPubHex: payload.sigPubHex,
          label: payload.label,
          tokenId: payload.tokenId ?? null,
          limit: MAX_DEVICE_REGISTRY_ROWS_PER_USER,
          nowMs: yield* Clock.currentTimeMillis,
        });
        if (!admitted) {
          return yield* Effect.fail(
            new DeviceRegistryLimitError({
              reason: "device-rows",
              limit: MAX_DEVICE_REGISTRY_ROWS_PER_USER,
            }),
          );
        }
        return noContent;
      }),
    )
    .handle(
      "remove",
      Effect.fn("handlers-devices.remove")(function* ({ params }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* DeviceRepo;
        const removed = yield* repo.remove(principal.userId, params.fp);
        if (!removed) {
          return yield* Effect.fail(new DeviceNotFoundError());
        }
        return noContent;
      }),
    )
    .handle(
      "requestCreate",
      Effect.fn("handlers-devices.requestCreate")(function* ({ payload }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const nowMs = yield* Clock.currentTimeMillis;
        const repo = yield* DeviceRepo;
        // Opportunistic deletion (the caller's own expired requests)
        yield* repo.requestSweep(principal.userId, nowMs);
        // Fixed window of 5 per hour per user (§13-11). The window
        // implementation is shared with the ledger's fixed windows
        // (key_wrap_windows kind `device-request` — design record §8
        // K3-8). The check precedes the collision check (repeated
        // rejections also consume the window — same discipline as the
        // ledger's windows)
        const decision = yield* (yield* KeyWrapRepo).consumeWindow({
          userId: principal.userId,
          kind: "device-request",
          limit: MAX_DEVICE_ADD_REQUESTS_PER_HOUR,
          nowMs,
        });
        if (!decision.allowed) {
          return yield* Effect.fail(
            new DeviceRegistryLimitError({
              reason: "add-requests",
              limit: MAX_DEVICE_ADD_REQUESTS_PER_HOUR,
              retryAfterSeconds: decision.retryAfterSeconds,
            }),
          );
        }
        const keyFingerprintHex = yield* fingerprintOf(payload.encPubHex, payload.sigPubHex);
        const outcome = yield* repo.requestCreate({
          userId: principal.userId,
          keyFingerprintHex,
          encPubHex: payload.encPubHex,
          sigPubHex: payload.sigPubHex,
          label: payload.label,
          nowMs,
          ttlMs: DEVICE_ADD_REQUEST_TTL_MS,
        });
        if (outcome !== "created") {
          return yield* Effect.fail(new DeviceRegistryConflictError({ reason: outcome }));
        }
        return { expiresAtMs: nowMs + DEVICE_ADD_REQUEST_TTL_MS };
      }),
    )
    .handle(
      "requestList",
      Effect.fn("handlers-devices.requestList")(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const nowMs = yield* Clock.currentTimeMillis;
        const repo = yield* DeviceRepo;
        yield* repo.requestSweep(principal.userId, nowMs);
        const rows = yield* repo.requestList(principal.userId, nowMs);
        return { requests: rows.map(toRequestSummary) };
      }),
    )
    .handle(
      "requestGet",
      Effect.fn("handlers-devices.requestGet")(function* ({ params }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* DeviceRepo;
        const row = yield* repo.requestFind(
          principal.userId,
          params.fp,
          yield* Clock.currentTimeMillis,
        );
        if (row === null) {
          return yield* Effect.fail(new DeviceNotFoundError());
        }
        return toRequestSummary(row);
      }),
    )
    .handle(
      "requestCancel",
      Effect.fn("handlers-devices.requestCancel")(function* ({ params }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* DeviceRepo;
        const removed = yield* repo.requestCancel(principal.userId, params.fp);
        if (!removed) {
          return yield* Effect.fail(new DeviceNotFoundError());
        }
        return noContent;
      }),
    ),
);
