// 端末登録簿と端末追加要求のハンドラ(AUTH_SPEC §13-11 — 2026-09-19 DK K3)。
//
// - 登録簿は advisory: 表示名・トークンの対応・追加要求の公開鍵の置き場であり、
//   検証・認可の入力にならない(真実源は各プロジェクトのチェーン)。サーバーは
//   `add_device` / `revoke_device` の受理でこの帳簿に触れず、`revoke_device` で
//   トークンも失効させない(§6 / 設計録 dk-design.md §6 K1-15)
// - 認可(§13-11 / §5): `list` は認証済み主体すべて(セッション主体も可 —
//   SESSION_ALLOWED_ENDPOINTS)。それ以外は `*` × admin トークンのみ
//   (ensureKeyMaterialAccess — §13-2 と同水準。セッション主体は拒否)
// - FP は body の公開鍵から**サーバーが再計算**し、パスの `:fp` と一致しなければ
//   400(登録簿・要求行に自分で導出しない FP を書かない)。承認クライアントも
//   応答の公開鍵から FP を再計算して人が運んだ FP と照合する(すり替え対策)
// - 監査イベントは持たない(§6 のトークン一覧と同じ規律)

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
import { RequestAuth } from "@maruhi/core";
import { computeUserKeyFingerprint, decodeHex, encodeHex } from "@maruhi/crypto";
import { Effect } from "effect";
import { HttpServerResponse } from "effect/unstable/http";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { ensureKeyMaterialAccess } from "./authz.ts";
import type { DeviceAddRequestRecord, DeviceRecord } from "./db.package/index.ts";
import { DeviceRepo, KeyWrapRepo } from "./db.package/index.ts";

const noContent = HttpServerResponse.empty({ status: 204 });

/**
 * 端末鍵 FP の再計算(CRYPTO_SPEC §3 — SHA-256(enc ‖ sig) の先頭 16 バイト)。
 * ワイヤ Schema が固定長 hex を保証するため decode / 計算の失敗は defect。
 */
const fingerprintOf = (encPubHex: string, sigPubHex: string) =>
  Effect.gen(function* () {
    const enc = decodeHex(encPubHex);
    const sig = decodeHex(sigPubHex);
    if (enc === null || sig === null) {
      return yield* Effect.die(new Error("device public keys are not valid hex"));
    }
    const digest = yield* Effect.promise(() => computeUserKeyFingerprint(enc, sig));
    if (!digest.ok) {
      return yield* Effect.die(new Error("device fingerprint computation failed"));
    }
    return encodeHex(digest.value);
  });

/** パスの `:fp` と body の公開鍵から再計算した FP の一致(不一致 = 400)。 */
const ensureFingerprintMatches = (fp: string, encPubHex: string, sigPubHex: string) =>
  Effect.gen(function* () {
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
    .handle("list", () =>
      Effect.gen(function* () {
        // 認証済み主体すべて(セッション主体は §5 の許可列挙を通過済み)。応答は
        // 本人の行のみ(userId はサーバー導出 — 他人の登録簿を探れる面が構造的に無い)
        const principal = yield* (yield* RequestAuth).principal;
        const repo = yield* DeviceRepo;
        const rows = yield* repo.list(principal.userId);
        return { devices: rows.map(toSummary) };
      }),
    )
    .handle("register", ({ params, payload }) =>
      Effect.gen(function* () {
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
          nowMs: Date.now(),
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
    .handle("remove", ({ params }) =>
      Effect.gen(function* () {
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
    .handle("requestCreate", ({ payload }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const nowMs = Date.now();
        const repo = yield* DeviceRepo;
        // 日和見削除(失効した自分の要求)
        yield* repo.requestSweep(principal.userId, nowMs);
        // 固定窓 5 回 / 時 / user(§13-11)。窓の実装は台帳の固定窓と共有する
        // (key_wrap_windows の種別 `device-request` — 設計録 §8 K3-8)。判定は
        // 衝突検査より前(拒否の反復も窓を消費する — 台帳の窓と同じ規律)
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
    .handle("requestList", () =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const nowMs = Date.now();
        const repo = yield* DeviceRepo;
        yield* repo.requestSweep(principal.userId, nowMs);
        const rows = yield* repo.requestList(principal.userId, nowMs);
        return { requests: rows.map(toRequestSummary) };
      }),
    )
    .handle("requestGet", ({ params }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* DeviceRepo;
        const row = yield* repo.requestFind(principal.userId, params.fp, Date.now());
        if (row === null) {
          return yield* Effect.fail(new DeviceNotFoundError());
        }
        return toRequestSummary(row);
      }),
    )
    .handle("requestCancel", ({ params }) =>
      Effect.gen(function* () {
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
