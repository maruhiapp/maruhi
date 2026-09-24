// 端末登録簿と端末追加要求の HttpApi 定義(AUTH_SPEC §13-11 — 2026-09-19 DK K3)。
//
// - 端末鍵の真実源は各プロジェクトのチェーン(CRYPTO_SPEC §6.2 — `add_device` /
//   `revoke_device`)。本グループの登録簿は**表示名・トークンの対応・追加要求の
//   公開鍵の置き場**であり、**いかなる検証・認可の入力にもならない**(advisory)。
//   サーバーが行を差し込んでもクライアントは端末を足さない
// - 認可(§13-11 / §5): `list`(登録簿の読み取り)は認証済み主体すべて(セッション
//   主体も可 — SESSION_ALLOWED_ENDPOINTS)。書き込みと要求は `*` × admin トークン
//   のみ(§13-2 の鍵素材条件と同水準。セッション主体は拒否)
// - 「承認」は API ではない: 承認端末は要求の公開鍵から FP を再計算し、人が運んだ
//   FP と一致するものだけを各プロジェクトのチェーンへ `add_device` する
// - 秘密を運ばない(公開鍵・FP・表示名・トークン id のみ)。監査イベントは持たない
//   (§6 のトークン一覧と同じ規律 — 端末の追加・失効の記録はチェーンのミラー行)

import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/unstable/httpapi";

import { TokenNameSchema } from "./auth-api.ts";
import { AuthMiddleware } from "./auth-middleware.ts";
import {
  DeviceFingerprintMismatchError,
  DeviceNotFoundError,
  DeviceRegistryConflictError,
  DeviceRegistryLimitError,
  ForbiddenError,
} from "./errors/index.ts";
import { EncPubHex, KeyFingerprintHex, PublicKeyHex } from "./hex.ts";
import { strictPayload } from "./strict.ts";

/** 端末登録簿の受理ポリシー(AUTH_SPEC §13-11 — 合意規則ではない)。 */
export const MAX_DEVICE_REGISTRY_ROWS_PER_USER = 32;
/** 端末追加要求: user あたり固定窓 1 時間 5 回。 */
export const MAX_DEVICE_ADD_REQUESTS_PER_HOUR = 5;
/** 端末追加要求の有効期間(15 分)。 */
export const DEVICE_ADD_REQUEST_TTL_MS = 15 * 60 * 1000;

/**
 * 端末の表示名(§13-11 — §6 のトークン名と同じ受理規律: 制御文字・bidi 制御文字
 * なし・128 文字以下)。空は許さない(登録簿の行は人が選ぶ名前を持つ)。
 */
export const DeviceLabelSchema = TokenNameSchema.check(Schema.isMinLength(1));

/** 登録簿 1 行(`GET /auth/devices`)。秘密を運ばない。 */
export const DeviceSummarySchema = Schema.Struct({
  keyFingerprintHex: KeyFingerprintHex,
  encPubHex: EncPubHex,
  sigPubHex: PublicKeyHex,
  label: DeviceLabelSchema,
  /** 任意: この端末の API トークン id(§6 — advisory。認可の入力にしない)。 */
  tokenId: Schema.optionalKey(Schema.String),
  createdAtMs: Schema.Number,
});

/** 登録簿の登録・表示名の更新(`PUT /auth/devices/:fp`)の body。 */
export const DeviceRegistrationSchema = Schema.Struct({
  encPubHex: EncPubHex,
  sigPubHex: PublicKeyHex,
  label: DeviceLabelSchema,
  tokenId: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(128))),
});

/** 端末追加要求の作成(`POST /auth/devices/requests`)の body。 */
export const DeviceAddRequestSchema = Schema.Struct({
  encPubHex: EncPubHex,
  sigPubHex: PublicKeyHex,
  label: DeviceLabelSchema,
});

/**
 * 端末追加要求 1 行(承認端末向け)。**承認クライアントは応答の公開鍵から FP を
 * 再計算し、人が運んだ FP と一致するもの以外を無視する**(サーバーによる公開鍵の
 * すり替えは FP 照合で落ちる — §13-11)。
 */
export const DeviceAddRequestSummarySchema = Schema.Struct({
  keyFingerprintHex: KeyFingerprintHex,
  encPubHex: EncPubHex,
  sigPubHex: PublicKeyHex,
  label: DeviceLabelSchema,
  expiresAtMs: Schema.Number,
});

/** 登録簿の一覧(`GET /auth/devices`)の応答 envelope(K5 申し送り (0) — Web が導出型で読む)。 */
export const DeviceListSchema = Schema.Struct({ devices: Schema.Array(DeviceSummarySchema) });

/**
 * 追加要求の作成(`POST /auth/devices/requests`)の応答: 要求の期限
 * (`DEVICE_ADD_REQUEST_TTL_MS` 後)。保護者ハンドオフの `HandoffCreateResultSchema` とは
 * 期限の意味が違うので共有しない(DK K9-4)。
 */
export const DeviceAddRequestCreateResultSchema = Schema.Struct({ expiresAtMs: Schema.Number });

/** 追加要求の一覧(`GET /auth/devices/requests` — 本人の未失効の要求)の応答 envelope。 */
export const DeviceAddRequestListSchema = Schema.Struct({
  requests: Schema.Array(DeviceAddRequestSummarySchema),
});

const fingerprintParams = { fp: KeyFingerprintHex };

/**
 * Device registry and device-add request endpoints (AUTH_SPEC §13-11 — DK K3).
 * HTTP statuses follow the §13-11 table: reads and request creation / listing
 * return 200; registry writes, deletions and request cancellation return 204.
 */
export const devicesGroup = HttpApiGroup.make("devices")
  .add(
    // 登録簿の読み取り: 認証済み主体すべて(セッション主体も可 — §5 の許可列挙)
    HttpApiEndpoint.get("list", "/auth/devices", {
      success: DeviceListSchema,
    }).middleware(AuthMiddleware),
  )
  .add(
    // 登録簿の登録・表示名の更新(upsert)。`fp` は body の公開鍵から再計算した値と
    // 一致すること(400)。行は user あたり 32 まで(429 — 更新は上限に数えない)
    HttpApiEndpoint.put("register", "/auth/devices/:fp", {
      params: fingerprintParams,
      // strict 受理(§12-10 (1) — 公開鍵の登録 = 鍵宣言クラス。未知フィールドを黙って落とさない)
      payload: strictPayload(DeviceRegistrationSchema),
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, DeviceFingerprintMismatchError, DeviceRegistryLimitError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // 登録簿からの削除(advisory の削除 — チェーンの失効とは独立)。無ければ 404
    HttpApiEndpoint.delete("remove", "/auth/devices/:fp", {
      params: fingerprintParams,
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, DeviceNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // 追加要求の作成(新端末自身 — 先に §4 でログインしている)。作成系の成功は
    // HttpApi の既定 200(§13-7 と同じ)。同じ FP の要求・登録簿の既存行との衝突は 409
    HttpApiEndpoint.post("requestCreate", "/auth/devices/requests", {
      payload: strictPayload(DeviceAddRequestSchema),
      success: DeviceAddRequestCreateResultSchema,
      error: [ForbiddenError, DeviceRegistryConflictError, DeviceRegistryLimitError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // 追加要求の一覧(承認する端末 — 本人のみ)。失効行は含めない
    HttpApiEndpoint.get("requestList", "/auth/devices/requests", {
      success: DeviceAddRequestListSchema,
      error: [ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // 追加要求の照会(本人のみ)。不明・失効は一様 404
    HttpApiEndpoint.get("requestGet", "/auth/devices/requests/:fp", {
      params: fingerprintParams,
      success: DeviceAddRequestSummarySchema,
      error: [ForbiddenError, DeviceNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // 追加要求の取消(本人のみ)。承認後にクライアントが消す。無ければ 404
    HttpApiEndpoint.delete("requestCancel", "/auth/devices/requests/:fp", {
      params: fingerprintParams,
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, DeviceNotFoundError],
    }).middleware(AuthMiddleware),
  );
