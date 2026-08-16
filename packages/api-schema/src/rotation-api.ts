// 要ローテーションフラグの HttpApi 定義(AUDIT_SPEC §4.1 / §6 / §7 — Wave 2 B2)。
//
// - flags: §4.1 手順 5 の導出(現在有効な recommended − 解消イベント)を
//   サーバーが実行して返す独立の導出ビュー(§7)。可視性はクラス 1
//   (チェーン role reader 以上 = 全メンバー — §6。検出の目的は上流 credential の
//   ローテーション促しであり、admin 限定では機能しない)
// - dismiss: rotation.dismissed の専用操作エンドポイント(§7 — 生イベントの
//   追記 API は作らない。イベントはサーバー側処理が生成する)。admin 以上 ×
//   admin スコープ(§3.3 の記録細則)
//
// 応答は識別子のみを運ぶ(表示名の解決はクライアントが検証済みメタ
// ステートメント — tombstone 含む — で行う。AUDIT_SPEC §7)。

import { EnvironmentIdSchema, ProjectIdSchema, VariableIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/unstable/httpapi";

import { AuthMiddleware } from "./auth-middleware.ts";
import {
  DataLimitExceededError,
  ForbiddenError,
  ProjectNotFoundError,
  RotationFlagNotFoundError,
} from "./errors/index.ts";
import { KeyFingerprintHex, PositiveInt } from "./hex.ts";

/**
 * Evidence rank of a rotation flag (AUDIT_SPEC §4.1 step 3): `read` = the
 * removed subject verifiably fetched the ciphertext during a membership /
 * grant interval, `readable` = it could have.
 */
export const RotationFlagBasisSchema = Schema.Literals(["read", "readable"]);

/**
 * One currently-effective `rotation.recommended` event (AUDIT_SPEC §3.3 —
 * one row per (variable × environment)). Exactly one of `targetUserId`
 * (remove_member variant) / `targetServerKeyFingerprintHex` (revoke_server
 * variant) is present. `triggerChainSeq` is the chain seq of the removal /
 * revocation entry that produced the flag; `seq` is the audit seq of the
 * recommendation row (resolution ordering anchor — §4.1 step 5).
 */
export const RotationFlagSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  variableId: VariableIdSchema,
  basis: RotationFlagBasisSchema,
  targetUserId: Schema.optionalKey(Schema.String),
  targetServerKeyFingerprintHex: Schema.optionalKey(KeyFingerprintHex),
  seq: PositiveInt,
  recommendedAtMs: Schema.Number,
  triggerChainSeq: PositiveInt,
});

/** One (environment, variable) dismissal target (AUDIT_SPEC §7). */
export const RotationDismissTargetSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  variableId: VariableIdSchema,
});

export const rotationGroup = HttpApiGroup.make("rotation")
  .add(
    HttpApiEndpoint.get("flags", "/projects/:projectId/rotation/flags", {
      params: { projectId: ProjectIdSchema },
      success: Schema.Struct({ flags: Schema.Array(RotationFlagSchema) }),
      error: [ProjectNotFoundError, ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("dismiss", "/projects/:projectId/rotation/dismissals", {
      params: { projectId: ProjectIdSchema },
      // 空列挙は Schema 検証の 400(監査痕跡を残す操作の呼び出し形として
      // 意味がない — deks.remove と同じ「黙って成功させない」規律)
      payload: Schema.Struct({
        targets: Schema.Array(RotationDismissTargetSchema).check(Schema.isMinLength(1)),
      }),
      success: HttpApiSchema.NoContent,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        // 有効なフラグの無い対への取り下げ(all-or-nothing で全体を拒否)
        RotationFlagNotFoundError,
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  );
