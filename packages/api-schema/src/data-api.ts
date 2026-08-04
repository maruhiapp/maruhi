// データプレーン(環境・変数・DEK)の HttpApi 定義(AUTH_SPEC §12)。
// サーバー実装(apps/server)と将来の CLI クライアント導出の共有源。
//
// 認可の規律(§12-3): 全エンドポイント認証必須(AuthMiddleware)。非メンバー・
// スコープ外は一律 404(§11-2)。EnvironmentNotFound / VariableNotFound が返る
// のはチェーン導出メンバーに対してのみ。
//
// 表示名は平文メタデータ(CRYPTO_SPEC §4)。上限 256 文字は §12-8 の受理
// ポリシー(値と違い専用の検証層がないため Schema で強制する)。

import { EnvironmentIdSchema, ProjectIdSchema, VariableIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/unstable/httpapi";

import { AuthMiddleware } from "./auth-middleware.ts";
import { CreateEnvironmentEntrySchema, RotateEpochEntrySchema } from "./chain.ts";
import {
  DekWrapRefSchema,
  EncryptedPayloadSchema,
  RecipientDekSchema,
  WrappedDekSchema,
} from "./data.ts";
import {
  ChainCapacityExceededError,
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  ChainHeadConflictError,
  DataLimitExceededError,
  DekWrapExistsError,
  DekWrapNotFoundError,
  DekWrapRejectedError,
  EnvironmentConflictError,
  EnvironmentNotFoundError,
  EpochConflictError,
  ForbiddenError,
  PayloadMismatchError,
  ProjectNotFoundError,
  ValueTooLargeError,
  VariableConflictError,
  VariableNotFoundError,
  VersionConflictError,
} from "./errors.ts";

/** Display name of an environment or variable (§12-8: 256 chars max). */
const ResourceNameSchema = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256));

const projectParams = { projectId: ProjectIdSchema };
const environmentParams = { projectId: ProjectIdSchema, environmentId: EnvironmentIdSchema };
const variableParams = {
  projectId: ProjectIdSchema,
  environmentId: EnvironmentIdSchema,
  variableId: VariableIdSchema,
};

/** One active environment (current epoch is chain-derived — CRYPTO_SPEC §3). */
export const EnvironmentSummarySchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  name: ResourceNameSchema,
  currentEpoch: Schema.Number,
});

/**
 * Result of a composite environment creation / rotation (AUTH_SPEC §12-4):
 * the accepted chain head (the entry was appended atomically with the data)
 * plus the resulting current epoch.
 */
export const EnvironmentChainResultSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  currentEpoch: Schema.Number,
  headSeq: Schema.Number,
  headHashHex: Schema.String,
});

/** Result of accepting a variable version (creation is version 1 — §12-5). */
export const VariableVersionSchema = Schema.Struct({
  variableId: VariableIdSchema,
  version: Schema.Number,
  epoch: Schema.Number,
});

/** One variable in a bulk pull: its latest version, self-describing via the AAD. */
export const PulledVariableSchema = Schema.Struct({
  variableId: VariableIdSchema,
  name: ResourceNameSchema,
  value: EncryptedPayloadSchema,
});

/**
 * Bulk pull of one environment (§12-7): every active variable's latest
 * version plus every epoch's DEK wrapped for the caller (latest versions may
 * span epochs until a rotation's re-encryption completes — CRYPTO_SPEC §7).
 */
export const EnvironmentPullSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  name: ResourceNameSchema,
  currentEpoch: Schema.Number,
  variables: Schema.Array(PulledVariableSchema),
  deks: Schema.Array(RecipientDekSchema),
});

/**
 * Environment management (AUTH_SPEC §12-4。2026-08-03 セッション 12 改訂 —
 * 環境作成のチェーン op 化に追随)。
 *
 * - `create` is a composite request: the `create_environment` chain entry
 *   (environment id + epoch-1 DEK commitment, appended with a parent-head
 *   CAS), the display name, and the complete epoch-1 DEK wrap set for the
 *   current member set — accepted atomically by the project DO. An
 *   environment never exists without its commitment and its members' wraps.
 *   PR-1 の意図的な中間状態: 表示名は裸の `name` のまま運ぶ
 *   (`EnvironmentMetaStatement` の同梱 — CRYPTO_SPEC §4.2 — は PR-3)。
 * - `rotate` is the composite rotation: the `rotate_epoch` entry (new-epoch
 *   commitment) plus the complete new-epoch wrap set, replacing the former
 *   two-step "generic chain append + DEK registration" flow. Re-encryption
 *   of current values stays a follow-up push (§12-7).
 */
export const environmentsGroup = HttpApiGroup.make("environments")
  .add(
    HttpApiEndpoint.post("create", "/projects/:projectId/environments", {
      params: projectParams,
      payload: Schema.Struct({
        parentHeadHashHex: Schema.String,
        entry: CreateEnvironmentEntrySchema,
        name: ResourceNameSchema,
        deks: Schema.Array(WrappedDekSchema),
      }),
      success: EnvironmentChainResultSchema,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        EnvironmentConflictError,
        ChainHeadConflictError,
        ChainEntryInvalidError,
        ChainEntryTooLargeError,
        ChainCapacityExceededError,
        DekWrapRejectedError,
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("rotate", "/projects/:projectId/environments/:environmentId/rotate", {
      params: environmentParams,
      payload: Schema.Struct({
        parentHeadHashHex: Schema.String,
        entry: RotateEpochEntrySchema,
        deks: Schema.Array(WrappedDekSchema),
      }),
      success: EnvironmentChainResultSchema,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        // 削除済み(tombstone)環境への rotate は 404(§12-4 — §7 の「全環境」は
        // 削除済みを含まない)
        EnvironmentNotFoundError,
        // URL の environmentId と entry.payload.environmentId の不一致(複合内整合検査)
        PayloadMismatchError,
        ChainHeadConflictError,
        ChainEntryInvalidError,
        ChainEntryTooLargeError,
        ChainCapacityExceededError,
        DekWrapRejectedError,
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("list", "/projects/:projectId/environments", {
      params: projectParams,
      success: Schema.Struct({ environments: Schema.Array(EnvironmentSummarySchema) }),
      error: [ProjectNotFoundError, ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.patch("rename", "/projects/:projectId/environments/:environmentId", {
      params: environmentParams,
      payload: Schema.Struct({ name: ResourceNameSchema }),
      success: HttpApiSchema.NoContent,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        EnvironmentNotFoundError,
        EnvironmentConflictError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.delete("remove", "/projects/:projectId/environments/:environmentId", {
      params: environmentParams,
      success: HttpApiSchema.NoContent,
      error: [ProjectNotFoundError, ForbiddenError, EnvironmentNotFoundError],
    }).middleware(AuthMiddleware),
  );

/**
 * Variable CRUD, versioned pushes and the bulk pull (AUTH_SPEC §12-5 / §12-7).
 * A push is a CAS: the declared AAD must name the current chain epoch and the
 * next version; conflicts return the current values for a client retry.
 */
export const variablesGroup = HttpApiGroup.make("variables")
  .add(
    HttpApiEndpoint.post("create", "/projects/:projectId/environments/:environmentId/variables", {
      params: environmentParams,
      payload: Schema.Struct({
        variableId: VariableIdSchema,
        name: ResourceNameSchema,
        value: EncryptedPayloadSchema,
      }),
      success: VariableVersionSchema,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        EnvironmentNotFoundError,
        VariableConflictError,
        PayloadMismatchError,
        VersionConflictError,
        EpochConflictError,
        ValueTooLargeError,
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post(
      "push",
      "/projects/:projectId/environments/:environmentId/variables/:variableId/versions",
      {
        params: variableParams,
        payload: Schema.Struct({ value: EncryptedPayloadSchema }),
        success: VariableVersionSchema,
        error: [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableNotFoundError,
          PayloadMismatchError,
          VersionConflictError,
          EpochConflictError,
          ValueTooLargeError,
          DataLimitExceededError,
        ],
      },
    ).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.patch(
      "rename",
      "/projects/:projectId/environments/:environmentId/variables/:variableId",
      {
        params: variableParams,
        payload: Schema.Struct({ name: ResourceNameSchema }),
        success: HttpApiSchema.NoContent,
        error: [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableNotFoundError,
          VariableConflictError,
        ],
      },
    ).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.delete(
      "remove",
      "/projects/:projectId/environments/:environmentId/variables/:variableId",
      {
        params: variableParams,
        success: HttpApiSchema.NoContent,
        error: [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableNotFoundError,
        ],
      },
    ).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("pull", "/projects/:projectId/environments/:environmentId/pull", {
      params: environmentParams,
      success: EnvironmentPullSchema,
      error: [ProjectNotFoundError, ForbiddenError, EnvironmentNotFoundError],
    }).middleware(AuthMiddleware),
  );

/**
 * DEK wrap registration, distribution and repair (AUTH_SPEC §12-6).
 * Registration covers both the full-set path (environment creation /
 * post-rotation) and the backfill path (wrapping historical epochs for a
 * newly added member). Distribution is caller-only: a member fetches the
 * wraps addressed to them. Deletion is the admin-only repair path for
 * poisoned wraps (overwriting stays forbidden); the deleted slots are then
 * re-registered through the append path.
 */
export const deksGroup = HttpApiGroup.make("deks")
  .add(
    HttpApiEndpoint.post("register", "/projects/:projectId/environments/:environmentId/deks", {
      params: environmentParams,
      // 空の deks は 400(§12-6。削除側の空 wraps と同じ「黙って成功させない」
      // 規律 — 2026-08-03 に 204 no-op から統一)。環境作成の deks は対象外
      // (空集合は完全一致要件の 422 recipient-missing が先に意味を持つ)
      payload: Schema.Struct({ deks: Schema.Array(WrappedDekSchema).check(Schema.isMinLength(1)) }),
      success: HttpApiSchema.NoContent,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        EnvironmentNotFoundError,
        DekWrapRejectedError,
        DekWrapExistsError,
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("listMine", "/projects/:projectId/environments/:environmentId/deks", {
      params: environmentParams,
      success: Schema.Struct({ deks: Schema.Array(RecipientDekSchema) }),
      error: [ProjectNotFoundError, ForbiddenError, EnvironmentNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // 削除対象は body で列挙する: recipientUserId はチェーン合意規則上の自由
    // 文字列(1024 バイト以下)であり、パス断片として安全に表現できないため。
    // 空列挙は 400(監査痕跡ゼロの破壊系呼び出し形を許さない — §12-6)
    HttpApiEndpoint.delete("remove", "/projects/:projectId/environments/:environmentId/deks", {
      params: environmentParams,
      payload: Schema.Struct({
        wraps: Schema.Array(DekWrapRefSchema).check(Schema.isMinLength(1)),
      }),
      success: HttpApiSchema.NoContent,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        EnvironmentNotFoundError,
        DekWrapNotFoundError,
        DekWrapRejectedError,
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  );
