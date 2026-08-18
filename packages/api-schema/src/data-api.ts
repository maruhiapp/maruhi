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
  CreateEnvironmentManifestSchema,
  CreateEnvironmentMetaStatementSchema,
  CreateVariableMetaStatementSchema,
  DekWrapRefSchema,
  DeleteEnvironmentMetaStatementSchema,
  DeleteVariableMetaStatementSchema,
  DistributedEncryptedPayloadSchema,
  DistributedEnvironmentManifestSchema,
  DistributedEnvironmentMetaStatementSchema,
  DistributedVariableMetaStatementSchema,
  EncryptedPayloadSchema,
  EnvironmentManifestSchema,
  RecipientDekSchema,
  RenameEnvironmentMetaStatementSchema,
  RenameVariableMetaStatementSchema,
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
  ManifestRejectedError,
  ManifestVersionConflictError,
  MetaStatementRejectedError,
  MetaVersionConflictError,
  NameNotNfcError,
  PayloadMismatchError,
  ProjectNotFoundError,
  ValueSignatureRejectedError,
  ValueTooLargeError,
  VariableConflictError,
  VariableNotFoundError,
  VersionConflictError,
} from "./errors/index.ts";
import { PositiveInt, Sha256Hex } from "./hex.ts";

const projectParams = { projectId: ProjectIdSchema };
const environmentParams = { projectId: ProjectIdSchema, environmentId: EnvironmentIdSchema };
const variableParams = {
  projectId: ProjectIdSchema,
  environmentId: EnvironmentIdSchema,
  variableId: VariableIdSchema,
};

/**
 * One environment in the listing (current epoch is chain-derived —
 * CRYPTO_SPEC §3). The display name travels as the latest verified-able
 * metadata statement + author info instead of a bare snapshot (AUTH_SPEC
 * §12-2 — 2026-08-04 改訂)。削除済み環境も最新の deleted ステートメント付きで
 * 列挙される(削除の否認・無断復活の検出材料 — §12-4)。
 */
export const EnvironmentSummarySchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  currentEpoch: Schema.Number,
  statement: DistributedEnvironmentMetaStatementSchema,
});

/**
 * Result of a composite environment creation / rotation (AUTH_SPEC §12-4):
 * the accepted chain head (the entry was appended atomically with the data)
 * plus the resulting current epoch.
 */
export const EnvironmentChainResultSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  currentEpoch: Schema.Number,
  headSeq: PositiveInt,
  headHashHex: Sha256Hex,
});

/** Result of accepting a variable version (creation is version 1 — §12-5). */
export const VariableVersionSchema = Schema.Struct({
  variableId: VariableIdSchema,
  version: Schema.Number,
  epoch: Schema.Number,
});

/**
 * One variable in a bulk pull: its latest version, self-describing via the
 * AAD, carried as the distributed form (writer identity + signature block —
 * AUTH_SPEC §12-7 の検証材料の同梱), plus its latest metadata statement +
 * author info(名前 → variableId の解決は検証済みステートメント経由 — §12-7)。
 */
export const PulledVariableSchema = Schema.Struct({
  variableId: VariableIdSchema,
  statement: DistributedVariableMetaStatementSchema,
  value: DistributedEncryptedPayloadSchema,
});

/**
 * Bulk pull of one environment (§12-7): every active variable's latest
 * version plus every epoch's DEK wrapped for the caller (latest versions may
 * span epochs until a rotation's re-encryption completes — CRYPTO_SPEC §7)。
 * `statement` は環境自身の最新メタステートメント、`deletedVariables` は削除
 * 済み変数の deleted ステートメント(保存・配布し続ける — §12-5。削除の否認・
 * 無断復活の検出材料。暗号文は削除済みなので値は伴わない)。
 */
export const EnvironmentPullSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  currentEpoch: Schema.Number,
  statement: DistributedEnvironmentMetaStatementSchema,
  variables: Schema.Array(PulledVariableSchema),
  deletedVariables: Schema.Array(DistributedVariableMetaStatementSchema),
  deks: Schema.Array(RecipientDekSchema),
  /**
   * 最新の環境マニフェスト + issuer 情報(§12-7 — 2026-08-18)。クライアントは
   * ダイジェスト再計算・エポック整合を検証し、**欠落は一律拒否**(CRYPTO_SPEC
   * §6.3)。optional なのはマニフェスト導入前に作成された環境の移行完了までの
   * 過渡状態のみ(サーバーは保存行があれば必ず同梱する)。
   */
  manifest: Schema.optionalKey(DistributedEnvironmentManifestSchema),
});

/**
 * Metadata-only bulk pull (§12-7 メタデータのみモード — 2026-08-10): the same
 * environment-scoped read without values (ciphertexts) or DEKs. The response
 * carries the environment statement, the chain-derived current epoch, every
 * active variable's latest statement and the deleted statements — the full
 * §6.3 metadata verification material, nothing else. Used for name →
 * variableId resolution (CLI push) and other value-free reads; the server
 * records no `var.read` for it(読んでいないものを読んだと記録しない)。
 */
export const EnvironmentMetadataPullSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  currentEpoch: Schema.Number,
  statement: DistributedEnvironmentMetaStatementSchema,
  variables: Schema.Array(DistributedVariableMetaStatementSchema),
  deletedVariables: Schema.Array(DistributedVariableMetaStatementSchema),
  /** 最新の環境マニフェスト(メタ検証の完全性はこのモードでも同水準 — §12-7)。 */
  manifest: Schema.optionalKey(DistributedEnvironmentManifestSchema),
});

/**
 * Environment management (AUTH_SPEC §12-4。2026-08-03 セッション 12 改訂 —
 * 環境作成のチェーン op 化に追随)。
 *
 * - `create` is a composite request: the `create_environment` chain entry
 *   (environment id + epoch-1 DEK commitment, appended with a parent-head
 *   CAS), the `EnvironmentMetaStatement` (metaVersion 1 — its declared head
 *   must be the pre-append current head = the entry's prev, §12-4), and the
 *   complete epoch-1 DEK wrap set for the current member set — accepted
 *   atomically by the project DO. An environment never exists without its
 *   commitment, its statement and its members' wraps.
 * - `rotate` is the composite rotation: the `rotate_epoch` entry (new-epoch
 *   commitment) plus the complete new-epoch wrap set, replacing the former
 *   two-step "generic chain append + DEK registration" flow. Re-encryption
 *   of current values stays a follow-up push (§12-7). rotate はステートメントを
 *   運ばない(名前・状態は変わらない)。
 * - `rename` / `remove` carry a signed `EnvironmentMetaStatement`
 *   (metaVersion CAS — §12-5 のメタ規則。削除は status = deleted で宣言ヘッド
 *   時点 admin — §12-3)。
 */
export const environmentsGroup = HttpApiGroup.make("environments")
  .add(
    HttpApiEndpoint.post("create", "/projects/:projectId/environments", {
      params: projectParams,
      payload: Schema.Struct({
        parentHeadHashHex: Sha256Hex,
        entry: CreateEnvironmentEntrySchema,
        statement: CreateEnvironmentMetaStatementSchema,
        deks: Schema.Array(WrappedDekSchema),
        // manifestVersion 1・変数空集合・epoch 1(§12-4 — 2026-08-18)
        manifest: CreateEnvironmentManifestSchema,
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
        // 複合内整合検査(§12-4): エントリ payload とステートメント / マニフェストの
        // environment_id / 宣言ヘッドの不一致
        PayloadMismatchError,
        MetaStatementRejectedError,
        // 同梱マニフェストも通常経路と同一の検証(§12-5 の (1)〜(7))を受ける。
        // ManifestVersionConflict は宣言しない: 作成はチェーン合意規則
        // (duplicate-environment)が環境の新規性を保証し、保存済みマニフェストの
        // ない環境への v1 は CAS 上競合しえない(ワイヤも Literal 1)
        ManifestRejectedError,
        NameNotNfcError,
        DekWrapRejectedError,
        // ラップ集合検査(§12-6 checkWrapSets)は既存 (エポック, 受信者) との
        // 重複を 409 で拒否しうる。確立エポック(create = 1)は現行チェーン規則
        // (duplicate-environment)の下では既存ラップを持ちえないが、規則の変化で
        // 409 が契約外(500)へ落ちないよう契約として宣言する
        DekWrapExistsError,
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("rotate", "/projects/:projectId/environments/:environmentId/rotate", {
      params: environmentParams,
      payload: Schema.Struct({
        parentHeadHashHex: Sha256Hex,
        entry: RotateEpochEntrySchema,
        deks: Schema.Array(WrappedDekSchema),
        // 新エポックを焼き込んだマニフェスト(manifestVersion = 最新 + 1。
        // メタ集合は不変でもエポック前進を反映する — CRYPTO_SPEC §4.3。
        // マニフェスト導入前に作成された環境の最初の rotate は v1 を同梱する
        // = 移行経路 — session-27 §14 PR-M1)
        manifest: EnvironmentManifestSchema,
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
        // 同梱マニフェストの検証(§12-5 の (1)〜(7)。epoch = 同梱エントリ適用後 =
        // new_epoch)。409 の再試行ではエントリとマニフェストの両方を再署名する
        ManifestRejectedError,
        ManifestVersionConflictError,
        DekWrapRejectedError,
        // 確立エポック(rotate = new_epoch)への既存ラップは現行チェーン規則
        // (エポック単調性)の下では存在しえないが、create と同じ理由で宣言する
        DekWrapExistsError,
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
      // 環境の rename はマニフェストも同梱する(manifestVersion + 1 — 新しい
      // envMetaSigHashHex を写す。§12-4)。metaVersion CAS と manifestVersion CAS は
      // 同一トランザクションで判定し、409 は両方の再署名で再試行する(§12-5)
      payload: Schema.Struct({
        statement: RenameEnvironmentMetaStatementSchema,
        manifest: EnvironmentManifestSchema,
      }),
      success: HttpApiSchema.NoContent,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        EnvironmentNotFoundError,
        EnvironmentConflictError,
        PayloadMismatchError,
        MetaVersionConflictError,
        MetaStatementRejectedError,
        ManifestRejectedError,
        ManifestVersionConflictError,
        NameNotNfcError,
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.delete("remove", "/projects/:projectId/environments/:environmentId", {
      params: environmentParams,
      // 削除も署名付きステートメント(status deleted。name は直前 active 名 —
      // CRYPTO_SPEC §4.2)を要する。DELETE + body は deks.remove の先例に倣う
      payload: Schema.Struct({ statement: DeleteEnvironmentMetaStatementSchema }),
      success: HttpApiSchema.NoContent,
      // DataLimitExceeded は宣言しない: 削除経路の数量検査は metaVersion 上限のみ
      // で、削除ステートメント(ワイヤ Schema が status = deleted を固定)は
      // その対象外(§12-8 — 上限で削除を遮断すると上限到達リソースが恒久的に
      // 削除不能になる。quotas.ts の metaVersionsExceeded とその固定
      // テストが根拠)。variables.remove も同じ
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        EnvironmentNotFoundError,
        PayloadMismatchError,
        MetaVersionConflictError,
        MetaStatementRejectedError,
      ],
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
      // 作成 = version 1 の値 + VariableMetaStatement(metaVersion 1)の同梱
      // (§12-5)。variableId と表示名はステートメントが運ぶ(裸のフィールドを
      // 併置しない — 二重運搬の不一致面を作らない)
      payload: Schema.Struct({
        statement: CreateVariableMetaStatementSchema,
        value: EncryptedPayloadSchema,
        // 作成後のメタ状態(新変数のステートメントを含む集合)を反映した
        // マニフェスト(§12-5 — メタ状態を変える全操作の複合受理)
        manifest: EnvironmentManifestSchema,
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
        // 同梱 version 1 の値・同梱ステートメントとも通常経路と同一の署名
        // 検証を受ける(§12-5 — 作成経由の検証迂回は値・メタとも不可)。
        // MetaVersionConflict はワイヤ Schema(metaVersion = 1 固定)の下では
        // 実質到達しないが、CAS の契約として宣言する(クライアントは名前から
        // 再解決してリトライする — 並行 rename との競合の受け皿)
        ValueSignatureRejectedError,
        MetaStatementRejectedError,
        MetaVersionConflictError,
        // 同梱マニフェストの検証と manifestVersion CAS(§12-5 (6) — 並行メタ
        // 操作は環境単位の manifestVersion で直列化される。一括投入は逐次実行)
        ManifestRejectedError,
        ManifestVersionConflictError,
        NameNotNfcError,
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
        // reencryption = 再暗号化マーカー(AUTH_SPEC §12-5 — 2026-08-15)。
        // 「直前バージョンと同一平文の新エポックへの再暗号化(CRYPTO_SPEC §7)」の
        // writer 自己申告で、受理判定・値署名には影響しない。要ローテーション
        // 検出の解消導出(AUDIT_SPEC §4.1-5)だけがこれを読む
        payload: Schema.Struct({
          value: EncryptedPayloadSchema,
          reencryption: Schema.optionalKey(Schema.Boolean),
        }),
        success: VariableVersionSchema,
        error: [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableNotFoundError,
          PayloadMismatchError,
          VersionConflictError,
          EpochConflictError,
          ValueSignatureRejectedError,
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
        payload: Schema.Struct({
          statement: RenameVariableMetaStatementSchema,
          manifest: EnvironmentManifestSchema,
        }),
        success: HttpApiSchema.NoContent,
        error: [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableNotFoundError,
          VariableConflictError,
          PayloadMismatchError,
          MetaVersionConflictError,
          MetaStatementRejectedError,
          ManifestRejectedError,
          ManifestVersionConflictError,
          NameNotNfcError,
          DataLimitExceededError,
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
        // 削除も署名付きステートメント(status deleted。name は直前 active 名)+
        // tombstone を含む集合を反映したマニフェスト(§12-5 — マニフェストは
        // 行数上限の対象外なので削除経路を遮断しない: 保持は最新 1 通 — §12-8)
        payload: Schema.Struct({
          statement: DeleteVariableMetaStatementSchema,
          manifest: EnvironmentManifestSchema,
        }),
        success: HttpApiSchema.NoContent,
        // DataLimitExceeded を宣言しない理由は environments.remove と同じ
        // (deleted は metaVersion 上限の対象外 — §12-8)
        error: [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableNotFoundError,
          PayloadMismatchError,
          MetaVersionConflictError,
          MetaStatementRejectedError,
          ManifestRejectedError,
          ManifestVersionConflictError,
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
  )
  .add(
    // メタデータのみモード(§12-7): 認可は pull と同一行(read × reader)。
    // var.read は記録されない(値を配布しないため — AUDIT_SPEC §3.3)
    HttpApiEndpoint.get(
      "pullMetadata",
      "/projects/:projectId/environments/:environmentId/pull/metadata",
      {
        params: environmentParams,
        success: EnvironmentMetadataPullSchema,
        error: [ProjectNotFoundError, ForbiddenError, EnvironmentNotFoundError],
      },
    ).middleware(AuthMiddleware),
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
