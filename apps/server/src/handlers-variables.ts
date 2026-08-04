// 変数 API のハンドラ(AUTH_SPEC §12-5 / §12-7)。
//
// 判定順(§12-3): 認証(ミドルウェア)→ 値サイズの先行検査(413。資源保護は
// 意味論的判定に優先)→ 申告 AAD / ステートメントの座標一致(422。リクエスト
// 内容のみに依存する自己整合検査で、存在情報を運ばない)→ トークンスコープ →
// DO(メンバーシップ / role / CAS / 署名 / 数量)。共通経路は data-http.ts の
// callProjectData。
//
// 作成は version 1 の値 + VariableMetaStatement(metaVersion 1)の同梱(§12-5)。
// variableId・表示名はステートメントが運ぶため、AAD 座標検査の期待 variableId は
// ステートメントの variableId を使う(URL に variableId を持たない唯一の値経路)。

import {
  DataLimitExceededError,
  EnvironmentNotFoundError,
  EpochConflictError,
  ForbiddenError,
  maruhiApi,
  MetaStatementRejectedError,
  MetaVersionConflictError,
  NameNotNfcError,
  PayloadMismatchError,
  ProjectNotFoundError,
  ValueSignatureRejectedError,
  VariableConflictError,
  VariableNotFoundError,
  VersionConflictError,
} from "@maruhi/api-schema";
import { Effect } from "effect";
import { HttpServerResponse } from "effect/unstable/http";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import {
  callProjectData,
  checkAadCoordinates,
  checkStatementCoordinates,
  checkValueSize,
  toMetaStatementInput,
  toValueInput,
} from "./data-http.ts";
import type { EnvironmentPullValue, VariableVersionValue } from "./data-plane.ts";

const noContent = HttpServerResponse.empty({ status: 204 });

/**
 * DO の保存行 → ワイヤの DistributedEncryptedPayload(§12-2 / §12-7)。AAD は
 * 保存座標から再構成する(保存時に座標一致を検査済みなので、これは同値の
 * 自己記述表現)。suite は保存行の値を返す(CRYPTO_SPEC §2 設計原則 4)。
 * 署名ブロックと writer / ステートメント + author(受理時点の user_id + 鍵 FP)は
 * 保存行をそのまま返す — 現メンバー集合から再導出しない(削除済み writer /
 * author の過去データの検証可能性)。サーバー再計算の signed_bytes ハッシュは
 * 値・ステートメントとも配布しない。
 */
function toWireVariable(
  projectId: string,
  environmentId: string,
  row: EnvironmentPullValue["variables"][number],
) {
  return {
    variableId: row.variableId,
    statement: row.statement,
    value: {
      suite: row.suite,
      aad: {
        projectId,
        environmentId,
        epoch: row.epoch,
        variableId: row.variableId,
        version: row.version,
      },
      nonceHex: row.nonceHex,
      ciphertextHex: row.ciphertextHex,
      prevValueSigHashHex: row.prevValueSigHashHex,
      chainHeadHashHex: row.chainHeadHashHex,
      chainHeadSeq: row.chainHeadSeq,
      signatureHex: row.signatureHex,
      writerUserId: row.writerUserId,
      writerKeyFingerprintHex: row.writerKeyFingerprintHex,
    },
  };
}

const VERSION_ERRORS = [
  ProjectNotFoundError,
  ForbiddenError,
  EnvironmentNotFoundError,
  VersionConflictError,
  EpochConflictError,
  ValueSignatureRejectedError,
  DataLimitExceededError,
] as const;

const META_ERRORS = [
  MetaStatementRejectedError,
  MetaVersionConflictError,
  PayloadMismatchError,
] as const;

export const variablesLive = HttpApiBuilder.group(maruhiApi, "variables", (handlers) =>
  handlers
    .handle("create", ({ params, payload }) =>
      Effect.gen(function* () {
        yield* checkValueSize(payload.value);
        yield* checkStatementCoordinates(payload.statement, {
          environmentId: params.environmentId,
        });
        yield* checkAadCoordinates(payload.value, {
          projectId: params.projectId,
          environmentId: params.environmentId,
          // variableId の保存先はステートメントが確定する(値の AAD との一致検査)
          variableId: payload.statement.variableId,
        });
        return yield* callProjectData<VariableVersionValue>()({
          projectId: params.projectId,
          permission: "write",
          // MetaVersionConflict は作成では契約外(ワイヤ Schema が metaVersion 1 を
          // 固定するため到達しない — DO の防衛 CAS が発火したら defect)
          allowed: [
            ...VERSION_ERRORS,
            MetaStatementRejectedError,
            PayloadMismatchError,
            NameNotNfcError,
            VariableConflictError,
          ],
          invoke: (stub, actor) =>
            stub.createVariable(actor, params.environmentId, {
              variableId: payload.statement.variableId,
              statement: toMetaStatementInput(payload.statement),
              value: toValueInput(payload.value),
            }),
        });
      }),
    )
    .handle("push", ({ params, payload }) =>
      Effect.gen(function* () {
        yield* checkValueSize(payload.value);
        yield* checkAadCoordinates(payload.value, {
          projectId: params.projectId,
          environmentId: params.environmentId,
          variableId: params.variableId,
        });
        return yield* callProjectData<VariableVersionValue>()({
          projectId: params.projectId,
          permission: "write",
          allowed: [...VERSION_ERRORS, PayloadMismatchError, VariableNotFoundError],
          invoke: (stub, actor) =>
            stub.pushVersion(
              actor,
              params.environmentId,
              params.variableId,
              toValueInput(payload.value),
            ),
        });
      }),
    )
    .handle("rename", ({ params, payload }) =>
      Effect.gen(function* () {
        yield* checkStatementCoordinates(payload.statement, {
          environmentId: params.environmentId,
          variableId: params.variableId,
        });
        return yield* callProjectData<void>()({
          projectId: params.projectId,
          permission: "write",
          allowed: [
            ProjectNotFoundError,
            ForbiddenError,
            EnvironmentNotFoundError,
            VariableNotFoundError,
            VariableConflictError,
            ...META_ERRORS,
            NameNotNfcError,
            DataLimitExceededError,
          ],
          invoke: (stub, actor) =>
            stub.renameVariable(
              actor,
              params.environmentId,
              params.variableId,
              toMetaStatementInput(payload.statement),
            ),
        });
      }).pipe(Effect.as(noContent)),
    )
    .handle("remove", ({ params, payload }) =>
      Effect.gen(function* () {
        yield* checkStatementCoordinates(payload.statement, {
          environmentId: params.environmentId,
          variableId: params.variableId,
        });
        return yield* callProjectData<void>()({
          projectId: params.projectId,
          permission: "write",
          allowed: [
            ProjectNotFoundError,
            ForbiddenError,
            EnvironmentNotFoundError,
            VariableNotFoundError,
            ...META_ERRORS,
          ],
          invoke: (stub, actor) =>
            stub.deleteVariable(
              actor,
              params.environmentId,
              params.variableId,
              toMetaStatementInput(payload.statement),
            ),
        });
      }).pipe(Effect.as(noContent)),
    )
    .handle("pull", ({ params }) =>
      callProjectData<EnvironmentPullValue>()({
        projectId: params.projectId,
        permission: "read",
        allowed: [ProjectNotFoundError, ForbiddenError, EnvironmentNotFoundError],
        invoke: (stub, actor) => stub.pullEnvironment(actor, params.environmentId),
      }).pipe(
        Effect.map((pulled) => ({
          environmentId: pulled.environmentId,
          currentEpoch: pulled.currentEpoch,
          statement: pulled.statement,
          variables: pulled.variables.map((row) =>
            toWireVariable(params.projectId, params.environmentId, row),
          ),
          deletedVariables: pulled.deletedVariables,
          deks: pulled.deks,
        })),
      ),
    ),
);
