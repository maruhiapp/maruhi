// 変数 API のハンドラ(AUTH_SPEC §12-5 / §12-7)。
//
// 判定順(§12-3): 認証(ミドルウェア)→ 値サイズの先行検査(413。資源保護は
// 意味論的判定に優先)→ 申告 AAD の座標一致(422。リクエスト内容のみに依存する
// 自己整合検査で、存在情報を運ばない)→ トークンスコープ → DO(メンバーシップ /
// role / CAS / 数量)。共通経路は data-http.ts の callProjectData。

import {
  DataLimitExceededError,
  EnvironmentNotFoundError,
  EpochConflictError,
  ForbiddenError,
  maruhiApi,
  ProjectNotFoundError,
  VariableConflictError,
  VariableNotFoundError,
  VersionConflictError,
} from "@maruhi/api-schema";
import { Effect } from "effect";
import { HttpServerResponse } from "effect/unstable/http";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { callProjectData, checkAadCoordinates, checkValueSize, toValueInput } from "./data-http.ts";
import type {
  EnvironmentPullValue,
  PulledVariableValue,
  VariableVersionValue,
} from "./data-plane.ts";

const noContent = HttpServerResponse.empty({ status: 204 });

/**
 * DO の保存行 → ワイヤの EncryptedPayload(§12-2)。AAD は保存座標から再構成する
 * (保存時に座標一致を検査済みなので、これは同値の自己記述表現)。
 */
function toWireVariable(projectId: string, environmentId: string, row: PulledVariableValue) {
  return {
    variableId: row.variableId,
    name: row.name,
    value: {
      suite: "maruhi/v1" as const,
      aad: {
        projectId,
        environmentId,
        epoch: row.epoch,
        variableId: row.variableId,
        version: row.version,
      },
      nonceHex: row.nonceHex,
      ciphertextHex: row.ciphertextHex,
    },
  };
}

const VERSION_ERRORS = [
  ProjectNotFoundError,
  ForbiddenError,
  EnvironmentNotFoundError,
  VersionConflictError,
  EpochConflictError,
  DataLimitExceededError,
] as const;

export const variablesLive = HttpApiBuilder.group(maruhiApi, "variables", (handlers) =>
  handlers
    .handle("create", ({ params, payload }) =>
      Effect.gen(function* () {
        yield* checkValueSize(payload.value);
        yield* checkAadCoordinates(payload.value, {
          projectId: params.projectId,
          environmentId: params.environmentId,
          variableId: payload.variableId,
        });
        return yield* callProjectData<VariableVersionValue>()({
          projectId: params.projectId,
          permission: "write",
          allowed: [...VERSION_ERRORS, VariableConflictError],
          invoke: (stub, actor) =>
            stub.createVariable(actor, params.environmentId, {
              variableId: payload.variableId,
              name: payload.name,
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
          allowed: [...VERSION_ERRORS, VariableNotFoundError],
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
      callProjectData<void>()({
        projectId: params.projectId,
        permission: "write",
        allowed: [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableNotFoundError,
          VariableConflictError,
        ],
        invoke: (stub, actor) =>
          stub.renameVariable(actor, params.environmentId, params.variableId, payload.name),
      }).pipe(Effect.as(noContent)),
    )
    .handle("remove", ({ params }) =>
      callProjectData<void>()({
        projectId: params.projectId,
        permission: "write",
        allowed: [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableNotFoundError,
        ],
        invoke: (stub, actor) =>
          stub.deleteVariable(actor, params.environmentId, params.variableId),
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
          name: pulled.name,
          currentEpoch: pulled.currentEpoch,
          variables: pulled.variables.map((row) =>
            toWireVariable(params.projectId, params.environmentId, row),
          ),
          deks: pulled.deks,
        })),
      ),
    ),
);
