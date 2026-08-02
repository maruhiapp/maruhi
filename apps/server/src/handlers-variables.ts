// 変数 API のハンドラ(AUTH_SPEC §12-5 / §12-7)。
//
// 判定順(§12-3): 認証(ミドルウェア)→ 値サイズの先行検査(413。資源保護は
// 意味論的判定に優先)→ 申告 AAD の座標一致(422。リクエスト内容のみに依存する
// 自己整合検査)→ トークンスコープ → DO(メンバーシップ / role / CAS / 数量)。

import {
  DataLimitExceededError,
  EnvironmentNotFoundError,
  EpochConflictError,
  ForbiddenError,
  maruhiApi,
  PayloadMismatchError,
  ProjectNotFoundError,
  VariableConflictError,
  VariableNotFoundError,
  VersionConflictError,
} from "@maruhi/api-schema";
import { RequestAuth } from "@maruhi/core";
import { Effect } from "effect";
import { HttpServerResponse } from "effect/unstable/http";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { ensureTokenScopeForProject } from "./authz.ts";
import {
  checkAadCoordinates,
  checkValueSize,
  dataActorOf,
  toValueInput,
  unwrapDataOutcome,
} from "./data-http.ts";
import type {
  DataOutcome,
  EnvironmentPullValue,
  PulledVariableValue,
  VariableVersionValue,
} from "./data-plane.ts";
import { projectStub, rpcCall, WorkerEnv } from "./worker-env.ts";

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

export const variablesLive = HttpApiBuilder.group(maruhiApi, "variables", (handlers) =>
  handlers
    .handle("create", ({ params, payload }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* checkValueSize(payload.value);
        yield* ensureTokenScopeForProject(principal, params.projectId, "write");
        yield* checkAadCoordinates(payload.value, {
          projectId: params.projectId,
          environmentId: params.environmentId,
          variableId: payload.variableId,
        });
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<DataOutcome<VariableVersionValue>>(() =>
          projectStub(env, params.projectId).createVariable(
            dataActorOf(principal),
            params.environmentId,
            {
              variableId: payload.variableId,
              name: payload.name,
              value: toValueInput(payload.value),
            },
          ),
        );
        return yield* unwrapDataOutcome(outcome, params.projectId, [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableConflictError,
          VersionConflictError,
          EpochConflictError,
          DataLimitExceededError,
        ]);
      }),
    )
    .handle("push", ({ params, payload }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* checkValueSize(payload.value);
        yield* ensureTokenScopeForProject(principal, params.projectId, "write");
        yield* checkAadCoordinates(payload.value, {
          projectId: params.projectId,
          environmentId: params.environmentId,
          variableId: params.variableId,
        });
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<DataOutcome<VariableVersionValue>>(() =>
          projectStub(env, params.projectId).pushVersion(
            dataActorOf(principal),
            params.environmentId,
            params.variableId,
            toValueInput(payload.value),
          ),
        );
        return yield* unwrapDataOutcome(outcome, params.projectId, [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableNotFoundError,
          VersionConflictError,
          EpochConflictError,
          DataLimitExceededError,
        ]);
      }),
    )
    .handle("rename", ({ params, payload }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureTokenScopeForProject(principal, params.projectId, "write");
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<DataOutcome<void>>(() =>
          projectStub(env, params.projectId).renameVariable(
            dataActorOf(principal),
            params.environmentId,
            params.variableId,
            payload.name,
          ),
        );
        yield* unwrapDataOutcome(outcome, params.projectId, [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableNotFoundError,
          VariableConflictError,
        ]);
        return noContent;
      }),
    )
    .handle("remove", ({ params }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureTokenScopeForProject(principal, params.projectId, "write");
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<DataOutcome<void>>(() =>
          projectStub(env, params.projectId).deleteVariable(
            dataActorOf(principal),
            params.environmentId,
            params.variableId,
          ),
        );
        yield* unwrapDataOutcome(outcome, params.projectId, [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableNotFoundError,
        ]);
        return noContent;
      }),
    )
    .handle("pull", ({ params }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureTokenScopeForProject(principal, params.projectId, "read");
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<DataOutcome<EnvironmentPullValue>>(() =>
          projectStub(env, params.projectId).pullEnvironment(
            dataActorOf(principal),
            params.environmentId,
          ),
        );
        const pulled = yield* unwrapDataOutcome(outcome, params.projectId, [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
        ]);
        return {
          environmentId: pulled.environmentId,
          name: pulled.name,
          currentEpoch: pulled.currentEpoch,
          variables: pulled.variables.map((row) =>
            toWireVariable(params.projectId, params.environmentId, row),
          ),
          deks: pulled.deks,
        };
      }),
    ),
);
