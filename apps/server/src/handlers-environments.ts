// 環境管理 API のハンドラ(AUTH_SPEC §12-4)。
//
// 判定順(§12-3): 認証(ミドルウェア)→ トークンスコープ(スコープ外 404 /
// 水準不足 403)→ DO(メンバーシップ 404 / チェーン role 403 / 意味論的検査)。

import {
  DataLimitExceededError,
  DekWrapRejectedError,
  EnvironmentConflictError,
  EnvironmentNotFoundError,
  ForbiddenError,
  maruhiApi,
  ProjectNotFoundError,
} from "@maruhi/api-schema";
import { RequestAuth } from "@maruhi/core";
import { Effect } from "effect";
import { HttpServerResponse } from "effect/unstable/http";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { ensureTokenScopeForProject } from "./authz.ts";
import { dataActorOf, unwrapDataOutcome } from "./data-http.ts";
import type { DataOutcome, EnvironmentSummaryValue } from "./data-plane.ts";
import { projectStub, rpcCall, WorkerEnv } from "./worker-env.ts";

const noContent = HttpServerResponse.empty({ status: 204 });

export const environmentsLive = HttpApiBuilder.group(maruhiApi, "environments", (handlers) =>
  handlers
    .handle("create", ({ params, payload }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureTokenScopeForProject(principal, params.projectId, "write");
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<DataOutcome<EnvironmentSummaryValue>>(() =>
          projectStub(env, params.projectId).createEnvironment(dataActorOf(principal), {
            environmentId: payload.environmentId,
            name: payload.name,
            deks: payload.deks,
          }),
        );
        return yield* unwrapDataOutcome(outcome, params.projectId, [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentConflictError,
          DekWrapRejectedError,
          DataLimitExceededError,
        ]);
      }),
    )
    .handle("list", ({ params }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureTokenScopeForProject(principal, params.projectId, "read");
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<DataOutcome<readonly EnvironmentSummaryValue[]>>(() =>
          projectStub(env, params.projectId).listEnvironments(dataActorOf(principal)),
        );
        const environments = yield* unwrapDataOutcome(outcome, params.projectId, [
          ProjectNotFoundError,
          ForbiddenError,
        ]);
        return { environments };
      }),
    )
    .handle("rename", ({ params, payload }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureTokenScopeForProject(principal, params.projectId, "write");
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<DataOutcome<void>>(() =>
          projectStub(env, params.projectId).renameEnvironment(
            dataActorOf(principal),
            params.environmentId,
            payload.name,
          ),
        );
        yield* unwrapDataOutcome(outcome, params.projectId, [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          EnvironmentConflictError,
        ]);
        return noContent;
      }),
    )
    .handle("remove", ({ params }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        // 環境の削除は admin スコープ + チェーン role admin 以上(§12-3)
        yield* ensureTokenScopeForProject(principal, params.projectId, "admin");
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<DataOutcome<void>>(() =>
          projectStub(env, params.projectId).deleteEnvironment(
            dataActorOf(principal),
            params.environmentId,
          ),
        );
        yield* unwrapDataOutcome(outcome, params.projectId, [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
        ]);
        return noContent;
      }),
    ),
);
