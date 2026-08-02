// 環境管理 API のハンドラ(AUTH_SPEC §12-4)。
//
// 判定順(§12-3): 認証(ミドルウェア)→ トークンスコープ(スコープ外 404 /
// 水準不足 403)→ DO(メンバーシップ 404 / チェーン role 403 / 意味論的検査)。
// 共通経路は data-http.ts の callProjectData。

import {
  DataLimitExceededError,
  DekWrapRejectedError,
  EnvironmentConflictError,
  EnvironmentNotFoundError,
  ForbiddenError,
  maruhiApi,
  ProjectNotFoundError,
} from "@maruhi/api-schema";
import { Effect } from "effect";
import { HttpServerResponse } from "effect/unstable/http";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { callProjectData } from "./data-http.ts";
import type { EnvironmentSummaryValue } from "./data-plane.ts";

const noContent = HttpServerResponse.empty({ status: 204 });

export const environmentsLive = HttpApiBuilder.group(maruhiApi, "environments", (handlers) =>
  handlers
    .handle("create", ({ params, payload }) =>
      callProjectData<EnvironmentSummaryValue>()({
        projectId: params.projectId,
        permission: "write",
        allowed: [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentConflictError,
          DekWrapRejectedError,
          DataLimitExceededError,
        ],
        invoke: (stub, actor) =>
          stub.createEnvironment(actor, {
            environmentId: payload.environmentId,
            name: payload.name,
            deks: payload.deks,
          }),
      }),
    )
    .handle("list", ({ params }) =>
      callProjectData<readonly EnvironmentSummaryValue[]>()({
        projectId: params.projectId,
        permission: "read",
        allowed: [ProjectNotFoundError, ForbiddenError],
        invoke: (stub, actor) => stub.listEnvironments(actor),
      }).pipe(Effect.map((environments) => ({ environments }))),
    )
    .handle("rename", ({ params, payload }) =>
      callProjectData<void>()({
        projectId: params.projectId,
        permission: "write",
        allowed: [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          EnvironmentConflictError,
        ],
        invoke: (stub, actor) => stub.renameEnvironment(actor, params.environmentId, payload.name),
      }).pipe(Effect.as(noContent)),
    )
    .handle("remove", ({ params }) =>
      // 環境の削除は admin スコープ + チェーン role admin 以上(§12-3)
      callProjectData<void>()({
        projectId: params.projectId,
        permission: "admin",
        allowed: [ProjectNotFoundError, ForbiddenError, EnvironmentNotFoundError],
        invoke: (stub, actor) => stub.deleteEnvironment(actor, params.environmentId),
      }).pipe(Effect.as(noContent)),
    ),
);
