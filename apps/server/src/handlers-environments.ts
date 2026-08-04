// 環境管理 API のハンドラ(AUTH_SPEC §12-4)。
//
// 判定順(§12-3): 認証(ミドルウェア)→ トークンスコープ(スコープ外 404 /
// 水準不足 403)→ DO(メンバーシップ 404 / チェーン role 403 / 意味論的検査)。
// 共通経路は data-http.ts の callProjectData。

import {
  ChainCapacityExceededError,
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  ChainHeadConflictError,
  DataLimitExceededError,
  DekWrapRejectedError,
  EnvironmentConflictError,
  EnvironmentNotFoundError,
  ForbiddenError,
  maruhiApi,
  PayloadMismatchError,
  ProjectNotFoundError,
} from "@maruhi/api-schema";
import { RequestAuth } from "@maruhi/core";
import { Effect } from "effect";
import { HttpServerResponse } from "effect/unstable/http";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { ensureActorMatches } from "./authz.ts";
import type { EnvironmentChainResultValue } from "./composite-programs.ts";
import { callProjectData } from "./data-http.ts";
import type { EnvironmentSummaryValue } from "./data-plane.ts";

const noContent = HttpServerResponse.empty({ status: 204 });

// 複合リクエスト(§12-4)がチェーンエントリを運ぶため返しうるエラー群
// (エラー契約の複合エンドポイントへの移動 — session-12 §6-8)
const COMPOSITE_CHAIN_ERRORS = [
  ChainHeadConflictError,
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  ChainCapacityExceededError,
] as const;

export const environmentsLive = HttpApiBuilder.group(maruhiApi, "environments", (handlers) =>
  handlers
    .handle("create", ({ params, payload }) =>
      Effect.gen(function* () {
        // §12-4: チェーンエントリの actor・ラップの署名者は呼び出し主体と厳密一致。
        // actor の一致は worker が先行検査する(§11-1 の汎用 append と同じ受理
        // ポリシー。署名者一致は DO の署名検証 — §12-6 — が担う)
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureActorMatches(principal, payload.entry);
        return yield* callProjectData<EnvironmentChainResultValue>()({
          projectId: params.projectId,
          permission: "write",
          allowed: [
            ProjectNotFoundError,
            ForbiddenError,
            EnvironmentConflictError,
            ...COMPOSITE_CHAIN_ERRORS,
            DekWrapRejectedError,
            DataLimitExceededError,
          ],
          invoke: (stub, actor) =>
            stub.createEnvironment(actor, {
              parentHeadHashHex: payload.parentHeadHashHex,
              entry: payload.entry,
              name: payload.name,
              deks: payload.deks,
            }),
        });
      }),
    )
    .handle("rotate", ({ params, payload }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureActorMatches(principal, payload.entry);
        return yield* callProjectData<EnvironmentChainResultValue>()({
          projectId: params.projectId,
          permission: "write",
          allowed: [
            ProjectNotFoundError,
            ForbiddenError,
            EnvironmentNotFoundError,
            PayloadMismatchError,
            ...COMPOSITE_CHAIN_ERRORS,
            DekWrapRejectedError,
            DataLimitExceededError,
          ],
          invoke: (stub, actor) =>
            stub.rotateEpoch(actor, params.environmentId, {
              parentHeadHashHex: payload.parentHeadHashHex,
              entry: payload.entry,
              deks: payload.deks,
            }),
        });
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
