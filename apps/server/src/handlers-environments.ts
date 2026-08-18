// 環境管理 API のハンドラ(AUTH_SPEC §12-4)。
//
// 判定順(§12-3): 認証(ミドルウェア)→ トークンスコープ(スコープ外 404 /
// 水準不足 403)→ DO(メンバーシップ 404 / チェーン role 403 / 意味論的検査)。
// 共通経路は data-http.ts の callProjectData。返しうるエラーの集合は各
// エンドポイントの契約宣言(api-schema)から導出される(手書きの列挙は無い)。

import { maruhiApi } from "@maruhi/api-schema";
import { RequestAuth } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { ensureActorMatches } from "./authz.ts";
import type { EnvironmentChainResultValue } from "./composite-programs.ts";
import {
  callProjectData,
  checkManifestCoordinates,
  checkStatementCoordinates,
  noContent,
  toManifestInput,
  toMetaStatementInput,
} from "./data-http.ts";
import type { EnvironmentSummaryValue } from "./data-plane.ts";

/**
 * §12-4: チェーンエントリの actor・ラップの署名者は呼び出し主体と厳密一致。
 * actor の一致は worker が先行検査する(§11-1 の汎用 append と同じ受理ポリシー。
 * 署名者一致は DO の署名検証 — §12-6 — が担う)。
 */
const ensureCompositeActor = (entry: ChainEntry) =>
  Effect.gen(function* () {
    const principal = yield* (yield* RequestAuth).principal;
    yield* ensureActorMatches(principal, entry);
  });

export const environmentsLive = HttpApiBuilder.group(maruhiApi, "environments", (handlers) =>
  handlers
    .handle("create", ({ params, payload, endpoint }) =>
      Effect.gen(function* () {
        yield* ensureCompositeActor(payload.entry);
        // 複合内整合検査(§12-4)の worker 側: エントリ payload とステートメント /
        // マニフェストの environment_id の一致(宣言ヘッド・エポックの一致検査は
        // 状態依存のため DO 側)
        yield* checkStatementCoordinates(payload.statement, {
          environmentId: payload.entry.payload.environmentId,
        });
        yield* checkManifestCoordinates(payload.manifest, payload.entry.payload.environmentId);
        return yield* callProjectData<EnvironmentChainResultValue>()({
          endpoint,
          projectId: params.projectId,
          permission: "write",
          invoke: (stub, actor) =>
            stub.createEnvironment(actor, {
              parentHeadHashHex: payload.parentHeadHashHex,
              entry: payload.entry,
              statement: toMetaStatementInput(payload.statement),
              deks: payload.deks,
              manifest: toManifestInput(payload.manifest),
            }),
        });
      }),
    )
    .handle("rotate", ({ params, payload, endpoint }) =>
      Effect.gen(function* () {
        yield* ensureCompositeActor(payload.entry);
        yield* checkManifestCoordinates(payload.manifest, params.environmentId);
        return yield* callProjectData<EnvironmentChainResultValue>()({
          endpoint,
          projectId: params.projectId,
          permission: "write",
          invoke: (stub, actor) =>
            stub.rotateEpoch(actor, params.environmentId, {
              parentHeadHashHex: payload.parentHeadHashHex,
              entry: payload.entry,
              deks: payload.deks,
              manifest: toManifestInput(payload.manifest),
            }),
        });
      }),
    )
    .handle("list", ({ params, endpoint }) =>
      callProjectData<readonly EnvironmentSummaryValue[]>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        invoke: (stub, actor) => stub.listEnvironments(actor),
      }).pipe(Effect.map((environments) => ({ environments }))),
    )
    .handle("rename", ({ params, payload, endpoint }) =>
      Effect.gen(function* () {
        yield* checkStatementCoordinates(payload.statement, {
          environmentId: params.environmentId,
        });
        yield* checkManifestCoordinates(payload.manifest, params.environmentId);
        return yield* callProjectData<void>()({
          endpoint,
          projectId: params.projectId,
          permission: "write",
          invoke: (stub, actor) =>
            stub.renameEnvironment(
              actor,
              params.environmentId,
              toMetaStatementInput(payload.statement),
              toManifestInput(payload.manifest),
            ),
        });
      }).pipe(Effect.as(noContent)),
    )
    .handle("remove", ({ params, payload, endpoint }) =>
      // 環境の削除は admin スコープ + チェーン role admin 以上(§12-3)。
      // 削除も署名付きステートメント(status deleted)を要する(§12-4)
      Effect.gen(function* () {
        yield* checkStatementCoordinates(payload.statement, {
          environmentId: params.environmentId,
        });
        return yield* callProjectData<void>()({
          endpoint,
          projectId: params.projectId,
          permission: "admin",
          invoke: (stub, actor) =>
            stub.deleteEnvironment(
              actor,
              params.environmentId,
              toMetaStatementInput(payload.statement),
            ),
        });
      }).pipe(Effect.as(noContent)),
    ),
);
