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
import type { EnvironmentListValue } from "./data-plane.ts";

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

/**
 * 複合のトークンスコープ水準(AUTH_SPEC §12-3 / §16-2): 通常は write、境界
 * checkpoint が監査ヘッドを公証する(非空 audit_head_hash)場合のみ admin
 * (実効権限 admin のスコープ半分 — 汎用 append の checkpoint と同一規則)。
 */
function requiredCompositePermission(checkpoint: {
  readonly payload: { readonly auditHeadHashHex: string };
}): "write" | "admin" {
  return checkpoint.payload.auditHeadHashHex === "" ? "write" : "admin";
}

export const environmentsLive = HttpApiBuilder.group(maruhiApi, "environments", (handlers) =>
  handlers
    .handle("create", ({ params, payload, endpoint }) =>
      Effect.gen(function* () {
        // §12-4: チェーンエントリ(create と境界 checkpoint の両方)の actor は
        // 呼び出し主体と厳密一致(2026-08-27 セッション 33 — 2 エントリ複合化)
        yield* ensureCompositeActor(payload.entry);
        yield* ensureCompositeActor(payload.checkpoint);
        // 複合内整合検査(§12-4)の worker 側: エントリ payload とステートメント /
        // マニフェストの environment_id の一致(宣言ヘッド・エポックの一致検査は
        // 状態依存のため DO 側。checkpoint タプルの座標・エポック・版・監査ヘッドの
        // 突合も DO 側 — ensureBoundaryCheckpointShape)
        yield* checkStatementCoordinates(payload.statement, {
          environmentId: payload.entry.payload.environmentId,
        });
        yield* checkManifestCoordinates(payload.manifest, payload.entry.payload.environmentId);
        return yield* callProjectData<EnvironmentChainResultValue>()({
          endpoint,
          projectId: params.projectId,
          // 境界 checkpoint が監査ヘッドを公証する(非空 audit_head_hash)場合は
          // 実効権限 admin のスコープ半分を要求する(§16-2 — standalone 経路と
          // 同一規則。role 半分は DO の ensureCheckpointAuditHead)
          permission: requiredCompositePermission(payload.checkpoint),
          invoke: (stub, actor) =>
            stub.createEnvironment(actor, {
              parentHeadHashHex: payload.parentHeadHashHex,
              entry: payload.entry,
              statement: toMetaStatementInput(payload.statement),
              deks: payload.deks,
              manifest: toManifestInput(payload.manifest),
              checkpoint: payload.checkpoint,
            }),
        });
      }),
    )
    .handle("rotate", ({ params, payload, endpoint }) =>
      Effect.gen(function* () {
        yield* ensureCompositeActor(payload.entry);
        yield* ensureCompositeActor(payload.checkpoint);
        yield* checkManifestCoordinates(payload.manifest, params.environmentId);
        return yield* callProjectData<EnvironmentChainResultValue>()({
          endpoint,
          projectId: params.projectId,
          // create と同じ: 非空 audit_head_hash の同梱は admin スコープ(§16-2)
          permission: requiredCompositePermission(payload.checkpoint),
          invoke: (stub, actor) =>
            stub.rotateEpoch(actor, params.environmentId, {
              parentHeadHashHex: payload.parentHeadHashHex,
              entry: payload.entry,
              deks: payload.deks,
              manifest: toManifestInput(payload.manifest),
              checkpoint: payload.checkpoint,
            }),
        });
      }),
    )
    .handle("list", ({ params, endpoint }) =>
      // schemaPolicy の advisory 同梱(§12-7 / §12-11)込みの一覧
      callProjectData<EnvironmentListValue>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        invoke: (stub, actor) => stub.listEnvironments(actor),
      }),
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
