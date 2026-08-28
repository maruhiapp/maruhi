// 変数 API のハンドラ(AUTH_SPEC §12-5 / §12-7)。
//
// 判定順(§12-3): 認証(ミドルウェア)→ 値サイズの先行検査(413。資源保護は
// 意味論的判定に優先)→ 申告 AAD / ステートメントの座標一致(422。リクエスト
// 内容のみに依存する自己整合検査で、存在情報を運ばない)→ トークンスコープ →
// DO(メンバーシップ / role / CAS / 署名 / 数量)。共通経路は data-http.ts の
// callProjectData。DO 拒否として返しうるエラーの集合は各エンドポイントの契約
// 宣言(api-schema)から導出される(手書きの列挙は無い)。
//
// 作成は version 1 の値 + VariableMetaStatement(metaVersion 1)の同梱(§12-5)。
// variableId・表示名はステートメントが運ぶため、AAD 座標検査の期待 variableId は
// ステートメントの variableId を使う(URL に variableId を持たない唯一の値経路)。

import { ForbiddenError, maruhiApi } from "@maruhi/api-schema";
import { RequestAuth } from "@maruhi/core";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { statefulGetCsrfViolated } from "./auth.package/index.ts";
import {
  callProjectData,
  checkAadCoordinates,
  checkManifestCoordinates,
  checkStatementCoordinates,
  checkValueSize,
  noContent,
  toManifestInput,
  toMetaStatementInput,
  toValueInput,
  toWireVariable,
} from "./data-http.ts";
import type {
  EnvironmentMetadataPullValue,
  EnvironmentPullValue,
  VariableVersionValue,
} from "./data-plane.ts";

export const variablesLive = HttpApiBuilder.group(maruhiApi, "variables", (handlers) =>
  handlers
    .handle("create", ({ params, payload, endpoint }) =>
      Effect.gen(function* () {
        yield* checkValueSize(payload.value);
        yield* checkStatementCoordinates(payload.statement, {
          environmentId: params.environmentId,
        });
        yield* checkManifestCoordinates(payload.manifest, params.environmentId);
        yield* checkAadCoordinates(payload.value, {
          projectId: params.projectId,
          environmentId: params.environmentId,
          // variableId の保存先はステートメントが確定する(値の AAD との一致検査)
          variableId: payload.statement.variableId,
        });
        return yield* callProjectData<VariableVersionValue>()({
          endpoint,
          projectId: params.projectId,
          permission: "write",
          invoke: (stub, actor) =>
            stub.createVariable(actor, params.environmentId, {
              variableId: payload.statement.variableId,
              statement: toMetaStatementInput(payload.statement),
              value: toValueInput(payload.value),
              manifest: toManifestInput(payload.manifest),
            }),
        });
      }),
    )
    .handle("push", ({ params, payload, endpoint }) =>
      Effect.gen(function* () {
        yield* checkValueSize(payload.value);
        yield* checkAadCoordinates(payload.value, {
          projectId: params.projectId,
          environmentId: params.environmentId,
          variableId: params.variableId,
        });
        return yield* callProjectData<VariableVersionValue>()({
          endpoint,
          projectId: params.projectId,
          permission: "write",
          invoke: (stub, actor) =>
            stub.pushVersion(
              actor,
              params.environmentId,
              params.variableId,
              toValueInput(payload.value),
              // 再暗号化マーカー(AUTH_SPEC §12-5 — 省略は false)
              payload.reencryption === true,
            ),
        });
      }),
    )
    .handle("rename", ({ params, payload, endpoint }) =>
      Effect.gen(function* () {
        yield* checkStatementCoordinates(payload.statement, {
          environmentId: params.environmentId,
          variableId: params.variableId,
        });
        yield* checkManifestCoordinates(payload.manifest, params.environmentId);
        return yield* callProjectData<void>()({
          endpoint,
          projectId: params.projectId,
          permission: "write",
          invoke: (stub, actor) =>
            stub.renameVariable(
              actor,
              params.environmentId,
              params.variableId,
              toMetaStatementInput(payload.statement),
              toManifestInput(payload.manifest),
            ),
        });
      }).pipe(Effect.as(noContent)),
    )
    .handle("remove", ({ params, payload, endpoint }) =>
      Effect.gen(function* () {
        yield* checkStatementCoordinates(payload.statement, {
          environmentId: params.environmentId,
          variableId: params.variableId,
        });
        yield* checkManifestCoordinates(payload.manifest, params.environmentId);
        return yield* callProjectData<void>()({
          endpoint,
          projectId: params.projectId,
          permission: "write",
          invoke: (stub, actor) =>
            stub.deleteVariable(
              actor,
              params.environmentId,
              params.variableId,
              toMetaStatementInput(payload.statement),
              toManifestInput(payload.manifest),
            ),
        });
      }).pipe(Effect.as(noContent)),
    )
    .handle("pull", ({ params, endpoint, request }) =>
      Effect.gen(function* () {
        // GET だが変数ごとの var.read 監査の記録という状態を持つ(§12-7 /
        // AUDIT_SPEC §3.3)— 第三者サイトが被害者のセッションで偽の var.read を
        // 刻む監査証跡の汚染の遮断(論拠は statefulGetCsrfViolated の JSDoc)。
        // メタデータのみモード(pullMetadata)は監査を記録しないため対象外
        const principal = yield* (yield* RequestAuth).principal;
        if (statefulGetCsrfViolated(principal, request.headers)) {
          return yield* Effect.fail(new ForbiddenError({ reason: "csrf-header-required" }));
        }
        const pulled = yield* callProjectData<EnvironmentPullValue>()({
          endpoint,
          projectId: params.projectId,
          permission: "read",
          invoke: (stub, actor) => stub.pullEnvironment(actor, params.environmentId),
        });
        return {
          environmentId: pulled.environmentId,
          currentEpoch: pulled.currentEpoch,
          statement: pulled.statement,
          variables: pulled.variables.map((row) =>
            toWireVariable(params.projectId, params.environmentId, row),
          ),
          deletedVariables: pulled.deletedVariables,
          deks: pulled.deks,
          // 最新マニフェスト(§12-7 — 保存行があれば必ず同梱。欠落 = 移行前の
          // 過渡状態のみで、クライアント側は一律拒否する — CRYPTO_SPEC §6.3)
          ...(pulled.manifest === undefined ? {} : { manifest: pulled.manifest }),
          // チェックポイント時点の値スナップショット(§12-7 — 基準 checkpoint の
          // 保存行があれば必ず同梱。クライアント規則 2 の材料 — CRYPTO_SPEC §6.3)
          ...(pulled.checkpointSnapshot === undefined
            ? {}
            : { checkpointSnapshot: pulled.checkpointSnapshot }),
        };
      }),
    )
    // メタデータのみモード(§12-7): 認可は pull と同一(read × reader)。
    // 値・DEK を返さず、var.read は記録されない(AUDIT_SPEC §3.3)
    .handle("pullMetadata", ({ params, endpoint }) =>
      callProjectData<EnvironmentMetadataPullValue>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        invoke: (stub, actor) => stub.pullEnvironmentMetadata(actor, params.environmentId),
      }),
    ),
);
