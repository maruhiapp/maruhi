// DEK ラップの保存・配布・修復 API のハンドラ(AUTH_SPEC §12-6)。
//
// 受信者検証(非メンバー宛・鍵不一致・欠落・重複・上書き)は DO 側
// (programs-dek.ts + dek-wraps.ts)が ChainState 導出の現メンバー集合に対して行う。
// 共通経路は data-http.ts の callProjectData。返しうるエラーの集合は各
// エンドポイントの契約宣言(api-schema)から導出される(手書きの列挙は無い)。

import { maruhiApi } from "@maruhi/api-schema";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { callProjectData, noContent } from "./data-http.ts";
import type { RecipientDekValue } from "./data-plane.ts";

export const deksLive = HttpApiBuilder.group(maruhiApi, "deks", (handlers) =>
  handlers
    .handle("register", ({ params, payload, endpoint }) =>
      callProjectData<void>()({
        endpoint,
        projectId: params.projectId,
        permission: "write",
        invoke: (stub, actor) => stub.registerDekWraps(actor, params.environmentId, payload.deks),
      }).pipe(Effect.as(noContent)),
    )
    .handle("listMine", ({ params, endpoint }) =>
      callProjectData<readonly RecipientDekValue[]>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        invoke: (stub, actor) => stub.listMyDekWraps(actor, params.environmentId),
      }).pipe(Effect.map((deks) => ({ deks }))),
    )
    .handle("remove", ({ params, payload, endpoint }) =>
      // ラップ削除(§12-6 の修復経路)は環境削除と同水準:
      // admin スコープ + チェーン role admin 以上(§12-3)
      callProjectData<void>()({
        endpoint,
        projectId: params.projectId,
        permission: "admin",
        invoke: (stub, actor) => stub.deleteDekWraps(actor, params.environmentId, payload.wraps),
      }).pipe(Effect.as(noContent)),
    ),
);
