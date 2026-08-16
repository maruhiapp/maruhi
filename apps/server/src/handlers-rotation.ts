// 要ローテーションフラグ API のハンドラ(AUDIT_SPEC §4.1 / §6 / §7 — Wave 2 B2)。
//
// - flags: 導出ビュー(read スコープ × チェーン role reader — クラス 1)。
//   フラグ集合は状態を持たない読み取り(監査記録なし)なので CSRF ヘッダーは
//   要求しない(一括 pull の var.read 記録とは異なる — AUTH_SPEC §12-7)
// - dismiss: 取り下げ操作(admin スコープ × チェーン role admin — §3.3。
//   ラップ削除と同水準)。対象検証(有効フラグの実在)は DO 側
//
// 共通経路は data-http.ts の callProjectData。返しうるエラーの集合は各
// エンドポイントの契約宣言(api-schema)から導出される。

import { maruhiApi } from "@maruhi/api-schema";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { callProjectData, noContent } from "./data-http.ts";
import type { EffectiveRotationFlag } from "./rotation-detect.ts";

export const rotationLive = HttpApiBuilder.group(maruhiApi, "rotation", (handlers) =>
  handlers
    .handle("flags", ({ params, endpoint }) =>
      callProjectData<readonly EffectiveRotationFlag[]>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        // 監査 seq は導出結果そのものが持たない(AUDIT_SPEC §7 — 2026-08-16
        // C1 裁定。境界 strip ではなく型から消して書き忘れの余地を無くす)
        invoke: (stub, actor) => stub.rotationFlags(actor),
      }).pipe(Effect.map((flags) => ({ flags }))),
    )
    .handle("dismiss", ({ params, payload, endpoint }) =>
      callProjectData<void>()({
        endpoint,
        projectId: params.projectId,
        permission: "admin",
        invoke: (stub, actor) => stub.dismissRotationFlags(actor, payload.targets),
      }).pipe(Effect.as(noContent)),
    ),
);
