// schemaPolicy 設定 API のハンドラ(AUTH_SPEC §12-11)。
//
// 判定順(§12-3): 認証(ミドルウェア)→ トークンスコープ(GET = read /
// PUT = admin。スコープ外 404 / 水準不足 403)→ DO(メンバーシップ 404 /
// チェーン role — GET = reader 以上 / PUT = admin 以上)。セッション主体は
// GET / PUT とも許可列挙外で 403(session-capability.ts — §5)。
// ペイロードは署名済み構造を運ばない(strict 対象クラス外 — §12-10 (1))。

import { maruhiApi } from "@maruhi/api-schema";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { callProjectData, noContent } from "./data-http.ts";
import type { SchemaPolicy } from "./data-plane.ts";

export const schemaPolicyLive = HttpApiBuilder.group(maruhiApi, "schemaPolicy", (handlers) =>
  handlers
    .handle("get", ({ params, endpoint }) =>
      callProjectData<{ readonly schemaPolicy: SchemaPolicy }>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        invoke: (stub, actor) => stub.schemaPolicyFor(actor),
      }),
    )
    .handle("set", ({ params, payload, endpoint }) =>
      callProjectData<void>()({
        endpoint,
        projectId: params.projectId,
        permission: "admin",
        invoke: (stub, actor) => stub.setSchemaPolicy(actor, payload.schemaPolicy),
      }).pipe(Effect.as(noContent)),
    ),
);
