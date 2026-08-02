// DEK ラップの保存・配布 API のハンドラ(AUTH_SPEC §12-6)。
//
// 受信者検証(非メンバー宛・鍵不一致・欠落・重複・上書き)は DO 側
// (data-programs.ts)が ChainState 導出の現メンバー集合に対して行う。
// 共通経路は data-http.ts の callProjectData。

import {
  DataLimitExceededError,
  DekWrapExistsError,
  DekWrapRejectedError,
  EnvironmentNotFoundError,
  ForbiddenError,
  maruhiApi,
  ProjectNotFoundError,
} from "@maruhi/api-schema";
import { Effect } from "effect";
import { HttpServerResponse } from "effect/unstable/http";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { callProjectData } from "./data-http.ts";
import type { RecipientDekValue } from "./data-plane.ts";

const noContent = HttpServerResponse.empty({ status: 204 });

export const deksLive = HttpApiBuilder.group(maruhiApi, "deks", (handlers) =>
  handlers
    .handle("register", ({ params, payload }) =>
      callProjectData<void>()({
        projectId: params.projectId,
        permission: "write",
        allowed: [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          DekWrapRejectedError,
          DekWrapExistsError,
          DataLimitExceededError,
        ],
        invoke: (stub, actor) => stub.registerDekWraps(actor, params.environmentId, payload.deks),
      }).pipe(Effect.as(noContent)),
    )
    .handle("listMine", ({ params }) =>
      callProjectData<readonly RecipientDekValue[]>()({
        projectId: params.projectId,
        permission: "read",
        allowed: [ProjectNotFoundError, ForbiddenError, EnvironmentNotFoundError],
        invoke: (stub, actor) => stub.listMyDekWraps(actor, params.environmentId),
      }).pipe(Effect.map((deks) => ({ deks }))),
    ),
);
