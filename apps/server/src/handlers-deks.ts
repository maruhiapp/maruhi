// DEK ラップの保存・配布 API のハンドラ(AUTH_SPEC §12-6)。
//
// 受信者検証(非メンバー宛・鍵不一致・欠落・重複・上書き)は DO 側
// (data-programs.ts)が ChainState 導出の現メンバー集合に対して行う。

import {
  DataLimitExceededError,
  DekWrapExistsError,
  DekWrapRejectedError,
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
import type { DataOutcome, RecipientDekValue } from "./data-plane.ts";
import { projectStub, rpcCall, WorkerEnv } from "./worker-env.ts";

export const deksLive = HttpApiBuilder.group(maruhiApi, "deks", (handlers) =>
  handlers
    .handle("register", ({ params, payload }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureTokenScopeForProject(principal, params.projectId, "write");
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<DataOutcome<void>>(() =>
          projectStub(env, params.projectId).registerDekWraps(
            dataActorOf(principal),
            params.environmentId,
            payload.deks,
          ),
        );
        yield* unwrapDataOutcome(outcome, params.projectId, [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          DekWrapRejectedError,
          DekWrapExistsError,
          DataLimitExceededError,
        ]);
        return HttpServerResponse.empty({ status: 204 });
      }),
    )
    .handle("listMine", ({ params }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureTokenScopeForProject(principal, params.projectId, "read");
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<DataOutcome<readonly RecipientDekValue[]>>(() =>
          projectStub(env, params.projectId).listMyDekWraps(
            dataActorOf(principal),
            params.environmentId,
          ),
        );
        const deks = yield* unwrapDataOutcome(outcome, params.projectId, [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
        ]);
        return { deks };
      }),
    ),
);
