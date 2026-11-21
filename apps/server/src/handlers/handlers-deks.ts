import { maruhiApi } from "@maruhi/api-schema";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/http-api";

import type { RecipientDekValue } from "../data.package/index.ts";
import { callProjectData, noContent } from "../data.package/index.ts";

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
      callProjectData<void>()({
        endpoint,
        projectId: params.projectId,
        permission: "admin",
        invoke: (stub, actor) => stub.deleteDekWraps(actor, params.environmentId, payload.wraps),
      }).pipe(Effect.as(noContent)),
    ),
);
