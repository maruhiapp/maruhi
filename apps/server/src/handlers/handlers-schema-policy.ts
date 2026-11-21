import { maruhiApi } from "@maruhi/api-schema";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/http-api";

import type { SchemaPolicy } from "../data.package/index.ts";
import { callProjectData, noContent } from "../data.package/index.ts";

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
