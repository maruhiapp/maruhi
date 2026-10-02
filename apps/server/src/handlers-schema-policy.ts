// Handlers for the schemaPolicy configuration API (AUTH_SPEC §12-11).
//
// Check order (§12-3): authentication (middleware) → token scope
// (GET = read / PUT = admin; out of scope 404 / insufficient level
// 403) → DO (membership 404 / chain role — GET = reader or above /
// PUT = admin or above). A session principal is outside the allowed
// enumeration for both GET / PUT → 403 (session-capability.ts — §5).
// The payload carries no signed structure (outside the strict-target
// class — §12-10 (1)).

import { maruhiApi } from "@maruhi/api-schema";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/http-api";

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
