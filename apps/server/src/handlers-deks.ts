// Handlers for the DEK-wrap store / distribute / repair API
// (AUTH_SPEC §12-6).
//
// Recipient validation (non-member recipients, key mismatch, missing,
// duplicate, overwrite) is performed DO-side (programs-dek.ts +
// dek-wraps.ts) against the current member set derived from ChainState.
// The shared path is callProjectData in data-http.ts. The set of
// returnable errors is derived from each endpoint's contract
// declaration (api-schema) — no hand-written enumeration.

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
      // Wrap deletion (the §12-6 repair path) is the same level as
      // environment deletion: admin scope + chain role admin or above
      // (§12-3)
      callProjectData<void>()({
        endpoint,
        projectId: params.projectId,
        permission: "admin",
        invoke: (stub, actor) => stub.deleteDekWraps(actor, params.environmentId, payload.wraps),
      }).pipe(Effect.as(noContent)),
    ),
);
