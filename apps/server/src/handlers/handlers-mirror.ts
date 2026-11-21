import { maruhiApi } from "@maruhi/api-schema";
import { HttpApiBuilder } from "effect/http-api";

import { callProjectData } from "../data.package/index.ts";
import type { MirrorPageValue, MirrorStatusValue } from "../programs/programs-mirror.ts";

export const mirrorLive = HttpApiBuilder.group(maruhiApi, "mirror", (handlers) =>
  handlers
    .handle("status", ({ params, endpoint }) =>
      callProjectData<MirrorStatusValue>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        invoke: (stub, actor) => stub.mirrorStatus(actor),
      }),
    )
    .handle("mark", ({ params, payload, endpoint }) =>
      callProjectData<MirrorStatusValue>()({
        endpoint,
        projectId: params.projectId,
        permission: "admin",
        invoke: (stub, actor) => stub.markMirror(actor, payload.sourceOrigin),
      }),
    )
    .handle("unmark", ({ params, endpoint }) =>
      callProjectData<MirrorStatusValue>()({
        endpoint,
        projectId: params.projectId,
        permission: "admin",
        invoke: (stub, actor) => stub.unmarkMirror(actor),
      }),
    )
    .handle("pages", ({ params, payload, endpoint }) =>
      callProjectData<MirrorPageValue>()({
        endpoint,
        projectId: params.projectId,
        permission: "admin",
        invoke: (stub, actor) =>
          stub.mirrorPage(actor, {
            sequence: payload.sequence,
            lines: payload.lines,
            sourceMutationSeq: payload.sourceMutationSeq,
          }),
      }),
    ),
);
