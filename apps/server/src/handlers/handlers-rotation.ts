import { maruhiApi } from "@maruhi/api-schema";
import { decodeEnvironmentId, decodeVariableId } from "@maruhi/core";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/http-api";

import { callProjectData, noContent } from "../data.package/index.ts";
import type { MemberProposalValue } from "../programs/programs-proposal.ts";
import type { EffectiveRotationFlag } from "../rotation-detect.ts";

export const rotationLive = HttpApiBuilder.group(maruhiApi, "rotation", (handlers) =>
  handlers
    .handle("flags", ({ params, endpoint }) =>
      callProjectData<readonly EffectiveRotationFlag[]>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        invoke: (stub, actor) => stub.rotationFlags(actor),
      }).pipe(
        Effect.map((flags) => ({
          flags: flags.map((flag) => ({
            ...flag,
            environmentId: decodeEnvironmentId(flag.environmentId),
            variableId: decodeVariableId(flag.variableId),
          })),
        })),
      ),
    )
    .handle("dismiss", ({ params, payload, endpoint }) =>
      callProjectData<void>()({
        endpoint,
        projectId: params.projectId,
        permission: "admin",
        invoke: (stub, actor) => stub.dismissRotationFlags(actor, payload.targets),
      }).pipe(Effect.as(noContent)),
    )
    .handle("proposals", ({ params, endpoint }) =>
      callProjectData<readonly MemberProposalValue[]>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        invoke: (stub, actor) => stub.listRotationProposals(actor),
      }).pipe(Effect.map((proposals) => ({ proposals }))),
    )
    .handle("resolveProposal", ({ params, payload, endpoint }) =>
      callProjectData<void>()({
        endpoint,
        projectId: params.projectId,
        permission: "write",
        invoke: (stub, actor) =>
          stub.resolveRotationProposal(actor, params.proposalId, {
            outcome: payload.outcome,
            versions: payload.versions ?? [],
          }),
      }).pipe(Effect.as(noContent)),
    ),
);
