// Handlers for the needs-rotation flag API (AUDIT_SPEC §4.1 / §6 / §7).
//
// - flags: a derived view (read scope × chain role reader — class 1).
//   The flag set is a stateless read (no audit record), so the CSRF
//   header is not required (unlike the var.read record of a bulk pull —
//   AUTH_SPEC §12-7)
// - dismiss: a withdrawal operation (admin scope × chain role admin —
//   §3.3; same level as wrap deletion). Target validation (existence of
//   an active flag) is on the DO side
//
// The shared path is callProjectData in data-http.ts. The set of
// returnable errors is derived from each endpoint's contract
// declaration (api-schema).

import { maruhiApi } from "@maruhi/api-schema";
import { decodeEnvironmentId, decodeVariableId } from "@maruhi/core";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/http-api";

import { callProjectData, noContent } from "../data/data-http.ts";
import type { MemberProposalValue } from "../programs/programs-proposal.ts";
import type { EffectiveRotationFlag } from "../rotation-detect.ts";

export const rotationLive = HttpApiBuilder.group(maruhiApi, "rotation", (handlers) =>
  handlers
    .handle("flags", ({ params, endpoint }) =>
      callProjectData<readonly EffectiveRotationFlag[]>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        // The audit seq is not carried by the derived result itself
        // (AUDIT_SPEC §7 — 2026-08-16 C1 ruling. Removed from the type
        // rather than stripped at the boundary, leaving no room to
        // forget)
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
    // Sealed value proposals (AUTH_SPEC §14-5): a member's view (read
    // scope × chain role member — own wraps only; the role floor and the
    // scope filter are on the DO side)
    .handle("proposals", ({ params, endpoint }) =>
      callProjectData<readonly MemberProposalValue[]>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        invoke: (stub, actor) => stub.listRotationProposals(actor),
      }).pipe(Effect.map((proposals) => ({ proposals }))),
    )
    // A member's resolution (write scope × chain role member × environment
    // ∈ scope — the DO verifies the named versions on acceptance)
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
