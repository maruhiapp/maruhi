// Handlers for the environment-management API (AUTH_SPEC §12-4).
//
// Check order (§12-3): authentication (middleware) → token scope (out
// of scope 404 / insufficient level 403) → DO (membership 404 / chain
// role 403 / semantic checks).
// The shared path is callProjectData in data-http.ts. The set of
// returnable errors is derived from each endpoint's contract
// declaration (api-schema) — no hand-written enumeration.

import { maruhiApi } from "@maruhi/api-schema";
import { RequestAuth } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/http-api";

import { ensureActorMatches } from "../authz.ts";
import {
  callProjectData,
  checkManifestCoordinates,
  checkStatementCoordinates,
  noContent,
  toManifestInput,
  toMetaStatementInput,
} from "../data/data-http.ts";
import type { EnvironmentListValue } from "../data/data-plane.ts";
import type { EnvironmentChainResultValue } from "../programs/composite-programs.ts";

/**
 * §12-4: the chain entry's actor and the wrap's signer must strictly
 * equal the caller. The actor match is checked ahead by the worker
 * (same acceptance policy as §11-1's generic append; the signer match
 * is carried by the DO's signature verification — §12-6).
 */
const ensureCompositeActor = Effect.fn("handlers-environments.ensureCompositeActor")(function* (
  entry: ChainEntry,
) {
  const principal = yield* (yield* RequestAuth).principal;
  yield* ensureActorMatches(principal, entry);
});

/**
 * The composite's token-scope level (AUTH_SPEC §12-3 / §16-2): normally
 * write; admin only when the boundary checkpoint notarizes the audit
 * head (non-empty audit_head_hash) — the scope half of effective
 * permission admin (same rule as the generic append's checkpoint).
 */
function requiredCompositePermission(checkpoint: {
  readonly payload: { readonly auditHeadHashHex: string };
}): "write" | "admin" {
  return checkpoint.payload.auditHeadHashHex === "" ? "write" : "admin";
}

export const environmentsLive = HttpApiBuilder.group(maruhiApi, "environments", (handlers) =>
  handlers
    .handle(
      "create",
      Effect.fn("handlers-environments.create")(function* ({ params, payload, endpoint }) {
        // §12-4: the actor of the chain entries (both create and the
        // boundary checkpoint) must strictly equal the caller
        // (2-entry composition)
        yield* ensureCompositeActor(payload.entry);
        yield* ensureCompositeActor(payload.checkpoint);
        // The worker side of the composite consistency check (§12-4):
        // matching the entry payload's and the statement / manifest's
        // environment_id (matching declared head and epoch is
        // state-dependent, so DO-side; the checkpoint tuple's
        // coordinates, epoch, version, and audit-head comparison is
        // also DO-side — ensureBoundaryCheckpointShape)
        yield* checkStatementCoordinates(payload.statement, {
          environmentId: payload.entry.payload.environmentId,
        });
        yield* checkManifestCoordinates(payload.manifest, payload.entry.payload.environmentId);
        return yield* callProjectData<EnvironmentChainResultValue>()({
          endpoint,
          projectId: params.projectId,
          // When the boundary checkpoint notarizes the audit head
          // (non-empty audit_head_hash), require the scope half of
          // effective permission admin (§16-2 — same rule as the
          // standalone path. The role half is the DO's
          // ensureCheckpointAuditHead)
          permission: requiredCompositePermission(payload.checkpoint),
          invoke: (stub, actor) =>
            stub.createEnvironment(actor, {
              parentHeadHashHex: payload.parentHeadHashHex,
              entry: payload.entry,
              statement: toMetaStatementInput(payload.statement),
              deks: payload.deks,
              manifest: toManifestInput(payload.manifest),
              checkpoint: payload.checkpoint,
            }),
        });
      }),
    )
    .handle(
      "rotate",
      Effect.fn("handlers-environments.rotate")(function* ({ params, payload, endpoint }) {
        yield* ensureCompositeActor(payload.entry);
        yield* ensureCompositeActor(payload.checkpoint);
        yield* checkManifestCoordinates(payload.manifest, params.environmentId);
        return yield* callProjectData<EnvironmentChainResultValue>()({
          endpoint,
          projectId: params.projectId,
          // Same as create: bundling a non-empty audit_head_hash
          // requires admin scope (§16-2)
          permission: requiredCompositePermission(payload.checkpoint),
          invoke: (stub, actor) =>
            stub.rotateEpoch(actor, params.environmentId, {
              parentHeadHashHex: payload.parentHeadHashHex,
              entry: payload.entry,
              deks: payload.deks,
              manifest: toManifestInput(payload.manifest),
              checkpoint: payload.checkpoint,
            }),
        });
      }),
    )
    .handle("list", ({ params, endpoint }) =>
      // List including the schemaPolicy advisory bundling (§12-7 / §12-11)
      callProjectData<EnvironmentListValue>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        invoke: (stub, actor) => stub.listEnvironments(actor),
      }),
    )
    .handle(
      "rename",
      Effect.fn("handlers-environments.rename")(function* ({ params, payload, endpoint }) {
        yield* checkStatementCoordinates(payload.statement, {
          environmentId: params.environmentId,
        });
        yield* checkManifestCoordinates(payload.manifest, params.environmentId);
        return yield* callProjectData<void>()({
          endpoint,
          projectId: params.projectId,
          permission: "write",
          invoke: (stub, actor) =>
            stub.renameEnvironment(
              actor,
              params.environmentId,
              toMetaStatementInput(payload.statement),
              toManifestInput(payload.manifest),
            ),
        });
      }, Effect.as(noContent)),
    )
    .handle(
      "remove",
      Effect.fn("handlers-environments.remove")(function* ({ params, payload, endpoint }) {
        // The deletion composite (§12-4 — 2026-10-07): the
        // delete_environment entry's actor must strictly equal the caller
        // (§11-1); admin scope + chain role admin or above (§12-3). The URL
        // / entry match, the CAS, the scope and the consensus rules are
        // judged by the DO (deleteEnvironmentCompositeProgram)
        yield* ensureCompositeActor(payload.entry);
        return yield* callProjectData<void>()({
          endpoint,
          projectId: params.projectId,
          permission: "admin",
          invoke: (stub, actor) =>
            stub.deleteEnvironment(actor, params.environmentId, {
              parentHeadHashHex: payload.parentHeadHashHex,
              entry: payload.entry,
            }),
        });
      }, Effect.as(noContent)),
    ),
);
