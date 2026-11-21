import { maruhiApi } from "@maruhi/api-schema";
import { RequestAuth } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/http-api";

import { ensureActorMatches } from "../authz.ts";
import type { EnvironmentListValue } from "../data.package/index.ts";
import {
  callProjectData,
  checkManifestCoordinates,
  checkStatementCoordinates,
  noContent,
  toManifestInput,
  toMetaStatementInput,
} from "../data.package/index.ts";
import type { EnvironmentChainResultValue } from "../programs/composite-programs.ts";

const ensureCompositeActor = Effect.fn("handlers-environments.ensureCompositeActor")(function* (
  entry: ChainEntry,
) {
  const principal = yield* (yield* RequestAuth).principal;
  yield* ensureActorMatches(principal, entry);
});

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
        yield* ensureCompositeActor(payload.entry);
        yield* ensureCompositeActor(payload.checkpoint);
        yield* checkStatementCoordinates(payload.statement, {
          environmentId: payload.entry.payload.environmentId,
        });
        yield* checkManifestCoordinates(payload.manifest, payload.entry.payload.environmentId);
        return yield* callProjectData<EnvironmentChainResultValue>()({
          endpoint,
          projectId: params.projectId,
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
