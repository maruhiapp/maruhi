import type { EnvironmentManifest } from "@maruhi/api-schema";
import { ForbiddenError, maruhiApi } from "@maruhi/api-schema";
import type { EnvironmentId, ProjectId, VariableId } from "@maruhi/core";
import { RequestAuth } from "@maruhi/core";
import { Effect } from "effect";
import type { HttpApiEndpoint } from "effect/http-api";
import { HttpApiBuilder } from "effect/http-api";

import { statefulGetCsrfViolated } from "../auth.package/index.ts";
import type {
  EnvironmentMetadataPullValue,
  EnvironmentPullValue,
  VariableVersionValue,
  WireMetaStatement,
} from "../data.package/index.ts";
import {
  callProjectData,
  checkAadCoordinates,
  checkManifestCoordinates,
  checkStatementCoordinates,
  checkValueSize,
  noContent,
  toManifestInput,
  toMetaStatementInput,
  toValueInput,
  toWireValue,
  toWireVariable,
} from "../data.package/index.ts";
import type {
  VariableVersionHistoryValue,
  VariableVersionValuesValue,
} from "../programs/programs-history.ts";

const ensureStatefulGetCsrf = Effect.fn("handlers-variables.ensureStatefulGetCsrf")(function* (
  headers: Parameters<typeof statefulGetCsrfViolated>[1],
) {
  const principal = yield* (yield* RequestAuth).principal;
  if (statefulGetCsrfViolated(principal, headers)) {
    return yield* Effect.fail(new ForbiddenError({ reason: "csrf-header-required" }));
  }
});

const applyVariableStatement = Effect.fn("handlers-variables.applyVariableStatement")(function* <
  Endpoint extends HttpApiEndpoint.Top,
>(
  method: "renameVariable" | "deleteVariable",
  {
    params,
    payload,
    endpoint,
  }: {
    readonly params: {
      readonly projectId: ProjectId;
      readonly environmentId: EnvironmentId;
      readonly variableId: VariableId;
    };
    readonly payload: {
      readonly statement: WireMetaStatement & {
        readonly environmentId: EnvironmentId;
        readonly variableId: VariableId;
      };
      readonly manifest: EnvironmentManifest;
    };
    readonly endpoint: Endpoint;
  },
) {
  yield* checkStatementCoordinates(payload.statement, params);
  yield* checkManifestCoordinates(payload.manifest, params.environmentId);
  yield* callProjectData<void>()({
    endpoint,
    projectId: params.projectId,
    permission: "write",
    invoke: (stub, actor) =>
      stub[method](
        actor,
        params.environmentId,
        params.variableId,
        toMetaStatementInput(payload.statement),
        toManifestInput(payload.manifest),
      ),
  });
  return noContent;
});

export const variablesLive = HttpApiBuilder.group(maruhiApi, "variables", (handlers) =>
  handlers
    .handle(
      "create",
      Effect.fn("handlers-variables.create")(function* ({ params, payload, endpoint }) {
        const value = "value" in payload ? payload.value : undefined;
        if (value !== undefined) {
          yield* checkValueSize(value);
        }
        yield* checkStatementCoordinates(payload.statement, {
          environmentId: params.environmentId,
        });
        yield* checkManifestCoordinates(payload.manifest, params.environmentId);
        if (value !== undefined) {
          yield* checkAadCoordinates(value, {
            projectId: params.projectId,
            environmentId: params.environmentId,
            variableId: payload.statement.variableId,
          });
        }
        return yield* callProjectData<VariableVersionValue>()({
          endpoint,
          projectId: params.projectId,
          permission: "write",
          invoke: (stub, actor) =>
            stub.createVariable(actor, params.environmentId, {
              variableId: payload.statement.variableId,
              statement: toMetaStatementInput(payload.statement),
              ...(value === undefined ? {} : { value: toValueInput(value) }),
              manifest: toManifestInput(payload.manifest),
            }),
        });
      }),
    )
    .handle(
      "push",
      Effect.fn("handlers-variables.push")(function* ({ params, payload, endpoint }) {
        yield* checkValueSize(payload.value);
        yield* checkAadCoordinates(payload.value, params);
        return yield* callProjectData<VariableVersionValue>()({
          endpoint,
          projectId: params.projectId,
          permission: "write",
          invoke: (stub, actor) =>
            stub.pushVersion(
              actor,
              params.environmentId,
              params.variableId,
              toValueInput(payload.value),
              payload.sameValueAs,
            ),
        });
      }),
    )
    .handle("history", ({ params, endpoint }) =>
      callProjectData<VariableVersionHistoryValue>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        invoke: (stub, actor) =>
          stub.variableHistory(actor, params.environmentId, params.variableId),
      }),
    )
    .handle(
      "versionValues",
      Effect.fn("handlers-variables.versionValues")(function* ({
        params,
        query,
        endpoint,
        request,
      }) {
        yield* ensureStatefulGetCsrf(request.headers);
        const range = yield* callProjectData<VariableVersionValuesValue>()({
          endpoint,
          projectId: params.projectId,
          permission: "read",
          invoke: (stub, actor) =>
            stub.variableVersionValues(
              actor,
              params.environmentId,
              params.variableId,
              query.fromVersion,
            ),
        });
        return {
          variableId: range.variableId,
          latestVersion: range.latestVersion,
          values: range.values.map((row) =>
            toWireValue(params.projectId, params.environmentId, row),
          ),
        };
      }),
    )
    .handle(
      "activate",
      Effect.fn("handlers-variables.activate")(function* ({ params, payload, endpoint }) {
        yield* checkValueSize(payload.value);
        yield* checkStatementCoordinates(payload.statement, params);
        yield* checkManifestCoordinates(payload.manifest, params.environmentId);
        yield* checkAadCoordinates(payload.value, params);
        return yield* callProjectData<VariableVersionValue>()({
          endpoint,
          projectId: params.projectId,
          permission: "write",
          invoke: (stub, actor) =>
            stub.activateVariable(actor, params.environmentId, params.variableId, {
              value: toValueInput(payload.value),
              statement: toMetaStatementInput(payload.statement),
              manifest: toManifestInput(payload.manifest),
            }),
        });
      }),
    )
    .handle("rename", (request) => applyVariableStatement("renameVariable", request))
    .handle("remove", (request) => applyVariableStatement("deleteVariable", request))
    .handle(
      "pull",
      Effect.fn("handlers-variables.pull")(function* ({ params, endpoint, request }) {
        yield* ensureStatefulGetCsrf(request.headers);
        const pulled = yield* callProjectData<EnvironmentPullValue>()({
          endpoint,
          projectId: params.projectId,
          permission: "read",
          invoke: (stub, actor) => stub.pullEnvironment(actor, params.environmentId),
        });
        return {
          environmentId: pulled.environmentId,
          currentEpoch: pulled.currentEpoch,
          statement: pulled.statement,
          variables: pulled.variables.map((row) =>
            toWireVariable(params.projectId, params.environmentId, row),
          ),
          deletedVariables: pulled.deletedVariables,
          ...(pulled.declaredVariables === undefined
            ? {}
            : { declaredVariables: pulled.declaredVariables }),
          deks: pulled.deks,
          schemaPolicy: pulled.schemaPolicy,
          manifest: pulled.manifest,
          ...(pulled.checkpointSnapshot === undefined
            ? {}
            : { checkpointSnapshot: pulled.checkpointSnapshot }),
        };
      }),
    )
    .handle("pullMetadata", ({ params, endpoint }) =>
      callProjectData<EnvironmentMetadataPullValue>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        invoke: (stub, actor) => stub.pullEnvironmentMetadata(actor, params.environmentId),
      }),
    ),
);
