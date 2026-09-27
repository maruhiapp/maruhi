// Handlers for the variable API (AUTH_SPEC §12-5 / §12-7).
//
// Check order (§12-3): authentication (middleware) → preliminary
// value-size check (413 — resource protection precedes semantic
// checks) → coordinate match of declared AAD / statement (422 — a
// self-consistency check depending only on request contents, carrying
// no existence information) → token scope → DO (membership / role /
// CAS / signature / quantity). The shared path is callProjectData in
// data-http.ts. The set of errors returnable as DO rejections is
// derived from each endpoint's contract declaration (api-schema) — no
// hand-written enumeration.
//
// Creation bundles a version-1 value with a VariableMetaStatement
// (metaVersion 1) (§12-5). Since variableId and the display name are
// carried by the statement, the expected variableId of the AAD
// coordinate check uses the statement's variableId (the only value
// path without a variableId in the URL).

import { ForbiddenError, maruhiApi } from "@maruhi/api-schema";
import { RequestAuth } from "@maruhi/core";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { statefulGetCsrfViolated } from "./auth.package/index.ts";
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
  toWireVariable,
} from "./data-http.ts";
import type {
  EnvironmentMetadataPullValue,
  EnvironmentPullValue,
  VariableVersionValue,
} from "./data-plane.ts";

export const variablesLive = HttpApiBuilder.group(maruhiApi, "variables", (handlers) =>
  handlers
    .handle("create", ({ params, payload, endpoint }) =>
      Effect.gen(function* () {
        // Union of the 2 create forms (§12-5): active = value bundled
        // / declared = no value (the wire Schema fixes the coupling of
        // status and value presence). The value-bearing preliminary
        // checks (size, AAD coordinates) apply only to the active form
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
            // The variableId destination is fixed by the statement
            // (match-checked against the value's AAD)
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
    .handle("push", ({ params, payload, endpoint }) =>
      Effect.gen(function* () {
        yield* checkValueSize(payload.value);
        yield* checkAadCoordinates(payload.value, {
          projectId: params.projectId,
          environmentId: params.environmentId,
          variableId: params.variableId,
        });
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
              // Re-encryption marker (AUTH_SPEC §12-5 — omission means false)
              payload.reencryption === true,
            ),
        });
      }),
    )
    .handle("activate", ({ params, payload, endpoint }) =>
      // The activation composite (§12-5): preliminary checks identical
      // to create (the value-bundled form), and the variableId is fixed
      // by the URL
      Effect.gen(function* () {
        yield* checkValueSize(payload.value);
        yield* checkStatementCoordinates(payload.statement, {
          environmentId: params.environmentId,
          variableId: params.variableId,
        });
        yield* checkManifestCoordinates(payload.manifest, params.environmentId);
        yield* checkAadCoordinates(payload.value, {
          projectId: params.projectId,
          environmentId: params.environmentId,
          variableId: params.variableId,
        });
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
    .handle("rename", ({ params, payload, endpoint }) =>
      Effect.gen(function* () {
        yield* checkStatementCoordinates(payload.statement, {
          environmentId: params.environmentId,
          variableId: params.variableId,
        });
        yield* checkManifestCoordinates(payload.manifest, params.environmentId);
        return yield* callProjectData<void>()({
          endpoint,
          projectId: params.projectId,
          permission: "write",
          invoke: (stub, actor) =>
            stub.renameVariable(
              actor,
              params.environmentId,
              params.variableId,
              toMetaStatementInput(payload.statement),
              toManifestInput(payload.manifest),
            ),
        });
      }).pipe(Effect.as(noContent)),
    )
    .handle("remove", ({ params, payload, endpoint }) =>
      Effect.gen(function* () {
        yield* checkStatementCoordinates(payload.statement, {
          environmentId: params.environmentId,
          variableId: params.variableId,
        });
        yield* checkManifestCoordinates(payload.manifest, params.environmentId);
        return yield* callProjectData<void>()({
          endpoint,
          projectId: params.projectId,
          permission: "write",
          invoke: (stub, actor) =>
            stub.deleteVariable(
              actor,
              params.environmentId,
              params.variableId,
              toMetaStatementInput(payload.statement),
              toManifestInput(payload.manifest),
            ),
        });
      }).pipe(Effect.as(noContent)),
    )
    .handle("pull", ({ params, endpoint, request }) =>
      Effect.gen(function* () {
        // A GET, but it carries state: the per-variable var.read audit
        // record (§12-7 / AUDIT_SPEC §3.3) — blocks pollution of the
        // audit trail by a third-party site stamping fake var.reads with
        // the victim's session (rationale in the JSDoc of
        // statefulGetCsrfViolated). The metadata-only mode
        // (pullMetadata) records no audit and is out of scope
        const principal = yield* (yield* RequestAuth).principal;
        if (statefulGetCsrfViolated(principal, request.headers)) {
          return yield* Effect.fail(new ForbiddenError({ reason: "csrf-header-required" }));
        }
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
          // Statements of declared variables (§12-7 — no value; present only when they exist)
          ...(pulled.declaredVariables === undefined
            ? {}
            : { declaredVariables: pulled.declaredVariables }),
          deks: pulled.deks,
          // The schemaPolicy advisory bundling (§12-7 / §12-11)
          schemaPolicy: pulled.schemaPolicy,
          // The latest manifest (§12-7 — always bundled when a stored
          // row exists; the client uniformly refuses its absence —
          // CRYPTO_SPEC §6.3)
          ...(pulled.manifest === undefined ? {} : { manifest: pulled.manifest }),
          // The value snapshot at checkpoint time (§12-7 — always
          // bundled when a stored row of the baseline checkpoint
          // exists; the material of client rule 2 — CRYPTO_SPEC §6.3)
          ...(pulled.checkpointSnapshot === undefined
            ? {}
            : { checkpointSnapshot: pulled.checkpointSnapshot }),
        };
      }),
    )
    // Metadata-only mode (§12-7): authorization identical to pull
    // (read × reader). Returns no values or DEKs; no var.read is
    // recorded (AUDIT_SPEC §3.3)
    .handle("pullMetadata", ({ params, endpoint }) =>
      callProjectData<EnvironmentMetadataPullValue>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        invoke: (stub, actor) => stub.pullEnvironmentMetadata(actor, params.environmentId),
      }),
    ),
);
