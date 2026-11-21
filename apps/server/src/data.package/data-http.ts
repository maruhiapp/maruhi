import type { EncryptedPayload, EnvironmentManifest } from "@maruhi/api-schema";
import {
  ActivationRequiredError,
  AttestationRateLimitedError,
  AttestationRegressionError,
  AttestationRejectedError,
  ChainCapacityExceededError,
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  ChainHeadConflictError,
  AuditHeadNotReadyError,
  CheckpointStateMismatchError,
  CompositeRequiredError,
  DataLimitExceededError,
  DekWrapExistsError,
  DekWrapNotFoundError,
  DekWrapRejectedError,
  DeviceLimitError,
  EnvironmentConflictError,
  EnvironmentNotFoundError,
  EpochConflictError,
  ExportChangedError,
  ExportRateLimitedError,
  ForbiddenError,
  ManifestRejectedError,
  ManifestVersionConflictError,
  MetaStatementRejectedError,
  MetaVersionConflictError,
  MirrorStateError,
  MirrorSyncRejectedError,
  NameNotNfcError,
  PayloadMismatchError,
  ProjectNotFoundError,
  ProposalLimitError,
  RotationFlagNotFoundError,
  RotationProposalNotFoundError,
  RotationProposalRejectedError,
  SchemaDescriptionRejectedError,
  SchemaPolicyRejectedError,
  ValueSignatureRejectedError,
  ValueTooLargeError,
  VariableConflictError,
  VariableNotFoundError,
  VersionConflictError,
} from "@maruhi/api-schema";
import type { EnvironmentId, ProjectId, TokenPermission, VariableId } from "@maruhi/core";
import { auditActorOf, RequestAuth } from "@maruhi/core";
import type { Role } from "@maruhi/crypto";
import { Effect, Schema } from "effect";
import { HttpServerResponse } from "effect/http";
import type { HttpApiEndpoint } from "effect/http-api";

import { ensureTokenScopeForProject } from "../authz.ts";
import type { ProjectChainDO } from "../do/chain-do.ts";
import { MAX_VALUE_CIPHERTEXT_BYTES } from "../policy.ts";
import { projectStub, rpcCall, WorkerEnv } from "../worker-env.ts";
import { roleAtLeast } from "./data-guards.ts";
import type {
  DataActor,
  EnvironmentPullValue,
  EnvManifestInput,
  MetaStatementInput,
  PulledVariableValue,
  ValueInput,
  WireMetaStatement,
  WireSchemaField,
} from "./data-plane.ts";
import type { DataOutcome, DataRejection } from "./data-rejection.ts";

export const noContent = HttpServerResponse.empty({ status: 204 });

export function toValueInput(payload: EncryptedPayload): ValueInput {
  return {
    suite: payload.suite,
    epoch: payload.aad.epoch,
    version: payload.aad.version,
    nonceHex: payload.nonceHex,
    ciphertextHex: payload.ciphertextHex,
    prevValueSigHashHex: payload.prevValueSigHashHex,
    chainHeadHashHex: payload.chainHeadHashHex,
    chainHeadSeq: payload.chainHeadSeq,
    signatureHex: payload.signatureHex,
  };
}

export function checkValueSize(payload: EncryptedPayload): Effect.Effect<void, ValueTooLargeError> {
  return payload.ciphertextHex.length / 2 > MAX_VALUE_CIPHERTEXT_BYTES
    ? Effect.fail(new ValueTooLargeError({ limitBytes: MAX_VALUE_CIPHERTEXT_BYTES }))
    : Effect.void;
}

interface AadCoordinates {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly variableId: VariableId;
}

function aadMismatchField(payload: EncryptedPayload, coordinates: AadCoordinates): string | null {
  if (payload.aad.projectId !== coordinates.projectId) {
    return "projectId";
  }
  if (payload.aad.environmentId !== coordinates.environmentId) {
    return "environmentId";
  }
  if (payload.aad.variableId !== coordinates.variableId) {
    return "variableId";
  }
  return null;
}

export function checkAadCoordinates(
  payload: EncryptedPayload,
  coordinates: AadCoordinates,
): Effect.Effect<void, PayloadMismatchError> {
  const field = aadMismatchField(payload, coordinates);
  return field === null ? Effect.void : Effect.fail(new PayloadMismatchError({ field }));
}

export function checkStatementCoordinates(
  statement: { readonly environmentId: EnvironmentId; readonly variableId?: VariableId },
  coordinates: { readonly environmentId: EnvironmentId; readonly variableId?: VariableId },
): Effect.Effect<void, PayloadMismatchError> {
  if (statement.environmentId !== coordinates.environmentId) {
    return Effect.fail(new PayloadMismatchError({ field: "statementEnvironmentId" }));
  }
  if (coordinates.variableId !== undefined && statement.variableId !== coordinates.variableId) {
    return Effect.fail(new PayloadMismatchError({ field: "statementVariableId" }));
  }
  return Effect.void;
}

export function checkManifestCoordinates(
  manifest: { readonly environmentId: EnvironmentId },
  environmentId: EnvironmentId,
): Effect.Effect<void, PayloadMismatchError> {
  return manifest.environmentId === environmentId
    ? Effect.void
    : Effect.fail(new PayloadMismatchError({ field: "manifestEnvironmentId" }));
}

export function toManifestInput(manifest: EnvironmentManifest): EnvManifestInput {
  return {
    suite: manifest.suite,
    epoch: manifest.epoch,
    manifestVersion: manifest.manifestVersion,
    variablesDigestHex: manifest.variablesDigestHex,
    envMetaVersion: manifest.envMetaVersion,
    envMetaSigHashHex: manifest.envMetaSigHashHex,
    prevManifestSigHashHex: manifest.prevManifestSigHashHex,
    chainHeadHashHex: manifest.chainHeadHashHex,
    chainHeadSeq: manifest.chainHeadSeq,
    signatureHex: manifest.signatureHex,
  };
}

export function toMetaStatementInput(statement: WireMetaStatement): MetaStatementInput {
  const base = {
    suite: statement.suite,
    name: statement.name,
    status: statement.status,
    metaVersion: statement.metaVersion,
    prevMetaSigHashHex: statement.prevMetaSigHashHex,
    chainHeadHashHex: statement.chainHeadHashHex,
    chainHeadSeq: statement.chainHeadSeq,
    signatureHex: statement.signatureHex,
  } satisfies Omit<WireMetaStatement, WireSchemaField | "layoutVersion">;
  const { layoutVersion, varType, required, description, maxAgeDays } = statement;
  if (
    layoutVersion === undefined ||
    varType === undefined ||
    required === undefined ||
    description === undefined
  ) {
    return base;
  }
  return {
    ...base,
    layoutVersion,
    schema: {
      varType,
      required,
      description,
      ...(maxAgeDays === undefined ? {} : { maxAgeDays }),
    },
  };
}

export function toWireVariable(
  projectId: ProjectId,
  environmentId: EnvironmentId,
  row: EnvironmentPullValue["variables"][number],
) {
  return {
    variableId: row.variableId,
    statement: row.statement,
    value: toWireValue(projectId, environmentId, row),
  };
}

export function toWireValue(
  projectId: ProjectId,
  environmentId: EnvironmentId,
  row: PulledVariableValue,
) {
  return {
    suite: row.suite,
    aad: {
      projectId,
      environmentId,
      epoch: row.epoch,
      variableId: row.variableId,
      version: row.version,
    },
    nonceHex: row.nonceHex,
    ciphertextHex: row.ciphertextHex,
    prevValueSigHashHex: row.prevValueSigHashHex,
    chainHeadHashHex: row.chainHeadHashHex,
    chainHeadSeq: row.chainHeadSeq,
    signatureHex: row.signatureHex,
    writerUserId: row.writerUserId,
    writerKeyFingerprintHex: row.writerKeyFingerprintHex,
  };
}

type DataApiError =
  | ProjectNotFoundError
  | ForbiddenError
  | AttestationRejectedError
  | AttestationRegressionError
  | AttestationRateLimitedError
  | EnvironmentNotFoundError
  | EnvironmentConflictError
  | CompositeRequiredError
  | DeviceLimitError
  | ProposalLimitError
  | CheckpointStateMismatchError
  | AuditHeadNotReadyError
  | ExportChangedError
  | ExportRateLimitedError
  | MirrorStateError
  | MirrorSyncRejectedError
  | ChainHeadConflictError
  | ChainEntryInvalidError
  | ChainEntryTooLargeError
  | ChainCapacityExceededError
  | PayloadMismatchError
  | VariableNotFoundError
  | VariableConflictError
  | VersionConflictError
  | EpochConflictError
  | ValueSignatureRejectedError
  | MetaStatementRejectedError
  | SchemaPolicyRejectedError
  | ActivationRequiredError
  | SchemaDescriptionRejectedError
  | MetaVersionConflictError
  | ManifestRejectedError
  | ManifestVersionConflictError
  | NameNotNfcError
  | DekWrapRejectedError
  | DekWrapExistsError
  | DekWrapNotFoundError
  | RotationFlagNotFoundError
  | RotationProposalNotFoundError
  | RotationProposalRejectedError
  | DataLimitExceededError;

const rejectionErrors = {
  "not-initialized": (_rejection, projectId) => new ProjectNotFoundError({ projectId }),
  "not-member": (_rejection, projectId) => new ProjectNotFoundError({ projectId }),
  "insufficient-role": () => new ForbiddenError({ reason: "insufficient-role" }),
  "insufficient-scope": () => new ForbiddenError({ reason: "insufficient-scope" }),
  "environment-not-found": (rejection) =>
    new EnvironmentNotFoundError({ environmentId: rejection.environmentId }),
  "environment-conflict": (rejection) =>
    new EnvironmentConflictError({
      environmentId: rejection.environmentId,
      reason: rejection.reason,
    }),
  "composite-required": (rejection) => new CompositeRequiredError({ op: rejection.op }),
  "device-limit": (rejection) => new DeviceLimitError({ limit: rejection.limit }),
  "proposal-limit": (rejection) =>
    new ProposalLimitError({ reason: rejection.reason, limit: rejection.limit }),
  "checkpoint-state-mismatch": (rejection) =>
    new CheckpointStateMismatchError({ reason: rejection.reason }),
  "audit-head-not-ready": () => new AuditHeadNotReadyError(),
  "export-changed": () => new ExportChangedError({ reason: "project-changed" }),
  "export-rate-limited": (rejection) =>
    new ExportRateLimitedError({ retryAfterSeconds: rejection.retryAfterSeconds }),
  "mirror-read-only": () => new ForbiddenError({ reason: "mirror-read-only" }),
  "mirror-state": (rejection) => new MirrorStateError({ reason: rejection.reason }),
  "mirror-sync-rejected": (rejection) => new MirrorSyncRejectedError({ reason: rejection.reason }),
  "chain-head-conflict": (rejection) =>
    new ChainHeadConflictError({
      currentHeadSeq: rejection.currentHeadSeq,
      currentHeadHashHex: rejection.currentHeadHashHex,
    }),
  "chain-entry-invalid": (rejection) =>
    new ChainEntryInvalidError({ seq: rejection.seq, reason: rejection.reason }),
  "chain-entry-too-large": (rejection) =>
    new ChainEntryTooLargeError({ limitBytes: rejection.limitBytes }),
  "chain-capacity-exceeded": (rejection) =>
    new ChainCapacityExceededError({
      maxEntries: rejection.maxEntries,
      maxTotalBytes: rejection.maxTotalBytes,
    }),
  "payload-mismatch": (rejection) => new PayloadMismatchError({ field: rejection.field }),
  "variable-not-found": (rejection) =>
    new VariableNotFoundError({ variableId: rejection.variableId }),
  "variable-conflict": (rejection) =>
    new VariableConflictError({ variableId: rejection.variableId, reason: rejection.reason }),
  "version-conflict": (rejection) =>
    new VersionConflictError({ currentVersion: rejection.currentVersion }),
  "epoch-conflict": (rejection) => new EpochConflictError({ currentEpoch: rejection.currentEpoch }),
  "value-rejected": (rejection) => new ValueSignatureRejectedError({ reason: rejection.reason }),
  "meta-rejected": (rejection) => new MetaStatementRejectedError({ reason: rejection.reason }),
  "schema-policy-rejected": (rejection) =>
    new SchemaPolicyRejectedError({ reason: rejection.reason }),
  "activation-required": (rejection) =>
    new ActivationRequiredError({ variableId: rejection.variableId }),
  "description-rejected": (rejection) =>
    new SchemaDescriptionRejectedError({ reason: rejection.reason }),
  "meta-version-conflict": (rejection) =>
    new MetaVersionConflictError({ currentMetaVersion: rejection.currentMetaVersion }),
  "manifest-rejected": (rejection) => new ManifestRejectedError({ reason: rejection.reason }),
  "manifest-version-conflict": (rejection) =>
    new ManifestVersionConflictError({ currentManifestVersion: rejection.currentManifestVersion }),
  "name-not-nfc": () => new NameNotNfcError(),
  "dek-wrap-rejected": (rejection) => new DekWrapRejectedError({ reason: rejection.reason }),
  "dek-wrap-exists": (rejection) =>
    new DekWrapExistsError({
      epoch: rejection.epoch,
      recipientUserId: rejection.recipientUserId,
      storedRecipientEncPubHex: rejection.storedRecipientEncPubHex,
    }),
  "dek-wrap-not-found": (rejection) =>
    new DekWrapNotFoundError({
      epoch: rejection.epoch,
      recipientUserId: rejection.recipientUserId,
    }),
  "rotation-flag-not-found": (rejection) =>
    new RotationFlagNotFoundError({
      environmentId: rejection.environmentId,
      variableId: rejection.variableId,
    }),
  "rotation-proposal-not-found": (rejection) =>
    new RotationProposalNotFoundError({ proposalId: rejection.proposalId }),
  "rotation-proposal-rejected": (rejection) =>
    new RotationProposalRejectedError({ reason: rejection.reason }),
  "limit-exceeded": (rejection) =>
    new DataLimitExceededError({ resource: rejection.resource, limit: rejection.limit }),

  "attestation-rejected": (rejection) => new AttestationRejectedError({ reason: rejection.reason }),
  "attestation-regression": (rejection) =>
    new AttestationRegressionError({ storedSeq: rejection.storedSeq }),
  "attestation-rate-limited": (rejection) =>
    new AttestationRateLimitedError({ retryAfterSeconds: rejection.retryAfterSeconds }),
} satisfies {
  readonly [K in DataRejection["kind"]]: (
    rejection: Extract<DataRejection, { kind: K }>,
    projectId: ProjectId,
  ) => DataApiError;
};

export function dataRejectionError<K extends DataRejection["kind"]>(
  rejection: Extract<DataRejection, { kind: K }>,
  projectId: ProjectId,
): ReturnType<(typeof rejectionErrors)[K]> {
  return rejectionErrors[rejection.kind](rejection as never, projectId) as ReturnType<
    (typeof rejectionErrors)[K]
  >;
}

type ContractDataError<Endpoint extends HttpApiEndpoint.Top> = Extract<
  HttpApiEndpoint.Error<Endpoint>["Type"],
  DataApiError
>;

const contractFilters = new WeakMap<object, ReadonlyArray<(error: DataApiError) => boolean>>();

function contractFilterOf(
  endpoint: HttpApiEndpoint.Top,
): ReadonlyArray<(error: DataApiError) => boolean> {
  let filters = contractFilters.get(endpoint);
  if (filters === undefined) {
    filters = Array.from(endpoint.error, (schema) => Schema.is(schema));
    contractFilters.set(endpoint, filters);
  }
  return filters;
}

export function unwrapDataOutcome<T, Endpoint extends HttpApiEndpoint.Top>(
  outcome: DataOutcome<T>,
  projectId: ProjectId,
  endpoint: Endpoint,
): Effect.Effect<T, ContractDataError<Endpoint>> {
  if (outcome.kind === "ok") {
    return Effect.succeed(outcome.value);
  }
  const error = dataRejectionError(outcome.rejection, projectId);
  return contractFilterOf(endpoint).some((allows) => allows(error))
    ? Effect.fail(error as ContractDataError<Endpoint>)
    : Effect.die(error);
}

export const callProjectData =
  <T>() =>
  <Endpoint extends HttpApiEndpoint.Top>(options: {
    readonly endpoint: Endpoint;
    readonly projectId: ProjectId;
    readonly permission: TokenPermission;
    readonly invoke: (
      stub: DurableObjectStub<ProjectChainDO>,
      actor: DataActor,
    ) => PromiseLike<unknown>;
  }) =>
    Effect.gen(function* () {
      const principal = yield* (yield* RequestAuth).principal;
      yield* ensureTokenScopeForProject(principal, options.projectId, options.permission);
      const env = yield* WorkerEnv;
      const outcome = yield* rpcCall<DataOutcome<T>>(() =>
        options.invoke(projectStub(env, options.projectId), auditActorOf(principal)),
      ).pipe(Effect.orDie);
      return yield* unwrapDataOutcome(outcome, options.projectId, options.endpoint);
    });

export const requireProjectChainAdmin = Effect.fn("data-http.requireProjectChainAdmin")(function* <
  Endpoint extends HttpApiEndpoint.Top,
>(projectId: ProjectId, endpoint: Endpoint) {
  const principal = yield* (yield* RequestAuth).principal;
  yield* ensureTokenScopeForProject(principal, projectId, "admin");
  const env = yield* WorkerEnv;
  const outcome = yield* rpcCall<DataOutcome<Role>>(() =>
    projectStub(env, projectId).memberRoleFor(principal.userId),
  ).pipe(Effect.orDie);
  const role = yield* unwrapDataOutcome(outcome, projectId, endpoint);
  if (!roleAtLeast(role, "admin")) {
    return yield* Effect.fail(new ForbiddenError({ reason: "insufficient-role" }));
  }
  return { principal, role };
});
