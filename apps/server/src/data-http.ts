// Common parts of the data-plane handlers (AUTH_SPEC §12).
//
// - Mapping of the DO's DataRejection onto api-schema typed errors
// - Consistency check between the declared AAD's components and the
//   destination coordinates (§12-2 — depends only on the request's
//   contents and carries no existence information)
// - Preliminary value-size check (§12-8 — resource protection precedes
//   semantic checks; §12-3)

import type { EncryptedPayload } from "@maruhi/api-schema";
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
  ForbiddenError,
  ManifestRejectedError,
  ManifestVersionConflictError,
  MetaStatementRejectedError,
  MetaVersionConflictError,
  NameNotNfcError,
  PayloadMismatchError,
  ProjectNotFoundError,
  ProposalLimitError,
  RotationFlagNotFoundError,
  SchemaDescriptionRejectedError,
  SchemaPolicyRejectedError,
  ValueSignatureRejectedError,
  ValueTooLargeError,
  VariableConflictError,
  VariableNotFoundError,
  VersionConflictError,
} from "@maruhi/api-schema";
import type { TokenPermission } from "@maruhi/core";
import { auditActorOf, RequestAuth } from "@maruhi/core";
import type { Role } from "@maruhi/crypto";
import { Effect, Schema } from "effect";
import { HttpServerResponse } from "effect/unstable/http";
import type { HttpApiEndpoint } from "effect/unstable/httpapi";

import { ensureTokenScopeForProject } from "./authz.ts";
import type { ProjectChainDO } from "./chain-do.ts";
import type {
  DataActor,
  DataOutcome,
  DataRejection,
  EnvironmentPullValue,
  EnvManifestInput,
  MetaStatementInput,
  ValueInput,
} from "./data-plane.ts";
import { roleAtLeast } from "./data-plane.ts";
import { MAX_VALUE_CIPHERTEXT_BYTES } from "./policy.ts";
import { projectStub, rpcCall, WorkerEnv } from "./worker-env.ts";

/** The 204 response (shared by write endpoints). */
export const noContent = HttpServerResponse.empty({ status: 204 });

/**
 * EncryptedPayload → the store input handed to the DO (carries verified
 * coordinates, the state-dependent part, and the signature block —
 * CRYPTO_SPEC §4.1).
 */
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

/** §12-8: preliminary check of the value's ciphertext size (hex: 1 byte = 2 chars). */
export function checkValueSize(payload: EncryptedPayload): Effect.Effect<void, ValueTooLargeError> {
  return payload.ciphertextHex.length / 2 > MAX_VALUE_CIPHERTEXT_BYTES
    ? Effect.fail(new ValueTooLargeError({ limitBytes: MAX_VALUE_CIPHERTEXT_BYTES }))
    : Effect.void;
}

interface AadCoordinates {
  readonly projectId: string;
  readonly environmentId: string;
  readonly variableId: string;
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

/**
 * §12-2: match check between the declared AAD's coordinate components
 * (project / environment / variable) and the request's destination
 * coordinates. epoch / version are state-dependent, so the DO checks them.
 */
export function checkAadCoordinates(
  payload: EncryptedPayload,
  coordinates: AadCoordinates,
): Effect.Effect<void, PayloadMismatchError> {
  const field = aadMismatchField(payload, coordinates);
  return field === null ? Effect.void : Effect.fail(new PayloadMismatchError({ field }));
}

/**
 * Match check between a statement's declared coordinates and the
 * request's destination coordinates (a premise of §12-5's coordinate
 * reconstruction). Since the DO reconstructs the signed content from the
 * URL / destination, a mismatched declaration fails signature
 * verification anyway — but like the AAD coordinate check (§12-2 step
 * 1a), the worker rejects early as a self-consistency check that depends
 * only on the request's contents, surfacing the disagreeing coordinates.
 */
export function checkStatementCoordinates(
  statement: { readonly environmentId: string; readonly variableId?: string },
  coordinates: { readonly environmentId: string; readonly variableId?: string },
): Effect.Effect<void, PayloadMismatchError> {
  if (statement.environmentId !== coordinates.environmentId) {
    return Effect.fail(new PayloadMismatchError({ field: "statementEnvironmentId" }));
  }
  if (coordinates.variableId !== undefined && statement.variableId !== coordinates.variableId) {
    return Effect.fail(new PayloadMismatchError({ field: "statementVariableId" }));
  }
  return Effect.void;
}

/**
 * Match check between a manifest's declared coordinates and the request's
 * destination coordinates (the manifest version of
 * checkStatementCoordinates — §12-5, where the DO reconstructs the signed
 * content from the URL / destination).
 */
export function checkManifestCoordinates(
  manifest: { readonly environmentId: string },
  environmentId: string,
): Effect.Effect<void, PayloadMismatchError> {
  return manifest.environmentId === environmentId
    ? Effect.void
    : Effect.fail(new PayloadMismatchError({ field: "manifestEnvironmentId" }));
}

/** Wire manifest → the store input handed to the DO (coordinates already verified — §12-5). */
export function toManifestInput(manifest: {
  readonly suite: "maruhi/v1";
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly variablesDigestHex: string;
  readonly envMetaVersion: number;
  readonly envMetaSigHashHex: string;
  readonly prevManifestSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}): EnvManifestInput {
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

/**
 * Wire statement → the store input handed to the DO (coordinates already
 * verified). In layout v2 (§12-2) layoutVersion and the schema fields are
 * present as a 4-field set — the wire Schema forces the coupling, so the
 * branch may test layoutVersion's presence alone (missing schema fields
 * fall earlier as a Schema 400).
 */
export function toMetaStatementInput(statement: {
  readonly suite: "maruhi/v1";
  readonly name: string;
  readonly status: "active" | "deleted" | "declared";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
  readonly layoutVersion?: number;
  readonly varType?: "" | "string" | "number" | "boolean" | "url";
  readonly required?: boolean;
  readonly description?: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}): MetaStatementInput {
  return {
    suite: statement.suite,
    name: statement.name,
    status: statement.status,
    metaVersion: statement.metaVersion,
    prevMetaSigHashHex: statement.prevMetaSigHashHex,
    ...(statement.layoutVersion === undefined ||
    statement.varType === undefined ||
    statement.required === undefined ||
    statement.description === undefined
      ? {}
      : {
          layoutVersion: statement.layoutVersion,
          schema: {
            varType: statement.varType,
            required: statement.required,
            description: statement.description,
          },
        }),
    chainHeadHashHex: statement.chainHeadHashHex,
    chainHeadSeq: statement.chainHeadSeq,
    signatureHex: statement.signatureHex,
  };
}

/**
 * DO stored row → the wire's DistributedEncryptedPayload (§12-2 / §12-7).
 * The AAD is reconstructed from the stored coordinates (a self-describing
 * representation equivalent to what was coordinate-checked at store
 * time). suite returns the stored row's value (CRYPTO_SPEC §2 design
 * principle 4). The signature block and writer / statement + author (the
 * user_id + key FP at acceptance time) are returned as stored — not
 * re-derived from the current member set (verifiability of past data from
 * removed writers / authors). The server-recomputed signed_bytes hash is
 * distributed for neither values nor statements.
 */
export function toWireVariable(
  projectId: string,
  environmentId: string,
  row: EnvironmentPullValue["variables"][number],
) {
  return {
    variableId: row.variableId,
    statement: row.statement,
    value: {
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
    },
  };
}

// ---------------------------------------------------------------------------
// DataRejection → typed errors
// ---------------------------------------------------------------------------

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
  | DataLimitExceededError;

// A small mapping per kind (§11-2: uninitialized and non-member are not
// distinguished; both fold to 404). satisfies enforces exhaustiveness
// while keeping a precise return type per kind (so callers of
// dataRejectionError — the chain-side mapping in handlers-membership.ts —
// receive a precise error union)
const rejectionErrors = {
  "not-initialized": (_rejection, projectId) => new ProjectNotFoundError({ projectId }),
  "not-member": (_rejection, projectId) => new ProjectNotFoundError({ projectId }),
  "insufficient-role": () => new ForbiddenError({ reason: "insufficient-role" }),
  // Environment ∉ the caller's scope (§9-2 / §12-3 — same layer, same type as insufficient role)
  "insufficient-scope": () => new ForbiddenError({ reason: "insufficient-scope" }),
  "environment-not-found": (rejection) =>
    new EnvironmentNotFoundError({ environmentId: rejection.environmentId }),
  "environment-conflict": (rejection) =>
    new EnvironmentConflictError({
      environmentId: rejection.environmentId,
      reason: rejection.reason,
    }),
  // Chain-acceptance kinds (shared by the composite request §12-4 and the generic chain API)
  "composite-required": (rejection) => new CompositeRequiredError({ op: rejection.op }),
  // Device-count acceptance policy (AUTH_SPEC §12-8 — 2026-09-19 DK K3)
  "device-limit": (rejection) => new DeviceLimitError({ limit: rejection.limit }),
  // Acceptance policy for the four-eyes propose (AUTH_SPEC §12-8 — K5)
  "proposal-limit": (rejection) =>
    new ProposalLimitError({ reason: rejection.reason, limit: rejection.limit }),
  "checkpoint-state-mismatch": (rejection) =>
    new CheckpointStateMismatchError({ reason: rejection.reason }),
  // Bounded extension of the audit-head derived column not yet complete
  // (retryable 503 — AUDIT_SPEC §5.1 / AUTH_SPEC §16-2; empty body —
  // no count leak)
  "audit-head-not-ready": () => new AuditHeadNotReadyError(),
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
  // The schemaPolicy acceptance gate (AUTH_SPEC §12-11 / §12-5)
  "schema-policy-rejected": (rejection) =>
    new SchemaPolicyRejectedError({ reason: rejection.reason }),
  // A normal push to a declared variable (§12-5 — requires the activation composite)
  "activation-required": (rejection) =>
    new ActivationRequiredError({ variableId: rejection.variableId }),
  // Acceptance check of a schema description (§12-8)
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
      // The occupying wrap's stored recipient enc public key (AUTH_SPEC §12-6)
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
  "limit-exceeded": (rejection) =>
    new DataLimitExceededError({ resource: rejection.resource, limit: rejection.limit }),
  // Head attestation (AUTH_SPEC §16-1)

  "attestation-rejected": (rejection) => new AttestationRejectedError({ reason: rejection.reason }),
  "attestation-regression": (rejection) =>
    new AttestationRegressionError({ storedSeq: rejection.storedSeq }),
  "attestation-rate-limited": (rejection) =>
    new AttestationRateLimitedError({ retryAfterSeconds: rejection.retryAfterSeconds }),
} satisfies {
  readonly [K in DataRejection["kind"]]: (
    rejection: Extract<DataRejection, { kind: K }>,
    projectId: string,
  ) => DataApiError;
};

/**
 * DataRejection → api-schema typed errors (the single home of the
 * per-kind mapping). The chain API handlers (handlers-membership.ts)
 * also align their RPC outcome kind to the DataRejection kind and pass
 * through here (no dual maintenance of mappings).
 */
export function dataRejectionError<K extends DataRejection["kind"]>(
  rejection: Extract<DataRejection, { kind: K }>,
  projectId: string,
): ReturnType<(typeof rejectionErrors)[K]> {
  return rejectionErrors[rejection.kind](rejection as never, projectId) as ReturnType<
    (typeof rejectionErrors)[K]
  >;
}

/**
 * Among the endpoint contract (HttpApiEndpoint's error declaration), the
 * error types that can appear as a mapping of a DO rejection
 * (rejectionErrors). Errors dedicated to the worker's preliminary checks
 * in the contract declaration (ValueTooLarge etc.) are excluded since
 * they are not generated from a DataRejection.
 */
type ContractDataError<Endpoint extends HttpApiEndpoint.Top> = Extract<
  HttpApiEndpoint.Error<Endpoint>["Type"],
  DataApiError
>;

// The predicate list "is this error value in the contract?", built from
// endpoint.error (the set of declared Schemas; a public property of
// HttpApiEndpoint). An endpoint is a value fixed at build time, so this
// needs to be built only once per endpoint
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

/**
 * Maps a DO outcome to the handler's success value / typed error. Since
 * the set of returnable errors is derived from the endpoint's contract
 * declaration itself (api-schema's error: [...]) on both the runtime
 * (Schema check on endpoint.error) and type (the Error type argument)
 * sides, the declaration and the mapping cannot drift apart. A rejection
 * outside the contract is dropped to a defect (500) as a program-side
 * invariant violation. Exported so tests can verify it directly.
 */
export function unwrapDataOutcome<T, Endpoint extends HttpApiEndpoint.Top>(
  outcome: DataOutcome<T>,
  projectId: string,
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

/**
 * The shared path of the data-plane handlers (the §12-3 check order):
 * resolve the authenticated principal → token scope (out of scope 404 /
 * insufficient level 403) → DO RPC → map the outcome. Handler-specific
 * preliminary checks (value size, AAD coordinates) are performed by the
 * caller before this.
 *
 * `endpoint` receives the handler's endpoint argument (the endpoint being
 * processed itself). The errors returnable under the contract are derived
 * from it, so there is no hand-written enumeration. The curried shape
 * reconciles "T (the RPC's value type) is explicit while Endpoint is
 * inferred" (TS does not allow partial type-argument application).
 */
export const callProjectData =
  <T>() =>
  <Endpoint extends HttpApiEndpoint.Top>(options: {
    readonly endpoint: Endpoint;
    readonly projectId: string;
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
      );
      return yield* unwrapDataOutcome(outcome, options.projectId, options.endpoint);
    });

/**
 * The common leading stage of the D1-backed per-project endpoints (shared
 * by the invite API — AUTH_SPEC §15-2 — and the invite.* audit read —
 * AUDIT_SPEC §7): token scope admin (out of scope 404 — §11-2) → the
 * DO's memberRoleFor (non-member 404) → chain role admin or higher (below
 * is 403). On pass, returns the caller and the role (for owner-only
 * checks).
 */
export const requireProjectChainAdmin = <Endpoint extends HttpApiEndpoint.Top>(
  projectId: string,
  endpoint: Endpoint,
) =>
  Effect.gen(function* () {
    const principal = yield* (yield* RequestAuth).principal;
    yield* ensureTokenScopeForProject(principal, projectId, "admin");
    const env = yield* WorkerEnv;
    const outcome = yield* rpcCall<DataOutcome<Role>>(() =>
      projectStub(env, projectId).memberRoleFor(principal.userId),
    );
    const role = yield* unwrapDataOutcome(outcome, projectId, endpoint);
    if (!roleAtLeast(role, "admin")) {
      return yield* Effect.fail(new ForbiddenError({ reason: "insufficient-role" }));
    }
    return { principal, role };
  });
