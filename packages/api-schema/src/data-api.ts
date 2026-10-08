// HttpApi definition of the data plane (environments, variables, DEKs)
// (AUTH_SPEC §12). The shared source for the server implementation
// (apps/server) and future CLI client derivation.
//
// Authorization discipline (§12-3): every endpoint requires
// authentication (AuthMiddleware). Non-members and out-of-scope callers
// get a uniform 404 (§11-2). EnvironmentNotFound / VariableNotFound are
// returned only to chain-derived members.
//
// Display names are plaintext metadata (CRYPTO_SPEC §4). The 256-character
// cap is a §12-8 acceptance policy (unlike values there is no dedicated
// verification layer, so the Schema enforces it).

import { EnvironmentIdSchema, ProjectIdSchema, VariableIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/http-api";

import { AuthMiddleware } from "./auth-middleware.ts";
import {
  CheckpointEntrySchema,
  CreateEnvironmentEntrySchema,
  DeleteEnvironmentEntrySchema,
  RotateEpochEntrySchema,
} from "./chain.ts";
import {
  ActivateVariableMetaStatementSchema,
  CheckpointValueSnapshotSchema,
  CreateEnvironmentManifestSchema,
  CreateEnvironmentMetaStatementSchema,
  CreateVariableMetaStatementSchema,
  CreateVariableMetaStatementV3Schema,
  DeclareVariableMetaStatementSchema,
  DekWrapRefSchema,
  DeleteVariableMetaStatementSchema,
  DeleteVariableMetaStatementV3Schema,
  DistributedEncryptedPayloadSchema,
  DistributedEnvironmentMetaStatementSchema,
  DistributedVariableMetaStatementSchema,
  EncryptedPayloadSchema,
  EnvironmentManifestSchema,
  RecipientDekSchema,
  RenameEnvironmentMetaStatementSchema,
  RenameVariableMetaStatementSchema,
  RenameVariableMetaStatementV3Schema,
  RequiredDistributedEnvironmentManifestSchema,
  SchemaPolicySchema,
  VariableVersionHistoryEntrySchema,
  WrappedDekSchema,
} from "./data.ts";
import {
  ActivationRequiredError,
  AuditHeadNotReadyError,
  ChainCapacityExceededError,
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  ChainHeadConflictError,
  CheckpointStateMismatchError,
  DataLimitExceededError,
  DekWrapExistsError,
  DekWrapNotFoundError,
  DekWrapRejectedError,
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
  SchemaDescriptionRejectedError,
  SchemaPolicyRejectedError,
  ValueSignatureRejectedError,
  ValueTooLargeError,
  VariableConflictError,
  VariableNotFoundError,
  VersionConflictError,
} from "./errors/index.ts";
import { PositiveInt, Sha256Hex } from "./hex.ts";
import { strictPayload } from "./strict.ts";

const projectParams = { projectId: ProjectIdSchema };
const environmentParams = { projectId: ProjectIdSchema, environmentId: EnvironmentIdSchema };
const variableParams = {
  projectId: ProjectIdSchema,
  environmentId: EnvironmentIdSchema,
  variableId: VariableIdSchema,
};

/**
 * One environment in the listing (current epoch is chain-derived —
 * CRYPTO_SPEC §3). The display name travels as the latest verified-able
 * metadata statement + author info instead of a bare snapshot (AUTH_SPEC
 * §12-2). Only live environments are listed; a deleted environment's
 * statements are deleted with its data, and clients derive deletion from
 * the delete_environment entry on their verified chain (CRYPTO_SPEC §6.3).
 */
export const EnvironmentSummarySchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  currentEpoch: Schema.Number,
  statement: DistributedEnvironmentMetaStatementSchema,
});

/** GET /projects/:projectId/environments: the project's environments (AUTH_SPEC §12-4). */
export const EnvironmentListSchema = Schema.Struct({
  environments: Schema.Array(EnvironmentSummarySchema),
  /** schemaPolicy advisory bundle (§12-7 / §12-11 — same convention as pull). */
  schemaPolicy: SchemaPolicySchema,
});

/**
 * Result of a composite environment creation / rotation (AUTH_SPEC §12-4):
 * the accepted chain head (the entry was appended atomically with the data)
 * plus the resulting current epoch.
 */
export const EnvironmentChainResultSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  currentEpoch: Schema.Number,
  headSeq: PositiveInt,
  headHashHex: Sha256Hex,
});

/** Result of accepting a variable version (creation is version 1 — §12-5). */
export const VariableVersionSchema = Schema.Struct({
  variableId: VariableIdSchema,
  version: Schema.Number,
  epoch: Schema.Number,
});

/**
 * GET …/variables/:variableId/versions: every stored version of one variable,
 * ascending (AUTH_SPEC §12-7 — 2026-09-27 VH). Metadata only — no ciphertext
 * or DEK, so no var.read is recorded; server-declared (see
 * VariableVersionHistoryEntrySchema). A declared variable has an empty list.
 */
export const VariableVersionHistorySchema = Schema.Struct({
  variableId: VariableIdSchema,
  versions: Schema.Array(VariableVersionHistoryEntrySchema),
});

/**
 * GET …/variables/:variableId/versions/values?fromVersion=k: the distributed
 * payloads of versions k, k + 1, … ascending — at most MAX_VERSION_VALUES_PAGE
 * versions and at most ~1 MiB of ciphertext (always at least one version)
 * (AUTH_SPEC §12-7 — 2026-09-27 VH). `latestVersion` tells the caller
 * whether to page on. The
 * caller trusts an old version only as an ancestor of the latest it verified
 * through a bulk pull (prev chain + epoch monotonicity — CRYPTO_SPEC §4.1).
 */
export const VariableVersionValuesSchema = Schema.Struct({
  variableId: VariableIdSchema,
  latestVersion: PositiveInt,
  values: Schema.Array(DistributedEncryptedPayloadSchema),
});

/** The page size of the version value range (AUTH_SPEC §12-7). */
export const MAX_VERSION_VALUES_PAGE = 100;

// The query-string version. Defined on NumberFromString to satisfy
// QueryConstraint (encode to string)
const VersionFromString = Schema.NumberFromString.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
);

/**
 * One variable in a bulk pull: its latest version, self-describing via the
 * AAD, carried as the distributed form (writer identity + signature
 * block — bundling the AUTH_SPEC §12-7 verification material), plus its
 * latest metadata statement + author info (name → variableId resolution
 * goes through verified statements — §12-7).
 */
export const PulledVariableSchema = Schema.Struct({
  variableId: VariableIdSchema,
  statement: DistributedVariableMetaStatementSchema,
  value: DistributedEncryptedPayloadSchema,
});

/**
 * Bulk pull of one environment (§12-7): every active variable's latest
 * version plus every epoch's DEK wrapped for the caller (latest versions may
 * span epochs until a rotation's re-encryption completes — CRYPTO_SPEC §7).
 * `statement` is the environment's own latest meta statement;
 * `deletedVariables` is the deleted statements of deleted variables
 * (kept in storage and distribution — §12-5; detection material for
 * denial of deletion and unauthorized revival. The ciphertexts are
 * deleted, so no values accompany them).
 */
export const EnvironmentPullSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  currentEpoch: Schema.Number,
  statement: DistributedEnvironmentMetaStatementSchema,
  variables: Schema.Array(PulledVariableSchema),
  deletedVariables: Schema.Array(DistributedVariableMetaStatementSchema),
  /**
   * The latest statements of declared variables (§12-7 — layout v3).
   * They have no value and no version (declared is the only legitimate
   * valueless state — the CRYPTO_SPEC §6.3 value-distribution
   * requirement). Bundling them is mandatory as material for manifest
   * digest recomputation (§4.3). Absent in environments with no declared
   * variables.
   */
  declaredVariables: Schema.optionalKey(Schema.Array(DistributedVariableMetaStatementSchema)),
  deks: Schema.Array(RecipientDekSchema),
  /**
   * Advisory bundle of the project's schemaPolicy (§12-7 / §12-11 — a
   * server assertion, unsigned; client use is UX only — never an input
   * to verification rules).
   */
  schemaPolicy: SchemaPolicySchema,
  /**
   * The latest environment manifest + issuer info (§12-7). Required —
   * a created environment always has a stored manifest (§12-4's atomic
   * write), so the server never omits it (a missing row is a server
   * fault, not an omission). The client verifies digest recomputation
   * and epoch consistency; **absence is refused unconditionally**
   * (CRYPTO_SPEC §6.3).
   */
  manifest: RequiredDistributedEnvironmentManifestSchema,
  /**
   * Enumeration of the value snapshots at checkpoint time (§12-7).
   * Always bundled when a latest `checkpoint` containing an entry for
   * this environment exists (the very enumeration stored at checkpoint
   * acceptance — §16-2). Client rule 2 (CRYPTO_SPEC §6.3 — value
   * non-regression) **refuses** a valued response that lacks the
   * enumeration when a baseline exists on the verified chain (an omission
   * must not degenerate into skipping rule 2). Absent in environments
   * without a baseline.
   */
  checkpointSnapshot: Schema.optionalKey(CheckpointValueSnapshotSchema),
});

/**
 * Metadata-only bulk pull (the §12-7 metadata-only mode): the same
 * environment-scoped read without values (ciphertexts) or DEKs. The response
 * carries the environment statement, the chain-derived current epoch, every
 * active variable's latest statement and the deleted statements — the full
 * §6.3 metadata verification material, nothing else. Used for name →
 * variableId resolution (CLI push) and other value-free reads; the server
 * records no `var.read` for it (it must not record as read what was not
 * read).
 */
export const EnvironmentMetadataPullSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  currentEpoch: Schema.Number,
  statement: DistributedEnvironmentMetaStatementSchema,
  // Statements of declared variables also land in this column (the latest
  // form of every non-deleted variable — §12-7: declared distribution is
  // statements only, and in metadata-only mode they naturally flow into
  // the same column as active ones; the status field discriminates)
  variables: Schema.Array(DistributedVariableMetaStatementSchema),
  deletedVariables: Schema.Array(DistributedVariableMetaStatementSchema),
  /**
   * The latest environment manifest (the completeness of metadata
   * verification is at the same level in this mode — §12-7). Required,
   * same as the with-values pull.
   */
  manifest: RequiredDistributedEnvironmentManifestSchema,
  /** schemaPolicy advisory bundle (§12-7 / §12-11 — same convention as EnvironmentPull). */
  schemaPolicy: SchemaPolicySchema,
});

/**
 * Environment management (AUTH_SPEC §12-4 — environment creation is a
 * chain op).
 *
 * - `create` is a composite request: the `create_environment` chain entry
 *   (environment id + epoch-1 DEK commitment, appended with a parent-head
 *   CAS), the `EnvironmentMetaStatement` (metaVersion 1 — its declared head
 *   must be the pre-append current head = the entry's prev, §12-4), and the
 *   complete epoch-1 DEK wrap set for the current member set — accepted
 *   atomically by the project DO. An environment never exists without its
 *   commitment, its statement and its members' wraps.
 * - `rotate` is the composite rotation: the `rotate_epoch` entry (new-epoch
 *   commitment) plus the complete new-epoch wrap set, replacing the former
 *   two-step "generic chain append + DEK registration" flow. Re-encryption
 *   of current values stays a follow-up push (§12-7). rotate carries no
 *   statement (name and state do not change).
 * - `rename` carries a signed `EnvironmentMetaStatement` (metaVersion CAS
 *   — the §12-5 meta rule).
 * - `remove` is the composite deletion (2026-10-07 — CRYPTO_SPEC §6.2): the
 *   `delete_environment` chain entry appended with a parent-head CAS and the
 *   environment's data deleted in the same DO transaction. No statement and
 *   no manifest accompany it — the chain entry is the deletion's record.
 */
export const environmentsGroup = HttpApiGroup.make("environments")
  .add(
    HttpApiEndpoint.post("create", "/projects/:projectId/environments", {
      params: projectParams,
      // strict acceptance (§12-10 (1) — the payload wrapper passes onExcessProperty: "error" into the nest)
      payload: strictPayload(
        Schema.Struct({
          parentHeadHashHex: Sha256Hex,
          entry: CreateEnvironmentEntrySchema,
          statement: CreateEnvironmentMetaStatementSchema,
          deks: Schema.Array(WrappedDekSchema),
          // manifestVersion 1, empty variable set, epoch 1 (§12-4)
          manifest: CreateEnvironmentManifestSchema,
          // Boundary checkpoint (§12-4).
          // create = H+1 and checkpoint = H+2 are accepted atomically as
          // two entries. Coverage is the single tuple of this environment
          // (epoch 1, manifestVersion 1, the bundled manifest's
          // signed_bytes hash, the empty variable set's values_digest)
          checkpoint: CheckpointEntrySchema,
        }),
      ),
      success: EnvironmentChainResultSchema,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        EnvironmentConflictError,
        ChainHeadConflictError,
        ChainEntryInvalidError,
        ChainEntryTooLargeError,
        ChainCapacityExceededError,
        // Composite-internal consistency check (§12-4): mismatch of
        // environment_id / declared head between the entry payload and
        // the statement / manifest
        PayloadMismatchError,
        MetaStatementRejectedError,
        // The bundled manifest undergoes the same verification as the
        // regular path (§12-5 (1)-(7)). ManifestVersionConflict is not
        // declared: creation's chain consensus rule (duplicate-environment)
        // guarantees environment novelty, and a v1 for an environment with
        // no stored manifest cannot CAS-conflict (the wire is Literal 1 too)
        ManifestRejectedError,
        NameNotNfcError,
        DekWrapRejectedError,
        // The wrap-set check (§12-6 checkWrapSets) may refuse a duplicate
        // of an existing (epoch, recipient) with 409. The established
        // epoch (create = 1) cannot have existing wraps under the current
        // chain rules (duplicate-environment), but it is declared in the
        // contract so a rule change cannot drop a 409 outside the
        // contract (500)
        DekWrapExistsError,
        // Content matching of the boundary checkpoint (§6.4 — the
        // post-application baseline of the composite; creation matches
        // the empty variable set's values_digest)
        CheckpointStateMismatchError,
        // Notarizing a non-empty audit_head_hash when the audit-head
        // derived column's bounded expansion is incomplete (AUDIT_SPEC
        // §5.1 — session-38). Retryable 503. A contract for other
        // clients: the CLI's boundary checkpoints do not notarize (empty
        // — ruling M-b)
        AuditHeadNotReadyError,
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("rotate", "/projects/:projectId/environments/:environmentId/rotate", {
      params: environmentParams,
      payload: strictPayload(
        Schema.Struct({
          parentHeadHashHex: Sha256Hex,
          entry: RotateEpochEntrySchema,
          deks: Schema.Array(WrappedDekSchema),
          // Manifest with the new epoch baked in (manifestVersion =
          // latest + 1; it reflects the epoch advance even when the meta
          // set is unchanged — CRYPTO_SPEC §4.3)
          manifest: EnvironmentManifestSchema,
          // Boundary checkpoint (§12-4).
          // rotate = H+1, checkpoint = H+2. The tuple's values_digest
          // covers new_epoch, the bundled manifest's (manifestVersion,
          // signed_bytes hash), and the current values at acceptance
          // time (not-yet-reencrypted = old-epoch values — a legitimate
          // §12-7 state)
          checkpoint: CheckpointEntrySchema,
        }),
      ),
      success: EnvironmentChainResultSchema,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        // Rotating a deleted (tombstone) environment is 404 (§12-4 —
        // §7's "all environments" does not include deleted ones)
        EnvironmentNotFoundError,
        // Mismatch between the URL's environmentId and
        // entry.payload.environmentId (composite-internal consistency
        // check)
        PayloadMismatchError,
        ChainHeadConflictError,
        ChainEntryInvalidError,
        ChainEntryTooLargeError,
        ChainCapacityExceededError,
        // Verification of the bundled manifest (§12-5 (1)-(7); epoch =
        // after applying the bundled entry = new_epoch). A 409 retry
        // re-signs both the entry and the manifest
        ManifestRejectedError,
        ManifestVersionConflictError,
        DekWrapRejectedError,
        // Existing wraps for the established epoch (rotate = new_epoch)
        // cannot exist under the current chain rules (epoch monotonicity),
        // but it is declared for the same reason as create
        DekWrapExistsError,
        // Content matching of the boundary checkpoint (§6.4 — the
        // post-application baseline of the composite). The 422 when a
        // concurrent push after the declared head is fixed knocked the
        // values_digest off — the client re-pulls and retries with a
        // bound (§12-4)
        CheckpointStateMismatchError,
        // Notarizing a non-empty audit_head_hash when the audit-head
        // derived column's bounded expansion is incomplete (AUDIT_SPEC
        // §5.1 — session-38). Retryable 503. A contract for other
        // clients: the CLI's boundary checkpoints do not notarize (empty
        // — ruling M-b)
        AuditHeadNotReadyError,
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("list", "/projects/:projectId/environments", {
      params: projectParams,
      success: EnvironmentListSchema,
      error: [ProjectNotFoundError, ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.patch("rename", "/projects/:projectId/environments/:environmentId", {
      params: environmentParams,
      // An environment rename also bundles the manifest (manifestVersion
      // + 1 — it copies the new envMetaSigHashHex; §12-4). The metaVersion
      // CAS and the manifestVersion CAS are decided in the same
      // transaction; a 409 retries with both re-signed (§12-5)
      payload: strictPayload(
        Schema.Struct({
          statement: RenameEnvironmentMetaStatementSchema,
          manifest: EnvironmentManifestSchema,
        }),
      ),
      success: HttpApiSchema.NoContent,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        EnvironmentNotFoundError,
        EnvironmentConflictError,
        PayloadMismatchError,
        MetaVersionConflictError,
        MetaStatementRejectedError,
        ManifestRejectedError,
        ManifestVersionConflictError,
        NameNotNfcError,
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.delete("remove", "/projects/:projectId/environments/:environmentId", {
      params: environmentParams,
      // The composite deletion (§12-4 — 2026-10-07): the delete_environment
      // entry (strict acceptance — §12-10 (1)) and the head it appends
      // onto. DELETE + body follows the deks.remove precedent
      payload: strictPayload(
        Schema.Struct({
          parentHeadHashHex: Sha256Hex,
          entry: DeleteEnvironmentEntrySchema,
        }),
      ),
      success: HttpApiSchema.NoContent,
      // Judgment order (§12-4): role (403) → the URL / entry environment
      // match and the parent / entry prev match (422 PayloadMismatch) →
      // the parent-head CAS (409 — stale) →
      // scope (403) → verifyChain (422 ChainEntryInvalid — unknown /
      // already deleted / out of scope). No 404 for the environment: its
      // existence and deleted state depend on the head the entry appends
      // onto, so they are judged after the CAS. DataLimitExceeded is not
      // declared: deletion is the "freed by deletion" path (§12-8 — the
      // storage guard never blocks it)
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        PayloadMismatchError,
        ChainHeadConflictError,
        ChainEntryInvalidError,
        ChainEntryTooLargeError,
        ChainCapacityExceededError,
      ],
    }).middleware(AuthMiddleware),
  );

/**
 * Variable CRUD, versioned pushes and the bulk pull (AUTH_SPEC §12-5 / §12-7).
 * A push is a CAS: the declared AAD must name the current chain epoch and the
 * next version; conflicts return the current values for a client retry.
 */
export const variablesGroup = HttpApiGroup.make("variables")
  .add(
    HttpApiEndpoint.post("create", "/projects/:projectId/environments/:environmentId/variables", {
      params: environmentParams,
      // Creation = a version-1 value plus a VariableMetaStatement
      // (metaVersion 1) bundled (§12-5). The statement carries variableId
      // and the display name (no bare fields alongside — no
      // double-carriage mismatch surface).
      //
      // Under layout v3, creation is a Union of two forms: active (value
      // bundled — the statement may be v1 or v3) and declared (no value —
      // a v3-only declaration; the sole exception to "a variable without
      // a value does not exist"). Neither form can create deleted (Schema
      // 400 — the wire face of the §12-5 transition rules; strictPayload
      // rejects unknown fields inside the Union too — §12-10 (1))
      payload: strictPayload(
        Schema.Union([
          Schema.Struct({
            statement: Schema.Union([
              CreateVariableMetaStatementSchema,
              CreateVariableMetaStatementV3Schema,
            ]),
            value: EncryptedPayloadSchema,
            // Manifest reflecting the post-creation meta state (the set
            // including the new variable's statement) (§12-5 — composite
            // acceptance of every operation that changes meta state)
            manifest: EnvironmentManifestSchema,
          }),
          Schema.Struct({
            statement: DeclareVariableMetaStatementSchema,
            manifest: EnvironmentManifestSchema,
          }),
        ]),
      ),
      success: VariableVersionSchema,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        EnvironmentNotFoundError,
        VariableConflictError,
        PayloadMismatchError,
        VersionConflictError,
        EpochConflictError,
        // The bundled version-1 value and bundled statement undergo the
        // same signature verification as the regular path (§12-5 —
        // verification bypass via the creation route is impossible for
        // value and meta alike). MetaVersionConflict is effectively
        // unreachable under the wire Schema (metaVersion pinned to 1) but
        // is declared as the CAS contract (the client re-resolves by name
        // and retries — the receptacle for races against a concurrent
        // rename)
        ValueSignatureRejectedError,
        MetaStatementRejectedError,
        MetaVersionConflictError,
        // Bundled-manifest verification and the manifestVersion CAS
        // (§12-5 (6) — concurrent meta operations serialize on the
        // per-environment manifestVersion; bulk submissions run
        // sequentially)
        ManifestRejectedError,
        ManifestVersionConflictError,
        NameNotNfcError,
        // Schema policy (§12-11): creating without varType under locked
        // is schema-required
        SchemaPolicyRejectedError,
        // description length/character limits (the §12-8 acceptance
        // check — 422)
        SchemaDescriptionRejectedError,
        ValueTooLargeError,
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post(
      "push",
      "/projects/:projectId/environments/:environmentId/variables/:variableId/versions",
      {
        params: variableParams,
        // sameValueAs = the value-lineage declaration (AUTH_SPEC §12-5 —
        // 2026-09-27 VH): the writer's self-declaration "this version's
        // plaintext equals version k's" (version − 1 = the re-encryption
        // of CRYPTO_SPEC §7; older = a rollback). Accepted only when
        // < version (422 payload-mismatch otherwise); it affects neither
        // the rest of acceptance nor the value signature. Only the lineage
        // derivation of rotation-needed detection (AUDIT_SPEC §4.1-5) reads it
        payload: strictPayload(
          Schema.Struct({
            value: EncryptedPayloadSchema,
            sameValueAs: Schema.optionalKey(PositiveInt),
          }),
        ),
        success: VariableVersionSchema,
        error: [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableNotFoundError,
          PayloadMismatchError,
          VersionConflictError,
          EpochConflictError,
          ValueSignatureRejectedError,
          // A normal push to a declared variable requires the activation
          // composite (§12-5)
          ActivationRequiredError,
          ValueTooLargeError,
          DataLimitExceededError,
        ],
      },
    ).middleware(AuthMiddleware),
  )
  .add(
    // Version history (§12-7 — 2026-09-27 VH): metadata only.
    // Authorization = the metadata-only mode's (reader, scope-agnostic);
    // no var.read (no ciphertext is distributed — AUDIT_SPEC §3.3)
    HttpApiEndpoint.get(
      "history",
      "/projects/:projectId/environments/:environmentId/variables/:variableId/versions",
      {
        params: variableParams,
        success: VariableVersionHistorySchema,
        error: [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableNotFoundError,
        ],
      },
    ).middleware(AuthMiddleware),
  )
  .add(
    // Version value range (§12-7 — 2026-09-27 VH): authorization = the
    // with-values pull's (reader × environment ∈ scope); records one
    // var.read row enumerating every returned version. fromVersion
    // outside 1 … latest (or a declared variable) is 422 payload-mismatch
    HttpApiEndpoint.get(
      "versionValues",
      "/projects/:projectId/environments/:environmentId/variables/:variableId/versions/values",
      {
        params: variableParams,
        query: { fromVersion: VersionFromString },
        success: VariableVersionValuesSchema,
        error: [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableNotFoundError,
          PayloadMismatchError,
        ],
      },
    ).middleware(AuthMiddleware),
  )
  .add(
    // activation (declared → active — §12-5; layout v3):
    // the first value push to a declared variable is accepted as the
    // composite "value version 1 + status-active v3 statement
    // (metaVersion + 1) + manifest". Meta state changes, so it
    // re-issues the manifest (the subject of the "a value push does not
    // touch the manifest" invariant is the normal push — CRYPTO_SPEC
    // §4.3). **Declared → active only**, not a generic "value push + meta
    // reissuance" composite: a form whose target is not declared, or
    // whose name changed from the declared name, is refused with 422
    // payload-mismatch (status / name) (renaming is the rename path's
    // job, together with its var.renamed audit. This restriction is what
    // makes the precondition of the §12-11 policy exemption — the prior
    // statement is always v3 — hold)
    HttpApiEndpoint.post(
      "activate",
      "/projects/:projectId/environments/:environmentId/variables/:variableId/activate",
      {
        params: variableParams,
        payload: strictPayload(
          Schema.Struct({
            value: EncryptedPayloadSchema,
            statement: ActivateVariableMetaStatementSchema,
            manifest: EnvironmentManifestSchema,
          }),
        ),
        success: VariableVersionSchema,
        error: [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableNotFoundError,
          PayloadMismatchError,
          // A declared variable's latest is always 0, so the CAS forces
          // value version 1
          VersionConflictError,
          EpochConflictError,
          ValueSignatureRejectedError,
          MetaStatementRejectedError,
          MetaVersionConflictError,
          ManifestRejectedError,
          ManifestVersionConflictError,
          SchemaDescriptionRejectedError,
          ValueTooLargeError,
          DataLimitExceededError,
        ],
      },
    ).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.patch(
      "rename",
      "/projects/:projectId/environments/:environmentId/variables/:variableId",
      {
        params: variableParams,
        // The v3 form doubles as a rename and a schema reissuance (a
        // change to the schema fields only) — the acceptance rule is the
        // same (§12-5). status keeps the current state (a transition
        // cannot happen in this form — a mismatch is 422
        // payload-mismatch)
        payload: strictPayload(
          Schema.Struct({
            statement: Schema.Union([
              RenameVariableMetaStatementSchema,
              RenameVariableMetaStatementV3Schema,
            ]),
            manifest: EnvironmentManifestSchema,
          }),
        ),
        success: HttpApiSchema.NoContent,
        error: [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableNotFoundError,
          VariableConflictError,
          PayloadMismatchError,
          MetaVersionConflictError,
          MetaStatementRejectedError,
          ManifestRejectedError,
          ManifestVersionConflictError,
          NameNotNfcError,
          SchemaDescriptionRejectedError,
          DataLimitExceededError,
        ],
      },
    ).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.delete(
      "remove",
      "/projects/:projectId/environments/:environmentId/variables/:variableId",
      {
        params: variableParams,
        // Deletion also requires a signed statement (status deleted; name
        // is the immediately preceding active name) plus a manifest
        // reflecting the set including the tombstone (§12-5 — manifests
        // are outside the row-count cap, so the deletion path is not
        // blocked: only the latest 1 is kept — §12-8). Deleting a v3
        // variable uses the v3 form (schema fields and layout match the
        // immediately preceding one — §12-5; accepted regardless of
        // policy as a continuation statement — §12-11 reversibility)
        payload: strictPayload(
          Schema.Struct({
            statement: Schema.Union([
              DeleteVariableMetaStatementSchema,
              DeleteVariableMetaStatementV3Schema,
            ]),
            manifest: EnvironmentManifestSchema,
          }),
        ),
        success: HttpApiSchema.NoContent,
        // The reason DataLimitExceeded is not declared is the same as
        // environments.remove (deleted is outside the metaVersion cap —
        // §12-8)
        error: [
          ProjectNotFoundError,
          ForbiddenError,
          EnvironmentNotFoundError,
          VariableNotFoundError,
          PayloadMismatchError,
          MetaVersionConflictError,
          MetaStatementRejectedError,
          ManifestRejectedError,
          ManifestVersionConflictError,
        ],
      },
    ).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("pull", "/projects/:projectId/environments/:environmentId/pull", {
      params: environmentParams,
      success: EnvironmentPullSchema,
      error: [ProjectNotFoundError, ForbiddenError, EnvironmentNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // Metadata-only mode (§12-7): authorization is the same row as pull
    // (read × reader). No var.read is recorded (no values are
    // distributed — AUDIT_SPEC §3.3)
    HttpApiEndpoint.get(
      "pullMetadata",
      "/projects/:projectId/environments/:environmentId/pull/metadata",
      {
        params: environmentParams,
        success: EnvironmentMetadataPullSchema,
        error: [ProjectNotFoundError, ForbiddenError, EnvironmentNotFoundError],
      },
    ).middleware(AuthMiddleware),
  );

/**
 * GET /projects/:projectId/environments/:environmentId/deks: the DEK wraps
 * addressed to the caller (AUTH_SPEC §12-6 — distribution is caller-only).
 */
export const RecipientDekListSchema = Schema.Struct({ deks: Schema.Array(RecipientDekSchema) });

/**
 * DEK wrap registration, distribution and repair (AUTH_SPEC §12-6).
 * Registration covers both the full-set path (environment creation /
 * post-rotation) and the backfill path (wrapping historical epochs for a
 * newly added member). Distribution is caller-only: a member fetches the
 * wraps addressed to them. Deletion is the admin-only repair path for
 * poisoned wraps (overwriting stays forbidden); the deleted slots are then
 * re-registered through the append path.
 */
export const deksGroup = HttpApiGroup.make("deks")
  .add(
    HttpApiEndpoint.post("register", "/projects/:projectId/environments/:environmentId/deks", {
      params: environmentParams,
      // An empty deks is 400 (§12-6; the same "don't silently succeed"
      // discipline as the delete side's empty wraps). The deks of
      // environment creation are out of scope (for an empty set the
      // exact-match requirement's 422 recipient-missing takes meaning
      // first)
      payload: strictPayload(
        Schema.Struct({
          deks: Schema.Array(WrappedDekSchema).check(Schema.isMinLength(1)),
        }),
      ),
      success: HttpApiSchema.NoContent,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        EnvironmentNotFoundError,
        DekWrapRejectedError,
        DekWrapExistsError,
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("listMine", "/projects/:projectId/environments/:environmentId/deks", {
      params: environmentParams,
      success: RecipientDekListSchema,
      error: [ProjectNotFoundError, ForbiddenError, EnvironmentNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // Deletion targets are enumerated in the body: recipientUserId is a
    // free string under the chain consensus rules (up to 1024 bytes) and
    // cannot be safely expressed as a path segment. An empty enumeration
    // is 400 (a destructive call shape with zero audit trace is not
    // allowed — §12-6)
    HttpApiEndpoint.delete("remove", "/projects/:projectId/environments/:environmentId/deks", {
      params: environmentParams,
      payload: Schema.Struct({
        wraps: Schema.Array(DekWrapRefSchema).check(Schema.isMinLength(1)),
      }),
      success: HttpApiSchema.NoContent,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        EnvironmentNotFoundError,
        DekWrapNotFoundError,
        DekWrapRejectedError,
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  );

/** GET /projects/:projectId/schema-policy: the project's schema policy (AUTH_SPEC §12-11). */
export const SchemaPolicyResultSchema = Schema.Struct({ schemaPolicy: SchemaPolicySchema });

/**
 * Project schema-policy setting (AUTH_SPEC §12-11 — schema-locked).
 *
 * - GET: read scope × chain role reader or higher (200 = `{ schemaPolicy }`)
 * - PUT: **admin scope × chain role admin or higher** (204). Session
 *   principals are refused (outside the §5 capability allowlist — the
 *   default deny applies as-is). A change records
 *   `project.schema_policy_changed` (AUDIT_SPEC §3.3 — old and new
 *   values)
 *
 * Decision order and existence concealment (non-member 404) are the same
 * as §12-3. The payload carries no signed structure (outside the §12-10
 * (1) strict target class — Schema verification closes over a 2-value
 * Literal).
 */
export const schemaPolicyGroup = HttpApiGroup.make("schemaPolicy")
  .add(
    HttpApiEndpoint.get("get", "/projects/:projectId/schema-policy", {
      params: projectParams,
      success: SchemaPolicyResultSchema,
      error: [ProjectNotFoundError, ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.put("set", "/projects/:projectId/schema-policy", {
      params: projectParams,
      payload: Schema.Struct({ schemaPolicy: SchemaPolicySchema }),
      success: HttpApiSchema.NoContent,
      // DataLimitExceeded (422 project-storage-bytes — AUTH_SPEC §12-8):
      // a DO at or above the refusal threshold does not accept setting
      // changes either (every change adds an audit row; GET passes as a
      // read)
      error: [ProjectNotFoundError, ForbiddenError, DataLimitExceededError],
    }).middleware(AuthMiddleware),
  );
