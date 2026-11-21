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
} from "./errors.package/index.ts";
import { PositiveInt, Sha256Hex } from "./hex.ts";
import { strictPayload } from "./strict.ts";

const projectParams = { projectId: ProjectIdSchema };
const environmentParams = { projectId: ProjectIdSchema, environmentId: EnvironmentIdSchema };
const variableParams = {
  projectId: ProjectIdSchema,
  environmentId: EnvironmentIdSchema,
  variableId: VariableIdSchema,
};

export const EnvironmentSummarySchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  currentEpoch: Schema.Number,
  statement: DistributedEnvironmentMetaStatementSchema,
});

export const EnvironmentListSchema = Schema.Struct({
  environments: Schema.Array(EnvironmentSummarySchema),
  schemaPolicy: SchemaPolicySchema,
});

export const EnvironmentChainResultSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  currentEpoch: Schema.Number,
  headSeq: PositiveInt,
  headHashHex: Sha256Hex,
});

export const VariableVersionSchema = Schema.Struct({
  variableId: VariableIdSchema,
  version: Schema.Number,
  epoch: Schema.Number,
});

export const VariableVersionHistorySchema = Schema.Struct({
  variableId: VariableIdSchema,
  versions: Schema.Array(VariableVersionHistoryEntrySchema),
});

export const VariableVersionValuesSchema = Schema.Struct({
  variableId: VariableIdSchema,
  latestVersion: PositiveInt,
  values: Schema.Array(DistributedEncryptedPayloadSchema),
});

export const MAX_VERSION_VALUES_PAGE = 100;

const VersionFromString = Schema.NumberFromString.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
);

export const PulledVariableSchema = Schema.Struct({
  variableId: VariableIdSchema,
  statement: DistributedVariableMetaStatementSchema,
  value: DistributedEncryptedPayloadSchema,
});

export const EnvironmentPullSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  currentEpoch: Schema.Number,
  statement: DistributedEnvironmentMetaStatementSchema,
  variables: Schema.Array(PulledVariableSchema),
  deletedVariables: Schema.Array(DistributedVariableMetaStatementSchema),
  declaredVariables: Schema.optionalKey(Schema.Array(DistributedVariableMetaStatementSchema)),
  deks: Schema.Array(RecipientDekSchema),
  schemaPolicy: SchemaPolicySchema,
  manifest: RequiredDistributedEnvironmentManifestSchema,
  checkpointSnapshot: Schema.optionalKey(CheckpointValueSnapshotSchema),
});

export const EnvironmentMetadataPullSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  currentEpoch: Schema.Number,
  statement: DistributedEnvironmentMetaStatementSchema,
  variables: Schema.Array(DistributedVariableMetaStatementSchema),
  deletedVariables: Schema.Array(DistributedVariableMetaStatementSchema),
  manifest: RequiredDistributedEnvironmentManifestSchema,
  schemaPolicy: SchemaPolicySchema,
});

export const environmentsGroup = HttpApiGroup.make("environments")
  .add(
    HttpApiEndpoint.post("create", "/projects/:projectId/environments", {
      params: projectParams,
      payload: strictPayload(
        Schema.Struct({
          parentHeadHashHex: Sha256Hex,
          entry: CreateEnvironmentEntrySchema,
          statement: CreateEnvironmentMetaStatementSchema,
          deks: Schema.Array(WrappedDekSchema),
          manifest: CreateEnvironmentManifestSchema,
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
        PayloadMismatchError,
        MetaStatementRejectedError,
        ManifestRejectedError,
        NameNotNfcError,
        DekWrapRejectedError,
        DekWrapExistsError,
        CheckpointStateMismatchError,
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
          manifest: EnvironmentManifestSchema,
          checkpoint: CheckpointEntrySchema,
        }),
      ),
      success: EnvironmentChainResultSchema,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        EnvironmentNotFoundError,
        PayloadMismatchError,
        ChainHeadConflictError,
        ChainEntryInvalidError,
        ChainEntryTooLargeError,
        ChainCapacityExceededError,
        ManifestRejectedError,
        ManifestVersionConflictError,
        DekWrapRejectedError,
        DekWrapExistsError,
        CheckpointStateMismatchError,
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
      payload: strictPayload(
        Schema.Struct({
          parentHeadHashHex: Sha256Hex,
          entry: DeleteEnvironmentEntrySchema,
        }),
      ),
      success: HttpApiSchema.NoContent,
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

export const variablesGroup = HttpApiGroup.make("variables")
  .add(
    HttpApiEndpoint.post("create", "/projects/:projectId/environments/:environmentId/variables", {
      params: environmentParams,
      payload: strictPayload(
        Schema.Union([
          Schema.Struct({
            statement: Schema.Union([
              CreateVariableMetaStatementSchema,
              CreateVariableMetaStatementV3Schema,
            ]),
            value: EncryptedPayloadSchema,
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
        ValueSignatureRejectedError,
        MetaStatementRejectedError,
        MetaVersionConflictError,
        ManifestRejectedError,
        ManifestVersionConflictError,
        NameNotNfcError,
        SchemaPolicyRejectedError,
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
          ActivationRequiredError,
          ValueTooLargeError,
          DataLimitExceededError,
        ],
      },
    ).middleware(AuthMiddleware),
  )
  .add(
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

export const RecipientDekListSchema = Schema.Struct({ deks: Schema.Array(RecipientDekSchema) });

export const deksGroup = HttpApiGroup.make("deks")
  .add(
    HttpApiEndpoint.post("register", "/projects/:projectId/environments/:environmentId/deks", {
      params: environmentParams,
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

export const SchemaPolicyResultSchema = Schema.Struct({ schemaPolicy: SchemaPolicySchema });

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
      error: [ProjectNotFoundError, ForbiddenError, DataLimitExceededError],
    }).middleware(AuthMiddleware),
  );
