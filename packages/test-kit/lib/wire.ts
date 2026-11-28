import type {
  CheckpointValueSnapshotSchema,
  DistributedEncryptedPayloadSchema,
  DistributedEnvironmentManifestSchema,
  DistributedEnvironmentMetaStatementSchema,
  DistributedVariableMetaStatementSchema,
  EncryptedPayloadSchema,
  EnvironmentManifestSchema,
  RecipientDekSchema,
  WrappedDekSchema,
} from "@maruhi/api-schema";

export type WireWrappedDek = typeof WrappedDekSchema.Encoded;

export type WireRecipientDek = typeof RecipientDekSchema.Encoded;

export type WireEncryptedPayload = typeof EncryptedPayloadSchema.Encoded;

export type WireDistributedValue = typeof DistributedEncryptedPayloadSchema.Encoded;

export type WireDistributedVariableStatement =
  typeof DistributedVariableMetaStatementSchema.Encoded;

export type WireStatementStatus = WireDistributedVariableStatement["status"];

export type WireDistributedEnvironmentStatement =
  typeof DistributedEnvironmentMetaStatementSchema.Encoded;

export type WireVariableMetaStatement = Omit<
  WireDistributedVariableStatement,
  "authorUserId" | "authorKeyFingerprintHex"
>;

export type WireStatementSchema = Required<
  Pick<WireDistributedVariableStatement, "varType" | "required" | "description">
> &
  Pick<WireDistributedVariableStatement, "maxAgeDays">;

export type WireEnvironmentManifest = typeof EnvironmentManifestSchema.Encoded;

export type WireDistributedManifest = typeof DistributedEnvironmentManifestSchema.Encoded;

export type WireCheckpointSnapshot = typeof CheckpointValueSnapshotSchema.Encoded;
