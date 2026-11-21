import {
  EnvironmentIdSchema,
  KeyFingerprintHexSchema,
  ProjectIdSchema,
  UserIdSchema,
  VariableIdSchema,
} from "@maruhi/core";
import { Schema } from "effect";

import {
  EncPubHex,
  hexString,
  HpkeEncHex,
  KeyFingerprintHex,
  ManifestSignatureHex,
  MetaSignatureHex,
  PositiveInt,
  Sha256Hex,
  ValueSignatureHex,
  WrapSignatureHex,
} from "./hex.ts";

const SuiteSchema = Schema.Literal("maruhi/v1");

const NonceHex = hexString(12);
const WrappedDekCiphertextHex = hexString(48);
const PrevValueSigHashHex = Schema.Union([Schema.Literal(""), Sha256Hex]);

const ValueCiphertextHex = Schema.String.check(
  Schema.isPattern(/^(?:[0-9a-f]{2}){16,}$/, {
    description: "lowercase hex AES-GCM ciphertext (>= 16 bytes incl. tag)",
  }),
);

export const BoundedUserId = UserIdSchema.check(
  Schema.isMinLength(1),
  Schema.makeFilter((s: string) =>
    new TextEncoder().encode(s).length <= 1024
      ? undefined
      : { path: [], issue: "at most 1024 UTF-8 bytes" },
  ),
);

export const VariableAadSchema = Schema.Struct({
  projectId: ProjectIdSchema,
  environmentId: EnvironmentIdSchema,
  epoch: PositiveInt,
  variableId: VariableIdSchema,
  version: PositiveInt,
});

export const EncryptedPayloadSchema = Schema.Struct({
  suite: SuiteSchema,
  aad: VariableAadSchema,
  nonceHex: NonceHex,
  ciphertextHex: ValueCiphertextHex,
  prevValueSigHashHex: PrevValueSigHashHex,
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: ValueSignatureHex,
});

export type EncryptedPayload = typeof EncryptedPayloadSchema.Type;

export const DistributedEncryptedPayloadSchema = Schema.Struct({
  ...EncryptedPayloadSchema.fields,
  writerUserId: BoundedUserId,
  writerKeyFingerprintHex: KeyFingerprintHex,
});

export type DistributedEncryptedPayload = typeof DistributedEncryptedPayloadSchema.Type;

export const VariableVersionHistoryEntrySchema = Schema.Struct({
  version: PositiveInt,
  epoch: PositiveInt,
  writerUserId: BoundedUserId,
  writerKeyFingerprintHex: KeyFingerprintHex,
  pushedAtMs: Schema.Number,
  sameValueAs: Schema.optionalKey(PositiveInt),
  flagsIfCurrent: Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(0)),
});

export type VariableVersionHistoryEntry = typeof VariableVersionHistoryEntrySchema.Type;

const StatementNameSchema = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256));

const VariableMetaStatementStatusSchema = Schema.Literals(["active", "deleted", "declared"]);
const MetaVersionAtLeast2 = Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(2));
const PrevMetaSigHashHex = Schema.Union([Schema.Literal(""), Sha256Hex]);

const varMetaBaseFields = {
  suite: SuiteSchema,
  environmentId: EnvironmentIdSchema,
  variableId: VariableIdSchema,
  name: StatementNameSchema,
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: MetaSignatureHex,
};

const envMetaBaseFields = {
  suite: SuiteSchema,
  environmentId: EnvironmentIdSchema,
  name: StatementNameSchema,
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: MetaSignatureHex,
};

const creationLifecycleFields = {
  status: Schema.Literal("active"),
  metaVersion: Schema.Literal(1),
  prevMetaSigHashHex: Schema.Literal(""),
};
const renameLifecycleFields = {
  status: Schema.Literal("active"),
  metaVersion: MetaVersionAtLeast2,
  prevMetaSigHashHex: Sha256Hex,
};
const deleteLifecycleFields = {
  status: Schema.Literal("deleted"),
  metaVersion: MetaVersionAtLeast2,
  prevMetaSigHashHex: Sha256Hex,
};
const environmentLifecycleFields = {
  status: Schema.Literal("active"),
  metaVersion: PositiveInt,
  prevMetaSigHashHex: PrevMetaSigHashHex,
};

export const MetaVarTypeSchema = Schema.Literals(["", "string", "number", "boolean", "url"]);

const MetaLayoutVersionSchema = Schema.Number.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(2),
);

export const MetaMaxAgeDaysSchema = Schema.NullOr(
  Schema.Number.check(
    Schema.isInt(),
    Schema.isGreaterThanOrEqualTo(1),
    Schema.isLessThanOrEqualTo(3650),
  ),
);

const varMetaV3Fields = {
  layoutVersion: MetaLayoutVersionSchema,
  varType: MetaVarTypeSchema,
  required: Schema.Boolean,
  description: Schema.String,
  maxAgeDays: Schema.optionalKey(MetaMaxAgeDaysSchema),
};

export const CreateVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  ...creationLifecycleFields,
});

export const CreateVariableMetaStatementV3Schema = Schema.Struct({
  ...varMetaBaseFields,
  ...creationLifecycleFields,
  ...varMetaV3Fields,
});

export const DeclareVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  status: Schema.Literal("declared"),
  metaVersion: Schema.Literal(1),
  prevMetaSigHashHex: Schema.Literal(""),
  ...varMetaV3Fields,
});

export const RenameVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  ...renameLifecycleFields,
});

export const RenameVariableMetaStatementV3Schema = Schema.Struct({
  ...varMetaBaseFields,
  status: Schema.Literals(["active", "declared"]),
  metaVersion: MetaVersionAtLeast2,
  prevMetaSigHashHex: Sha256Hex,
  ...varMetaV3Fields,
});

export const ActivateVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  ...renameLifecycleFields,
  ...varMetaV3Fields,
});

export const DeleteVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  ...deleteLifecycleFields,
});

export const DeleteVariableMetaStatementV3Schema = Schema.Struct({
  ...varMetaBaseFields,
  ...deleteLifecycleFields,
  ...varMetaV3Fields,
});

export const CreateEnvironmentMetaStatementSchema = Schema.Struct({
  ...envMetaBaseFields,
  ...creationLifecycleFields,
});

export const RenameEnvironmentMetaStatementSchema = Schema.Struct({
  ...envMetaBaseFields,
  ...renameLifecycleFields,
});

export const DistributedVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  status: VariableMetaStatementStatusSchema,
  metaVersion: PositiveInt,
  prevMetaSigHashHex: PrevMetaSigHashHex,
  layoutVersion: Schema.optionalKey(MetaLayoutVersionSchema),
  varType: Schema.optionalKey(MetaVarTypeSchema),
  required: Schema.optionalKey(Schema.Boolean),
  description: Schema.optionalKey(Schema.String),
  maxAgeDays: Schema.optionalKey(MetaMaxAgeDaysSchema),
  authorUserId: BoundedUserId,
  authorKeyFingerprintHex: KeyFingerprintHex,
});

export type DistributedVariableMetaStatement = typeof DistributedVariableMetaStatementSchema.Type;

export const DistributedEnvironmentMetaStatementSchema = Schema.Struct({
  ...envMetaBaseFields,
  ...environmentLifecycleFields,
  authorUserId: BoundedUserId,
  authorKeyFingerprintHex: KeyFingerprintHex,
});

export type DistributedEnvironmentMetaStatement =
  typeof DistributedEnvironmentMetaStatementSchema.Type;

const PrevManifestSigHashHex = Schema.Union([Schema.Literal(""), Sha256Hex]);

const manifestBaseFields = {
  suite: SuiteSchema,
  environmentId: EnvironmentIdSchema,
  epoch: PositiveInt,
  variablesDigestHex: Sha256Hex,
  envMetaVersion: PositiveInt,
  envMetaSigHashHex: Sha256Hex,
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: ManifestSignatureHex,
};

export const CreateEnvironmentManifestSchema = Schema.Struct({
  ...manifestBaseFields,
  manifestVersion: Schema.Literal(1),
  prevManifestSigHashHex: Schema.Literal(""),
});

export const EnvironmentManifestSchema = Schema.Struct({
  ...manifestBaseFields,
  manifestVersion: PositiveInt,
  prevManifestSigHashHex: PrevManifestSigHashHex,
});

export type EnvironmentManifest = typeof EnvironmentManifestSchema.Type;

export const DistributedEnvironmentManifestSchema = Schema.Struct({
  ...manifestBaseFields,
  manifestVersion: PositiveInt,
  prevManifestSigHashHex: PrevManifestSigHashHex,
  issuerUserId: BoundedUserId,
  issuerKeyFingerprintHex: KeyFingerprintHex,
});

export type DistributedEnvironmentManifest = typeof DistributedEnvironmentManifestSchema.Type;

export const RequiredDistributedEnvironmentManifestSchema =
  DistributedEnvironmentManifestSchema.pipe(
    Schema.annotateKey({
      messageMissingKey:
        "the environment manifest is required — an omitted manifest is refused as manifest suppression (CRYPTO_SPEC §6.3)",
    }),
  );

export const CheckpointValueSnapshotEntrySchema = Schema.Struct({
  variableId: VariableIdSchema,
  version: PositiveInt,
  valueSigHashHex: Sha256Hex,
});

export type CheckpointValueSnapshotEntry = typeof CheckpointValueSnapshotEntrySchema.Type;

export const CheckpointValueSnapshotSchema = Schema.Struct({
  chainSeq: PositiveInt,
  entryHashHex: Sha256Hex,
  values: Schema.Array(CheckpointValueSnapshotEntrySchema),
});

export type CheckpointValueSnapshot = typeof CheckpointValueSnapshotSchema.Type;

export const SchemaPolicySchema = Schema.Literals(["enabled", "locked"]);

export type SchemaPolicy = typeof SchemaPolicySchema.Type;

const MemberRecipientFields = {
  recipientClass: Schema.Literal("member"),
  recipientUserId: BoundedUserId,
};

const ServerRecipientFields = {
  recipientClass: Schema.Literal("server"),
  recipientUserId: KeyFingerprintHexSchema,
};

const WrappedDekFields = {
  suite: SuiteSchema,
  epoch: PositiveInt,
  recipientEncPubHex: EncPubHex,
  encHex: HpkeEncHex,
  ciphertextHex: WrappedDekCiphertextHex,
  signatureHex: WrapSignatureHex,
};

export const WrappedDekSchema = Schema.Union([
  Schema.Struct({ ...WrappedDekFields, ...MemberRecipientFields }),
  Schema.Struct({ ...WrappedDekFields, ...ServerRecipientFields }),
]);

export type WrappedDek = typeof WrappedDekSchema.Type;

export const RecipientDekSchema = Schema.Struct({
  suite: SuiteSchema,
  epoch: PositiveInt,
  recipientEncPubHex: EncPubHex,
  encHex: HpkeEncHex,
  ciphertextHex: WrappedDekCiphertextHex,
  signatureHex: WrapSignatureHex,
  signerUserId: BoundedUserId,
  signerKeyFingerprintHex: KeyFingerprintHex,
});

export type RecipientDek = typeof RecipientDekSchema.Type;

const DekWrapRefFields = {
  epoch: PositiveInt,
  recipientEncPubHex: EncPubHex,
};

export const DekWrapRefSchema = Schema.Union([
  Schema.Struct({ ...DekWrapRefFields, ...MemberRecipientFields }),
  Schema.Struct({ ...DekWrapRefFields, ...ServerRecipientFields }),
]);

export type DekWrapRef = typeof DekWrapRefSchema.Type;

export const LeasedDekSchema = Schema.Struct({
  suite: SuiteSchema,
  epoch: PositiveInt,
  encHex: HpkeEncHex,
  ciphertextHex: WrappedDekCiphertextHex,
});

export type LeasedDek = typeof LeasedDekSchema.Type;
