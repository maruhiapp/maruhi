import type {
  DistributedEnvironmentMetaStatement,
  DistributedVariableMetaStatement,
} from "@maruhi/api-schema";
import type { AuditActor, EnvironmentId, ProjectId, UserId, VariableId } from "@maruhi/core";
import { decodeProjectId } from "@maruhi/core";
import type { KeyFingerprintHex } from "@maruhi/crypto";

export function projectIdOf(chain: { readonly genesisHashHex: string }): ProjectId {
  return decodeProjectId(chain.genesisHashHex);
}

export type DataActor = AuditActor;

export type WireSuite = "maruhi/v1";

export type DekRecipientClass = "member" | "server";

export type DekRecipientPosition =
  | { readonly recipientClass: "member"; readonly recipientUserId: UserId }
  | { readonly recipientClass: "server"; readonly recipientUserId: KeyFingerprintHex };

export type DekWrapInput = DekRecipientPosition & {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly signatureHex: string;
};

export type DekWrapRefInput = DekRecipientPosition & {
  readonly epoch: number;
  readonly recipientEncPubHex: string;
};

export type WireMetaStatement = Omit<
  DistributedVariableMetaStatement,
  "environmentId" | "variableId" | "authorUserId" | "authorKeyFingerprintHex"
>;

export type MetaStatementStatusInput = WireMetaStatement["status"];

export type MetaVarTypeInput = Exclude<WireMetaStatement["varType"], undefined>;

export type MetaVariableSchemaInput = Required<
  Pick<WireMetaStatement, "varType" | "required" | "description">
> &
  Pick<WireMetaStatement, "maxAgeDays">;

export type WireSchemaField = keyof MetaVariableSchemaInput;

export type MetaStatementInput = Omit<WireMetaStatement, WireSchemaField> & {
  readonly schema?: MetaVariableSchemaInput;
};

export type DistributedMetaStatementValue = Omit<
  DistributedEnvironmentMetaStatement,
  "authorKeyFingerprintHex"
> & {
  readonly authorKeyFingerprintHex: KeyFingerprintHex;
};

export type DistributedVariableMetaStatementValue = Omit<
  DistributedVariableMetaStatement,
  "authorKeyFingerprintHex"
> & {
  readonly authorKeyFingerprintHex: KeyFingerprintHex;
};

export interface EnvManifestInput {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly variablesDigestHex: string;
  readonly envMetaVersion: number;
  readonly envMetaSigHashHex: string;
  readonly prevManifestSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

export interface DistributedEnvManifestValue extends EnvManifestInput {
  readonly environmentId: EnvironmentId;
  readonly issuerUserId: UserId;
  readonly issuerKeyFingerprintHex: KeyFingerprintHex;
}

export interface ValueInput {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly version: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  readonly prevValueSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

export interface EnvironmentSummaryValue {
  readonly environmentId: EnvironmentId;
  readonly currentEpoch: number;
  readonly statement: DistributedMetaStatementValue;
}

export interface VariableVersionValue {
  readonly variableId: VariableId;
  readonly version: number;
  readonly epoch: number;
}

export interface PulledVariableValue {
  readonly variableId: VariableId;
  readonly version: number;
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  readonly prevValueSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
  readonly writerUserId: UserId;
  readonly writerKeyFingerprintHex: KeyFingerprintHex;
}

export interface RecipientDekValue {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly signatureHex: string;
  readonly signerUserId: UserId;
  readonly signerKeyFingerprintHex: KeyFingerprintHex;
}

export interface CheckpointSnapshotEntryValue {
  readonly variableId: VariableId;
  readonly version: number;
  readonly valueSigHashHex: string;
}

export interface CheckpointSnapshotValue {
  readonly chainSeq: number;
  readonly entryHashHex: string;
  readonly values: readonly CheckpointSnapshotEntryValue[];
}

export function optionalCheckpointSnapshot(checkpointSnapshot: CheckpointSnapshotValue | null): {
  readonly checkpointSnapshot?: CheckpointSnapshotValue;
} {
  return checkpointSnapshot === null ? {} : { checkpointSnapshot };
}

export interface EnvironmentPullValue {
  readonly environmentId: EnvironmentId;
  readonly currentEpoch: number;
  readonly statement: DistributedMetaStatementValue;
  readonly variables: readonly (PulledVariableValue & {
    readonly statement: DistributedVariableMetaStatementValue;
  })[];
  readonly deletedVariables: readonly DistributedVariableMetaStatementValue[];
  readonly declaredVariables?: readonly DistributedVariableMetaStatementValue[];
  readonly deks: readonly RecipientDekValue[];
  readonly schemaPolicy: SchemaPolicy;
  readonly manifest: DistributedEnvManifestValue;
  readonly checkpointSnapshot?: CheckpointSnapshotValue;
}

export interface EnvironmentMetadataPullValue {
  readonly environmentId: EnvironmentId;
  readonly currentEpoch: number;
  readonly statement: DistributedMetaStatementValue;
  readonly variables: readonly DistributedVariableMetaStatementValue[];
  readonly deletedVariables: readonly DistributedVariableMetaStatementValue[];
  readonly manifest: DistributedEnvManifestValue;
  readonly schemaPolicy: SchemaPolicy;
}

export interface EnvironmentListValue {
  readonly environments: readonly EnvironmentSummaryValue[];
  readonly schemaPolicy: SchemaPolicy;
}

export type SchemaPolicy = "enabled" | "locked";
