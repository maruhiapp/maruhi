import type {
  CheckpointValueSnapshot,
  DistributedEncryptedPayload,
  DistributedEnvironmentManifest,
  DistributedEnvironmentMetaStatement,
  DistributedVariableMetaStatement,
} from "@maruhi/api-schema";
import {
  cryptoEffect,
  CryptoMetaStatementInvalidError,
  CryptoUnsupportedMetaLayoutError,
  CryptoValueInvalidError,
  type WrappedCryptoError,
  type EnvironmentId,
  type UserId,
  type VariableId,
} from "@maruhi/core";
import type { MetaStatementContext, MetaVariableSchema } from "@maruhi/crypto";
import {
  SUPPORTED_META_LAYOUT_VERSIONS,
  verifyDistributedMetaStatement,
  verifyDistributedValue,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { cryptoErrorKind } from "./crypto-error-kind.ts";
import { displayText } from "./display.ts";
import type {
  VerifiedEnvironmentStatement,
  VerifiedMetaEvidence,
  VerifiedSchemaFields,
  VerifiedTombstone,
  VerifiedVariableStatement,
} from "./floor-check.ts";

export interface VerifiedPulledValue {
  readonly variableId: VariableId;
  readonly name: string;
  readonly version: number;
  readonly epoch: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  readonly prevValueSigHashHex: string;
  readonly signedBytesHashHex: string;
  readonly metaVersion: number;
  readonly metaSignedBytesHashHex: string;
  readonly prevMetaSigHashHex: string;
  readonly valueChainHeadSeq: number;
  readonly valueChainHeadHashHex: string;
  readonly metaChainHeadSeq: number;
  readonly metaChainHeadHashHex: string;
  readonly valueSignatureHex: string;
  readonly writerUserId: UserId;
  readonly writerKeyFingerprintHex: string;
  readonly metaSignatureHex: string;
  readonly authorUserId: UserId;
  readonly authorKeyFingerprintHex: string;
  readonly layoutVersion: number;
  readonly schema: VerifiedSchemaFields | null;
}

export interface PulledWire {
  readonly variableId: VariableId;
  readonly statement: DistributedVariableMetaStatement;
  readonly value: DistributedEncryptedPayload;
}

export type VerifyOutcome<T> =
  | { readonly kind: "ok"; readonly value: T }
  | { readonly kind: "future" }
  | {
      readonly kind: "rejected";
      readonly message: string;
      readonly evidence: boolean;
    };

function coordinatesMatch(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  variable: PulledWire,
): boolean {
  const aad = variable.value.aad;
  return (
    aad.projectId === verified.projectId &&
    aad.environmentId === environmentId &&
    aad.variableId === variable.variableId
  );
}

function isFutureFailure(
  verified: VerifiedProject,
  chainHeadSeq: number,
  error: WrappedCryptoError,
): boolean {
  if (
    !(error instanceof CryptoValueInvalidError) &&
    !(error instanceof CryptoMetaStatementInvalidError)
  ) {
    return false;
  }
  const unknownSigner = error.reason === "writer-unknown" || error.reason === "author-unknown";
  return (
    error.reason === "chain-head-future" ||
    (unknownSigner && chainHeadSeq > verified.history.headSeq)
  );
}

function failureOutcome<T>(
  verified: VerifiedProject,
  label: string,
  chainHeadSeq: number,
  error: WrappedCryptoError,
): VerifyOutcome<T> {
  if (error instanceof CryptoUnsupportedMetaLayoutError) {
    return {
      kind: "rejected",
      evidence: false,
      message: `${label} uses statement layout version ${error.layoutVersion}, which this CLI does not support (supported: ${SUPPORTED_META_LAYOUT_VERSIONS.join(", ")}). This is not a tampering indication — update the maruhi CLI (CRYPTO_SPEC §4.2)`,
    };
  }
  if (isFutureFailure(verified, chainHeadSeq, error)) {
    return { kind: "future" };
  }
  return {
    kind: "rejected",
    evidence: true,
    message: `Verification of ${label} failed (reason=${"reason" in error ? error.reason : cryptoErrorKind(error)}). It may have been replaced or forged by the server`,
  };
}

function metaEvidenceFields(
  statement: DistributedVariableMetaStatement | DistributedEnvironmentMetaStatement,
  metaSigHashHex: string,
): Omit<VerifiedMetaEvidence, "status"> {
  return {
    metaVersion: statement.metaVersion,
    metaSigHashHex,
    chainHeadSeq: statement.chainHeadSeq,
    chainHeadHashHex: statement.chainHeadHashHex,
    signatureHex: statement.signatureHex,
    authorUserId: statement.authorUserId,
    authorKeyFingerprintHex: statement.authorKeyFingerprintHex,
  };
}

type WireStatementLayout =
  | { readonly layoutVersion: 1; readonly schema: null }
  | { readonly layoutVersion: number; readonly schema: VerifiedSchemaFields };

function wireStatementLayoutOf(
  statement: DistributedVariableMetaStatement,
): WireStatementLayout | null {
  const present = [
    statement.layoutVersion !== undefined,
    statement.varType !== undefined,
    statement.required !== undefined,
    statement.description !== undefined,
  ].filter(Boolean).length;
  if (present === 0) {
    return { layoutVersion: 1, schema: null };
  }
  if (
    statement.layoutVersion === undefined ||
    statement.varType === undefined ||
    statement.required === undefined ||
    statement.description === undefined
  ) {
    return null;
  }
  if (!maxAgeCoupled(statement.layoutVersion, statement.maxAgeDays !== undefined)) {
    return null;
  }
  return {
    layoutVersion: statement.layoutVersion,
    schema: {
      varType: statement.varType,
      required: statement.required,
      description: statement.description,
      maxAgeDays: statement.maxAgeDays ?? null,
    },
  };
}

function maxAgeCoupled(layoutVersion: number, present: boolean): boolean {
  return layoutVersion !== 3 || present;
}

function partialLayoutMessage(label: string): string {
  return `${label} carries only part of the layout-v3 field set (layoutVersion / varType / required / description / maxAgeDays must be all present or all absent — an inconsistent server response)`;
}

function contextLayoutFields(
  layout: WireStatementLayout | null,
): Pick<MetaStatementContext, "layoutVersion" | "schema"> {
  if (layout === null || layout.schema === null) {
    return {};
  }
  const schema: MetaVariableSchema = {
    varType: layout.schema.varType,
    required: layout.schema.required ? "true" : "false",
    description: layout.schema.description,
    maxAgeDays: layout.schema.maxAgeDays === null ? "" : String(layout.schema.maxAgeDays),
  };
  return { layoutVersion: layout.layoutVersion, schema };
}

async function verifyStatement(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  target: MetaStatementContext["target"],
  statement: DistributedVariableMetaStatement | DistributedEnvironmentMetaStatement,
  label: string,
  layout?: WireStatementLayout | null,
): Promise<VerifyOutcome<{ readonly signedBytesHashHex: string }>> {
  return await Effect.runPromise(
    cryptoEffect(() =>
      verifyDistributedMetaStatement({
        history: verified.history,
        context: {
          suite: statement.suite,
          projectId: verified.projectId,
          environmentId,
          target,
          name: statement.name,
          status: statement.status,
          ...contextLayoutFields(layout ?? null),
          metaVersion: statement.metaVersion,
          prevMetaSigHashHex: statement.prevMetaSigHashHex,
          authorUserId: statement.authorUserId,
          chainHeadHashHex: statement.chainHeadHashHex,
          chainHeadSeq: statement.chainHeadSeq,
        },
        authorKeyFingerprintHex: statement.authorKeyFingerprintHex,
        signatureHex: statement.signatureHex,
      }),
    ).pipe(
      Effect.match({
        onSuccess: (value): VerifyOutcome<{ readonly signedBytesHashHex: string }> => ({
          kind: "ok",
          value,
        }),
        onFailure: (error): VerifyOutcome<{ readonly signedBytesHashHex: string }> =>
          failureOutcome(verified, label, statement.chainHeadSeq, error),
      }),
    ),
  );
}

async function verifyVariableStatement(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  statement: DistributedVariableMetaStatement,
  label: string,
): Promise<
  VerifyOutcome<{ readonly signedBytesHashHex: string; readonly layout: WireStatementLayout }>
> {
  const layout = wireStatementLayoutOf(statement);
  if (layout === null) {
    return { kind: "rejected", message: partialLayoutMessage(label), evidence: true };
  }
  const outcome = await verifyStatement(
    verified,
    environmentId,
    { kind: "variable", variableId: statement.variableId },
    statement,
    label,
    layout,
  );
  if (outcome.kind !== "ok") {
    return outcome;
  }
  return { kind: "ok", value: { signedBytesHashHex: outcome.value.signedBytesHashHex, layout } };
}

async function verifyOne(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  variable: PulledWire,
): Promise<VerifyOutcome<VerifiedPulledValue>> {
  const payload = variable.value;
  const statement = variable.statement;
  if (!coordinatesMatch(verified, environmentId, variable)) {
    return {
      kind: "rejected",
      evidence: true,
      message: `Variable ${displayText(variable.variableId)} declares AAD coordinates that do not match the requested context (an inconsistent server response)`,
    };
  }
  if (statement.environmentId !== environmentId || statement.variableId !== variable.variableId) {
    return {
      kind: "rejected",
      evidence: true,
      message: `Variable ${displayText(variable.variableId)} has statement coordinates that do not match the requested context (possible renaming or transplantation)`,
    };
  }
  const verifiedStatement = await verifyVariableStatement(
    verified,
    environmentId,
    statement,
    `variable ${displayText(variable.variableId)}'s meta statement`,
  );
  if (verifiedStatement.kind !== "ok") {
    return verifiedStatement;
  }
  if (statement.status !== "active") {
    return {
      kind: "rejected",
      evidence: true,
      message: `Variable ${displayText(variable.variableId)} was served a ${statement.status} statement together with a value (a value must only accompany an active statement — an inconsistent server response)`,
    };
  }
  return await Effect.runPromise(
    cryptoEffect(() =>
      verifyDistributedValue({
        history: verified.history,
        context: {
          suite: payload.suite,
          projectId: verified.projectId,
          environmentId,
          epoch: payload.aad.epoch,
          variableId: variable.variableId,
          version: payload.aad.version,
          nonceHex: payload.nonceHex,
          ciphertextHex: payload.ciphertextHex,
          prevValueSigHashHex: payload.prevValueSigHashHex,
          writerUserId: payload.writerUserId,
          chainHeadHashHex: payload.chainHeadHashHex,
          chainHeadSeq: payload.chainHeadSeq,
        },
        writerKeyFingerprintHex: payload.writerKeyFingerprintHex,
        signatureHex: payload.signatureHex,
      }),
    ).pipe(
      Effect.match({
        onSuccess: (result): VerifyOutcome<VerifiedPulledValue> => ({
          kind: "ok",
          value: {
            variableId: variable.variableId,
            name: statement.name,
            version: payload.aad.version,
            epoch: payload.aad.epoch,
            nonceHex: payload.nonceHex,
            ciphertextHex: payload.ciphertextHex,
            prevValueSigHashHex: payload.prevValueSigHashHex,
            signedBytesHashHex: result.signedBytesHashHex,
            metaVersion: statement.metaVersion,
            metaSignedBytesHashHex: verifiedStatement.value.signedBytesHashHex,
            prevMetaSigHashHex: statement.prevMetaSigHashHex,
            valueChainHeadSeq: payload.chainHeadSeq,
            valueChainHeadHashHex: payload.chainHeadHashHex,
            metaChainHeadSeq: statement.chainHeadSeq,
            metaChainHeadHashHex: statement.chainHeadHashHex,
            valueSignatureHex: payload.signatureHex,
            writerUserId: payload.writerUserId,
            writerKeyFingerprintHex: payload.writerKeyFingerprintHex,
            metaSignatureHex: statement.signatureHex,
            authorUserId: statement.authorUserId,
            authorKeyFingerprintHex: statement.authorKeyFingerprintHex,
            layoutVersion: verifiedStatement.value.layout.layoutVersion,
            schema: verifiedStatement.value.layout.schema,
          },
        }),
        onFailure: (error): VerifyOutcome<VerifiedPulledValue> =>
          failureOutcome(
            verified,
            `variable ${displayText(statement.name)}'s value signature`,
            payload.chainHeadSeq,
            error,
          ),
      }),
    ),
  );
}

export interface PullWire {
  readonly statement: DistributedEnvironmentMetaStatement;
  readonly variables: readonly PulledWire[];
  readonly deletedVariables: readonly DistributedVariableMetaStatement[];
  readonly declaredVariables?: readonly DistributedVariableMetaStatement[] | undefined;
  readonly manifest: DistributedEnvironmentManifest;
  readonly checkpointSnapshot?: CheckpointValueSnapshot | undefined;
}

export async function verifyEnvironmentStatement(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  statement: DistributedEnvironmentMetaStatement,
): Promise<VerifyOutcome<VerifiedEnvironmentStatement>> {
  const deletedAtSeq = verified.state.environments.get(environmentId)?.deletedAtSeq ?? null;
  if (deletedAtSeq !== null) {
    return {
      kind: "rejected",
      evidence: true,
      message: `Environment ${displayText(environmentId)} is deleted on the verified chain (delete_environment at seq ${deletedAtSeq}), yet the server distributed it as live (an unauthorized resurrection — a deleted environment is never distributed)`,
    };
  }
  if (statement.environmentId !== environmentId) {
    return {
      kind: "rejected",
      evidence: true,
      message: `The environment statement's coordinates do not match the requested environment ${environmentId} (possible transplantation)`,
    };
  }
  const result = await verifyStatement(
    verified,
    environmentId,
    { kind: "environment" },
    statement,
    `environment ${environmentId}'s meta statement`,
  );
  if (result.kind !== "ok") {
    return result;
  }
  return {
    kind: "ok",
    value: {
      status: "active",
      name: statement.name,
      ...metaEvidenceFields(statement, result.value.signedBytesHashHex),
    },
  };
}

export async function verifyDeletedStatements(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  deleted: readonly DistributedVariableMetaStatement[],
  liveIds: ReadonlySet<string>,
): Promise<VerifyOutcome<readonly VerifiedTombstone[]>> {
  const outcomes = await Promise.all(
    deleted.map((statement) =>
      verifyVariableStatement(
        verified,
        environmentId,
        statement,
        `deleted variable ${displayText(statement.variableId)}'s meta statement`,
      ),
    ),
  );
  const seen = new Set<string>();
  const tombstones: VerifiedTombstone[] = [];
  for (const [index, statement] of deleted.entries()) {
    if (statement.environmentId !== environmentId) {
      return {
        kind: "rejected",
        evidence: true,
        message: `Deleted variable ${displayText(statement.variableId)} has statement coordinates that do not match the requested environment`,
      };
    }
    if (seen.has(statement.variableId) || liveIds.has(statement.variableId)) {
      return {
        kind: "rejected",
        evidence: true,
        message: `Variable ${displayText(statement.variableId)} was served as both live (active or declared) and deleted (an unauthorized undeletion = equivocation in transit)`,
      };
    }
    seen.add(statement.variableId);
    if (statement.status !== "deleted") {
      return {
        kind: "rejected",
        evidence: true,
        message: `A non-deleted statement was served in the deleted list: ${displayText(statement.variableId)}`,
      };
    }
    const result = outcomes[index]!;
    if (result.kind !== "ok") {
      return result;
    }
    tombstones.push({
      variableId: statement.variableId,
      name: statement.name,
      status: "deleted",
      ...metaEvidenceFields(statement, result.value.signedBytesHashHex),
    });
  }
  return { kind: "ok", value: tombstones };
}

export function checkVerifiedNames(
  values: readonly { readonly variableId: VariableId; readonly name: string }[],
  warnings: string[],
): string | null {
  const seenNames = new Set<string>();
  for (const value of values) {
    if (seenNames.has(value.name)) {
      return `Multiple live statements with the same name passed verification (server equivocation): ${displayText(value.name)}. Refusing name resolution`;
    }
    seenNames.add(value.name);
    if (value.name.normalize("NFC") !== value.name) {
      warnings.push(
        `Variable ${displayText(value.variableId)} has a name that is not NFC-normalized (an honest server would not accept it — beware that visually identical names may coexist)`,
      );
    }
  }
  return null;
}

export async function verifyVariableStatements(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  statements: readonly DistributedVariableMetaStatement[],
): Promise<
  VerifyOutcome<{
    readonly values: readonly VerifiedVariableStatement[];
    readonly ids: Set<string>;
  }>
> {
  const outcomes = await verifyStatementsInParallel(
    verified,
    environmentId,
    statements,
    (statement) => `variable ${displayText(statement.variableId)}'s meta statement`,
  );
  const seenIds = new Set<string>();
  const values: VerifiedVariableStatement[] = [];
  for (const [index, statement] of statements.entries()) {
    const refusal = refuseMismatchedOrDuplicate(
      statement,
      environmentId,
      seenIds,
      `Variable ${displayText(statement.variableId)}`,
      (candidate) => seenIds.has(candidate.variableId),
    );
    if (refusal !== null) {
      return refusal;
    }
    const outcome = outcomes[index]!;
    if (outcome.kind !== "ok") {
      return outcome;
    }
    if (statement.status === "deleted") {
      return {
        kind: "rejected",
        evidence: true,
        message: `Variable ${displayText(statement.variableId)} was served a deleted statement in the live list (a possible unauthorized undeletion)`,
      };
    }
    values.push({
      variableId: statement.variableId,
      name: statement.name,
      status: statement.status,
      ...metaEvidenceFields(statement, outcome.value.signedBytesHashHex),
      layoutVersion: outcome.value.layout.layoutVersion,
      schema: outcome.value.layout.schema,
    });
  }
  return { kind: "ok", value: { values, ids: seenIds } };
}

type StatementVerification = VerifyOutcome<{
  readonly signedBytesHashHex: string;
  readonly layout: WireStatementLayout;
}>;

async function verifyStatementsInParallel(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  statements: readonly DistributedVariableMetaStatement[],
  describe: (statement: DistributedVariableMetaStatement) => string,
): Promise<readonly StatementVerification[]> {
  return Promise.all(
    statements.map((statement) =>
      verifyVariableStatement(verified, environmentId, statement, describe(statement)),
    ),
  );
}

function refuseMismatchedOrDuplicate(
  statement: DistributedVariableMetaStatement,
  environmentId: EnvironmentId,
  seenIds: Set<string>,
  subject: string,
  isDuplicate: (statement: DistributedVariableMetaStatement) => boolean,
): VerifyOutcome<never> | null {
  if (statement.environmentId !== environmentId) {
    return {
      kind: "rejected",
      evidence: true,
      message: `${subject} has statement coordinates that do not match the requested context (possible renaming or transplantation)`,
    };
  }
  if (isDuplicate(statement)) {
    return {
      kind: "rejected",
      evidence: true,
      message: `Duplicate variable IDs within one response (an inconsistent server response): ${statement.variableId}`,
    };
  }
  seenIds.add(statement.variableId);
  return null;
}

export async function verifyDeclaredStatements(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  declared: readonly DistributedVariableMetaStatement[],
  activeIds: ReadonlySet<string>,
): Promise<
  VerifyOutcome<{
    readonly values: readonly VerifiedVariableStatement[];
    readonly ids: Set<string>;
  }>
> {
  const outcomes = await verifyStatementsInParallel(
    verified,
    environmentId,
    declared,
    (statement) => `declared variable ${displayText(statement.variableId)}'s meta statement`,
  );
  const seenIds = new Set<string>();
  const values: VerifiedVariableStatement[] = [];
  for (const [index, statement] of declared.entries()) {
    const refusal = refuseMismatchedOrDuplicate(
      statement,
      environmentId,
      seenIds,
      `Declared variable ${displayText(statement.variableId)}`,
      (candidate) => seenIds.has(candidate.variableId) || activeIds.has(candidate.variableId),
    );
    if (refusal !== null) {
      return refusal;
    }
    if (statement.status !== "declared") {
      return {
        kind: "rejected",
        evidence: true,
        message:
          statement.status === "active"
            ? `Variable ${displayText(statement.variableId)} has a verified active statement, but the value-bearing response carries no value for it (a value omission — CRYPTO_SPEC §6.3: only declared variables legitimately have no value)`
            : `A deleted statement was served in the declared list: ${displayText(statement.variableId)}`,
      };
    }
    const outcome = outcomes[index]!;
    if (outcome.kind !== "ok") {
      return outcome;
    }
    values.push({
      variableId: statement.variableId,
      name: statement.name,
      status: "declared",
      ...metaEvidenceFields(statement, outcome.value.signedBytesHashHex),
      layoutVersion: outcome.value.layout.layoutVersion,
      schema: outcome.value.layout.schema,
    });
  }
  return { kind: "ok", value: { values, ids: seenIds } };
}

export async function verifyActiveVariables(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  variables: readonly PulledWire[],
): Promise<
  VerifyOutcome<{ readonly values: readonly VerifiedPulledValue[]; readonly ids: Set<string> }>
> {
  const outcomes = await Promise.all(
    variables.map((variable) => verifyOne(verified, environmentId, variable)),
  );
  const seenIds = new Set<string>();
  const values: VerifiedPulledValue[] = [];
  for (const [index, variable] of variables.entries()) {
    if (seenIds.has(variable.variableId)) {
      return {
        kind: "rejected",
        evidence: true,
        message: `Duplicate variable IDs within one response (an inconsistent server response): ${variable.variableId}`,
      };
    }
    seenIds.add(variable.variableId);
    const outcome = outcomes[index]!;
    if (outcome.kind !== "ok") {
      return outcome;
    }
    values.push(outcome.value);
  }
  return { kind: "ok", value: { values, ids: seenIds } };
}
