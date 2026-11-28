import type { EnvironmentId, KeyFingerprintHex, UserId, VariableId } from "@maruhi/core";
import {
  decodeEnvironmentId,
  decodeKeyFingerprintHex,
  decodeUserId,
  decodeVariableId,
} from "@maruhi/core";

import type {
  DistributedMetaStatementValue,
  DistributedVariableMetaStatementValue,
  MetaStatementStatusInput,
  MetaVariableSchemaInput,
  MetaVarTypeInput,
  WireSuite,
} from "./data-plane.ts";
import type { MetaAnchor, ResourceCounts } from "./data-store.ts";

export type StoredRow = Record<string, unknown>;

export function columnValue(row: StoredRow, column: string): unknown {
  const value = row[column];
  if (value === undefined) {
    throw new Error(`stored row is missing column "${column}"`);
  }
  return value;
}

export function stringColumn(row: StoredRow, column: string): string {
  const value = columnValue(row, column);
  if (typeof value !== "string") {
    throw new Error(`stored column "${column}" is not a string`);
  }
  return value;
}

export function userIdColumn(row: StoredRow, column: string): UserId {
  return decodeUserId(stringColumn(row, column));
}

export function keyFingerprintColumn(row: StoredRow, column: string): KeyFingerprintHex {
  return decodeKeyFingerprintHex(stringColumn(row, column));
}

export function environmentIdColumn(row: StoredRow, column: string): EnvironmentId {
  return decodeEnvironmentId(stringColumn(row, column));
}

export function variableIdColumn(row: StoredRow, column: string): VariableId {
  return decodeVariableId(stringColumn(row, column));
}

export function numberColumn(row: StoredRow, column: string): number {
  const value = columnValue(row, column);
  if (typeof value !== "number") {
    throw new Error(`stored column "${column}" is not a number`);
  }
  return value;
}

export function nullableNumberColumn(row: StoredRow, column: string): number | null {
  const value = columnValue(row, column);
  if (value !== null && typeof value !== "number") {
    throw new Error(`stored column "${column}" is not a number or NULL`);
  }
  return value;
}

export function countsOf(row: StoredRow | undefined): ResourceCounts {
  if (row === undefined) {
    return { active: 0, rows: 0 };
  }
  const active = nullableNumberColumn(row, "active_rows");
  return { active: active ?? 0, rows: numberColumn(row, "total_rows") };
}

export function storedSuite(value: unknown): WireSuite {
  if (value !== "maruhi/v1") {
    throw new Error("unexpected suite in stored row");
  }
  return value;
}

function storedEnvStatus(value: string): "active" {
  if (value !== "active") {
    throw new Error("unexpected status in stored meta statement row");
  }
  return value;
}

export function storedVariableStatus(value: string): MetaStatementStatusInput {
  if (value !== "active" && value !== "deleted" && value !== "declared") {
    throw new Error("unexpected status in stored meta statement row");
  }
  return value;
}

function storedVarType(value: string): MetaVarTypeInput {
  if (
    value !== "" &&
    value !== "string" &&
    value !== "number" &&
    value !== "boolean" &&
    value !== "url"
  ) {
    throw new Error("unexpected var_type in stored meta statement row");
  }
  return value;
}

function storedRequired(value: string): boolean {
  if (value !== "true" && value !== "false") {
    throw new Error("unexpected required in stored meta statement row");
  }
  return value === "true";
}

function nullableStringColumn(row: StoredRow, column: string): string | null {
  const value = columnValue(row, column);
  if (value !== null && typeof value !== "string") {
    throw new Error(`stored column "${column}" is not a string or NULL`);
  }
  return value;
}

function storedSchemaColumns(row: StoredRow, prefix: string): MetaVariableSchemaInput | null {
  const layoutVersion = numberColumn(row, `${prefix}layout_version`);
  if (layoutVersion === 1) {
    return null;
  }
  if (layoutVersion !== 3) {
    throw new Error("meta statement row has an unsupported layout");
  }
  const varType = nullableStringColumn(row, `${prefix}var_type`);
  const required = nullableStringColumn(row, `${prefix}required`);
  const description = nullableStringColumn(row, `${prefix}description`);
  const maxAge = nullableStringColumn(row, `${prefix}max_age_days`);
  if (varType === null || required === null || description === null || maxAge === null) {
    throw new Error("layout v3 meta statement row is missing schema columns");
  }
  return {
    varType: storedVarType(varType),
    required: storedRequired(required),
    description,
    maxAgeDays: maxAge === "" ? null : Number(maxAge),
  };
}

export function statementColumns<S extends MetaStatementStatusInput>(
  row: StoredRow,
  prefix: string,
  statusOf: (value: string) => S,
): Omit<DistributedMetaStatementValue, "environmentId" | "status"> & { readonly status: S } {
  return {
    suite: storedSuite(columnValue(row, `${prefix}suite`)),
    name: stringColumn(row, `${prefix}name`),
    status: statusOf(stringColumn(row, `${prefix}status`)),
    metaVersion: numberColumn(row, `${prefix}meta_version`),
    prevMetaSigHashHex: stringColumn(row, `${prefix}prev_meta_sig_hash_hex`),
    chainHeadHashHex: stringColumn(row, `${prefix}chain_head_hash_hex`),
    chainHeadSeq: numberColumn(row, `${prefix}chain_head_seq`),
    signatureHex: stringColumn(row, `${prefix}signature_hex`),
    authorUserId: userIdColumn(row, `${prefix}author_user_id`),
    authorKeyFingerprintHex: keyFingerprintColumn(row, `${prefix}author_key_fingerprint`),
  };
}

export function statementOf(row: StoredRow): DistributedMetaStatementValue {
  return {
    environmentId: environmentIdColumn(row, "environment_id"),
    ...statementColumns(row, "", storedEnvStatus),
  };
}

export function variableStatementV3Fields(
  row: StoredRow,
  prefix: string,
): Pick<
  DistributedVariableMetaStatementValue,
  "layoutVersion" | "varType" | "required" | "description" | "maxAgeDays"
> {
  const schema = storedSchemaColumns(row, prefix);
  if (schema === null) {
    return {};
  }
  return {
    layoutVersion: numberColumn(row, `${prefix}layout_version`),
    varType: schema.varType,
    required: schema.required,
    description: schema.description,
    maxAgeDays: schema.maxAgeDays ?? null,
  };
}

export function variableStatementOf(row: StoredRow): DistributedVariableMetaStatementValue {
  return {
    environmentId: environmentIdColumn(row, "environment_id"),
    variableId: variableIdColumn(row, "variable_id"),
    ...statementColumns(row, "", storedVariableStatus),
    ...variableStatementV3Fields(row, ""),
  };
}

export function variableAnchorOf(row: StoredRow | undefined): MetaAnchor | null {
  if (row === undefined) {
    return null;
  }
  return {
    signedBytesHashHex: stringColumn(row, "signed_bytes_hash_hex"),
    name: stringColumn(row, "name"),
    status: storedVariableStatus(stringColumn(row, "status")),
    layoutVersion: numberColumn(row, "layout_version"),
    schema: storedSchemaColumns(row, ""),
  };
}

export function environmentAnchorOf(row: StoredRow | undefined): MetaAnchor | null {
  if (row === undefined) {
    return null;
  }
  return {
    signedBytesHashHex: stringColumn(row, "signed_bytes_hash_hex"),
    name: stringColumn(row, "name"),
    status: storedEnvStatus(stringColumn(row, "status")),
    layoutVersion: 1,
    schema: null,
  };
}

export const MS_COLUMNS =
  "ms.environment_id, ms.suite, ms.name, ms.status, ms.meta_version, ms.prev_meta_sig_hash_hex, ms.chain_head_hash_hex, ms.chain_head_seq, ms.signature_hex, ms.author_user_id, ms.author_key_fingerprint";

export const VAR_MS_COLUMNS = `${MS_COLUMNS}, ms.layout_version, ms.var_type, ms.required, ms.description, ms.max_age_days`;
