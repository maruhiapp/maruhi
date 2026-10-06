// The data store's stored-row decoders, shared by every query file
// (the service itself is data-store.ts).

import type {
  DistributedMetaStatementValue,
  DistributedVariableMetaStatementValue,
  MetaStatementStatusInput,
  MetaVariableSchemaInput,
  MetaVarTypeInput,
  WireSuite,
} from "./data-plane.ts";
import type { MetaAnchor, ResourceCounts } from "./data-store.ts";

// ---------------------------------------------------------------------------
// The row-decode safety layer: check a required column's presence and
// type; a mismatch becomes a defect with an explanation. A bare
// String(...) / Number(...) passthrough would let a column-name typo /
// rename through as the string "undefined" or NaN, so every row →
// domain-type mapping goes through here (the same discipline as
// storedSuite / statementOf's status check — "an unknown value is a
// defect" — extended to every column).
// ---------------------------------------------------------------------------

export type StoredRow = Record<string, unknown>;

/** A column's existence check (a column-name mismatch between the SELECT clause and the decoder = detection of an implementation bug). */
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
  // SUM(CASE ...) returns NULL on zero rows, so it is read as 0 (COUNT is always a number)
  const active = nullableNumberColumn(row, "active_rows");
  return { active: active ?? 0, rows: numberColumn(row, "total_rows") };
}

/**
 * Read out the stored suite column. Since the write path is pinned by
 * the Schema Literal (§12-2), a value outside the known set is storage
 * corruption and drops to a defect (never swallowed by a cast).
 */
export function storedSuite(value: unknown): WireSuite {
  if (value !== "maruhi/v1") {
    throw new Error("unexpected suite in stored row");
  }
  return value;
}

/**
 * The stored status column → an environment statement's 2 values
 * (environment meta is outside the schema layout's scope — CRYPTO_SPEC §4.2). An
 * unknown value is a defect as storage corruption.
 */
function storedEnvStatus(value: string): "active" | "deleted" {
  if (value !== "active" && value !== "deleted") {
    // The write path is pinned by the Schema Literal (an unknown value is storage corruption)
    throw new Error("unexpected status in stored meta statement row");
  }
  return value;
}

/** The stored status column → a variable statement's 3 values (declared is v3 only). */
export function storedVariableStatus(value: string): MetaStatementStatusInput {
  if (value !== "active" && value !== "deleted" && value !== "declared") {
    throw new Error("unexpected status in stored meta statement row");
  }
  return value;
}

/** The stored var_type column → the closed set (CRYPTO_SPEC §4.2 — an unknown value is a defect). */
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

/** The stored required column ("true" / "false" — the signed-target representation) → boolean. */
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

/**
 * Decode the layout-v3 schema columns (a v1 row = all 5 columns treated
 * as absent → null). Any other stored layout, or a NULL schema column on a
 * v3 row, is an invariant violation of the write path (a defect — the
 * acceptance path stores supported layouts only).
 */
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
  // max_age_days is stored as the signed string ("" = none)
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

/**
 * Decode the meta-statement columns (the common part excluding
 * environmentId / variableId). prefix serves latestVersions's SQL
 * aliases (ms_*) — the aliased row is read as-is without assembling a
 * pseudo-row object. The caller picks the status decode between
 * environment (2 values) and variable (3 values).
 */
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
    authorUserId: stringColumn(row, `${prefix}author_user_id`),
    authorKeyFingerprintHex: stringColumn(row, `${prefix}author_key_fingerprint`),
  };
}

/** An environment meta-statement row → the distributed form (author included; environmentId comes from the column). */
export function statementOf(row: StoredRow): DistributedMetaStatementValue {
  return {
    environmentId: stringColumn(row, "environment_id"),
    ...statementColumns(row, "", storedEnvStatus),
  };
}

/**
 * Variable-statement columns → the distributed form's v3 carried
 * fields (§12-2): on a v1 row all five fields are absent (no new field
 * is added to a v1 distribution); on a v3 row layoutVersion + the
 * schema fields are expanded.
 */
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
    // null = no declaration
    maxAgeDays: schema.maxAgeDays ?? null,
  };
}

export function variableStatementOf(row: StoredRow): DistributedVariableMetaStatementValue {
  return {
    environmentId: stringColumn(row, "environment_id"),
    variableId: stringColumn(row, "variable_id"),
    ...statementColumns(row, "", storedVariableStatus),
    ...variableStatementV3Fields(row, ""),
  };
}

/** A variable statement's anchor row → MetaAnchor (layoutVersion is the stored actual value). */
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

/** An environment statement's anchor row → MetaAnchor (environment meta is always layout 1). */
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

// Distribution (§12-2) does not select signed_bytes_hash_hex = never
// distributes it (a verifier recomputes it themselves). Only the
// anchor lookups (*AnchorOf) read the hash column
export const MS_COLUMNS =
  "ms.environment_id, ms.suite, ms.name, ms.status, ms.meta_version, ms.prev_meta_sig_hash_hex, ms.chain_head_hash_hex, ms.chain_head_seq, ms.signature_hex, ms.author_user_id, ms.author_key_fingerprint";

// A variable statement also selects the v3 carried-field columns
// (columns that do not exist in the environment side's SELECT —
// environment_meta_statements is outside the schema layout's scope)
export const VAR_MS_COLUMNS = `${MS_COLUMNS}, ms.layout_version, ms.var_type, ms.required, ms.description, ms.max_age_days`;
