import type { VariableId } from "./chain-types.ts";
import type { CryptoResult } from "./errors.ts";
import type { MetaStatementStatus } from "./meta-sign.ts";
import { computeVariableKeyedDigest } from "./sorted-digest.ts";
import { isLowercaseHexOfLength } from "./validate.ts";

const SHA256_HEX_LENGTH = 32 * 2;

export interface EnvValuesDigestEntry {
  readonly variableId: VariableId;
  readonly version: number;
  readonly valueSigHashHex: string;
}

function valuesDigestEntryInvalidField(entry: EnvValuesDigestEntry): string | null {
  if (entry.variableId.length === 0) {
    return "entry variableId";
  }
  if (!Number.isSafeInteger(entry.version) || entry.version < 1) {
    return "entry version";
  }
  if (!isLowercaseHexOfLength(entry.valueSigHashHex, SHA256_HEX_LENGTH)) {
    return "entry valueSigHashHex";
  }
  return null;
}

export type EnvValuesDigestSource =
  | (EnvValuesDigestEntry & { readonly status: "active" })
  | {
      readonly variableId: VariableId;
      readonly status: Exclude<MetaStatementStatus, "active">;
    };

export function selectEnvValuesDigestEntries(
  variables: readonly EnvValuesDigestSource[],
): EnvValuesDigestEntry[] {
  return variables
    .filter(
      (variable): variable is EnvValuesDigestEntry & { readonly status: "active" } =>
        variable.status === "active",
    )
    .map((variable) => ({
      variableId: variable.variableId,
      version: variable.version,
      valueSigHashHex: variable.valueSigHashHex,
    }));
}

export async function computeEnvValuesDigest(
  suite: string,
  entries: readonly EnvValuesDigestEntry[],
): Promise<CryptoResult<string>> {
  return computeVariableKeyedDigest({
    suite,
    domain: "env-values-digest",
    entries,
    variableIdOf: (entry) => entry.variableId,
    entryInvalidField: valuesDigestEntryInvalidField,
    entryFields: (entry) => [entry.variableId, entry.version, entry.valueSigHashHex],
  });
}
