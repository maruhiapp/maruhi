// CRYPTO_SPEC §6.2: a checkpoint's values_digest (the normalized form of an
// environment's value-level view).
//   values_digest_hex = lower_hex(SHA-256(LP("<suite>/env-values-digest", v_1, …, v_m)))
//   v_j = LP(variable_id, version, value_sig_hash_hex)
//     — **UTF-8 byte-ascending order** of variable_id. Only `active` variables
//     (tombstones are captured by the manifest side — §4.3 — and status =
//     declared [§4.2 layout v2, value not yet set] has no value and hence no
//     coordinates to notarize, so it is out of scope).
//     The empty set is also valid (an environment with zero variables = an
//     LP with zero elements. The boundary checkpoint at environment creation
//     — AUTH_SPEC §12-4).
// The encoding is §2.1 (numbers base-10 stringified, binaries lowercase hex
// strings).
// The skeleton (validate → reject duplicates → internal sort → nested LP) is
// the shared implementation in sorted-digest.ts, isomorphic to §4.3's
// variables_digest (manifest-sign.ts). Introducing layout v2's declared left
// the encoder unchanged — only the target-selection rule
// (selectEnvValuesDigestEntries) looks at status.
// Test vectors: the values_digests section of test-vectors/chain-entries.json
// (the LP normalized form) + test-vectors/checkpoint-digest.json (target selection)

import type { CryptoResult } from "./errors.ts";
import type { MetaStatementStatus } from "./meta-sign.ts";
import { computeVariableKeyedDigest } from "./sorted-digest.ts";
import { isLowercaseHexOfLength } from "./validate.ts";

const SHA256_HEX_LENGTH = 32 * 2;

/**
 * One entry of a checkpoint values digest (CRYPTO_SPEC §6.2): one active
 * variable's latest version and the SHA-256 (lowercase hex) of that
 * version's `value_signed_bytes` (§4.1).
 */
export interface EnvValuesDigestEntry {
  readonly variableId: string;
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

/**
 * One variable's value-level state as seen by a checkpoint issuer (CRYPTO_SPEC
 * §6.2 target selection): an `active` variable carries its latest value
 * coordinates; `declared` (§4.2 layout v2 — value not yet set) and `deleted`
 * variables have no value coordinates at all, so the type makes carrying them
 * unrepresentable.
 */
export type EnvValuesDigestSource =
  | (EnvValuesDigestEntry & { readonly status: "active" })
  | {
      readonly variableId: string;
      readonly status: Exclude<MetaStatementStatus, "active">;
    };

/**
 * Selects the values-digest subjects from a variable set with statement
 * statuses (CRYPTO_SPEC §6.2): only `active` variables appear. `declared`
 * variables (§4.2 layout v2) have no value to attest, and tombstones are
 * captured by the manifest side (§4.3). The digest encoder itself is
 * unchanged — this selection rule is the only status-aware step.
 * Test vectors: test-vectors/checkpoint-digest.json
 */
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

/**
 * Computes the canonical checkpoint values digest (CRYPTO_SPEC §6.2). The
 * canonical byte-ascending order is applied internally, duplicate variable
 * ids are rejected, and the empty set is valid (an environment with no
 * variables — the creation-composite boundary checkpoint).
 */
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
