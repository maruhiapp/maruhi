// Checks for the values_digest **subject selection** of CRYPTO_SPEC §6.2
// (declared of §4.2 layout v2): variables with status = declared (value not
// yet set) do not appear in values_digest. The LP canonical form itself is
// already pinned and invariant by the values_digests section of
// chain-entries.json (checkpoint.ts) — this file pins only the selection rule
// of selectEnvValuesDigestEntries via checkpoint-digest.json.

import type { EnvValuesDigestEntry, EnvValuesDigestSource } from "../../src/index.ts";
import { computeEnvValuesDigest, selectEnvValuesDigestEntries } from "../../src/index.ts";
import digestVectors from "../../test-vectors/checkpoint-digest.json" with { type: "json" };
import { type CheckResult, Checks } from "./support.ts";

interface VectorVariable {
  readonly variable_id: string;
  readonly status: string;
  readonly version?: string;
  readonly value_sig_hash_hex?: string;
}

interface VectorEntry {
  readonly variable_id: string;
  readonly version: string;
  readonly value_sig_hash_hex: string;
}

interface DigestCase {
  readonly name: string;
  readonly variables: readonly VectorVariable[];
  readonly values_digest_entries: readonly VectorEntry[];
  readonly values_digest_hex: string;
}

function sourceOf(variable: VectorVariable): EnvValuesDigestSource {
  return variable.status === "active"
    ? {
        variableId: variable.variable_id,
        status: "active",
        version: Number(variable.version),
        valueSigHashHex: variable.value_sig_hash_hex ?? "",
      }
    : {
        variableId: variable.variable_id,
        status: variable.status as "declared" | "deleted",
      };
}

function entryOf(entry: VectorEntry): EnvValuesDigestEntry {
  return {
    variableId: entry.variable_id,
    version: Number(entry.version),
    valueSigHashHex: entry.value_sig_hash_hex,
  };
}

export async function checkpointDigestChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  const cases = digestVectors.cases as readonly DigestCase[];
  for (const digestCase of cases) {
    // Selection: only active entries match the vector's expected entry set, value coordinates included
    const selected = selectEnvValuesDigestEntries(digestCase.variables.map(sourceOf));
    const expected = digestCase.values_digest_entries.map(entryOf);
    c.push(
      `checkpoint-digest ${digestCase.name}: selection keeps active entries only`,
      JSON.stringify(selected) === JSON.stringify(expected),
    );
    // The digest of the selection result matches the vector's expected value (the encoder is
    // invariant — it passes straight through the canonical form of chain-entries.json values_digests)
    const computed = await computeEnvValuesDigest("maruhi/v1", selected);
    c.push(
      `checkpoint-digest ${digestCase.name}: digest over selected entries`,
      computed.ok && computed.value === digestCase.values_digest_hex,
      computed.ok ? undefined : JSON.stringify(computed.error),
    );
  }
  // The digest of an environment with only declared variables equals the digest of the empty set (§6.2 —
  // the boundary form of "declared does not appear in values_digest")
  const allDeclared = cases.find((digestCase) => digestCase.name === "all-declared-empty");
  const emptySet = await computeEnvValuesDigest("maruhi/v1", []);
  c.push(
    "checkpoint-digest all-declared-empty: equals the empty-set digest",
    allDeclared !== undefined && emptySet.ok && emptySet.value === allDeclared.values_digest_hex,
  );
  return c.results;
}
