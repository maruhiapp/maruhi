// CRYPTO_SPEC §6.2 の values_digest **対象選別**のチェック(2026-08-30 —
// §4.2 レイアウト v2 の declared 導入): status = declared(値未設定)の変数は
// values_digest に現れない。LP 正規形そのものは chain-entries.json の
// values_digests セクション(checkpoint.ts)が固定済みで不変 — 本ファイルは
// selectEnvValuesDigestEntries の選別規則だけを checkpoint-digest.json で固定する。

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
    // 選別: active のみが、値座標ごとベクターの期待エントリ集合と一致する
    const selected = selectEnvValuesDigestEntries(digestCase.variables.map(sourceOf));
    const expected = digestCase.values_digest_entries.map(entryOf);
    c.push(
      `checkpoint-digest ${digestCase.name}: selection keeps active entries only`,
      JSON.stringify(selected) === JSON.stringify(expected),
    );
    // 選別結果のダイジェストがベクターの期待値と一致する(エンコーダは不変 —
    // chain-entries.json values_digests の正規形をそのまま通る)
    const computed = await computeEnvValuesDigest("maruhi/v1", selected);
    c.push(
      `checkpoint-digest ${digestCase.name}: digest over selected entries`,
      computed.ok && computed.value === digestCase.values_digest_hex,
      computed.ok ? undefined : JSON.stringify(computed.error),
    );
  }
  // declared のみの環境のダイジェストは空集合のダイジェストと同値(§6.2 —
  // 「declared は values_digest に現れない」の境界形)
  const allDeclared = cases.find((digestCase) => digestCase.name === "all-declared-empty");
  const emptySet = await computeEnvValuesDigest("maruhi/v1", []);
  c.push(
    "checkpoint-digest all-declared-empty: equals the empty-set digest",
    allDeclared !== undefined && emptySet.ok && emptySet.value === allDeclared.values_digest_hex,
  );
  return c.results;
}
