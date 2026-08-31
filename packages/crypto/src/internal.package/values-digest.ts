// CRYPTO_SPEC §6.2: checkpoint の values_digest(環境の値レベルビューの正規形)。
//   values_digest_hex = lower_hex(SHA-256(LP("<suite>/env-values-digest", v_1, …, v_m)))
//   v_j = LP(variable_id, version, value_sig_hash_hex)
//     — variable_id の **UTF-8 バイト昇順**。active 変数のみ(tombstone は
//     マニフェスト側 — §4.3 — が捕捉し、status = declared〔§4.2 レイアウト v2・
//     値未設定〕は値が存在せず公証する座標がないため対象外 — 2026-08-30)。
//     空集合も有効(変数ゼロの環境 = 要素ゼロの LP。環境作成の境界
//     チェックポイント — AUTH_SPEC §12-4)。
// エンコーディングは §2.1(数値は 10 進文字列化、バイナリは hex 小文字文字列)。
// 骨格(検証 → 重複拒否 → 内部ソート → 入れ子 LP)は sorted-digest.ts の共有
// 実装で、§4.3 の variables_digest(manifest-sign.ts)と同型。レイアウト v2 の
// declared 導入でエンコーダは不変 — 対象選別(selectEnvValuesDigestEntries)の
// 規則だけが status を見る。
// テストベクター: test-vectors/chain-entries.json の values_digests セクション
// (LP 正規形)+ test-vectors/checkpoint-digest.json(対象選別)

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
 * §6.2 対象選別): an `active` variable carries its latest value coordinates;
 * `declared` (§4.2 layout v2 — 値未設定) and `deleted` variables have no value
 * coordinates at all, so the type makes carrying them unrepresentable.
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
 * テストベクター: test-vectors/checkpoint-digest.json
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
