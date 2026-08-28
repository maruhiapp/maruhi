// 「variable_id バイト昇順・入れ子 LP・ドメイン分離」ダイジェストの共有骨格。
// CRYPTO_SPEC §4.3 の variables_digest(マニフェスト — manifest-sign.ts)と
// §6.2 の values_digest(checkpoint — values-digest.ts)は同型の正規形を持つ:
//   digest_hex = lower_hex(SHA-256(LP("<suite>/<domain>", entry_1, …, entry_n)))
//   entry_i = LP(エントリ固有のフィールド列)、variable_id の UTF-8 バイト昇順。
// 骨格(検証 → 重複拒否 → 内部ソート → 入れ子 LP → SHA-256)をここに 1 実装だけ
// 置き、フィールド列と検証規則だけを呼び出し側が与える(正規形実装の重複を
// 作らない — CLAUDE.md の「1 実装のみ」の規律)。

import { encodeHex, utf8Encode } from "./bytes.ts";
import { encodeLengthPrefixed, type LengthPrefixedField } from "./encoding.ts";
import type { CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { invalidInput } from "./validate.ts";

/** UTF-8 バイト列としての辞書順比較(ロケール・大文字小文字非依存の正規順)。 */
function compareUtf8Bytes(a: string, b: string): number {
  const bytesA = utf8Encode(a);
  const bytesB = utf8Encode(b);
  const length = Math.min(bytesA.length, bytesB.length);
  for (let i = 0; i < length; i += 1) {
    const delta = (bytesA[i] ?? 0) - (bytesB[i] ?? 0);
    if (delta !== 0) {
      return delta;
    }
  }
  return bytesA.length - bytesB.length;
}

/**
 * Computes one canonical variable-keyed digest: entries are validated, then
 * sorted by variable id byte-ascending **inside this function** — the
 * canonical order is part of each digest's definition, so callers cannot
 * produce a non-canonical digest through this API. Duplicate variable ids
 * are a caller bug (one latest entry per variable) and are rejected. The
 * empty set is valid.
 */
export async function computeVariableKeyedDigest<Entry>(spec: {
  readonly suite: string;
  /** Domain suffix after the suite (e.g. `env-manifest-vars`). */
  readonly domain: string;
  readonly entries: readonly Entry[];
  readonly variableIdOf: (entry: Entry) => string;
  /** Per-entry structural validation: the invalid field name, or null. */
  readonly entryInvalidField: (entry: Entry) => string | null;
  /** The entry's canonical LP field order (fixed by the test vectors). */
  readonly entryFields: (entry: Entry) => readonly LengthPrefixedField[];
}): Promise<CryptoResult<string>> {
  if (spec.suite.length === 0) {
    return invalidInput("suite");
  }
  const seen = new Set<string>();
  for (const entry of spec.entries) {
    const field = spec.entryInvalidField(entry);
    if (field !== null) {
      return invalidInput(field);
    }
    const variableId = spec.variableIdOf(entry);
    if (seen.has(variableId)) {
      return invalidInput("entry variableId (duplicate)");
    }
    seen.add(variableId);
  }
  const ordered = spec.entries.toSorted((a, b) =>
    compareUtf8Bytes(spec.variableIdOf(a), spec.variableIdOf(b)),
  );
  const fields: LengthPrefixedField[] = [`${spec.suite}/${spec.domain}`];
  for (const entry of ordered) {
    fields.push(encodeLengthPrefixed(spec.entryFields(entry)));
  }
  return { ok: true, value: encodeHex(await sha256(encodeLengthPrefixed(fields))) };
}
