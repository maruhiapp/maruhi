// packages/crypto/test-vectors/chain-entries.json のサーバーテスト向けビュー。
// ベクター JSON → 型付きエントリの変換は packages/crypto/test/checks/chain-vector.ts
// の実装(テストベクターの正規変換)を再利用し、ここでは重複させない。
// crypto の型付きエントリ(camelCase)は api-schema のワイヤ形式と構造的に同一。

import type { ChainEntry } from "@maruhi/crypto";

import {
  toTypedEntry,
  vectorEntries,
  vectorNegatives,
  type VectorEntry,
} from "../../../../packages/crypto/test/checks/chain-vector.ts";

export { vectorEntries };
export type { VectorEntry };

interface VectorAuthzNegative {
  readonly name: string;
  readonly entry: VectorEntry;
  readonly expected_reason: string;
}

/** 認可系 negative(完全なエントリを持ち、API 経由の追記拒否テストに再利用できる) */
export const vectorAuthzNegatives: readonly VectorAuthzNegative[] = vectorNegatives.flatMap(
  (negative) =>
    negative.kind === "authorization" &&
    negative.entry !== undefined &&
    negative.expected_reason !== undefined
      ? [{ name: negative.name, entry: negative.entry, expected_reason: negative.expected_reason }]
      : [],
);

/** ベクターエントリを API ワイヤ形式(= crypto の ChainEntry)へ変換する */
export const toWireEntry = (vector: VectorEntry): ChainEntry => toTypedEntry(vector);

/** ベクターチェーンのプロジェクト ID = genesis エントリハッシュ(CRYPTO_SPEC §6.4) */
export const vectorProjectId = (() => {
  const genesis = vectorEntries[0];
  if (genesis === undefined) {
    throw new Error("chain vectors: missing genesis entry");
  }
  return genesis.entry_hash_hex;
})();
