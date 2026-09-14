// packages/crypto/test-vectors/chain-entries.json のサーバーテスト向けビュー。
// ベクター JSON → 型付きエントリの変換は @maruhi/crypto/test-support の実装
// (テストベクターの正規変換)を再利用し、ここでは重複させない。
// crypto の型付きエントリ(camelCase)は api-schema のワイヤ形式と構造的に同一。

import type { ChainEntry } from "@maruhi/crypto";
import {
  toTypedEntry,
  vectorEntries,
  type VectorEntry,
  vectorExtendedChains,
  vectorNegatives,
} from "@maruhi/crypto/test-support";

export { vectorEntries, vectorExtendedChains };
export type { VectorEntry };

interface VectorAuthzNegative {
  readonly name: string;
  readonly entry: VectorEntry;
  readonly expected_reason: string;
  /** 前提チェーン(extended_chains のキー。無指定 = 正規チェーン)。 */
  readonly chain?: string;
}

/** 認可系 negative(完全なエントリを持ち、API 経由の追記拒否テストに再利用できる) */
export const vectorAuthzNegatives: readonly VectorAuthzNegative[] = vectorNegatives.flatMap(
  (negative) =>
    negative.kind === "authorization" &&
    negative.entry !== undefined &&
    negative.expected_reason !== undefined
      ? [
          {
            name: negative.name,
            entry: negative.entry,
            expected_reason: negative.expected_reason,
            ...(negative.chain === undefined ? {} : { chain: negative.chain }),
          },
        ]
      : [],
);

/** 四眼の 4 op(CRYPTO_SPEC §6.2 PF1) — サーバーは K5 まで受理しない。 */
export const FOUR_EYES_OPS: ReadonlySet<string> = new Set([
  "set_approval_policy",
  "propose",
  "approve",
  "withdraw",
]);

/** 正規チェーンで最初の四眼 op の seq(以降はサーバーで再生できない)。 */
export const firstFourEyesSeq: number = (() => {
  const first = vectorEntries.find((v) => FOUR_EYES_OPS.has(v.op));
  if (first === undefined) {
    throw new Error("chain vectors: no four-eyes entry in the canonical chain");
  }
  return first.seq;
})();

const fourEyesChains: ReadonlySet<string> = new Set(
  Object.entries(vectorExtendedChains).flatMap(([name, chain]) =>
    chain.base_seq >= firstFourEyesSeq || chain.entries.some((e) => FOUR_EYES_OPS.has(e.op))
      ? [name]
      : [],
  ),
);

/**
 * negative の**前提チェーン**がサーバーで再生できるか(四眼 op の受理を要しないか)。
 * negative 自身の op が四眼 op である場合は含めない(その場合は受理ガードで拒否される
 * ことを固定する)
 */
export function prefixReplayable(negative: {
  readonly entry: VectorEntry;
  readonly chain?: string;
}): boolean {
  if (negative.chain !== undefined) {
    return !fourEyesChains.has(negative.chain);
  }
  return negative.entry.seq - 1 < firstFourEyesSeq;
}

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
