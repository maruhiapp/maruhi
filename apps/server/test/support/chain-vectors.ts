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

/** 四眼の 4 op(CRYPTO_SPEC §6.2 PF1 — K5 からサーバーが受理する)。 */
const FOUR_EYES_OPS: ReadonlySet<string> = new Set([
  "set_approval_policy",
  "propose",
  "approve",
  "withdraw",
]);

/** 正規チェーンで最初の四眼 op の seq(seq 20 = set_approval_policy。方針オフのヘッドは直前)。 */
export const firstFourEyesSeq: number = (() => {
  const first = vectorEntries.find((v) => FOUR_EYES_OPS.has(v.op));
  if (first === undefined) {
    throw new Error("chain vectors: no four-eyes entry in the canonical chain");
  }
  return first.seq;
})();

/** 端末鍵の 2 op(CRYPTO_SPEC §6.2 — 2026-09-19 DK。K3 までサーバーは受理しない)。 */
export const DEVICE_OPS: ReadonlySet<string> = new Set(["add_device", "revoke_device"]);

/** 端末 op を含む派生チェーン(K3 まで API では再生できない — 前提チェーンが受理ガードに掛かる)。 */
const deviceChains: ReadonlySet<string> = new Set(
  Object.entries(vectorExtendedChains).flatMap(([name, chain]) =>
    chain.entries.some((entry) => DEVICE_OPS.has(entry.op)) ? [name] : [],
  ),
);

/**
 * negative の**前提チェーン**がサーバーで再生できるか(端末 op の受理を要しないか —
 * 正規チェーン seq 1〜24 に端末 op は無い)。negative 自身の op が端末 op の場合は
 * 前提を問わず受理ガードで拒否されることを別途固定する(K3 で受理ガードを外すときに
 * 本判定ごと外し、通常の 422 (expected_reason) 経路へ戻す — ES K2-10 / K5 の先例)
 */
export function prefixReplayable(negative: { readonly chain?: string }): boolean {
  return negative.chain === undefined || !deviceChains.has(negative.chain);
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
