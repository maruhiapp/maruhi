// A server-test view over packages/crypto/test-vectors/chain-entries.json.
// The vector JSON -> typed entry conversion reuses the implementation in
// @maruhi/crypto/test-support (the canonical conversion for test vectors)
// rather than duplicating it here.
// crypto's typed entries (camelCase) are structurally identical to the
// api-schema wire form.

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
  /** Prerequisite chain (key into extended_chains; unset = the canonical
   * chain). */
  readonly chain?: string;
}

/** Authorization negatives (carry a complete entry; reusable for
 * API-driven append-rejection tests). */
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

/** The 4 four-eyes ops (CRYPTO_SPEC §6.2 PF1 — accepted by the server since
 * K5). */
const FOUR_EYES_OPS: ReadonlySet<string> = new Set([
  "set_approval_policy",
  "propose",
  "approve",
  "withdraw",
]);

/** Seq of the first four-eyes op in the canonical chain (seq 20 =
 * set_approval_policy; the policy-off head is the one right before). */
export const firstFourEyesSeq: number = (() => {
  const first = vectorEntries.find((v) => FOUR_EYES_OPS.has(v.op));
  if (first === undefined) {
    throw new Error("chain vectors: no four-eyes entry in the canonical chain");
  }
  return first.seq;
})();

/** Converts a vector entry to the API wire form (= crypto's ChainEntry) */
export const toWireEntry = (vector: VectorEntry): ChainEntry => toTypedEntry(vector);

/** The vector chain's project ID = genesis entry hash (CRYPTO_SPEC §6.4) */
export const vectorProjectId = (() => {
  const genesis = vectorEntries[0];
  if (genesis === undefined) {
    throw new Error("chain vectors: missing genesis entry");
  }
  return genesis.entry_hash_hex;
})();
