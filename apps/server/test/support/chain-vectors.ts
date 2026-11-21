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
  readonly chain?: string;
}

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

const FOUR_EYES_OPS: ReadonlySet<string> = new Set([
  "set_approval_policy",
  "propose",
  "approve",
  "withdraw",
]);

export const firstFourEyesSeq: number = (() => {
  const first = vectorEntries.find((v) => FOUR_EYES_OPS.has(v.op));
  if (first === undefined) {
    throw new Error("chain vectors: no four-eyes entry in the canonical chain");
  }
  return first.seq;
})();

export const toWireEntry = (vector: VectorEntry): ChainEntry => toTypedEntry(vector);

export const vectorProjectId = (() => {
  const genesis = vectorEntries[0];
  if (genesis === undefined) {
    throw new Error("chain vectors: missing genesis entry");
  }
  return genesis.entry_hash_hex;
})();
