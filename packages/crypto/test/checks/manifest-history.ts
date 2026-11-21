import type { ChainHistoryIndex } from "../../src/index.ts";
import { verifyChainWithHistory } from "../../src/index.ts";
import manifestVectors from "../../test-vectors/env-manifest.json" with { type: "json" };
import { toTypedEntry, typedEntries } from "./chain-vector.ts";

export async function manifestExtendedHistory(): Promise<ChainHistoryIndex> {
  const raw = manifestVectors.tenure_extension.entry;
  const entry = toTypedEntry({
    seq: raw.seq,
    suite: raw.suite,
    prev_hash_hex: raw.prev_hash_hex,
    op: raw.op,
    actor: raw.actor,
    payload: raw.payload,
    timestamp_ms: raw.timestamp_ms,
    payload_bytes_hex: raw.payload_bytes_hex,
    signed_bytes_hex: raw.signed_bytes_hex,
    signature_hex: raw.signature_hex,
    entry_bytes_hex: raw.entry_bytes_hex,
    entry_hash_hex: raw.entry_hash_hex,
  });
  const result = await verifyChainWithHistory([...typedEntries, entry]);
  if (!result.ok) {
    throw new Error("env-manifest tenure-extension chain failed verification");
  }
  return result.value.history;
}
