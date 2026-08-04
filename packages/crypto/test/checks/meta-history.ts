// metadata-signature.json の tenure_extension(正規 12 エントリ + seq 13 の
// 新鍵 re-add)から派生チェーンの検証済み履歴索引を作る。value-signature.json の
// tenure_extension と同一内容だが、メタベクターの自己完結性のために自ファイルの
// エントリから構築する(将来 2 ファイルが乖離しても検査対象がずれない)。

import type { ChainHistoryIndex } from "../../src/index.ts";
import { verifyChainWithHistory } from "../../src/index.ts";
import metaVectors from "../../test-vectors/metadata-signature.json" with { type: "json" };
import { toTypedEntry, typedEntries } from "./chain-vector.ts";

/** 正規 12 エントリ + メタベクターの seq 13 re-add の派生チェーンの履歴索引。 */
export async function metaExtendedHistory(): Promise<ChainHistoryIndex> {
  const raw = metaVectors.tenure_extension.entry;
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
    throw new Error("metadata tenure-extension chain failed verification");
  }
  return result.value.history;
}
