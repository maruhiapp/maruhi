import { ChainEntrySchema } from "@maruhi/api-schema";
import { ChainInvalidError, cryptoEffect } from "@maruhi/core";
import type { ChainEntry, ChainHistoryIndex, ChainState } from "@maruhi/crypto";
import { canonicalChainEntryBytes, verifyChainWithHistory } from "@maruhi/crypto";
import { Context, Effect, Layer, Result, Schema } from "effect";

import { catchCryptoErrors } from "../crypto-catch.ts";
import { projectDoInitialized } from "./do-schema.ts";

export interface StoredChain {
  readonly entries: readonly ChainEntry[];
  readonly headSeq: number;
  readonly headHashHex: string | null;
  readonly genesisHashHex: string | null;
  readonly totalCanonicalBytes: number;
}

interface ChainStoreShape {
  readonly load: Effect.Effect<StoredChain>;
  readonly insertSync: (entry: ChainEntry, entryHashHex: string, canonicalBytes: number) => void;
}

export class ChainStore extends Context.Service<ChainStore, ChainStoreShape>()("ChainStore") {}

interface LoadedRows {
  readonly entries: ChainEntry[];
  readonly hashes: string[];
  readonly lastSeq: number | null;
  readonly addedBytes: number;
}

function decodeStoredEntry(seq: number, entryJson: string): ChainEntry {
  const decoded = Schema.decodeUnknownResult(Schema.fromJsonString(ChainEntrySchema))(entryJson);
  if (Result.isFailure(decoded)) {
    throw new ChainInvalidError({ seq, reason: "invalid-payload" });
  }
  return decoded.success;
}

function loadRowsAfter(sql: SqlStorage, afterSeq: number): LoadedRows {
  const rows = sql
    .exec(
      "SELECT seq, entry_json, entry_hash_hex, canonical_bytes FROM chain_entries WHERE seq > ? ORDER BY seq",
      afterSeq,
    )
    .toArray();
  let addedBytes = 0;
  for (const row of rows) {
    addedBytes += Number(row["canonical_bytes"]);
  }
  const last = rows[rows.length - 1];
  return {
    entries: rows.map((row) => decodeStoredEntry(Number(row["seq"]), String(row["entry_json"]))),
    hashes: rows.map((row) => String(row["entry_hash_hex"])),
    lastSeq: last === undefined ? null : Number(last["seq"]),
    addedBytes,
  };
}

const EMPTY_CHAIN: StoredChain = {
  entries: [],
  headSeq: 0,
  headHashHex: null,
  genesisHashHex: null,
  totalCanonicalBytes: 0,
};

function mergeLoadedDiff(base: StoredChain, diff: LoadedRows): StoredChain {
  return {
    entries: [...base.entries, ...diff.entries],
    headSeq: diff.lastSeq ?? base.headSeq,
    headHashHex: diff.hashes[diff.hashes.length - 1] ?? base.headHashHex,
    genesisHashHex: base.genesisHashHex ?? diff.hashes[0] ?? null,
    totalCanonicalBytes: base.totalCanonicalBytes + diff.addedBytes,
  };
}

function loadChain(sql: SqlStorage, cache: StateCache): StoredChain {
  if (cache.chain === null && !projectDoInitialized(sql)) {
    return EMPTY_CHAIN;
  }
  const base = cache.chain ?? EMPTY_CHAIN;
  const diff = loadRowsAfter(sql, base.headSeq);
  if (diff.entries.length === 0 && cache.chain !== null) {
    return base;
  }
  const chain = mergeLoadedDiff(base, diff);
  cache.chain = chain;
  return chain;
}

export const chainStoreLayer = (sql: SqlStorage, cache: StateCache): Layer.Layer<ChainStore> =>
  Layer.sync(ChainStore, () => ({
    load: Effect.sync(() => loadChain(sql, cache)),
    insertSync: (entry, entryHashHex, canonicalBytes) => {
      sql.exec(
        "INSERT INTO chain_entries (seq, entry_json, entry_hash_hex, canonical_bytes) VALUES (?, ?, ?, ?)",
        entry.seq,
        JSON.stringify(entry),
        entryHashHex,
        canonicalBytes,
      );
      const cached = cache.chain;
      cache.chain =
        cached !== null && entry.seq === cached.headSeq + 1
          ? {
              entries: [...cached.entries, entry],
              headSeq: entry.seq,
              headHashHex: entryHashHex,
              genesisHashHex: cached.genesisHashHex ?? entryHashHex,
              totalCanonicalBytes: cached.totalCanonicalBytes + canonicalBytes,
            }
          : null;
    },
  }));

export interface VerifiedChainView {
  readonly state: ChainState;
  readonly history: ChainHistoryIndex;
}

export function verifyChainEffect(
  entries: readonly ChainEntry[],
): Effect.Effect<VerifiedChainView, ChainInvalidError> {
  return catchCryptoErrors(
    cryptoEffect(() => verifyChainWithHistory(entries)),
    {
      ChainInvalid: (error) => Effect.fail(error),
      CryptoInvalidInput: "die",
      CryptoKeyImport: "die",
      CryptoKeyExport: "die",
      CryptoEncrypt: "die",
      CryptoDecrypt: "die",
      CryptoDekWrap: "die",
      CryptoDekUnwrap: "die",
      CryptoSign: "die",
      CryptoDekWrapSignature: "die",
      CryptoInviteAcceptSignature: "die",
      CryptoInviteLinkSignature: "die",
      CryptoInviteIssueSignature: "die",
      CryptoDekCommitment: "die",
      CryptoValueInvalid: "die",
      CryptoMetaStatementInvalid: "die",
      CryptoUnsupportedMetaLayout: "die",
      CryptoEnvManifestInvalid: "die",
      CryptoHeadAttestationInvalid: "die",
    },
  );
}

export function canonicalBytesOf(entry: ChainEntry): Effect.Effect<number, ChainInvalidError> {
  return Effect.try({
    try: () => canonicalChainEntryBytes(entry).length,
    catch: () => new ChainInvalidError({ seq: entry.seq, reason: "invalid-payload" }),
  });
}

export interface StateCache {
  current: { readonly headHashHex: string; readonly verified: VerifiedChainView } | null;
  chain: StoredChain | null;
}

export function updateStateCache(cache: StateCache, verified: VerifiedChainView): void {
  if (cache.current === null || verified.state.headSeq >= cache.current.verified.state.headSeq) {
    cache.current = { headHashHex: verified.state.headHashHex, verified };
  }
}

export function deriveStoredState(
  chain: StoredChain,
  cache: StateCache,
): Effect.Effect<VerifiedChainView> {
  const cached = cache.current;
  if (cached !== null && cached.headHashHex === chain.headHashHex) {
    return Effect.succeed(cached.verified);
  }
  return verifyChainEffect(chain.entries).pipe(
    Effect.orDie,
    Effect.tap((verified) => Effect.sync(() => updateStateCache(cache, verified))),
  );
}
