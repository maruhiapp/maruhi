// Shared parts of the project DO's chain storage (ChainStore) and derived
// state (ChainState).
//
// Used by both chain-do.ts (the chain API's programs) and the data-plane
// programs (programs-environment.ts / programs-variable.ts /
// programs-dek.ts): the authorization source of truth is the chain-derived
// current member set (CRYPTO_SPEC §6.4), and data operations are also
// authorized by the chain-derived role (§6.2, AUTH_SPEC §12-3).
//
// The tables' DDL lives in do-schema.ts (applied by the DO constructor).

import { ChainInvalidError, toWrappedCryptoError } from "@maruhi/core";
import type { ChainEntry, ChainHistoryIndex, ChainState } from "@maruhi/crypto";
import { canonicalChainEntryBytes, verifyChainWithHistory } from "@maruhi/crypto";
import { Context, Effect, Layer } from "effect";

export interface StoredChain {
  readonly entries: readonly ChainEntry[];
  /** 0 = uninitialized */
  readonly headSeq: number;
  readonly headHashHex: string | null;
  /** Hash of the genesis entry = the project ID (CRYPTO_SPEC §6.4). null when uninitialized */
  readonly genesisHashHex: string | null;
  readonly totalCanonicalBytes: number;
}

interface ChainStoreShape {
  readonly load: Effect.Effect<StoredChain>;
  /**
   * Synchronous insert. Called in the same synchronous block as the audit
   * mirror's append (audit-store.ts) so the chain insert and the mirror
   * commit atomically in one task (implements the placement rationale of
   * AUDIT_SPEC §5.1's "writable in the same transaction").
   */
  readonly insertSync: (entry: ChainEntry, entryHashHex: string, canonicalBytes: number) => void;
}

export class ChainStore extends Context.Service<ChainStore, ChainStoreShape>()("ChainStore") {}

/**
 * Differential load (only rows after the cached head). afterSeq = 0 means
 * a full load. Because the chain is append-only (no delete or update
 * surface — insertSync only), concatenating the cached prefix with
 * `seq > afterSeq` yields the same result as a full load.
 */
interface LoadedRows {
  readonly entries: ChainEntry[];
  readonly hashes: string[];
  readonly lastSeq: number | null;
  readonly addedBytes: number;
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
    entries: rows.map((row) => JSON.parse(String(row["entry_json"])) as ChainEntry),
    hashes: rows.map((row) => String(row["entry_hash_hex"])),
    lastSeq: last === undefined ? null : Number(last["seq"]),
    addedBytes,
  };
}

/** The empty chain (the base of a differential load when the cache is invalid = a full load). */
const EMPTY_CHAIN: StoredChain = {
  entries: [],
  headSeq: 0,
  headHashHex: null,
  genesisHashHex: null,
  totalCanonicalBytes: 0,
};

function loadChain(sql: SqlStorage, cache: StateCache): StoredChain {
  // An invalid cache (e.g. right after a DO restart) makes the differential load off the empty base = a full load
  const base = cache.chain ?? EMPTY_CHAIN;
  const diff = loadRowsAfter(sql, base.headSeq);
  if (diff.entries.length === 0 && cache.chain !== null) {
    return base;
  }
  const chain: StoredChain = {
    entries: [...base.entries, ...diff.entries],
    headSeq: diff.lastSeq ?? base.headSeq,
    headHashHex: diff.hashes[diff.hashes.length - 1] ?? base.headHashHex,
    genesisHashHex: base.genesisHashHex ?? diff.hashes[0] ?? null,
    totalCanonicalBytes: base.totalCanonicalBytes + diff.addedBytes,
  };
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
      // Incremental reflection of an accepted append into the cache. An
      // insert discontinuous with the cache is not expected (every path is
      // serialized load → verify → insertSync), but should it happen the
      // cache is invalidated back to a full load (a defensive line against
      // serving stale state)
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

/**
 * The pair of a verified chain's derived state and history index
 * (CRYPTO_SPEC §6.3 / §4.1). The history index is the input to the value
 * signature's "at the declared head" verification and is built alongside
 * the verification loop (verifyChainWithHistory), so no index exists for
 * an unverified chain.
 */
export interface VerifiedChainView {
  readonly state: ChainState;
  readonly history: ChainHistoryIndex;
}

/** Lifts verifyChainWithHistory into Effect; failures other than ChainInvalid (contractually impossible) become defects. */
export function verifyChainEffect(
  entries: readonly ChainEntry[],
): Effect.Effect<VerifiedChainView, ChainInvalidError> {
  return Effect.flatMap(
    Effect.promise(() => verifyChainWithHistory(entries)),
    (result) => {
      if (result.ok) {
        return Effect.succeed(result.value);
      }
      const wrapped = toWrappedCryptoError(result.error);
      // verifyChain contractually returns only ChainInvalid; anything else is an implementation bug
      return wrapped instanceof ChainInvalidError ? Effect.fail(wrapped) : Effect.die(wrapped);
    },
  );
}

/**
 * The length of the canonical byte string. Cannot fail on a
 * Schema-validated entry, but an encoder exception is confined to
 * invalid-payload (does not take the DO down with a defect).
 */
export function canonicalBytesOf(entry: ChainEntry): Effect.Effect<number, ChainInvalidError> {
  return Effect.try({
    try: () => canonicalChainEntryBytes(entry).length,
    catch: () => new ChainInvalidError({ seq: entry.seq, reason: "invalid-payload" }),
  });
}

/**
 * Cache of the chain-derived state + history index (DO instance memory).
 * A stored chain was already verified at acceptance, so re-deriving for
 * the same head is skipped (so that §6.2 authorization, §11-2 membership
 * checks, and the value signature's declared-head-time verification —
 * §12-8 — do not become a per-read O(n) signature verification).
 *
 * chain is a cache of the parsed chain: it bounds the load SQL to the
 * `seq > headSeq` diff and skips the "SELECT all rows + JSON.parse" that
 * would otherwise precede every operation (hot-path optimization). The
 * chain is append-only, so a diff concat = a full load. null means the
 * cache is invalid (e.g. right after a DO restart) and the next load
 * rebuilds it with a full load.
 */
export interface StateCache {
  current: { readonly headHashHex: string; readonly verified: VerifiedChainView } | null;
  chain: StoredChain | null;
}

/**
 * Cache updates carry a monotonic guard on headSeq (the chain is
 * append-only, so a headSeq comparison suffices). With every operation
 * serialized under the permit this defensive line is effectively
 * unreachable today, but it is kept so that a future derivation path
 * outside the permit cannot overwrite with stale state.
 */
export function updateStateCache(cache: StateCache, verified: VerifiedChainView): void {
  if (cache.current === null || verified.state.headSeq >= cache.current.verified.state.headSeq) {
    cache.current = { headHashHex: verified.state.headHashHex, verified };
  }
}

/** Derives the verified view (state + history index) from a stored chain. Verification failure is an implementation bug (defect). */
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
