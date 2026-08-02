// プロジェクト DO 内のチェーン保存(ChainStore)と導出状態(ChainState)の共有部。
//
// chain-do.ts(チェーン API のプログラム)と data-programs.ts(データプレーン)の
// 両方が使う: 認可の真実源はチェーン導出の現メンバー集合であり(CRYPTO_SPEC §6.4)、
// データ操作もチェーン導出 role で認可する(§6.2、AUTH_SPEC §12-3)。
//
// テーブルの DDL は do-schema.ts(DO コンストラクタが適用済み)。

import { ChainInvalidError, toWrappedCryptoError } from "@maruhi/core";
import type { ChainEntry, ChainState } from "@maruhi/crypto";
import { canonicalChainEntryBytes, verifyChain } from "@maruhi/crypto";
import { Context, Effect, Layer } from "effect";

export interface StoredChain {
  readonly entries: readonly ChainEntry[];
  /** 0 = 未初期化 */
  readonly headSeq: number;
  readonly headHashHex: string | null;
  readonly totalCanonicalBytes: number;
}

interface ChainStoreShape {
  readonly load: Effect.Effect<StoredChain>;
  readonly insert: (
    entry: ChainEntry,
    entryHashHex: string,
    canonicalBytes: number,
  ) => Effect.Effect<void>;
}

export class ChainStore extends Context.Service<ChainStore, ChainStoreShape>()("ChainStore") {}

export const chainStoreLayer = (sql: SqlStorage): Layer.Layer<ChainStore> =>
  Layer.sync(ChainStore, () => ({
    load: Effect.sync(() => {
      const rows = sql
        .exec(
          "SELECT seq, entry_json, entry_hash_hex, canonical_bytes FROM chain_entries ORDER BY seq",
        )
        .toArray();
      const entries = rows.map((row) => JSON.parse(String(row["entry_json"])) as ChainEntry);
      const last = rows[rows.length - 1];
      let totalCanonicalBytes = 0;
      for (const row of rows) {
        totalCanonicalBytes += Number(row["canonical_bytes"]);
      }
      return {
        entries,
        headSeq: last === undefined ? 0 : Number(last["seq"]),
        headHashHex: last === undefined ? null : String(last["entry_hash_hex"]),
        totalCanonicalBytes,
      };
    }),
    insert: (entry, entryHashHex, canonicalBytes) =>
      Effect.sync(() => {
        sql.exec(
          "INSERT INTO chain_entries (seq, entry_json, entry_hash_hex, canonical_bytes) VALUES (?, ?, ?, ?)",
          entry.seq,
          JSON.stringify(entry),
          entryHashHex,
          canonicalBytes,
        );
      }),
  }));

/** verifyChain を Effect に持ち上げ、ChainInvalid 以外の(契約上起こらない)失敗は defect にする。 */
export function verifyChainEffect(
  entries: readonly ChainEntry[],
): Effect.Effect<ChainState, ChainInvalidError> {
  return Effect.flatMap(
    Effect.promise(() => verifyChain(entries)),
    (result) => {
      if (result.ok) {
        return Effect.succeed(result.value);
      }
      const wrapped = toWrappedCryptoError(result.error);
      // verifyChain は契約上 ChainInvalid しか返さない。それ以外は実装バグ
      return wrapped instanceof ChainInvalidError ? Effect.fail(wrapped) : Effect.die(wrapped);
    },
  );
}

/**
 * 正規化バイト列の長さ。Schema 検証済みエントリでは失敗しないが、エンコーダの
 * 例外は invalid-payload に封じ込める(DO を defect で落とさない)。
 */
export function canonicalBytesOf(entry: ChainEntry): Effect.Effect<number, ChainInvalidError> {
  return Effect.try({
    try: () => canonicalChainEntryBytes(entry).length,
    catch: () => new ChainInvalidError({ seq: entry.seq, reason: "invalid-payload" }),
  });
}

/**
 * チェーン導出状態のキャッシュ(DO インスタンスメモリ)。保存済みチェーンは
 * 受理時に検証済みなので、同一ヘッドへの再導出を省く(§6.2 の認可・§11-2 の
 * メンバーシップ判定を読み取りごとの O(n) 署名検証にしないため)。
 */
export interface StateCache {
  current: { readonly headHashHex: string; readonly state: ChainState } | null;
}

/**
 * キャッシュ更新は headSeq の単調ガード付き: permit を持たない読み取り
 * (snapshotFor / pull 系)の導出中に追記がコミットした場合、古い状態で新しい
 * キャッシュを上書きしない(チェーンは append-only なので headSeq 比較で十分)。
 */
export function updateStateCache(cache: StateCache, state: ChainState): void {
  if (cache.current === null || state.headSeq >= cache.current.state.headSeq) {
    cache.current = { headHashHex: state.headHashHex, state };
  }
}

/** 保存済みチェーンから ChainState を導出する。検証失敗は実装バグ(defect)。 */
export function deriveStoredState(
  chain: StoredChain,
  cache: StateCache,
): Effect.Effect<ChainState> {
  const cached = cache.current;
  if (cached !== null && cached.headHashHex === chain.headHashHex) {
    return Effect.succeed(cached.state);
  }
  return verifyChainEffect(chain.entries).pipe(
    Effect.orDie,
    Effect.tap((state) => Effect.sync(() => updateStateCache(cache, state))),
  );
}
