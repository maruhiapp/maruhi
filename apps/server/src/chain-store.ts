// プロジェクト DO 内のチェーン保存(ChainStore)と導出状態(ChainState)の共有部。
//
// chain-do.ts(チェーン API のプログラム)と data-programs.ts(データプレーン)の
// 両方が使う: 認可の真実源はチェーン導出の現メンバー集合であり(CRYPTO_SPEC §6.4)、
// データ操作もチェーン導出 role で認可する(§6.2、AUTH_SPEC §12-3)。
//
// テーブルの DDL は do-schema.ts(DO コンストラクタが適用済み)。

import { ChainInvalidError, toWrappedCryptoError } from "@maruhi/core";
import type { ChainEntry, ChainHistoryIndex, ChainState } from "@maruhi/crypto";
import { canonicalChainEntryBytes, verifyChainWithHistory } from "@maruhi/crypto";
import { Context, Effect, Layer } from "effect";

export interface StoredChain {
  readonly entries: readonly ChainEntry[];
  /** 0 = 未初期化 */
  readonly headSeq: number;
  readonly headHashHex: string | null;
  /** genesis エントリのハッシュ = プロジェクト ID(CRYPTO_SPEC §6.4)。未初期化なら null */
  readonly genesisHashHex: string | null;
  readonly totalCanonicalBytes: number;
}

interface ChainStoreShape {
  readonly load: Effect.Effect<StoredChain>;
  /**
   * 同期挿入。監査ミラーの追記(audit-store.ts)と同じ同期ブロックで呼び、
   * チェーン挿入とミラーを同一タスクで原子コミットする(AUDIT_SPEC §5.1 の
   * 「同一トランザクションで書ける」配置根拠を実装で保証する)。
   */
  readonly insertSync: (entry: ChainEntry, entryHashHex: string, canonicalBytes: number) => void;
}

export class ChainStore extends Context.Service<ChainStore, ChainStoreShape>()("ChainStore") {}

/**
 * 差分ロード(キャッシュ済みヘッドより後の行のみ)。afterSeq = 0 はフルロード。
 * チェーンは append-only(削除・更新の口がない — insertSync のみ)なので、
 * キャッシュ済み接頭辞 + `seq > afterSeq` の連結はフルロードと同一結果になる。
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

function loadChain(sql: SqlStorage, cache: StateCache): StoredChain {
  const cached = cache.chain;
  if (cached === null) {
    // キャッシュ無効(DO 再起動直後など)はフルロードして張り直す
    const loaded = loadRowsAfter(sql, 0);
    const chain: StoredChain = {
      entries: loaded.entries,
      headSeq: loaded.lastSeq ?? 0,
      headHashHex: loaded.hashes[loaded.hashes.length - 1] ?? null,
      genesisHashHex: loaded.hashes[0] ?? null,
      totalCanonicalBytes: loaded.addedBytes,
    };
    cache.chain = chain;
    return chain;
  }
  const diff = loadRowsAfter(sql, cached.headSeq);
  if (diff.entries.length === 0) {
    return cached;
  }
  const chain: StoredChain = {
    entries: [...cached.entries, ...diff.entries],
    headSeq: diff.lastSeq ?? cached.headSeq,
    headHashHex: diff.hashes[diff.hashes.length - 1] ?? cached.headHashHex,
    genesisHashHex: cached.genesisHashHex ?? diff.hashes[0] ?? null,
    totalCanonicalBytes: cached.totalCanonicalBytes + diff.addedBytes,
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
      // 受理済み追記のキャッシュへの増分反映。キャッシュと不連続な挿入は
      // 起こらない想定(全経路が load → 検証 → insertSync の直列)だが、万一の
      // 場合は無効化してフルロードに戻す(古い状態を配らない防御線)
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
 * 検証済みチェーンの導出状態と履歴索引の対(CRYPTO_SPEC §6.3 / §4.1)。
 * 履歴索引は値署名の「宣言ヘッド時点」検証の入力で、検証ループと同時に構築
 * されるため(verifyChainWithHistory)、未検証チェーンの索引は存在しない。
 */
export interface VerifiedChainView {
  readonly state: ChainState;
  readonly history: ChainHistoryIndex;
}

/** verifyChainWithHistory を Effect に持ち上げ、ChainInvalid 以外の(契約上起こらない)失敗は defect にする。 */
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
 * チェーン導出状態 + 履歴索引のキャッシュ(DO インスタンスメモリ)。保存済み
 * チェーンは受理時に検証済みなので、同一ヘッドへの再導出を省く(§6.2 の認可・
 * §11-2 のメンバーシップ判定・値署名の宣言ヘッド時点検証 — §12-8 — を
 * 読み取りごとの O(n) 署名検証にしないため)。
 *
 * chain は parse 済みチェーンのキャッシュ: ロード SQL を `seq > headSeq` の
 * 差分に限定し、全操作前段の「全行 SELECT + JSON.parse」を省く(ホットパス
 * 最適化)。チェーンは append-only なので差分連結 = フルロードと同一結果。
 * null はキャッシュ無効(DO 再起動直後など)で、次のロードがフルロードで張り直す。
 */
export interface StateCache {
  current: { readonly headHashHex: string; readonly verified: VerifiedChainView } | null;
  chain: StoredChain | null;
}

/**
 * キャッシュ更新は headSeq の単調ガード付き(チェーンは append-only なので
 * headSeq 比較で十分)。全操作が permit 下で直列化された現在は実質的に到達しない
 * 防御線だが、permit 外の導出経路が将来増えても古い状態で上書きしないよう残す。
 */
export function updateStateCache(cache: StateCache, verified: VerifiedChainView): void {
  if (cache.current === null || verified.state.headSeq >= cache.current.verified.state.headSeq) {
    cache.current = { headHashHex: verified.state.headHashHex, verified };
  }
}

/** 保存済みチェーンから検証済みビュー(状態 + 履歴索引)を導出する。検証失敗は実装バグ(defect)。 */
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
