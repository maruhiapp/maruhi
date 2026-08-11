// チェーンエントリ受理の共有実装(CRYPTO_SPEC §6.4)。
//
// 「正規化サイズ検査 → チェーン容量 → verifyChain 再実行 → insert + 監査ミラー」の
// 受理 4 手順は、汎用チェーン API(chain-do.ts の init / append)と複合リクエスト
// (composite-programs.ts の create / rotate)の全経路がここを通る。上限意味論の
// 修正が片側にしか当たらないズレを構造的に防ぐ。エラーは DataRejection で運び、
// 呼び出し側には outcome への畳み込みだけを残す(A-4 の写像一本化と対)。

import type { ChainInvalidError } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { Effect } from "effect";

import type { AuditEventInput } from "./audit-store.ts";
import { chainMirrorEvent } from "./audit-store.ts";
import type { StoredChain, VerifiedChainView } from "./chain-store.ts";
import { canonicalBytesOf, verifyChainEffect } from "./chain-store.ts";
import type { DataRejectedError } from "./data-plane.ts";
import { rejectData } from "./data-plane.ts";
import {
  MAX_CHAIN_ENTRIES,
  MAX_CHAIN_TOTAL_CANONICAL_BYTES,
  MAX_ENTRY_CANONICAL_BYTES,
} from "./policy.ts";

/** ChainInvalid(検証・エンコーダ失敗)→ chain-entry-invalid 拒否。 */
const rejectChainInvalid = (error: ChainInvalidError): DataRejectedError =>
  rejectData({ kind: "chain-entry-invalid", seq: error.seq, reason: error.reason });

/** §6.4: 1 エントリの正規化サイズ検査。通過したら正規化バイト数を返す。 */
function checkEntrySize(entry: ChainEntry): Effect.Effect<number, DataRejectedError> {
  return canonicalBytesOf(entry).pipe(
    Effect.mapError(rejectChainInvalid),
    Effect.flatMap((bytes) =>
      bytes > MAX_ENTRY_CANONICAL_BYTES
        ? Effect.fail(
            rejectData({ kind: "chain-entry-too-large", limitBytes: MAX_ENTRY_CANONICAL_BYTES }),
          )
        : Effect.succeed(bytes),
    ),
  );
}

/**
 * 受理ポリシー(§6.4): チェーン全体のエントリ数・累積バイト数の上限。
 * 判定は数値のみに依存する純関数(エントリ数上限のユニットテストのために公開。
 * 10,000 本の有効チェーンを統合テストで実生成するのは非現実的なため)。
 */
export function chainCapacityExceeded(
  entryCount: number,
  totalCanonicalBytes: number,
  addedCanonicalBytes: number,
): boolean {
  return (
    entryCount + 1 > MAX_CHAIN_ENTRIES ||
    totalCanonicalBytes + addedCanonicalBytes > MAX_CHAIN_TOTAL_CANONICAL_BYTES
  );
}

function ensureChainCapacity(
  chain: StoredChain,
  canonicalBytes: number,
): Effect.Effect<void, DataRejectedError> {
  if (chainCapacityExceeded(chain.entries.length, chain.totalCanonicalBytes, canonicalBytes)) {
    return Effect.fail(
      rejectData({
        kind: "chain-capacity-exceeded",
        maxEntries: MAX_CHAIN_ENTRIES,
        maxTotalBytes: MAX_CHAIN_TOTAL_CANONICAL_BYTES,
      }),
    );
  }
  return Effect.void;
}

/**
 * CAS(§6.4): 親ヘッドが現ヘッドと一致しなければ現ヘッド情報付きで拒否
 * (worker が 409 に写す)。未初期化の検査は呼び出し側の前段(loadChainForMember /
 * loadInitializedChain)が済ませている前提で、ここでは head の一致のみを見る。
 */
export function ensureParentHead(
  chain: { readonly headSeq: number; readonly headHashHex: string },
  parentHeadHashHex: string,
): Effect.Effect<void, DataRejectedError> {
  if (parentHeadHashHex !== chain.headHashHex) {
    return Effect.fail(
      rejectData({
        kind: "chain-head-conflict",
        currentHeadSeq: chain.headSeq,
        currentHeadHashHex: chain.headHashHex,
      }),
    );
  }
  return Effect.void;
}

/**
 * 受理検査(サイズ → 容量 → §6.4 の全チェーン再検証 = prev_hash 連続性・署名・
 * 合意規則)。受理される場合は正規化バイト数と「エントリ適用後の検証済み
 * ビュー」を返す(複合のラップ判定基準状態 — AUTH_SPEC §12-4 — と、受理後の
 * StateCache 更新の入力)。
 */
export const verifyAcceptableEntry = (
  chain: StoredChain,
  entry: ChainEntry,
): Effect.Effect<
  { readonly canonicalBytes: number; readonly applied: VerifiedChainView },
  DataRejectedError
> =>
  Effect.gen(function* () {
    const canonicalBytes = yield* checkEntrySize(entry);
    yield* ensureChainCapacity(chain, canonicalBytes);
    const applied = yield* verifyChainEffect([...chain.entries, entry]).pipe(
      Effect.mapError(rejectChainInvalid),
    );
    return { canonicalBytes, applied };
  });

/** insertAcceptedEntrySync が書き込みに使うストア面(構造的部分型)。 */
export interface ChainAcceptStores {
  readonly chainStore: {
    readonly insertSync: (entry: ChainEntry, entryHashHex: string, canonicalBytes: number) => void;
  };
  readonly audit: { readonly appendSync: (event: AuditEventInput) => void };
}

/**
 * 受理済みエントリの挿入 + §3.4 の監査ミラー(同期)。チェーン挿入とミラー追記を
 * 同一同期ブロック(= 同一タスク)で原子コミットするために、呼び出し側の
 * 書き込みフェーズ内から呼ぶ。serverTs(nowMs)は必ず引数で受け取り、取得
 * タイミング(全検査後・書き込みフェーズ直前)を全経路で統一する。
 */
export function insertAcceptedEntrySync(
  stores: ChainAcceptStores,
  entry: ChainEntry,
  applied: VerifiedChainView,
  canonicalBytes: number,
  nowMs: number,
): void {
  stores.chainStore.insertSync(entry, applied.state.headHashHex, canonicalBytes);
  stores.audit.appendSync(chainMirrorEvent(entry, nowMs));
}
