// チェーン追記の受理と同時に §3.4 のミラーイベントを記録する書き込みフェーズの
// 共有(汎用追記 = chain-do.ts / standalone checkpoint = checkpoint-accept.ts)。
// 単一の同期ブロック(= 同一イベントループタスク)でチェーン挿入・ミラー追記・
// 受理副作用(+ 経路固有の追加同期書き込み)を書き、クラッシュしても「チェーン
// だけ書けてミラーが欠ける」不整合を作らない(ミラーは v1 バックフィルなし —
// AUDIT_SPEC §3.4 — なので欠落は恒久化する)。serverTs は全検査後・書き込み
// フェーズ直前に取得する(複合経路と同じタイミング — chain-accept.ts の
// insertAcceptedEntrySync 参照)。

import type { ChainEntry } from "@maruhi/crypto";
import { Effect } from "effect";

import { AuditStore } from "./audit-store.ts";
import type { AppliedProposal } from "./chain-accept.ts";
import { insertAcceptedEntrySync, proposalIndexOf } from "./chain-accept.ts";
import type { StoredChain, VerifiedChainView } from "./chain-store.ts";
import { ChainStore } from "./chain-store.ts";
import { DataStore } from "./data-store.ts";

/**
 * 受理済みエントリの原子コミット。`chain` は受理前の保存チェーン(受理済み
 * エントリを足した列が §3.4 の提案索引の入力 — chain-accept.ts)。`extraSync` は
 * 同じ同期ブロック内で追加の書き込み(standalone checkpoint のスナップショット
 * 保存 — §6.4)を行う口で、serverTs(nowMs)を共有する。戻り値は完成した approve が
 * 適用した提案(それ以外は null)。
 */
export const commitAcceptedEntry = (
  chain: StoredChain,
  entry: ChainEntry,
  applied: VerifiedChainView,
  canonicalBytes: number,
  extraSync?: (nowMs: number) => void,
): Effect.Effect<AppliedProposal | null, never, ChainStore | AuditStore | DataStore> =>
  Effect.gen(function* () {
    const chainStore = yield* ChainStore;
    const audit = yield* AuditStore;
    // 受理副作用(chain-accept.ts): add_member の旧鍵ラップ掃除がラップ行を
    // 削除するため、汎用チェーン受理もデータストアの書き込み面を渡す
    const dataStore = yield* DataStore;
    const nowMs = Date.now();
    const proposals = proposalIndexOf([...chain.entries, entry], applied);
    return yield* Effect.sync(() => {
      const appliedProposal = insertAcceptedEntrySync(
        { chainStore, audit, dataStore },
        entry,
        applied,
        canonicalBytes,
        nowMs,
        proposals,
      );
      extraSync?.(nowMs);
      return appliedProposal;
    });
  });
