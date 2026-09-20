// チェーン追記の受理と同時に §3.4 のミラーイベントを記録する書き込みフェーズの
// 共有(汎用追記 = chain-do.ts / standalone checkpoint = checkpoint-accept.ts)。
// 単一の同期ブロック(= 同一イベントループタスク)でチェーン挿入・ミラー追記・
// 受理副作用(+ 経路固有の追加同期書き込み)を書き、クラッシュしても「チェーン
// だけ書けてミラーが欠ける」不整合を作らない(ミラーは v1 バックフィルなし —
// AUDIT_SPEC §3.4 — なので欠落は恒久化する)。serverTs は全検査後・書き込み
// フェーズ直前に取得する(複合経路と同じタイミング — chain-accept.ts の
// insertAcceptedEntrySync 参照)。

import type { ChainMirrorSubject } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { computeUserKeyFingerprint, decodeHex, encodeHex } from "@maruhi/crypto";
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
/** `add_device` の載せた端末 FP(CRYPTO_SPEC §3 — enc ‖ sig の SHA-256 先頭 16 バイト)。 */
const mirrorSubjectOf = (entry: ChainEntry): Effect.Effect<ChainMirrorSubject> =>
  Effect.gen(function* () {
    if (entry.op !== "add_device") {
      return {};
    }
    // verifyChain 通過済みの payload(hex 小文字 64)なので decode / 計算は成功する。
    // 失敗は検証器のバグ = defect(静かに FP 無しの行を作らない — K2-12 の契約)
    const enc = decodeHex(entry.payload.encPubHex);
    const sig = decodeHex(entry.payload.sigPubHex);
    if (enc === null || sig === null) {
      return yield* Effect.die(new Error("add_device payload keys are not valid hex"));
    }
    const fingerprint = yield* Effect.promise(() => computeUserKeyFingerprint(enc, sig));
    if (!fingerprint.ok) {
      return yield* Effect.die(new Error("add_device fingerprint computation failed"));
    }
    return { addedDeviceKeyFingerprintHex: encodeHex(fingerprint.value) };
  });

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
    // add_device のミラー行(AUDIT_SPEC §3.4)は載せた端末の FP を要する。SHA-256 は
    // 非同期なので同期の書き込みフェーズの前に受理側が計算して写像へ渡す
    // (設計録 dk-design.md §7 K2-12)
    const subject = yield* mirrorSubjectOf(entry);
    return yield* Effect.sync(() => {
      const appliedProposal = insertAcceptedEntrySync(
        { chainStore, audit, dataStore },
        entry,
        applied,
        canonicalBytes,
        nowMs,
        proposals,
        subject,
      );
      extraSync?.(nowMs);
      return appliedProposal;
    });
  });
