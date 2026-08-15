// DEK ラップの登録・配布・修復の Effect プログラム(AUTH_SPEC §12-6)。
//
// 受理検証の本体(受信者・集合・登録署名・行数上限)は dek-wraps.ts。
// permit 直列化の前提は旧 data-programs.ts のとおり。

import { Effect } from "effect";

import { AuditStore } from "./audit-store.ts";
import type { StateCache } from "./chain-store.ts";
import type { DataActor, DekWrapInput, DekWrapRefInput } from "./data-plane.ts";
import { currentEpochOf, dataEvent, rejectData, requireMemberState } from "./data-plane.ts";
import { DataStore } from "./data-store.ts";
import {
  checkWrapRequestCount,
  dekRegisteredEvent,
  ensureWrapSetAcceptable,
  wrapRecipientClass,
  wrapRefKey,
} from "./dek-wraps.ts";
import { requireActiveEnvironment } from "./quotas.ts";

export const registerDekWrapsProgram = (
  actor: DataActor,
  environmentId: string,
  wraps: readonly DekWrapInput[],
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { state, member, projectId } = yield* requireMemberState(actor.userId, "member", cache);
    yield* requireActiveEnvironment(environmentId);
    const currentEpoch = currentEpochOf(state, environmentId);
    yield* ensureWrapSetAcceptable(projectId, environmentId, state, member, currentEpoch, wraps);
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = Date.now();
    yield* Effect.sync(() => {
      for (const wrap of wraps) {
        store.write.insertWrap(environmentId, wrap, member, now);
      }
      audit.appendManySync(
        wraps.map((wrap) => dekRegisteredEvent(actor, member, now, environmentId, wrap)),
      );
    });
  });

/**
 * §12-6 の修復経路: admin による (環境, エポック, 受信者) 単位のラップ削除。
 * 上書き禁止(可用性攻撃の遮断)は維持したまま、毒ラップを削除 → 不足分の
 * 追記経路で再登録する。存在しないタプルは 404(黙って成功させない)。
 */
export const deleteDekWrapsProgram = (
  actor: DataActor,
  environmentId: string,
  refs: readonly DekWrapRefInput[],
  cache: StateCache,
) =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "admin", cache);
    yield* requireActiveEnvironment(environmentId);
    const countRejection = checkWrapRequestCount(refs.length);
    if (countRejection !== null) {
      return yield* rejectData(countRejection);
    }
    const store = yield* DataStore;
    const seen = new Set<string>();
    for (const ref of refs) {
      const key = wrapRefKey(ref);
      if (seen.has(key)) {
        return yield* rejectData({ kind: "dek-wrap-rejected", reason: "duplicate-recipient" });
      }
      seen.add(key);
      // 保存済み行の受信者クラスと突合する: クライアント申告の class を監査列の
      // 選択(下の dek.deleted の書き分け)にそのまま使わせない。不一致 =
      // そのクラスのラップは存在しない(404 と同じ扱い — 黙って成功させない)。
      // これで「class 違いの同一 (epoch, recipient) ref」も片方が必ずここで落ち、
      // 1 行の削除に監査 2 行が積まれる形も同時に塞がる
      const stored = yield* store.wrapStoredRecipient(
        environmentId,
        ref.epoch,
        ref.recipientUserId,
      );
      if (stored === null || stored.recipientClass !== wrapRecipientClass(ref)) {
        return yield* rejectData({
          kind: "dek-wrap-not-found",
          epoch: ref.epoch,
          recipientUserId: ref.recipientUserId,
        });
      }
    }
    const audit = yield* AuditStore;
    const now = Date.now();
    // 書き込みフェーズ(単一タスク): 削除と dek.deleted(1 受信者 1 行 —
    // AUDIT_SPEC §3.3)を原子的に書く
    yield* Effect.sync(() => {
      for (const ref of refs) {
        store.write.deleteWrap(environmentId, ref.epoch, ref.recipientUserId);
      }
      audit.appendManySync(
        refs.map((ref) =>
          // server 受信者は user_id を持たないため FP を target_key_fingerprint に
          // 載せる(dek.registered — dek-wraps.ts — と同じ書き分け。AUDIT_SPEC §3.3)。
          // ここで ref の class を使ってよいのは、上の検証フェーズで保存行の
          // recipient_class と一致することを確認済みだからである
          dataEvent(actor, now, "dek.deleted", {
            environmentId,
            epoch: ref.epoch,
            ...(wrapRecipientClass(ref) === "server"
              ? { targetKeyFingerprintHex: ref.recipientUserId }
              : { targetUserId: ref.recipientUserId }),
          }),
        ),
      );
    });
  });

export const listMyDekWrapsProgram = (actor: DataActor, environmentId: string, cache: StateCache) =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "reader", cache);
    yield* requireActiveEnvironment(environmentId);
    const store = yield* DataStore;
    return yield* store.listWrapsForRecipient(environmentId, actor.userId);
  });
