// 要ローテーションフラグの Effect プログラム(AUDIT_SPEC §4.1 / §6 / §7 —
// Wave 2 B2)。
//
// - flags: §4.1 手順 5 の導出ビュー。可視性はクラス 1(チェーン role reader
//   以上 = 全メンバー — §6。検出の目的は上流 credential のローテーション促し)
// - dismiss: rotation.dismissed の専用操作(§7 — 生イベントの追記 API は
//   作らない)。admin 以上(§3.3 — ラップ削除と同水準のガバナンス操作)。
//   有効なフラグの無い対への取り下げは 404(黙って成功させない)
//
// permit 直列化の前提は他の programs-* と同じ。導出はイベント列の畳み込みのみ
// (フラグを可変ストアに持たない — §4.1)。

import { Effect } from "effect";

import { AuditStore } from "./audit-store.ts";
import type { StateCache } from "./chain-store.ts";
import type { DataActor } from "./data-plane.ts";
import { dataEvent, rejectData, requireMemberState } from "./data-plane.ts";
import { MAX_ROTATION_DISMISSALS_PER_REQUEST } from "./policy.ts";
import type { EffectiveRotationFlag } from "./rotation-detect.ts";
import { deriveEffectiveFlags } from "./rotation-detect.ts";

/** 取り下げ対象(RPC 境界を渡る)。 */
export interface RotationDismissTargetInput {
  readonly environmentId: string;
  readonly variableId: string;
}

const pairKey = (target: RotationDismissTargetInput): string =>
  `${target.environmentId} ${target.variableId}`;

export const rotationFlagsProgram = (actor: DataActor, cache: StateCache) =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "reader", cache);
    const audit = yield* AuditStore;
    return yield* Effect.sync((): readonly EffectiveRotationFlag[] =>
      deriveEffectiveFlags(audit.readRotationSync.rotationFlagEvents()),
    );
  });

export const dismissRotationFlagsProgram = (
  actor: DataActor,
  targets: readonly RotationDismissTargetInput[],
  cache: StateCache,
) =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "admin", cache);
    if (targets.length > MAX_ROTATION_DISMISSALS_PER_REQUEST) {
      return yield* rejectData({
        kind: "limit-exceeded",
        resource: "rotation-dismissals-per-request",
        limit: MAX_ROTATION_DISMISSALS_PER_REQUEST,
      });
    }
    const audit = yield* AuditStore;
    const live = new Set(
      deriveEffectiveFlags(audit.readRotationSync.rotationFlagEvents()).map(pairKey),
    );
    // 同一対の重複は 1 件に畳む(取り下げの意味論は対単位で冪等 — 1 リクエスト
    // 1 対 1 イベント)。有効フラグの無い対は all-or-nothing で全体を拒否する
    const deduped: RotationDismissTargetInput[] = [];
    const seen = new Set<string>();
    for (const target of targets) {
      const key = pairKey(target);
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      if (!live.has(key)) {
        return yield* rejectData({
          kind: "rotation-flag-not-found",
          environmentId: target.environmentId,
          variableId: target.variableId,
        });
      }
      deduped.push(target);
    }
    const now = Date.now();
    // 書き込みフェーズ(単一タスク): rotation.dismissed を対ごとに 1 行
    // (AUDIT_SPEC §3.3 — actor は取り下げた本人)
    yield* Effect.sync(() => {
      audit.appendManySync(
        deduped.map((target) =>
          dataEvent(actor, now, "rotation.dismissed", {
            environmentId: target.environmentId,
            variableId: target.variableId,
          }),
        ),
      );
    });
  });
