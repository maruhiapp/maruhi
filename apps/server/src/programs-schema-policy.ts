// プロジェクト設定 schemaPolicy の Effect プログラム(AUTH_SPEC §12-11)。
//
// - 取得: read スコープ(worker)× チェーン role reader 以上(ここ)
// - 変更: admin スコープ(worker)× チェーン role admin 以上(ここ)。204。
//   変更は project.schema_policy_changed(AUDIT_SPEC §3.3 — payload = 旧値・
//   新値、actor = type=user。署名を伴わない設定操作のため鍵 FP は持たない)
// - 受理判定側(programs-variable.ts / verify-meta.ts)は同じ permit 下で
//   store.schemaPolicy を読む — 変更との競合窓を作らない(§12-11)

import { Effect } from "effect";

import { AuditStore } from "./audit-store.ts";
import type { StateCache } from "./chain-store.ts";
import type { DataActor, SchemaPolicy } from "./data-plane.ts";
import { dataEvent, requireMemberState } from "./data-plane.ts";
import { DataStore } from "./data-store.ts";
import { ensureStorageAdmitsGrowth } from "./storage-guard.ts";

export const getSchemaPolicyProgram = (actor: DataActor, cache: StateCache) =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "reader", cache);
    const store = yield* DataStore;
    return { schemaPolicy: yield* store.schemaPolicy };
  });

export const setSchemaPolicyProgram = (
  actor: DataActor,
  schemaPolicy: SchemaPolicy,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "admin", cache);
    // DO ストレージ総量ガード(AUTH_SPEC §12-8 — H2): 設定変更は内容の成長面
    // ではないが、退出・解放・セキュリティ是正のいずれにも要らず、変更のたびに
    // 監査行を積む(admin の反復で非有界)ため拒否対象に含める。取得
    // (getSchemaPolicyProgram)は読み取り = 拒否下でも通る
    yield* ensureStorageAdmitsGrowth;
    const store = yield* DataStore;
    const previous = yield* store.schemaPolicy;
    if (previous === schemaPolicy) {
      // 冪等な同値 PUT は 204 のまま監査を記録しない(「変更」イベントに
      // 変わっていない遷移を書かない — AUDIT_SPEC §3.3 の payload は旧値・新値)
      return;
    }
    const audit = yield* AuditStore;
    const now = Date.now();
    // 設定の upsert と監査行を同一の同期ブロックで書く(原子性)
    yield* Effect.sync(() => {
      store.write.setSchemaPolicy(schemaPolicy);
      audit.appendSync(
        dataEvent(actor, now, "project.schema_policy_changed", {
          payload: { previous, next: schemaPolicy },
        }),
      );
    });
  });
