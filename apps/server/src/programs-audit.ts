// project DO 監査イベント読み取りの Effect プログラム(AUDIT_SPEC §6 / §7 — C1)。
//
// - 可視性クラス(§6)は認可段で強制する: admin 可視(全行)は「チェーン role
//   admin 以上 × トークンスコープ admin」(§12-3 の min(スコープ, role) 規律 —
//   worker が scopeAdmin を判定して渡す)。それ未満はクラス 1 の行 + 本人が
//   actor の行のみで、クラス 2 の行は件数・ページング・カーソルにも現れない
//   (audit-store.ts の WHERE 句 — 「存在しないかのように振る舞う」)
// - actor_user_id フィルタの他人指定は admin 可視でなければ 403(§6 の
//   「他人が actor の行の横断検索はクラス 2」。データ非依存の静的規則なので
//   存在情報は漏れない)
// - 応答は記録どおりの行(識別子 + 記録 payload)のみ。表示名の解決・ミラーの
//   検証はクライアントの領分(AUDIT_SPEC §7 / §1-5)
//
// permit 直列化の前提は他の programs-* と同じ。

import { DEFAULT_AUDIT_EVENTS_PAGE_LIMIT, MAX_AUDIT_EVENTS_PAGE_LIMIT } from "@maruhi/api-schema";
import { Effect, type Schema } from "effect";

import type { StoredAuditEventRow } from "./audit-store.ts";
import { AuditStore } from "./audit-store.ts";
import type { StateCache } from "./chain-store.ts";
import type { DataActor } from "./data-plane.ts";
import { rejectData, requireMemberState, roleAtLeast } from "./data-plane.ts";

/** 読み取りクエリ(RPC 境界を渡る)。フィルタ語彙は AUDIT_SPEC §7 のとおり。 */
export interface AuditEventsQueryInput {
  readonly beforeSeq?: number;
  readonly limit?: number;
  readonly event?: string;
  readonly actorUserId?: string;
  readonly targetUserId?: string;
  readonly variableId?: string;
  readonly environmentId?: string;
  /**
   * worker 判定のトークンスコープ半分(admin スコープが対象プロジェクトを
   * 覆うか)。DO は「× チェーン role admin 以上」と合成してクラス 2 可視を
   * 決める。actor(auditActorOf)と同じ worker 信頼境界の入力。
   */
  readonly scopeAdmin: boolean;
}

/** 監査イベントのアクター(ワイヤの AuditActorSchema と構造一致)。 */
export interface AuditActorValue {
  readonly type: "user" | "server" | "system";
  readonly userId?: string;
  readonly keyFingerprintHex?: string;
  readonly apiTokenId?: string;
}

/** 監査イベント 1 行(ワイヤの AuditEventSchema と構造一致)。 */
export interface AuditEventValue {
  readonly seq: number;
  readonly serverTs: number;
  readonly clientTs?: number;
  readonly event: string;
  readonly actor: AuditActorValue;
  readonly targetUserId?: string;
  readonly targetKeyFingerprintHex?: string;
  readonly environmentId?: string;
  readonly variableId?: string;
  readonly epoch?: number;
  readonly version?: number;
  readonly chainSeq?: number;
  /** org 系列(D1 行のみ。project DO 行では常に欠落)。 */
  readonly orgId?: string;
  readonly payload?: Readonly<Record<string, Schema.Json>>;
}

/** 保存行の actor_type 列 → アクター種別(§2 の 3 値。列は書き込み時に固定済み)。 */
function actorTypeOf(stored: string): AuditActorValue["type"] {
  return stored === "server" || stored === "system" ? stored : "user";
}

function spreadIf<K extends string, V>(key: K, value: V | null): { readonly [P in K]?: V } {
  return value === null ? {} : ({ [key]: value } as { [P in K]: V });
}

/** 保存行 → RPC 値。NULL 列はキーごと落とす(ワイヤの optionalKey と同型)。 */
function toAuditEventValue(row: StoredAuditEventRow): AuditEventValue {
  return {
    seq: row.seq,
    serverTs: row.serverTs,
    ...spreadIf("clientTs", row.clientTs),
    event: row.event,
    actor: {
      type: actorTypeOf(row.actorType),
      ...spreadIf("userId", row.actorUserId),
      ...spreadIf("keyFingerprintHex", row.actorKeyFingerprintHex),
      ...spreadIf("apiTokenId", row.actorApiTokenId),
    },
    ...spreadIf("targetUserId", row.targetUserId),
    ...spreadIf("targetKeyFingerprintHex", row.targetKeyFingerprintHex),
    ...spreadIf("environmentId", row.environmentId),
    ...spreadIf("variableId", row.variableId),
    ...spreadIf("epoch", row.epoch),
    ...spreadIf("version", row.version),
    ...spreadIf("chainSeq", row.chainSeq),
    // JSON.parse 由来の値は実行時に必ず JSON 語彙(encode 時の Schema.Json
    // 検証が最終防衛)。unknown → Json は型のみの狭め
    ...spreadIf("payload", row.payload as Readonly<Record<string, Schema.Json>> | null),
  };
}

/** limit の確定(既定 50)。Schema が上限 200 を強制済みだが、DO 側でも束ねる(多層防御)。 */
export function resolvePageLimit(limit: number | undefined): number {
  const requested = limit ?? DEFAULT_AUDIT_EVENTS_PAGE_LIMIT;
  return Math.max(1, Math.min(requested, MAX_AUDIT_EVENTS_PAGE_LIMIT));
}

export const auditEventsProgram = (
  actor: DataActor,
  query: AuditEventsQueryInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const context = yield* requireMemberState(actor.userId, "reader", cache);
    const adminVisibility = query.scopeAdmin && roleAtLeast(context.member.role, "admin");
    if (!adminVisibility && query.actorUserId !== undefined && query.actorUserId !== actor.userId) {
      return yield* rejectData({ kind: "insufficient-role" });
    }
    const audit = yield* AuditStore;
    return yield* Effect.sync((): readonly AuditEventValue[] =>
      audit
        .queryEventsSync({
          beforeSeq: query.beforeSeq ?? null,
          limit: resolvePageLimit(query.limit),
          event: query.event ?? null,
          actorUserId: query.actorUserId ?? null,
          targetUserId: query.targetUserId ?? null,
          variableId: query.variableId ?? null,
          environmentId: query.environmentId ?? null,
          visibility: adminVisibility
            ? { kind: "admin" }
            : { kind: "class1-or-self", selfUserId: actor.userId },
        })
        .map(toAuditEventValue),
    );
  });
