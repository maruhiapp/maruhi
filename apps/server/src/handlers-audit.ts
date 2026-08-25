// 監査イベント読み取り API のハンドラ(AUDIT_SPEC §6 / §7 — C1)。
//
// - events(project DO): read スコープ × チェーン role reader 以上で到達。
//   クラス 2 可視(全行)は「チェーン role admin × トークンスコープ admin」
//   (§12-3 の min 規律)— スコープ半分はここで判定して DO へ渡す。状態を
//   持たない読み取り(監査記録なし)なので CSRF ヘッダーは要求しない
//   (rotation flags と同じ論拠 — AUTH_SPEC §12-7 の一括 pull とは異なる)
// - invites(D1): 権限軸は当該プロジェクトのチェーン role admin 以上 ×
//   トークンスコープ admin(§7 の例外規定 — org admin は閲覧権限を与えない。
//   requireProjectChainAdmin = 招待 API と同一の前段)
// - self(D1): 本人のみ(§6)。トークン条件は鍵素材クラス(§13-2)と同水準
//
// 応答は記録どおりの行のみ(表示名の解決・ミラー検証はクライアントの領分)。

import { maruhiApi } from "@maruhi/api-schema";
import { RequestAuth } from "@maruhi/core";
import { Effect, type Schema } from "effect";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { ensureKeyMaterialAccess, tokenScopeAllowsForProject } from "./authz.ts";
import { callProjectData, requireProjectChainAdmin } from "./data-http.ts";
import type { D1StoredAuditEventRow } from "./db.package/index.ts";
import { D1AuditRepo } from "./db.package/index.ts";
import type { AuditActorValue, AuditEventValue } from "./programs-audit.ts";
import { resolvePageLimit } from "./programs-audit.ts";

/** 保存行の actor_type 列 → アクター種別(D1 側は書き込み経路が 'user' のみ)。 */
function actorTypeOf(stored: string): AuditActorValue["type"] {
  return stored === "server" || stored === "system" ? stored : "user";
}

/**
 * D1 監査行 → ワイヤ形。`seq` は**誰にも**載せない(§7 — D1 の autoincrement は
 * デプロイメント全域の共有採番で、序数はテナント・ユーザーを跨ぐ活動量を漏らす)。
 */
function toWireD1Event(row: D1StoredAuditEventRow): AuditEventValue {
  return {
    id: row.rowId,
    serverTs: row.serverTs,
    event: row.event,
    actor: {
      type: actorTypeOf(row.actorType),
      ...(row.actorUserId === null ? {} : { userId: row.actorUserId }),
      ...(row.actorApiTokenId === null ? {} : { apiTokenId: row.actorApiTokenId }),
    },
    ...(row.targetUserId === null ? {} : { targetUserId: row.targetUserId }),
    ...(row.orgId === null ? {} : { orgId: row.orgId }),
    ...(row.projectId === null ? {} : { projectId: row.projectId }),
    // JSON.parse 由来の値は実行時に必ず JSON 語彙(encode 時の Schema.Json
    // 検証が最終防衛)。unknown → Json は型のみの狭め
    ...(row.payload === null
      ? {}
      : { payload: row.payload as Readonly<Record<string, Schema.Json>> }),
  };
}

export const auditLive = HttpApiBuilder.group(maruhiApi, "audit", (handlers) =>
  handlers
    .handle("events", ({ params, query, endpoint }) =>
      Effect.gen(function* () {
        // クラス 2 可視のスコープ半分(min(スコープ, チェーン role) — §12-3)。
        // role 半分は DO(チェーン導出の権威)が判定する
        const principal = yield* (yield* RequestAuth).principal;
        const scopeAdmin = tokenScopeAllowsForProject(principal, params.projectId, "admin");
        const events = yield* callProjectData<readonly AuditEventValue[]>()({
          endpoint,
          projectId: params.projectId,
          permission: "read",
          invoke: (stub, actor) =>
            stub.auditEvents(actor, {
              ...(query.before === undefined ? {} : { beforeRowId: query.before }),
              ...(query.limit === undefined ? {} : { limit: query.limit }),
              ...(query.event === undefined ? {} : { event: query.event }),
              ...(query.eventPrefix === undefined ? {} : { eventPrefix: query.eventPrefix }),
              ...(query.actorUserId === undefined ? {} : { actorUserId: query.actorUserId }),
              ...(query.targetUserId === undefined ? {} : { targetUserId: query.targetUserId }),
              ...(query.variableId === undefined ? {} : { variableId: query.variableId }),
              ...(query.environmentId === undefined ? {} : { environmentId: query.environmentId }),
              scopeAdmin,
            }),
        });
        return { events };
      }),
    )
    .handle("invites", ({ params, query, endpoint }) =>
      Effect.gen(function* () {
        yield* requireProjectChainAdmin(params.projectId, endpoint);
        const audit = yield* D1AuditRepo;
        const rows = yield* audit.readProjectInviteEvents(params.projectId, {
          beforeRowId: query.before ?? null,
          limit: resolvePageLimit(query.limit),
        });
        return { events: rows.map(toWireD1Event) };
      }),
    )
    .handle("self", ({ query }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        // アカウント全域の履歴(要監視イベント含む)はスコープ限定トークンに
        // 読ませない(§13-2 と同水準 — audit-api.ts の宣言コメント)
        yield* ensureKeyMaterialAccess(principal);
        const audit = yield* D1AuditRepo;
        const rows = yield* audit.readUserEventsFor(principal.userId, {
          beforeRowId: query.before ?? null,
          limit: resolvePageLimit(query.limit),
        });
        return { events: rows.map(toWireD1Event) };
      }),
    ),
);
