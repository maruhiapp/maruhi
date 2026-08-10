// D1 側監査ログの追記(AUDIT_SPEC §3.1〜§3.2 / §5.2 案 A)。
//
// - append-only(§1-4): この層は追記のみを公開する(更新・削除の口を作らない)。
//   読み取り API は Phase 2 の監査ログ UI と同時に設計する(§6・§7)
// - 主データ書き込みと同一トランザクションでの追記(§5.2 の採用理由 (2))は、
//   各リポジトリが自分の batch へ挿入文(userAuditInsert / orgAuditInsert)を
//   同梱することで実現する。単独追記(login_failed 等、主データ書き込みを
//   伴わないイベント)だけが D1AuditRepo を使う
// - アイデンティティ規則(§1-2): actor / target は内部 user_id(+ maruhi 発行
//   トークン id)と auth_method 種別名のみ。プロバイダ ID・login・メールを
//   この層に持ち込まないこと

import type { AuthenticatedPrincipal } from "@maruhi/core";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import { orgAuditEvents, userAuditEvents } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

/**
 * 監査アクター(AUDIT_SPEC §2)。userId 省略は「未認証の外部主体」
 * (auth.login_failed のみ — 人はいるが特定できていない。type=system は
 * 主体のない内部処理用であり、外部からの失敗試行には使わない)。
 */
export interface D1AuditActor {
  readonly userId?: string;
  readonly apiTokenId?: string;
  readonly authMethod?: string;
}

/** 監査イベント 1 行の入力(列は schema.ts の共通列。未指定は NULL)。 */
export interface D1AuditEventInput {
  readonly event: string;
  readonly actor: D1AuditActor;
  readonly targetUserId?: string;
  readonly orgId?: string;
  readonly projectId?: string;
  readonly payload?: Readonly<Record<string, unknown>>;
}

/** 認証主体 → 監査アクター(data-http.ts の dataActorOf と同じ写像)。 */
export function principalAuditActor(principal: AuthenticatedPrincipal): D1AuditActor {
  return principal.kind === "token"
    ? { userId: principal.userId, apiTokenId: principal.tokenId }
    : { userId: principal.userId, authMethod: principal.authMethod };
}

/** 挿入行への写像。auth_method は DO 側と同じく payload に載る(§2)。 */
function rowOf(event: D1AuditEventInput, serverTs: number) {
  const payload = {
    ...event.payload,
    ...(event.actor.authMethod === undefined ? {} : { authMethod: event.actor.authMethod }),
  };
  return {
    serverTs,
    event: event.event,
    actorType: "user",
    actorUserId: event.actor.userId ?? null,
    actorApiTokenId: event.actor.apiTokenId ?? null,
    targetUserId: event.targetUserId ?? null,
    orgId: event.orgId ?? null,
    projectId: event.projectId ?? null,
    payload: Object.keys(payload).length === 0 ? null : JSON.stringify(payload),
  };
}

/** 認証系イベント(§3.1)の挿入文。リポジトリの batch に同梱する。 */
export function userAuditInsert(db: Db, serverTs: number, event: D1AuditEventInput) {
  return db.insert(userAuditEvents).values(rowOf(event, serverTs));
}

/** org 系イベント(§3.2)の挿入文。リポジトリの batch に同梱する。 */
export function orgAuditInsert(db: Db, serverTs: number, event: D1AuditEventInput) {
  return db.insert(orgAuditEvents).values(rowOf(event, serverTs));
}

interface D1AuditRepoShape {
  /** 単独イベントの追記(主データ書き込みを伴わないイベント用)。 */
  readonly appendUserEvent: (event: D1AuditEventInput, serverTs: number) => Effect.Effect<void>;
}

export class D1AuditRepo extends Context.Service<D1AuditRepo, D1AuditRepoShape>()("D1AuditRepo") {}

export function makeD1AuditRepo(db: Db): D1AuditRepoShape {
  return {
    appendUserEvent: (event, serverTs) =>
      Effect.promise(async () => {
        await userAuditInsert(db, serverTs, event);
      }),
  };
}
