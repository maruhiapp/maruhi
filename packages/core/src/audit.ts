// 監査アクターの共有型と写像(AUDIT_SPEC §2)。
//
// アイデンティティ規則(§1-2)の関門: 監査ログ(D1 側)とメンバーシップログの
// ミラー・データ系イベント(DO 側)のアクターは**内部 user_id と鍵フィンガー
// プリントのみ**で表す。認証主体 → アクターの写像はここ(auditActorOf)が唯一の
// 実装であり、GitHub ID・login・メール等のプロバイダ情報をこの型に足さないこと。
// DO 用(apps/server data-plane.ts の DataActor)/ D1 用(db.package/audit.ts の
// D1AuditActor)の入力型はこの型から派生する。

import type { AuthenticatedPrincipal } from "./auth.ts";

/**
 * A resolved audit actor (AUDIT_SPEC §2): the internal user id plus, depending
 * on how the request was authenticated, the maruhi-issued token id or the auth
 * method name. Never carries provider identifiers (GitHub id, login, email).
 */
export interface AuditActor {
  readonly userId: string;
  readonly apiTokenId?: string;
  readonly authMethod?: string;
}

/**
 * Maps an authenticated principal to its audit actor (AUDIT_SPEC §2). The only
 * principal-to-actor mapping — both the DO data plane and the D1 audit log go
 * through this.
 */
export function auditActorOf(principal: AuthenticatedPrincipal): AuditActor {
  return principal.kind === "token"
    ? { userId: principal.userId, apiTokenId: principal.tokenId }
    : { userId: principal.userId, authMethod: principal.authMethod };
}

/**
 * Merges the actor's auth method into the event payload (AUDIT_SPEC §5.1:
 * auth_method is a payload attribute, not a column). Shared by the DO event
 * builder and the D1 row builder so the merge cannot drift between the two.
 */
export function auditPayloadWith(
  actor: Pick<AuditActor, "authMethod">,
  payload: Readonly<Record<string, unknown>> | undefined,
): Readonly<Record<string, unknown>> {
  return {
    ...payload,
    ...(actor.authMethod === undefined ? {} : { authMethod: actor.authMethod }),
  };
}
