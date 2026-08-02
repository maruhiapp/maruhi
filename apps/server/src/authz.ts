// チェーン API のリクエスト認可ヘルパ(AUTH_SPEC §9-2 / §11)。
//
// - チェーン role の認可は verifyChain(CRYPTO_SPEC §6.2)が真実源。ここで行うのは
//   「トークンスコープ側の必要条件」(実効権限 = min(スコープ, チェーン role) の
//   スコープ半分)と、認証主体とエントリ actor の一致(§11-1)のみ
// - スコープが対象プロジェクトを覆っていない場合は 404(存在秘匿。§11-2)、
//   覆っているが権限水準が足りない場合は 403

import { ForbiddenError, ProjectNotFoundError } from "@maruhi/api-schema";
import type { AuthenticatedPrincipal, TokenPermission } from "@maruhi/core";
import { permissionAtLeast, scopePermissionFor } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { Effect } from "effect";

/**
 * 追記エントリの op が要求するトークン権限水準(AUTH_SPEC §6)。
 * `rotate_epoch` = write、メンバー / サーバー鍵管理系 = admin。
 * append に genesis が来た場合も admin(verifyChain が bad-genesis で拒否する)。
 */
export function requiredPermissionForOp(op: ChainEntry["op"]): TokenPermission {
  return op === "rotate_epoch" ? "write" : "admin";
}

/** §11-1: 認証主体の内部 user_id と entry.actor.user_id の厳密一致(受理ポリシー)。 */
export function ensureActorMatches(
  principal: AuthenticatedPrincipal,
  entry: ChainEntry,
): Effect.Effect<void, ForbiddenError> {
  return entry.actor.userId === principal.userId
    ? Effect.void
    : Effect.fail(new ForbiddenError({ reason: "actor-mismatch" }));
}

/**
 * 既存プロジェクトへの操作: スコープ外 = 404(§11-2)、水準不足 = 403。
 * セッション主体はスコープを持たない(本人のフルパワー。チェーン role が束縛)。
 */
export function ensureTokenScopeForProject(
  principal: AuthenticatedPrincipal,
  projectId: string,
  required: TokenPermission,
): Effect.Effect<void, ProjectNotFoundError | ForbiddenError> {
  if (principal.kind !== "token") {
    return Effect.void;
  }
  const granted = scopePermissionFor(principal.scopes, projectId);
  if (granted === null) {
    return Effect.fail(new ProjectNotFoundError({ projectId }));
  }
  return permissionAtLeast(granted, required)
    ? Effect.void
    : Effect.fail(new ForbiddenError({ reason: "insufficient-permission" }));
}

/**
 * プロジェクト作成(init): まだ存在しないプロジェクトなので存在秘匿の対象外。
 * スコープ不足はすべて 403。必要水準は admin(AUTH_SPEC §6)。
 */
export function ensureTokenScopeForInit(
  principal: AuthenticatedPrincipal,
  projectId: string,
): Effect.Effect<void, ForbiddenError> {
  if (principal.kind !== "token") {
    return Effect.void;
  }
  const granted = scopePermissionFor(principal.scopes, projectId);
  return granted !== null && permissionAtLeast(granted, "admin")
    ? Effect.void
    : Effect.fail(new ForbiddenError({ reason: "insufficient-permission" }));
}
