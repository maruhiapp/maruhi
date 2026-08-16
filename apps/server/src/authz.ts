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
 * `create_environment` / `rotate_epoch` = write(ただしこの 2 op は複合
 * エンドポイント経由のみで、汎用 append はハンドラが CompositeRequired で
 * 先に拒否する — ここの写像は表の網羅性のために保持)、メンバー / サーバー鍵
 * 管理系 = admin。append に genesis が来た場合も admin(verifyChain が
 * bad-genesis で拒否する)。
 */
export function requiredPermissionForOp(op: ChainEntry["op"]): TokenPermission {
  return op === "rotate_epoch" || op === "create_environment" ? "write" : "admin";
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
 * 非表明のスコープ水準判定(実効権限 = min(スコープ, チェーン role) のスコープ
 * 半分を**確かめるだけ**の形 — 監査読み取りのクラス 2 可視性の材料。AUDIT_SPEC
 * §6 の可視性クラスはチェーン role で定義されるが、盗まれた read スコープの
 * トークンに同僚の読み取りパターン(クラス 2)を開示しないため、スコープ側も
 * admin を要求する)。セッション主体はスコープを持たない(本人のフルパワー)。
 */
export function tokenScopeAllowsForProject(
  principal: AuthenticatedPrincipal,
  projectId: string,
  required: TokenPermission,
): boolean {
  if (principal.kind !== "token") {
    return true;
  }
  const granted = scopePermissionFor(principal.scopes, projectId);
  return granted !== null && permissionAtLeast(granted, required);
}

/**
 * 鍵素材クラスの操作のトークン条件(AUTH_SPEC §13-2): セッション主体は常に可、
 * トークン主体は `*` × admin スコープを含む場合のみ可。リカバリーブロブの
 * 登録・再発行・取得(スコープ限定トークンにラップの置換 = 可用性攻撃や要監視の
 * ブロブ取得を許さない)に加え、招待の受諾にも適用する(B1a 裁定 — 受諾は
 * 「自分の公開鍵を自分の user_id に束縛して宣言する」鍵宣言クラスの操作であり、
 * CI 等の露出しやすい文脈に置かれるスコープ限定トークンの窃取と招待リンクの
 * 複合で攻撃者鍵を束縛する経路を、FP 相互確認 — CRYPTO_SPEC §6.5 — の手前で
 * 塞ぐ。§15-2 の「認証済み主体」より狭い — AUTH_SPEC 追補の提案は PR 申し送り)。
 */
export function ensureKeyMaterialAccess(
  principal: AuthenticatedPrincipal,
): Effect.Effect<void, ForbiddenError> {
  if (principal.kind === "session") {
    return Effect.void;
  }
  const allowed = principal.scopes.some(
    (scope) => scope.project === "*" && scope.permission === "admin",
  );
  return allowed
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
