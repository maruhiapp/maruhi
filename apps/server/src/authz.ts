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
 * 追記エントリが要求するトークン権限水準(AUTH_SPEC §6 / §16-2)。
 * `create_environment` / `rotate_epoch` = write(ただしこの 2 op は複合
 * エンドポイント経由のみで、汎用 append はハンドラが CompositeRequired で
 * 先に拒否する — ここの写像は表の網羅性のために保持)、`checkpoint` は
 * payload 依存: 空 audit_head_hash = write、非空 = admin(§16-2 — 実効権限
 * admin のスコープ半分。チェーン role 半分は DO が判定する)。メンバー /
 * サーバー鍵管理系 = admin。append に genesis が来た場合も admin(verifyChain
 * が bad-genesis で拒否する)。
 */
export function requiredPermissionForEntry(entry: ChainEntry): TokenPermission {
  if (entry.op === "checkpoint") {
    return entry.payload.auditHeadHashHex === "" ? "write" : "admin";
  }
  return entry.op === "rotate_epoch" || entry.op === "create_environment" ? "write" : "admin";
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
 * セッション主体はスコープを持たず素通しする — ここへ到達するセッションは
 * §5 の能力制限(AuthMiddleware の宣言層)を通過済みの許可列挙面(読み取り +
 * 失効系)に限られ、チェーン role が束縛する。
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
 * admin を要求する)。セッション主体はスコープを持たず素通しする(§5 の能力
 * 制限を通過済みの許可列挙面に限られる — ensureTokenScopeForProject と同じ)。
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
 * プロジェクト一覧の候補列挙に渡すスコープ交差フィルタ(AUTH_SPEC §11-5)。
 * null = 制限なし(セッション主体・`*` スコープを含むトークン)、それ以外は
 * スコープが名指しするプロジェクト ID の重複排除済み列(どの permission も
 * read 以上なので全エントリが一覧の資格を満たす)。空列 = 見えるプロジェクトが
 * 存在しない(呼び出し側は候補列挙自体を省く)。
 *
 * 交差を**候補索引の段**で行うのは応答行の絞り込みのためだけではない:
 * `nextAfter` カーソルは候補ページの末尾から出るため、後段の絞り込みだけでは
 * スコープ外の project_id(ID = capability)がカーソルに載って漏れる
 * (PR #106 Cursor Security Agent 指摘)。
 */
export function scopedProjectIdsFor(principal: AuthenticatedPrincipal): readonly string[] | null {
  if (principal.kind !== "token") {
    return null;
  }
  if (principal.scopes.some((scope) => scope.project === "*")) {
    return null;
  }
  return [...new Set(principal.scopes.map((scope) => scope.project))];
}

/**
 * 鍵素材クラスの操作のトークン条件(AUTH_SPEC §13-2 / §15-2): トークン主体は
 * `*` × admin スコープを含む場合のみ可。リカバリーブロブの登録・再発行・取得
 * (スコープ限定トークンにラップの置換 = 可用性攻撃や要監視のブロブ取得を
 * 許さない)に加え、招待の受諾にも適用する(B1a 裁定 — 受諾は「自分の公開鍵を
 * 自分の user_id に束縛して宣言する」鍵宣言クラスの操作であり、CI 等の露出し
 * やすい文脈に置かれるスコープ限定トークンの窃取と招待リンクの複合で攻撃者鍵を
 * 束縛する経路を、FP 相互確認 — CRYPTO_SPEC §6.5 — の手前で塞ぐ)。
 *
 * セッション主体は拒否(§5 の能力制限 — §13-2 / §15-2 の表 = トークンのみ)。
 * 通常は AuthMiddleware の宣言層(SESSION_ALLOWED_ENDPOINTS)が先に 403 を
 * 返すため到達しない — ここは同方向の fail-closed の第 2 層であり、独立の
 * 真実源ではない。
 */
export function ensureKeyMaterialAccess(
  principal: AuthenticatedPrincipal,
): Effect.Effect<void, ForbiddenError> {
  if (principal.kind === "session") {
    return Effect.fail(new ForbiddenError({ reason: "session-not-allowed" }));
  }
  const allowed = principal.scopes.some(
    (scope) => scope.project === "*" && scope.permission === "admin",
  );
  return allowed
    ? Effect.void
    : Effect.fail(new ForbiddenError({ reason: "insufficient-permission" }));
}

/**
 * 本人軸の監査読み取り(AUDIT_SPEC §6 — `GET /auth/audit/events`)の主体条件:
 * セッション主体は可(§5 の許可列挙「監査読み取り」)、トークン主体は `*` ×
 * admin スコープを含む場合のみ可(§13-2 と同水準 — 要監視イベントを含む
 * アカウント全域の履歴を、露出しやすいスコープ限定トークンに読ませない)。
 * 鍵素材クラス(上の ensureKeyMaterialAccess — §5 でセッション拒否へ反転)とは
 * セッション側の規範が異なるため独立の関数に分ける。
 */
export function ensureSelfAuditAccess(
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
