// 認証・認可のドメイン型と Effect サービス境界(AUTH_SPEC §5〜§6, §8, §11)。
//
// ここに置く理由: HttpApi のミドルウェア契約(@maruhi/api-schema)が RequestAuth を
// `provides` として参照し、サーバー(apps/server)が実装を結線する。両者から見える
// 共有境界はドメイン型パッケージである core に置く(apps/server/src/auth.ts の
// 旧境界はセッション 06 でここへ移動した)。
//
// 禁止事項(AUTH_SPEC §10): この境界のどの型もセッション / トークンの生値を
// 永続化・ログ出力する形で運ばない。resolve 系はハッシュ照合の結果だけを返す。

import { Context, Data, Effect, Schema } from "effect";

import { ProjectIdSchema } from "./project.ts";

// ---------------------------------------------------------------------------
// org ロール(AUTH_SPEC §9-1。プロジェクトアクセスには関与しない)
// ---------------------------------------------------------------------------

/** Organization role (AUTH_SPEC §9-1). Authorizes org management only. */
export const OrgRoleSchema = Schema.Literals(["owner", "admin", "member"]);

/** Organization role: `owner` | `admin` | `member`. */
export type OrgRole = typeof OrgRoleSchema.Type;

// ---------------------------------------------------------------------------
// API トークンのスコープ(AUTH_SPEC §6)
// ---------------------------------------------------------------------------

/** Token permission level (AUTH_SPEC §6): `read` < `write` < `admin`. */
export const TokenPermissionSchema = Schema.Literals(["read", "write", "admin"]);

/** Token permission level. */
export type TokenPermission = typeof TokenPermissionSchema.Type;

/**
 * One token scope entry (AUTH_SPEC §6): a project id (or `"*"` for all of the
 * owner's projects) paired with a permission level. Effective permission is
 * always min(scope, chain role) — a token never exceeds its owner's chain role.
 * project はプロジェクト ID 形式(hex 64)か `"*"` のみ(任意文字列による
 * scopes JSON の肥大を API 境界で遮断する)。
 */
export const TokenScopeSchema = Schema.Struct({
  project: Schema.Union([ProjectIdSchema, Schema.Literal("*")]),
  permission: TokenPermissionSchema,
});

/** One token scope entry. */
export type TokenScope = typeof TokenScopeSchema.Type;

const PERMISSION_RANK: Record<TokenPermission, number> = { read: 1, write: 2, admin: 3 };

/** Returns true when `permission` is at least `minimum` (read < write < admin). */
export function permissionAtLeast(permission: TokenPermission, minimum: TokenPermission): boolean {
  return PERMISSION_RANK[permission] >= PERMISSION_RANK[minimum];
}

/**
 * Resolves the permission a scope list grants for `projectId` (the strongest
 * matching entry), or null when no entry covers the project — the caller must
 * then conceal the project's existence (AUTH_SPEC §11-2).
 */
export function scopePermissionFor(
  scopes: readonly TokenScope[],
  projectId: string,
): TokenPermission | null {
  let best: TokenPermission | null = null;
  for (const scope of scopes) {
    if (scope.project !== "*" && scope.project !== projectId) {
      continue;
    }
    if (best === null || permissionAtLeast(scope.permission, best)) {
      best = scope.permission;
    }
  }
  return best;
}

/** Parses a stored scopes JSON string; null when the shape is not a scope array. */
export function parseTokenScopes(json: string): readonly TokenScope[] | null {
  try {
    return decodeScopes(JSON.parse(json));
  } catch {
    // JSON 構文エラーは「不正な保存値」であり呼び出し側が失敗として扱う
    return null;
  }
}

function decodeScopes(value: unknown): readonly TokenScope[] | null {
  if (!Array.isArray(value) || !value.every(isTokenScope)) {
    return null;
  }
  return value;
}

function isTokenScope(value: unknown): value is TokenScope {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    typeof record["project"] === "string" &&
    (record["permission"] === "read" ||
      record["permission"] === "write" ||
      record["permission"] === "admin")
  );
}

// ---------------------------------------------------------------------------
// リクエスト主体(AUTH_SPEC §5 / §6 / §11-1)
// ---------------------------------------------------------------------------

/**
 * An authenticated request principal. Session principals carry the full power
 * of the user (bounded by chain roles) plus the auth method used to establish
 * the session (recorded in audit events — AUDIT_SPEC §2); token principals
 * additionally carry the token's scopes for min(scope, chain role)
 * enforcement (AUTH_SPEC §9-2).
 */
export type AuthenticatedPrincipal =
  | { readonly kind: "session"; readonly userId: string; readonly authMethod: string }
  | {
      readonly kind: "token";
      readonly userId: string;
      readonly tokenId: string;
      readonly scopes: readonly TokenScope[];
    };

/** A resolved request principal: anonymous or authenticated. */
export type Principal = { readonly kind: "anonymous" } | AuthenticatedPrincipal;

/** The anonymous principal (failed or absent credentials resolve to this). */
export const anonymousPrincipal: Principal = { kind: "anonymous" };

// ---------------------------------------------------------------------------
// Effect サービス境界(AUTH_SPEC §8)
// ---------------------------------------------------------------------------

/** Result of issuing a session: the raw cookie value is returned exactly once. */
export interface IssuedSession {
  readonly rawValue: string;
  readonly expiresAtMs: number;
}

/** AUTH_SPEC §8: セッションの発行・検証・失効(§5)。 */
export interface SessionServiceShape {
  /** 256-bit セッションを発行する。DB にはハッシュのみ保存し、生値はここでのみ返す。 */
  readonly issueSession: (userId: string, authMethod: string) => Effect.Effect<IssuedSession>;
  /** クッキー生値から主体を解決する。失効・不明・期限切れは匿名として扱う。 */
  readonly resolveSession: (rawValue: string) => Effect.Effect<Principal>;
  /** クッキー生値のセッションを失効させる(ログアウト)。 */
  readonly revokeSession: (rawValue: string) => Effect.Effect<void>;
}

export class SessionService extends Context.Service<SessionService, SessionServiceShape>()(
  "SessionService",
) {}

/** Result of issuing an API token: the raw token is returned exactly once. */
export interface IssuedToken {
  readonly rawToken: string;
  readonly tokenId: string;
}

/** ユーザーあたりのトークン本数上限(AUTH_SPEC §6)に達している。 */
export class TokenLimitReachedError extends Data.TaggedError("TokenLimitReached")<{
  readonly limit: number;
}> {}

/** AUTH_SPEC §8: API トークンの発行・検証・失効・スコープ判定(§6)。 */
export interface TokenServiceShape {
  /**
   * `maruhi_pat_` トークンを発行する。DB にはハッシュのみ保存し、生値はここでのみ
   * 返す。同名は既存の失効を伴う再発行(ローテーション)、別名の新規発行は
   * ユーザーあたり上限まで(§6)。
   */
  readonly issueToken: (
    userId: string,
    name: string,
    scopes: readonly TokenScope[],
  ) => Effect.Effect<IssuedToken, TokenLimitReachedError>;
  /** `maruhi_pat_…` トークンから主体を解決する。失敗は匿名として扱う。 */
  readonly resolveApiToken: (rawToken: string) => Effect.Effect<Principal>;
  /** 提示されたトークン自身を失効させる(AUTH_SPEC §6 の v1 線引き)。 */
  readonly revokePresentedToken: (rawToken: string) => Effect.Effect<void>;
}

export class TokenService extends Context.Service<TokenService, TokenServiceShape>()(
  "TokenService",
) {}

/**
 * ハンドラが要求する境界: 認証済みリクエスト主体。認証必須エンドポイントの
 * ミドルウェア(@maruhi/api-schema の AuthMiddleware)だけがこれを提供する。
 */
export interface RequestAuthShape {
  readonly principal: Effect.Effect<AuthenticatedPrincipal>;
}

export class RequestAuth extends Context.Service<RequestAuth, RequestAuthShape>()("RequestAuth") {}
