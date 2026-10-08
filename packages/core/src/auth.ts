// Domain types and Effect service boundaries for authentication /
// authorization (AUTH_SPEC §5-§6, §8, §11).
//
// Why this lives here: the HttpApi middleware contract
// (@maruhi/api-schema) references RequestAuth as `provides`, and the
// server (apps/server) wires the implementation. The shared boundary
// visible to both lives in core, the domain-types package.
//
// Prohibitions (AUTH_SPEC §10): no type on this boundary carries a
// session's or token's raw value in a form that gets persisted or
// logged. The resolve functions return only the result of the hash
// match.

import { Context, Data, Effect, Option, Schema } from "effect";

import type { UserId } from "./identity.ts";
import { ProjectIdSchema } from "./project.ts";

// ---------------------------------------------------------------------------
// Authentication vocabulary (AUTH_SPEC §3 / §4). The single definitions: the
// api-schema error schemas, the server and the audit payloads (AUDIT_SPEC
// §3.1) all derive from these.
// ---------------------------------------------------------------------------

/**
 * The authentication means' kind names (AUTH_SPEC §3 Web OAuth / §4 the CLI
 * handoff) — the only provider-related value an audit row may carry
 * (AUDIT_SPEC §1-2).
 */
export const AUTH_METHODS = ["github_oauth", "cli_handoff"] as const;

/** An authentication means' kind name. */
export type AuthMethod = (typeof AUTH_METHODS)[number];

/** Why a GitHub authentication dance failed (AUTH_SPEC §3 / §4 — the reason code only). */
export const AUTH_FLOW_FAILURE_REASONS = [
  "state-mismatch",
  "code-exchange-failed",
  "github-token-invalid",
] as const;

/** Why signupPolicy refused a new account (AUTH_SPEC §3 — 2026-09-01 H1). */
export const SIGNUP_DENIAL_REASONS = [
  "policy-closed",
  "invite-required",
  "invite-invalid",
] as const;

/** A signupPolicy denial reason. */
export type SignupDenialReason = (typeof SIGNUP_DENIAL_REASONS)[number];

// ---------------------------------------------------------------------------
// Organization ids (AUTH_SPEC §9). Branded for the same reason UserId is:
// organizations.id and memberships.org_id are ULID columns adjacent to
// user-id columns of the same shape, and the brand is what keeps one out of
// the other's positions. Minted only at trust boundaries — this schema (wire
// decode), a branded Drizzle column, or generation (`newOrgId` on the
// server); `.oxlintrc.json` pins the mint sites.
// ---------------------------------------------------------------------------

/** Schema for an organization id (AUTH_SPEC §9 `organizations.id`). Decoding mints an {@link OrgId}. */
export const OrgIdSchema = Schema.String.pipe(Schema.brand("OrgId"));

/** An organization id: the ULID identifying one organization row. */
export type OrgId = typeof OrgIdSchema.Type;

/**
 * Mints an {@link OrgId} where no Schema field does the decoding — only at a
 * trust boundary: generating a new organization id, a hand-written parser of
 * a wire or stored record, or a branded column read.
 */
export const decodeOrgId: (value: string) => OrgId = Schema.decodeSync(OrgIdSchema);

// ---------------------------------------------------------------------------
// Org roles (AUTH_SPEC §9-1 — not involved in project access)
// ---------------------------------------------------------------------------

/** Organization role (AUTH_SPEC §9-1). Authorizes org management only. */
export const OrgRoleSchema = Schema.Literals(["owner", "admin", "member"]);

/** Organization role: `owner` | `admin` | `member`. */
export type OrgRole = typeof OrgRoleSchema.Type;

// ---------------------------------------------------------------------------
// API token scopes (AUTH_SPEC §6)
// ---------------------------------------------------------------------------

/** Token permission level (AUTH_SPEC §6): `read` < `write` < `admin`. */
export const TokenPermissionSchema = Schema.Literals(["read", "write", "admin"]);

/** Token permission level. */
export type TokenPermission = typeof TokenPermissionSchema.Type;

/**
 * One token scope entry (AUTH_SPEC §6): a project id (or `"*"` for all of the
 * owner's projects) paired with a permission level. Effective permission is
 * always min(scope, chain role) — a token never exceeds its owner's chain role.
 * `project` is only a project-id form (64 hex) or `"*"` (the API
 * boundary blocks scopes-JSON bloat via arbitrary strings).
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

const decodeStoredScopes = Schema.decodeUnknownOption(
  Schema.fromJsonString(Schema.Array(TokenScopeSchema)),
);

/**
 * Parses a stored scopes JSON string; null when the value does not
 * decode as a scope array (the same failure value as before — the
 * caller's handling is unchanged)
 */
export function parseTokenScopes(json: string): readonly TokenScope[] | null {
  return Option.getOrNull(decodeStoredScopes(json));
}

// ---------------------------------------------------------------------------
// Request principals (AUTH_SPEC §5 / §6 / §11-1)
// ---------------------------------------------------------------------------

/**
 * An authenticated request principal. Session principals carry the full power
 * of the user (bounded by chain roles) plus the auth method used to establish
 * the session (recorded in audit events — AUDIT_SPEC §2); token principals
 * additionally carry the token's scopes for min(scope, chain role)
 * enforcement (AUTH_SPEC §9-2).
 */
export type AuthenticatedPrincipal =
  | { readonly kind: "session"; readonly userId: UserId; readonly authMethod: AuthMethod }
  | {
      readonly kind: "token";
      readonly userId: UserId;
      readonly tokenId: string;
      readonly scopes: readonly TokenScope[];
      /**
       * The presented token's expiry (AUTH_SPEC §6's default TTL —
       * W3a ruling CI). Always non-null because only a principal that
       * passed verification (expired = anonymous) is constructed. Same
       * kind of "an attribute of the credential it presented" as
       * scopes; /auth/me discloses it (the same category as §16-2's
       * tokenScopes).
       */
      readonly expiresAtMs: number;
    };

/** A resolved request principal: anonymous or authenticated. */
export type Principal = { readonly kind: "anonymous" } | AuthenticatedPrincipal;

/** The anonymous principal (failed or absent credentials resolve to this). */
export const anonymousPrincipal: Principal = { kind: "anonymous" };

// ---------------------------------------------------------------------------
// Effect service boundaries (AUTH_SPEC §8)
// ---------------------------------------------------------------------------

/** Result of issuing a session: the raw cookie value is returned exactly once. */
export interface IssuedSession {
  readonly rawValue: string;
  readonly expiresAtMs: number;
}

/** AUTH_SPEC §8: session issuance, verification, revocation (§5). */
export interface SessionServiceShape {
  /** Issues a 256-bit session. Only the hash is stored in the DB; the raw value is returned only here. */
  readonly issueSession: (userId: UserId, authMethod: AuthMethod) => Effect.Effect<IssuedSession>;
  /** Resolves a principal from a raw cookie value. Revoked, unknown, and expired are treated as anonymous. */
  readonly resolveSession: (rawValue: string) => Effect.Effect<Principal>;
  /** Revokes the session of a raw cookie value (logout). */
  readonly revokeSession: (rawValue: string) => Effect.Effect<void>;
}

export class SessionService extends Context.Service<SessionService, SessionServiceShape>()(
  "SessionService",
) {}

/**
 * Result of issuing an API token: the raw token is returned exactly once.
 * `expiresAtMs` is the expiry fixed at issuance time (AUTH_SPEC §6's
 * default TTL — W3a; deliberately asymmetric with the §5 sliding
 * renewal of sessions).
 */
export interface IssuedToken {
  readonly rawToken: string;
  readonly tokenId: string;
  readonly expiresAtMs: number;
}

/** The per-user token-count cap (AUTH_SPEC §6) has been reached. */
export class TokenLimitReachedError extends Data.TaggedError("TokenLimitReached")<{
  readonly limit: number;
}> {}

/** AUTH_SPEC §8: API-token issuance, verification, revocation, scope judgement (§6). */
export interface TokenServiceShape {
  /**
   * Issues a `maruhi_pat_` token. Only the hash is stored in the DB;
   * the raw value is returned only here. Reissuing under the same name
   * revokes the existing one (rotation); issuing under a new name is
   * allowed up to the per-user cap (§6). expires_at is fixed at
   * issuance from `ttlMs` (§6's default TTL — W3a; the caller resolves
   * the default / an explicit value and passes it in).
   */
  readonly issueToken: (
    userId: UserId,
    name: string,
    scopes: readonly TokenScope[],
    ttlMs: number,
  ) => Effect.Effect<IssuedToken, TokenLimitReachedError>;
  /** Resolves a principal from a `maruhi_pat_…` token. Failures are treated as anonymous. */
  readonly resolveApiToken: (rawToken: string) => Effect.Effect<Principal>;
  /** Revokes the presented token itself (AUTH_SPEC §6's v1 line). */
  readonly revokePresentedToken: (rawToken: string) => Effect.Effect<void>;
}

export class TokenService extends Context.Service<TokenService, TokenServiceShape>()(
  "TokenService",
) {}

/**
 * The boundary handlers require: the authenticated request principal.
 * Only the middleware of auth-required endpoints (AuthMiddleware in
 * @maruhi/api-schema) provides it.
 */
export interface RequestAuthShape {
  readonly principal: Effect.Effect<AuthenticatedPrincipal>;
}

export class RequestAuth extends Context.Service<RequestAuth, RequestAuthShape>()("RequestAuth") {}
