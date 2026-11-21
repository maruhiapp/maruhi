import { Context, Data, Effect, Option, Schema } from "effect";
import type { Digest, SecureRandom } from "effect/crypto";

import type { UserId } from "./identity.ts";
import { ProjectIdSchema } from "./project.ts";

export const AUTH_METHODS = ["github_oauth", "cli_handoff"] as const;

export type AuthMethod = (typeof AUTH_METHODS)[number];

export const AUTH_FLOW_FAILURE_REASONS = [
  "state-mismatch",
  "code-exchange-failed",
  "github-token-invalid",
] as const;

export const SIGNUP_DENIAL_REASONS = [
  "policy-closed",
  "invite-required",
  "invite-invalid",
] as const;

export type SignupDenialReason = (typeof SIGNUP_DENIAL_REASONS)[number];

export const OrgIdSchema = Schema.String.pipe(Schema.brand("OrgId"));

export type OrgId = typeof OrgIdSchema.Type;

export const decodeOrgId: (value: string) => OrgId = Schema.decodeSync(OrgIdSchema);

export const OrgRoleSchema = Schema.Literals(["owner", "admin", "member"]);

export type OrgRole = typeof OrgRoleSchema.Type;

export const TokenPermissionSchema = Schema.Literals(["read", "write", "admin"]);

export type TokenPermission = typeof TokenPermissionSchema.Type;

export const TokenScopeSchema = Schema.Struct({
  project: Schema.Union([ProjectIdSchema, Schema.Literal("*")]),
  permission: TokenPermissionSchema,
});

export type TokenScope = typeof TokenScopeSchema.Type;

const PERMISSION_RANK: Record<TokenPermission, number> = { read: 1, write: 2, admin: 3 };

export function permissionAtLeast(permission: TokenPermission, minimum: TokenPermission): boolean {
  return PERMISSION_RANK[permission] >= PERMISSION_RANK[minimum];
}

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

export function parseTokenScopes(json: string): readonly TokenScope[] | null {
  return Option.getOrNull(decodeStoredScopes(json));
}

export type AuthenticatedPrincipal =
  | { readonly kind: "session"; readonly userId: UserId; readonly authMethod: AuthMethod }
  | {
      readonly kind: "token";
      readonly userId: UserId;
      readonly tokenId: string;
      readonly scopes: readonly TokenScope[];
      readonly expiresAtMs: number;
    };

export type Principal = { readonly kind: "anonymous" } | AuthenticatedPrincipal;

export const anonymousPrincipal: Principal = { kind: "anonymous" };

export interface IssuedSession {
  readonly rawValue: string;
  readonly expiresAtMs: number;
}

export interface SessionServiceShape {
  readonly issueSession: (
    userId: UserId,
    authMethod: AuthMethod,
  ) => Effect.Effect<IssuedSession, never, SecureRandom.SecureRandom | Digest.Digest>;
  readonly resolveSession: (rawValue: string) => Effect.Effect<Principal, never, Digest.Digest>;
  readonly revokeSession: (rawValue: string) => Effect.Effect<void, never, Digest.Digest>;
}

export class SessionService extends Context.Service<SessionService, SessionServiceShape>()(
  "SessionService",
) {}

export interface IssuedToken {
  readonly rawToken: string;
  readonly tokenId: string;
  readonly expiresAtMs: number;
}

export class TokenLimitReachedError extends Data.TaggedError("TokenLimitReached")<{
  readonly limit: number;
}> {}

export interface TokenServiceShape {
  readonly issueToken: (
    userId: UserId,
    name: string,
    scopes: readonly TokenScope[],
    ttlMs: number,
  ) => Effect.Effect<
    IssuedToken,
    TokenLimitReachedError,
    SecureRandom.SecureRandom | Digest.Digest
  >;
  readonly resolveApiToken: (rawToken: string) => Effect.Effect<Principal, never, Digest.Digest>;
  readonly revokePresentedToken: (rawToken: string) => Effect.Effect<void, never, Digest.Digest>;
}

export class TokenService extends Context.Service<TokenService, TokenServiceShape>()(
  "TokenService",
) {}

export interface RequestAuthShape {
  readonly principal: Effect.Effect<AuthenticatedPrincipal>;
}

export class RequestAuth extends Context.Service<RequestAuth, RequestAuthShape>()("RequestAuth") {}
