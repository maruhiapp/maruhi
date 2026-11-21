import { ForbiddenError, ProjectNotFoundError } from "@maruhi/api-schema";
import type { AuthenticatedPrincipal, ProjectId, TokenPermission, TokenScope } from "@maruhi/core";
import { permissionAtLeast, scopePermissionFor } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { Effect } from "effect";

export function requiredPermissionForEntry(entry: ChainEntry): TokenPermission {
  if (entry.op === "checkpoint") {
    return entry.payload.auditHeadHashHex === "" ? "write" : "admin";
  }
  if (entry.op === "add_device") {
    return "write";
  }
  if (entry.op === "revoke_device") {
    return entry.payload.targetUserId === entry.actor.userId ? "write" : "admin";
  }
  return entry.op === "rotate_epoch" || entry.op === "create_environment" ? "write" : "admin";
}

export function ensureActorMatches(
  principal: AuthenticatedPrincipal,
  entry: ChainEntry,
): Effect.Effect<void, ForbiddenError> {
  return entry.actor.userId === principal.userId
    ? Effect.void
    : Effect.fail(new ForbiddenError({ reason: "actor-mismatch" }));
}

export function ensureTokenScopeForProject(
  principal: AuthenticatedPrincipal,
  projectId: ProjectId,
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

export function tokenScopeAllowsForProject(
  principal: AuthenticatedPrincipal,
  projectId: ProjectId,
  required: TokenPermission,
): boolean {
  if (principal.kind !== "token") {
    return true;
  }
  const granted = scopePermissionFor(principal.scopes, projectId);
  return granted !== null && permissionAtLeast(granted, required);
}

export function scopedProjectIdsFor(
  principal: AuthenticatedPrincipal,
): readonly ProjectId[] | null {
  if (principal.kind !== "token") {
    return null;
  }
  if (principal.scopes.some((scope) => scope.project === "*")) {
    return null;
  }
  return [
    ...new Set<ProjectId>(
      principal.scopes.flatMap((scope) => (scope.project === "*" ? [] : [scope.project])),
    ),
  ];
}

export function ensureKeyMaterialAccess(
  principal: AuthenticatedPrincipal,
): Effect.Effect<void, ForbiddenError> {
  if (principal.kind === "session") {
    return Effect.fail(new ForbiddenError({ reason: "session-not-allowed" }));
  }
  return ensureWildcardAdminScope(principal.scopes);
}

function ensureWildcardAdminScope(
  scopes: readonly TokenScope[],
): Effect.Effect<void, ForbiddenError> {
  const allowed = scopes.some((scope) => scope.project === "*" && scope.permission === "admin");
  return allowed
    ? Effect.void
    : Effect.fail(new ForbiddenError({ reason: "insufficient-permission" }));
}

export function ensureSelfAuditAccess(
  principal: AuthenticatedPrincipal,
): Effect.Effect<void, ForbiddenError> {
  if (principal.kind === "session") {
    return Effect.void;
  }
  return ensureWildcardAdminScope(principal.scopes);
}

export function ensureTokenManagementAccess(
  principal: AuthenticatedPrincipal,
): Effect.Effect<void, ForbiddenError> {
  return ensureSelfAuditAccess(principal);
}

export function ensureTokenScopeForInit(
  principal: AuthenticatedPrincipal,
  projectId: ProjectId,
): Effect.Effect<void, ForbiddenError> {
  if (principal.kind !== "token") {
    return Effect.void;
  }
  const granted = scopePermissionFor(principal.scopes, projectId);
  return granted !== null && permissionAtLeast(granted, "admin")
    ? Effect.void
    : Effect.fail(new ForbiddenError({ reason: "insufficient-permission" }));
}
