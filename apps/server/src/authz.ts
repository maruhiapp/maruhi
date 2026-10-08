// Request authorization helpers for the chain API (AUTH_SPEC §9-2 / §11).
//
// - Chain-role authorization has verifyChain (CRYPTO_SPEC §6.2) as its source
//   of truth. What happens here is only the "necessary condition on the token
//   scope side" (the scope half of effective permission = min(scope, chain
//   role)) and the match between the authenticated principal and the entry
//   actor (§11-1)
// - If the scope does not cover the target project: 404 (existence hiding,
//   §11-2); if it covers it but the permission level is insufficient: 403

import { ForbiddenError, ProjectNotFoundError } from "@maruhi/api-schema";
import type { AuthenticatedPrincipal, ProjectId, TokenPermission } from "@maruhi/core";
import { permissionAtLeast, scopePermissionFor } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { Effect } from "effect";

/**
 * The token permission level an appended entry requires (AUTH_SPEC §6 /
 * §16-2). `create_environment` / `rotate_epoch` = write and
 * `delete_environment` = admin (these 3 ops are only reachable via the
 * composite endpoints, though — the handler rejects a generic append with
 * CompositeRequired first; the mapping here is kept for the table's
 * exhaustiveness). `checkpoint` is payload-dependent: empty
 * audit_head_hash = write, non-empty = admin (§16-2 — the scope half of
 * effective permission admin; the chain-role half is judged by the DO). The
 * 2 device-key ops (§11-1 — 2026-09-19 DK): `add_device` and `revoke_device`
 * whose target is oneself = write (adding a device is followed by a
 * backfill [write], revocation by a rotate [write] — a read token cannot do
 * these), `revoke_device` whose target is another = admin (same as
 * `remove_member`). Member / server-key management = admin. A genesis
 * arriving at append is also admin (verifyChain rejects it with
 * bad-genesis).
 */
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

/** §11-1: exact match between the authenticated principal's internal user_id and entry.actor.user_id (acceptance policy). */
export function ensureActorMatches(
  principal: AuthenticatedPrincipal,
  entry: ChainEntry,
): Effect.Effect<void, ForbiddenError> {
  return entry.actor.userId === principal.userId
    ? Effect.void
    : Effect.fail(new ForbiddenError({ reason: "actor-mismatch" }));
}

/**
 * Operations on an existing project: out of scope = 404 (§11-2),
 * insufficient level = 403. Session principals carry no scope and pass
 * through — a session reaching this point is limited to the allow-enumerated
 * surface (reads + revocation kinds) that has passed §5's capability
 * restriction (AuthMiddleware's declaration layer), and the chain role is
 * the binding.
 */
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

/**
 * Non-asserting scope-level check (a shape that **only checks** the scope
 * half of effective permission = min(scope, chain role) — material for the
 * class-2 visibility of audit reads. AUDIT_SPEC §6 visibility classes are
 * defined by chain role, but so that a stolen read-scoped token cannot be
 * shown colleagues' read patterns (class 2), the scope side also requires
 * admin). Session principals carry no scope and pass through (limited to the
 * allow-enumerated surface that passed §5's capability restriction — same as
 * ensureTokenScopeForProject).
 */
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

/**
 * The scope-intersection filter handed to candidate enumeration for the
 * project list (AUTH_SPEC §11-5). null = no restriction (session principals,
 * tokens carrying a `*` scope); otherwise the deduplicated list of project
 * IDs the scope names (every permission is read or higher, so all entries
 * qualify for the list). An empty list = no visible project exists (the
 * caller skips candidate enumeration entirely).
 *
 * The intersection happens at the **candidate-index stage** not merely to
 * narrow response rows: the `nextAfter` cursor is emitted from the tail of
 * the candidate page, so filtering only at a later stage would leak
 * out-of-scope project_ids (ID = capability) onto the cursor.
 */
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

/**
 * Token requirement for operations of the key-material class (AUTH_SPEC
 * §13-2 / §15-2): a token principal is allowed only when it includes the
 * `*` × admin scope. Applies to recovery-blob registration, reissuance, and
 * fetch (a scoped token must not be allowed wrap replacement = availability
 * attack, or watchlisted blob fetches), and also to invite acceptance (B1a
 * ruling — acceptance is a key-declaration-class operation, "declaring a
 * binding of one's own public key to one's own user_id", and the path where
 * stealing a scope-limited token placed in an exposure-prone context such as
 * CI, combined with an invite link, binds an attacker key is closed off
 * before FP mutual confirmation — CRYPTO_SPEC §6.5).
 *
 * Session principals are denied (§5 capability restriction — the §13-2 /
 * §15-2 table = tokens only). Normally unreachable because AuthMiddleware's
 * declaration layer (SESSION_ALLOWED_ENDPOINTS) returns 403 first — this is
 * a same-direction fail-closed second layer, not an independent source of
 * truth.
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
 * Principal requirement for the self-axis audit read (AUDIT_SPEC §6 —
 * `GET /auth/audit/events`): session principals allowed (§5's allow
 * enumeration "audit read"); token principals only when they include the
 * `*` × admin scope (same level as §13-2 — an account-wide history that
 * includes watchlisted events must not be readable by an exposure-prone
 * scoped token). Kept as a separate function from the key-material class
 * (ensureKeyMaterialAccess above — flips to session-denied under §5)
 * because the session-side norm differs.
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
 * Principal requirement for the token-management surface (AUTH_SPEC §6 —
 * W3a: listing `GET /auth/tokens`, targeted revocation): session principals
 * allowed (§5's allow enumeration); token principals only when they include
 * the `*` × admin scope. Targeted revocation is the same level as §13-2's
 * key-material condition (blocking the availability attack where a stolen
 * scoped token revokes other tokens — §6). Listing is under the same
 * condition (ruling CH — same reason as self-axis audit
 * ensureSelfAuditAccess: an account-wide token inventory = reconnaissance
 * material must not be readable by an exposure-prone scoped token). The
 * decision is computable solely from the caller's credentials and carries
 * no information about the target token (ruling CG's ordering — returning
 * 403 before the uniform 404 still leaks no existence information).
 */
export function ensureTokenManagementAccess(
  principal: AuthenticatedPrincipal,
): Effect.Effect<void, ForbiddenError> {
  return ensureSelfAuditAccess(principal);
}

/**
 * Project creation (init): the project does not exist yet, so it is outside
 * existence hiding. Any insufficient scope is 403. The required level is
 * admin (AUTH_SPEC §6).
 */
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
