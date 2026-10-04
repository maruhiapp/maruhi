// Handlers for the audit-event read API (AUDIT_SPEC §6 / §7 — C1).
//
// - events (project DO): reached with read scope × chain role reader or
//   above. Class-2 visibility (all rows) requires "chain role admin ×
//   token scope admin" (§12-3's min discipline) — the scope half is
//   decided here and passed to the DO. Being a stateless read (no audit
//   record), the CSRF header is not required (same rationale as
//   rotation flags — unlike AUTH_SPEC §12-7's bulk pull)
// - invites (D1): the authority axis is chain role admin or above on
//   that project × token scope admin (§7's exception provision — org
//   admin grants no read permission. requireProjectChainAdmin = the
//   same leading stage as the invite API)
// - self (D1): the principal only (§6). The token condition is the same
//   level as the key-material class (§13-2)
//
// Responses contain only the rows as recorded (resolving display names
// and verifying mirrors are the client's domain).

import { maruhiApi } from "@maruhi/api-schema";
import { RequestAuth } from "@maruhi/core";
import { Effect, type Schema } from "effect";
import { HttpApiBuilder } from "effect/http-api";

import { ensureSelfAuditAccess, tokenScopeAllowsForProject } from "../authz.ts";
import { callProjectData, requireProjectChainAdmin } from "../data/data-http.ts";
import type { D1StoredAuditEventRow } from "../db.package/index.ts";
import { D1AuditRepo } from "../db.package/index.ts";
import type { AuditActorValue, AuditEventValue } from "../programs/programs-audit.ts";
import { resolvePageLimit } from "../programs/programs-audit.ts";

/** Stored row's actor_type column → actor kind (on the D1 side the write path is 'user' only). */
function actorTypeOf(stored: string): AuditActorValue["type"] {
  return stored === "server" || stored === "system" ? stored : "user";
}

/** Maps the optional query onto RPC input. undefined drops the key itself. */
function spreadIfDefined<K extends string, V>(
  key: K,
  value: V | undefined,
): { readonly [P in K]?: V } {
  return value === undefined ? {} : ({ [key]: value } as { [P in K]: V });
}

/**
 * D1 audit row → wire form. `seq` is **never** exposed to anyone
 * (§7 — D1's autoincrement is a sequence shared across the whole
 * deployment, and the ordinal would leak activity volume across
 * tenants and users).
 */
function toWireD1Event(row: D1StoredAuditEventRow): AuditEventValue {
  return {
    id: row.rowId,
    serverTs: row.serverTs,
    event: row.event,
    actor: {
      type: actorTypeOf(row.actorType),
      ...(row.actorUserId === null ? {} : { userId: row.actorUserId }),
      ...(row.actorApiTokenId === null ? {} : { apiTokenId: row.actorApiTokenId }),
    },
    ...(row.targetUserId === null ? {} : { targetUserId: row.targetUserId }),
    ...(row.orgId === null ? {} : { orgId: row.orgId }),
    ...(row.projectId === null ? {} : { projectId: row.projectId }),
    // A value from JSON.parse is always JSON vocabulary at runtime
    // (Schema.Json validation at encode time is the last line of
    // defense). unknown → Json is a type-only narrowing
    ...(row.payload === null
      ? {}
      : { payload: row.payload as Readonly<Record<string, Schema.Json>> }),
  };
}

export const auditLive = HttpApiBuilder.group(maruhiApi, "audit", (handlers) =>
  handlers
    .handle("events", ({ params, query, endpoint }) =>
      Effect.gen(function* () {
        // The scope half of class-2 visibility (min(scope, chain role)
        // — §12-3). The role half is decided by the DO (the
        // chain-derived authority)
        const principal = yield* (yield* RequestAuth).principal;
        const scopeAdmin = tokenScopeAllowsForProject(principal, params.projectId, "admin");
        const events = yield* callProjectData<readonly AuditEventValue[]>()({
          endpoint,
          projectId: params.projectId,
          permission: "read",
          invoke: (stub, actor) =>
            stub.auditEvents(actor, {
              ...spreadIfDefined("beforeRowId", query.before),
              ...spreadIfDefined("limit", query.limit),
              ...spreadIfDefined("event", query.event),
              ...spreadIfDefined("eventPrefix", query.eventPrefix),
              ...spreadIfDefined(
                "chainSeqPresent",
                query.chainSeqPresent === undefined ? undefined : (true as const),
              ),
              ...spreadIfDefined("actorUserId", query.actorUserId),
              ...spreadIfDefined("targetUserId", query.targetUserId),
              ...spreadIfDefined("variableId", query.variableId),
              ...spreadIfDefined("environmentId", query.environmentId),
              scopeAdmin,
            }),
        });
        return { events };
      }),
    )
    .handle("auditHead", ({ params, endpoint }) =>
      Effect.gen(function* () {
        // Effective permission admin (AUTH_SPEC §16-2): the scope half
        // is permission: "admin" (out of scope 404 / insufficient level
        // 403); the chain-role half is the DO (auditHeadProgram —
        // non-member 404 / below admin 403)
        return yield* callProjectData<{ readonly auditHeadHashHex: string }>()({
          endpoint,
          projectId: params.projectId,
          permission: "admin",
          invoke: (stub, actor) => stub.auditHeadFor(actor),
        });
      }),
    )
    .handle("invites", ({ params, query, endpoint }) =>
      Effect.gen(function* () {
        yield* requireProjectChainAdmin(params.projectId, endpoint);
        const audit = yield* D1AuditRepo;
        const rows = yield* audit.readProjectInviteEvents(params.projectId, {
          beforeRowId: query.before ?? null,
          limit: resolvePageLimit(query.limit),
        });
        return { events: rows.map(toWireD1Event) };
      }),
    )
    .handle("self", ({ query }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        // The account-wide history (including watch-list events) is not
        // readable by scope-limited tokens (same level as §13-2 — see
        // the declaration comment in audit-api.ts). Session principals
        // are allowed (§5's allowed enumeration "audit read")
        yield* ensureSelfAuditAccess(principal);
        const audit = yield* D1AuditRepo;
        const rows = yield* audit.readUserEventsFor(principal.userId, {
          beforeRowId: query.before ?? null,
          limit: resolvePageLimit(query.limit),
        });
        return { events: rows.map(toWireD1Event) };
      }),
    ),
);
