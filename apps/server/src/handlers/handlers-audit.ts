import { maruhiApi } from "@maruhi/api-schema";
import { RequestAuth } from "@maruhi/core";
import { Effect, type Schema } from "effect";
import { HttpApiBuilder } from "effect/http-api";

import { resolvePageLimit } from "../audit-store-query.ts";
import { ensureSelfAuditAccess, tokenScopeAllowsForProject } from "../authz.ts";
import { callProjectData, requireProjectChainAdmin } from "../data.package/index.ts";
import type { D1StoredAuditEventRow } from "../db.package/index.ts";
import { D1AuditRepo } from "../db.package/index.ts";
import type { AuditActorValue, AuditEventValue } from "../programs/programs-audit.ts";

function actorTypeOf(stored: string): AuditActorValue["type"] {
  return stored === "server" || stored === "system" ? stored : "user";
}

function spreadIfDefined<K extends string, V>(
  key: K,
  value: V | undefined,
): { readonly [P in K]?: V } {
  return value === undefined ? {} : ({ [key]: value } as { [P in K]: V });
}

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
    ...(row.payload === null
      ? {}
      : { payload: row.payload as Readonly<Record<string, Schema.Json>> }),
  };
}

export const auditLive = HttpApiBuilder.group(maruhiApi, "audit", (handlers) =>
  handlers
    .handle(
      "events",
      Effect.fn("handlers-audit.events")(function* ({ params, query, endpoint }) {
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
    .handle(
      "auditHead",
      Effect.fn("handlers-audit.auditHead")(function* ({ params, endpoint }) {
        return yield* callProjectData<{ readonly auditHeadHashHex: string }>()({
          endpoint,
          projectId: params.projectId,
          permission: "admin",
          invoke: (stub, actor) => stub.auditHeadFor(actor),
        });
      }),
    )
    .handle(
      "invites",
      Effect.fn("handlers-audit.invites")(function* ({ params, query, endpoint }) {
        yield* requireProjectChainAdmin(params.projectId, endpoint);
        const audit = yield* D1AuditRepo;
        const rows = yield* audit.readProjectInviteEvents(params.projectId, {
          beforeRowId: query.before ?? null,
          limit: resolvePageLimit(query.limit),
        });
        return { events: rows.map(toWireD1Event) };
      }),
    )
    .handle(
      "self",
      Effect.fn("handlers-audit.self")(function* ({ query }) {
        const principal = yield* (yield* RequestAuth).principal;
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
