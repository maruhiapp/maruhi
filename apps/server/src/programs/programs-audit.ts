import { DEFAULT_AUDIT_EVENTS_PAGE_LIMIT, MAX_AUDIT_EVENTS_PAGE_LIMIT } from "@maruhi/api-schema";
import type { KeyFingerprintHex, OrgId, UserId } from "@maruhi/core";
import { Effect, type Schema } from "effect";

import type { StoredAuditEventRow } from "../audit-store-query.ts";
import { AuditStore } from "../audit-store.ts";
import type { DataActor } from "../data.package/index.ts";
import { rejectData, requireMemberState, roleAtLeast } from "../data.package/index.ts";
import type { StateCache } from "../do/chain-store.ts";
import { ensureStorageAdmitsAuditHeadExtension } from "../storage-guard.ts";

export interface AuditEventsQueryInput {
  readonly beforeRowId?: string;
  readonly limit?: number;
  readonly event?: string;
  readonly eventPrefix?: string;
  readonly chainSeqPresent?: true;
  readonly actorUserId?: UserId;
  readonly targetUserId?: UserId;
  readonly variableId?: string;
  readonly environmentId?: string;
  readonly scopeAdmin: boolean;
}

export interface AuditActorValue {
  readonly type: "user" | "server" | "system";
  readonly userId?: UserId;
  readonly keyFingerprintHex?: KeyFingerprintHex;
  readonly apiTokenId?: string;
}

export interface AuditEventValue {
  readonly id: string;
  readonly seq?: number;
  readonly serverTs: number;
  readonly clientTs?: number;
  readonly event: string;
  readonly actor: AuditActorValue;
  readonly targetUserId?: UserId;
  readonly targetKeyFingerprintHex?: KeyFingerprintHex;
  readonly environmentId?: string;
  readonly variableId?: string;
  readonly epoch?: number;
  readonly version?: number;
  readonly chainSeq?: number;
  readonly orgId?: OrgId;
  readonly payload?: Readonly<Record<string, Schema.Json>>;
}

function actorTypeOf(stored: string): AuditActorValue["type"] {
  return stored === "server" || stored === "system" ? stored : "user";
}

function spreadIf<K extends string, V>(key: K, value: V | null): { readonly [P in K]?: V } {
  return value === null ? {} : ({ [key]: value } as { [P in K]: V });
}

function toAuditEventValue(row: StoredAuditEventRow, includeSeq: boolean): AuditEventValue {
  return {
    id: row.rowId,
    ...(includeSeq ? { seq: row.seq } : {}),
    serverTs: row.serverTs,
    ...spreadIf("clientTs", row.clientTs),
    event: row.event,
    actor: {
      type: actorTypeOf(row.actorType),
      ...spreadIf("userId", row.actorUserId),
      ...spreadIf("keyFingerprintHex", row.actorKeyFingerprintHex),
      ...spreadIf("apiTokenId", row.actorApiTokenId),
    },
    ...spreadIf("targetUserId", row.targetUserId),
    ...spreadIf("targetKeyFingerprintHex", row.targetKeyFingerprintHex),
    ...spreadIf("environmentId", row.environmentId),
    ...spreadIf("variableId", row.variableId),
    ...spreadIf("epoch", row.epoch),
    ...spreadIf("version", row.version),
    ...spreadIf("chainSeq", row.chainSeq),
    ...spreadIf("payload", row.payload as Readonly<Record<string, Schema.Json>> | null),
  };
}

export function resolvePageLimit(limit: number | undefined): number {
  const requested = limit ?? DEFAULT_AUDIT_EVENTS_PAGE_LIMIT;
  return Math.max(1, Math.min(requested, MAX_AUDIT_EVENTS_PAGE_LIMIT));
}

export const auditHeadProgram = Effect.fn("programs-audit.auditHeadProgram")(function* (
  actor: DataActor,
  cache: StateCache,
) {
  const context = yield* requireMemberState(actor.userId, "reader", cache);
  if (!roleAtLeast(context.member.role, "admin")) {
    return yield* rejectData({ kind: "insufficient-role" });
  }
  const audit = yield* AuditStore;
  yield* ensureStorageAdmitsAuditHeadExtension;
  if ((yield* audit.ensureHeadCurrent) === "more-remains") {
    return yield* rejectData({ kind: "audit-head-not-ready" });
  }
  return { auditHeadHashHex: audit.currentHeadHexSync() };
});

export const auditEventsProgram = Effect.fn("programs-audit.auditEventsProgram")(function* (
  actor: DataActor,
  query: AuditEventsQueryInput,
  cache: StateCache,
) {
  const context = yield* requireMemberState(actor.userId, "reader", cache);
  const adminVisibility = query.scopeAdmin && roleAtLeast(context.member.role, "admin");
  if (!adminVisibility && query.actorUserId !== undefined && query.actorUserId !== actor.userId) {
    return yield* rejectData({ kind: "insufficient-role" });
  }
  const audit = yield* AuditStore;
  return yield* Effect.sync((): readonly AuditEventValue[] =>
    audit
      .queryEventsSync({
        beforeRowId: query.beforeRowId ?? null,
        limit: resolvePageLimit(query.limit),
        event: query.event ?? null,
        eventPrefix: query.eventPrefix ?? null,
        chainSeqPresent: query.chainSeqPresent === true,
        actorUserId: query.actorUserId ?? null,
        targetUserId: query.targetUserId ?? null,
        variableId: query.variableId ?? null,
        environmentId: query.environmentId ?? null,
        visibility: adminVisibility
          ? { kind: "admin" }
          : { kind: "class1-or-self", selfUserId: actor.userId },
      })
      .map((row) => toAuditEventValue(row, adminVisibility)),
  );
});
