// Effect programs for reading a project DO's audit events
// (AUDIT_SPEC §6 / §7).
//
// - Visibility classes (§6) are enforced at the authorization stage:
//   admin visibility (all rows) is "chain role admin-or-above × token
//   scope admin" (§12-3's min(scope, role) discipline — the worker
//   judges scopeAdmin and passes it in). Below that, only class-1
//   rows and rows where the requester is the actor are visible, and
//   class-2 rows appear in neither the count, the pages, nor the
//   cursor (audit-store.ts's WHERE clause — "they behave as if they
//   do not exist")
// - Specifying someone else in the actor_user_id filter is a 403
//   without admin visibility (§6's "cross-sectional search of rows
//   where someone else is the actor is class 2" — a static rule
//   independent of the data, so no existence information leaks)
// - The response is the rows as recorded (identifiers + recorded
//   payload) only. Resolving display names and validating mirrors is
//   the client's domain (AUDIT_SPEC §7 / §1-5)
//
// The permit-serialization premise is the same as the other
// programs-*.

import { DEFAULT_AUDIT_EVENTS_PAGE_LIMIT, MAX_AUDIT_EVENTS_PAGE_LIMIT } from "@maruhi/api-schema";
import { Effect, type Schema } from "effect";

import type { StoredAuditEventRow } from "../audit-store.ts";
import { AuditStore } from "../audit-store.ts";
import type { DataActor } from "../data/data-plane.ts";
import { rejectData, requireMemberState, roleAtLeast } from "../data/data-plane.ts";
import type { StateCache } from "../do/chain-store.ts";
import { ensureStorageAdmitsAuditHeadExtension } from "../storage-guard.ts";

/** A read query (crosses the RPC boundary). The filter vocabulary is per AUDIT_SPEC §7. */
export interface AuditEventsQueryInput {
  /** The paging cursor = the id of the previous page's last row (row_id — §7's opaque cursor). */
  readonly beforeRowId?: string;
  readonly limit?: number;
  readonly event?: string;
  /** A prefix match on the event namespace (AUDIT_SPEC §7). */
  readonly eventPrefix?: string;
  /** Returns only rows whose chain_seq is not NULL (AUDIT_SPEC §7). */
  readonly chainSeqPresent?: true;
  readonly actorUserId?: string;
  readonly targetUserId?: string;
  readonly variableId?: string;
  readonly environmentId?: string;
  /**
   * The worker-judged token-scope half (whether the admin scope
   * covers the target project). The DO composites it with "× chain
   * role admin-or-above" to decide class-2 visibility. An input of
   * the same worker trust boundary as actor (auditActorOf).
   */
  readonly scopeAdmin: boolean;
}

/** An audit event's actor (structurally identical to the wire's AuditActorSchema). */
export interface AuditActorValue {
  readonly type: "user" | "server" | "system";
  readonly userId?: string;
  readonly keyFingerprintHex?: string;
  readonly apiTokenId?: string;
}

/** One audit-event row (structurally identical to the wire's AuditEventSchema). */
export interface AuditEventValue {
  /** The wire row identifier (row_id — §5.1 / §7). */
  readonly id: string;
  /** The stored seq. Only on admin-visible project DO responses (§7 — non-disclosure of the ordinal). */
  readonly seq?: number;
  readonly serverTs: number;
  readonly clientTs?: number;
  readonly event: string;
  readonly actor: AuditActorValue;
  readonly targetUserId?: string;
  readonly targetKeyFingerprintHex?: string;
  readonly environmentId?: string;
  readonly variableId?: string;
  readonly epoch?: number;
  readonly version?: number;
  readonly chainSeq?: number;
  /** The org axis (D1 rows only; always absent on project DO rows). */
  readonly orgId?: string;
  readonly payload?: Readonly<Record<string, Schema.Json>>;
}

/** The stored row's actor_type column → the actor kind (§2's 3 values; the column is already fixed at write time). */
function actorTypeOf(stored: string): AuditActorValue["type"] {
  return stored === "server" || stored === "system" ? stored : "user";
}

function spreadIf<K extends string, V>(key: K, value: V | null): { readonly [P in K]?: V } {
  return value === null ? {} : ({ [key]: value } as { [P in K]: V });
}

/**
 * Stored row → RPC value. NULL columns are dropped with their keys
 * (same shape as the wire's optionalKey).
 * `seq` rides only on admin-visible responses (§7: the gapless
 * ordinal would leak the class-2 row count to below-admin. §6's
 * "a gap = a trace of deletion" detection is meaningful only to an
 * admin who sees every row).
 */
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
    // A JSON.parse-derived value is always JSON vocabulary at
    // runtime (the Schema.Json check at encode is the last line of
    // defense). unknown → Json is a type-only narrowing
    ...spreadIf("payload", row.payload as Readonly<Record<string, Schema.Json>> | null),
  };
}

/** Resolution of limit (default 50). The Schema already enforces the 200 cap, but the DO side bounds it too (defense in depth). */
export function resolvePageLimit(limit: number | undefined): number {
  const requested = limit ?? DEFAULT_AUDIT_EVENTS_PAGE_LIMIT;
  return Math.max(1, Math.min(requested, MAX_AUDIT_EVENTS_PAGE_LIMIT));
}

/**
 * GET /projects/:projectId/audit-head (AUTH_SPEC §16-2 — the
 * declaration source of checkpoint's audit_head_hash notarization).
 * Authorization is the effective permission admin: the scope half
 * (admin scope) is the worker's (callProjectData's
 * permission: "admin"); the chain-role half is checked here
 * (opening it to member level would let polling of accumulated-hash
 * changes leak the class-2 activity window — §16-2's timing side
 * channel). The response is the accumulated hash only (neither audit
 * seq nor the row count rides — §7's count non-disclosure). Zero
 * audit rows return the empty string.
 */
export const auditHeadProgram = (actor: DataActor, cache: StateCache) =>
  Effect.gen(function* () {
    const context = yield* requireMemberState(actor.userId, "reader", cache);
    if (!roleAtLeast(context.member.role, "admin")) {
      return yield* rejectData({ kind: "insufficient-role" });
    }
    const audit = yield* AuditStore;
    // Extend the accumulated-hash column up to MAX(seq) before
    // reading (lazy materialization — the first call doubles as the
    // initialization migration over existing rows. AUDIT_SPEC §5.1).
    // Note: this GET is read-shaped but is an endpoint that
    // **deliberately writes** (lazy materialization of a derived
    // column = the contract "the read path extends before reading").
    // It is serialized under the op permit and the extension is
    // idempotent, so retries are safe; but introducing response
    // caching or rerouting on the assumption "GET = side-effect-free"
    // would break this side effect.
    // Bounded extension: hitting the cap (= not reaching MAX(seq))
    // returns a retryable audit-head-not-ready (503) rather than a
    // stale head — since the refusal comes after the authorization
    // checks (the 404 / 403 above), it composes with §11-2's
    // existence hiding.
    // The DO storage-total guard (AUTH_SPEC §12-8): only when the
    // materialization above needs a write (the column is short of
    // MAX(seq)), a DO at or beyond the refusal threshold is rejected
    // with 422 project-storage-bytes (reading the audit rows
    // themselves — auditEvents — is not guarded). After the
    // authorization checks (404 / 403) = composes with §11-2
    yield* ensureStorageAdmitsAuditHeadExtension;
    if ((yield* audit.ensureHeadCurrent) === "more-remains") {
      return yield* rejectData({ kind: "audit-head-not-ready" });
    }
    return { auditHeadHashHex: audit.currentHeadHexSync() };
  });

export const auditEventsProgram = (
  actor: DataActor,
  query: AuditEventsQueryInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
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
