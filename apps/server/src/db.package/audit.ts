import type {
  AUTH_FLOW_FAILURE_REASONS,
  AuditActor,
  AuthMethod,
  OrgId,
  ProjectId,
  SignupDenialReason,
  UserId,
  UserOrgAuditEventPayload,
} from "@maruhi/core";
import { assertUserOrgAuditPayload, auditPayloadWith } from "@maruhi/core";
import { and, desc, eq, inArray, lt, or, type SQL, sql } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import { randomHexSync } from "../ids.ts";
import { tryD1 } from "./errors.ts";
import { loginFailedWindows, orgAuditEvents, userAuditEvents } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

export type D1AuditActor = Omit<AuditActor, "userId"> & { readonly userId?: UserId };

export type D1AuditEventInput = UserOrgAuditEventPayload & {
  readonly actor: D1AuditActor;
  readonly targetUserId?: UserId;
  readonly orgId?: OrgId;
  readonly projectId?: ProjectId;
};

function rowOf(event: D1AuditEventInput, serverTs: number) {
  assertUserOrgAuditPayload(event);
  const payload = auditPayloadWith(event.actor, event.payload);
  return {
    rowId: randomHexSync(16),
    serverTs,
    event: event.event,
    actorType: "user",
    actorUserId: event.actor.userId ?? null,
    actorApiTokenId: event.actor.apiTokenId ?? null,
    targetUserId: event.targetUserId ?? null,
    orgId: event.orgId ?? null,
    projectId: event.projectId ?? null,
    payload: Object.keys(payload).length === 0 ? null : JSON.stringify(payload),
  };
}

export function userAuditInsert(db: Db, serverTs: number, event: D1AuditEventInput) {
  return db.insert(userAuditEvents).values(rowOf(event, serverTs));
}

export function guardedAuditSelectColumns(
  input: UserOrgAuditEventPayload & {
    readonly actor: D1AuditActor;
    readonly nowMs: number;
    readonly targetUserId?: UserId | null;
  } & (
      | { readonly replacedTokenIdSql?: never }
      | {
          readonly event: "auth.token_created";
          readonly replacedTokenIdSql: SQL<string>;
        }
    ),
) {
  assertUserOrgAuditPayload(input);
  const payload = auditPayloadWith(input.actor, input.payload);
  const stored = Object.keys(payload).length === 0 ? null : JSON.stringify(payload);
  const payloadSql =
    input.replacedTokenIdSql === undefined
      ? sql<string | null>`${stored}`
      : sql<
          string | null
        >`json_patch(${stored ?? "{}"}, json_object('replacedTokenId', ${input.replacedTokenIdSql}))`;
  return {
    rowId: sql<string>`${randomHexSync(16)}`.as("row_id"),
    serverTs: sql<number>`${input.nowMs}`.as("server_ts"),
    event: sql<string>`${input.event}`.as("event"),
    actorType: sql<string>`'user'`.as("actor_type"),
    actorUserId: sql<UserId | null>`${input.actor.userId ?? null}`.as("actor_user_id"),
    actorApiTokenId: sql<string | null>`${input.actor.apiTokenId ?? null}`.as("actor_api_token_id"),
    targetUserId: sql<UserId | null>`${input.targetUserId ?? null}`.as("target_user_id"),
    payload: payloadSql.as("payload"),
  };
}

export function orgAuditInsert(db: Db, serverTs: number, event: D1AuditEventInput) {
  return db.insert(orgAuditEvents).values(rowOf(event, serverTs));
}

export const LOGIN_FAILED_WINDOW_MS = 60 * 60 * 1000;
export const LOGIN_FAILED_WINDOW_LIMIT = 100;

interface LoginFailedBucket {
  readonly authMethod: AuthMethod;
  readonly reason: (typeof AUTH_FLOW_FAILURE_REASONS)[number];
}

interface SuppressionCounts {
  readonly windowMs: number;
  readonly limit: number;
  readonly suppressedCount: number;
}

function loginFailedBucketKey(bucket: LoginFailedBucket): string {
  return JSON.stringify([bucket.authMethod, bucket.reason]);
}

const LOGIN_FAILED_SUPPRESSED_EVENT = "auth.login_failed_suppressed" as const;

const SIGNUP_DENIED_SUPPRESSED_EVENT = "auth.signup_denied_suppressed" as const;

function isSuppressionMilestone(suppressedCount: number): boolean {
  if (suppressedCount < 1) {
    return false;
  }
  let remaining = suppressedCount;
  while (remaining % 10 === 0) {
    remaining /= 10;
  }
  return remaining === 1;
}

interface D1AuditReadPage {
  readonly beforeRowId: string | null;
  readonly limit: number;
}

export interface D1StoredAuditEventRow {
  readonly seq: number;
  readonly rowId: string;
  readonly serverTs: number;
  readonly event: string;
  readonly actorType: string;
  readonly actorUserId: UserId | null;
  readonly actorApiTokenId: string | null;
  readonly targetUserId: UserId | null;
  readonly orgId: OrgId | null;
  readonly projectId: ProjectId | null;
  readonly payload: Readonly<Record<string, unknown>> | null;
}

export const INVITE_AUDIT_EVENTS = ["invite.created", "invite.accepted", "invite.revoked"] as const;

interface D1AuditRepoShape {
  readonly appendUserEvent: (event: D1AuditEventInput, serverTs: number) => Effect.Effect<void>;
  readonly appendLoginFailed: (
    event: D1AuditEventInput,
    serverTs: number,
    bucket: LoginFailedBucket,
  ) => Effect.Effect<void>;
  readonly appendSignupDenied: (
    event: D1AuditEventInput,
    serverTs: number,
    reason: SignupDenialReason,
  ) => Effect.Effect<void>;
  readonly readProjectInviteEvents: (
    projectId: ProjectId,
    page: D1AuditReadPage,
  ) => Effect.Effect<readonly D1StoredAuditEventRow[]>;
  readonly readUserEventsFor: (
    userId: UserId,
    page: D1AuditReadPage,
  ) => Effect.Effect<readonly D1StoredAuditEventRow[]>;
}

export class D1AuditRepo extends Context.Service<D1AuditRepo, D1AuditRepoShape>()("D1AuditRepo") {}

function parseStoredPayload(value: string | null): Readonly<Record<string, unknown>> | null {
  if (value === null) {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(value);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

type D1AuditTable = typeof userAuditEvents | typeof orgAuditEvents;

async function readAuditPageRows(
  db: Db,
  table: D1AuditTable,
  predicate: SQL | undefined,
  page: D1AuditReadPage,
): Promise<
  readonly (Omit<D1StoredAuditEventRow, "payload"> & {
    readonly payload: string | null;
  })[]
> {
  let where = predicate;
  if (page.beforeRowId !== null) {
    const cursor = await db
      .select({ seq: table.seq })
      .from(table)
      .where(and(predicate, eq(table.rowId, page.beforeRowId)))
      .get();
    if (cursor === undefined) {
      return [];
    }
    where = and(predicate, lt(table.seq, cursor.seq));
  }
  return db
    .select({
      seq: table.seq,
      rowId: table.rowId,
      serverTs: table.serverTs,
      event: table.event,
      actorType: table.actorType,
      actorUserId: table.actorUserId,
      actorApiTokenId: table.actorApiTokenId,
      targetUserId: table.targetUserId,
      orgId: table.orgId,
      projectId: table.projectId,
      payload: table.payload,
    })
    .from(table)
    .where(where)
    .orderBy(desc(table.seq))
    .limit(page.limit);
}

async function selectAuditPage(
  db: Db,
  table: D1AuditTable,
  predicate: SQL | undefined,
  page: D1AuditReadPage,
): Promise<readonly D1StoredAuditEventRow[]> {
  const rows = await readAuditPageRows(db, table, predicate, page);
  return rows.map((row) => ({ ...row, payload: parseStoredPayload(row.payload) }));
}

async function appendWithFixedWindow(
  db: Db,
  event: D1AuditEventInput,
  serverTs: number,
  spec: {
    readonly bucketKey: string;
    readonly marker: (counts: SuppressionCounts) => D1AuditEventInput;
  },
): Promise<void> {
  const expired = sql`${serverTs} - ${loginFailedWindows.windowStart} >= ${LOGIN_FAILED_WINDOW_MS}`;
  const underLimit = sql`${loginFailedWindows.recordedCount} < ${LOGIN_FAILED_WINDOW_LIMIT}`;
  const counted = await db
    .insert(loginFailedWindows)
    .values({
      bucket: spec.bucketKey,
      windowStart: serverTs,
      recordedCount: 1,
      suppressedCount: 0,
    })
    .onConflictDoUpdate({
      target: loginFailedWindows.bucket,
      set: {
        windowStart: sql`case when ${expired} then ${serverTs} else ${loginFailedWindows.windowStart} end`,
        recordedCount: sql`case when ${expired} then 1 when ${underLimit} then ${loginFailedWindows.recordedCount} + 1 else ${loginFailedWindows.recordedCount} end`,
        suppressedCount: sql`case when ${expired} then 0 when ${underLimit} then ${loginFailedWindows.suppressedCount} else ${loginFailedWindows.suppressedCount} + 1 end`,
      },
    })
    .returning({
      recordedCount: loginFailedWindows.recordedCount,
      suppressedCount: loginFailedWindows.suppressedCount,
    })
    .get();
  const recorded = counted?.recordedCount ?? 1;
  const suppressed = counted?.suppressedCount ?? 0;
  if (recorded >= LOGIN_FAILED_WINDOW_LIMIT && suppressed >= 1) {
    if (isSuppressionMilestone(suppressed)) {
      await userAuditInsert(
        db,
        serverTs,
        spec.marker({
          windowMs: LOGIN_FAILED_WINDOW_MS,
          limit: LOGIN_FAILED_WINDOW_LIMIT,
          suppressedCount: suppressed,
        }),
      );
    }
    return;
  }
  await userAuditInsert(db, serverTs, event);
}

export function makeD1AuditRepo(db: Db): D1AuditRepoShape {
  return {
    appendUserEvent: (event, serverTs) =>
      tryD1(async () => {
        await userAuditInsert(db, serverTs, event);
      }).pipe(Effect.orDie),
    appendLoginFailed: (event, serverTs, bucket) =>
      tryD1(() =>
        appendWithFixedWindow(db, event, serverTs, {
          bucketKey: loginFailedBucketKey(bucket),
          marker: (counts) => ({
            event: LOGIN_FAILED_SUPPRESSED_EVENT,
            actor: {},
            payload: { authMethod: bucket.authMethod, reason: bucket.reason, ...counts },
          }),
        }),
      ).pipe(Effect.orDie),
    appendSignupDenied: (event, serverTs, reason) =>
      tryD1(() =>
        appendWithFixedWindow(db, event, serverTs, {
          bucketKey: JSON.stringify(["auth.signup_denied", reason]),
          marker: (counts) => ({
            event: SIGNUP_DENIED_SUPPRESSED_EVENT,
            actor: {},
            payload: { authMethod: "github_oauth", reason, ...counts },
          }),
        }),
      ).pipe(Effect.orDie),
    readProjectInviteEvents: (projectId, page) =>
      tryD1(() =>
        selectAuditPage(
          db,
          orgAuditEvents,
          and(
            eq(orgAuditEvents.projectId, projectId),
            inArray(orgAuditEvents.event, [...INVITE_AUDIT_EVENTS]),
          ),
          page,
        ),
      ).pipe(Effect.orDie),
    readUserEventsFor: (userId, page) =>
      tryD1(() =>
        selectAuditPage(
          db,
          userAuditEvents,
          or(eq(userAuditEvents.actorUserId, userId), eq(userAuditEvents.targetUserId, userId)),
          page,
        ),
      ).pipe(Effect.orDie),
  };
}
