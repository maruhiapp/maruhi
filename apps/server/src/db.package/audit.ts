// Appends to and reads of the D1-side audit log (AUDIT_SPEC §3.1-§3.2 /
// §5.2 option A / §7).
//
// - append-only (§1-4): this layer exposes only append and read (no update
//   or delete surface)
// - Appending in the same transaction as the primary data write (the §5.2
//   adoption rationale (2)) is realized by each repository bundling an
//   insert statement (userAuditInsert / orgAuditInsert) into its own batch.
//   Only standalone appends (login_failed and other events with no primary
//   data write) use D1AuditRepo
// - Reads (§7) are only the invite.* project_id scope (the permission axis
//   is enforced by the worker via chain role admin) and the self axis of
//   user-family events. The org admin axis ships together with the org
//   management API
// - Identity rule (§1-2): actor / target carry only the internal user_id
//   (+ the maruhi-issued token id) and the auth_method kind name. Provider
//   IDs, logins, and emails must not enter this layer

import type { AuditActor } from "@maruhi/core";
import { auditPayloadWith } from "@maruhi/core";
import { and, desc, eq, inArray, lt, or, type SQL, sql } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import { randomHex } from "../ids.ts";
import { tryD1 } from "./errors.ts";
import { loginFailedWindows, orgAuditEvents, userAuditEvents } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

// D1 access goes through the shared tryD1 adapter (errors.ts —
// ADR-0006). Every method pipes `Effect.orDie` at its boundary: the
// public repository types keep an empty error channel because the
// handlers turning D1FailureError into typed errors belong to other
// lanes. An unexpected D1 failure stays a defect = a 500, as before

/**
 * The audit actor (AUDIT_SPEC §2). Derived from the shared AuditActor
 * (@maruhi/core — the sole exit of the auditActorOf mapping from an
 * authenticated principal), with only userId made omittable: an omission
 * means "an unauthenticated external principal" (auth.login_failed only —
 * a person exists but is not identified. type=system is for internal
 * processing with no principal, not for failed attempts from outside).
 */
export type D1AuditActor = Omit<AuditActor, "userId"> & { readonly userId?: string };

/** Input for one audit-event row (columns are the common columns of schema.ts; unspecified = NULL). */
export interface D1AuditEventInput {
  readonly event: string;
  readonly actor: D1AuditActor;
  readonly targetUserId?: string;
  readonly orgId?: string;
  readonly projectId?: string;
  readonly payload?: Readonly<Record<string, unknown>>;
}

/** Mapping onto the inserted row. auth_method rides the payload, as on the DO side (§2). */
function rowOf(event: D1AuditEventInput, serverTs: number) {
  const payload = auditPayloadWith(event.actor, event.payload);
  return {
    // The wire row identifier (AUDIT_SPEC §5.1 row_id — §7's opaque cursor)
    rowId: randomHex(16),
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

/** The insert statement for an auth-family event (§3.1). Bundled into a repository's batch. */
export function userAuditInsert(db: Db, serverTs: number, event: D1AuditEventInput) {
  return db.insert(userAuditEvents).values(rowOf(event, serverTs));
}

/**
 * The shared select columns for a `changes() = 1`-guarded INSERT…SELECT
 * (AUDIT_SPEC §5.2 — insert the audit row only when the preceding
 * conditional UPDATE took effect). The SELECT-side version of rowOf's
 * column mapping — if the callers (the invites CAS, the recovery fetch
 * count) each copied the column list by hand, they would silently diverge
 * when the row shape changes.
 * The caller owns the FROM, the WHERE (the guard condition), and the extra
 * column (invites' project_id).
 */
export function guardedAuditSelectColumns(input: {
  readonly event: string;
  readonly actor: D1AuditActor;
  readonly nowMs: number;
  readonly targetUserId?: string | null;
  readonly payload?: Readonly<Record<string, unknown>>;
  /** A dynamic payload built from the stored row. When given, it takes precedence over the static payload. */
  readonly payloadSql?: SQL<string | null>;
}) {
  const payload = auditPayloadWith(input.actor, input.payload);
  const payloadSql =
    input.payloadSql ??
    sql<string | null>`${Object.keys(payload).length === 0 ? null : JSON.stringify(payload)}`;
  return {
    // The wire row identifier (AUDIT_SPEC §5.1 row_id). A guarded insert
    // produces at most one row, so a constant picked at statement-build
    // time suffices
    rowId: sql<string>`${randomHex(16)}`.as("row_id"),
    serverTs: sql<number>`${input.nowMs}`.as("server_ts"),
    event: sql<string>`${input.event}`.as("event"),
    actorType: sql<string>`'user'`.as("actor_type"),
    actorUserId: sql<string | null>`${input.actor.userId ?? null}`.as("actor_user_id"),
    actorApiTokenId: sql<string | null>`${input.actor.apiTokenId ?? null}`.as("actor_api_token_id"),
    targetUserId: sql<string | null>`${input.targetUserId ?? null}`.as("target_user_id"),
    payload: payloadSql.as("payload"),
  };
}

/** The insert statement for an org-family event (§3.2). Bundled into a repository's batch. */
export function orgAuditInsert(db: Db, serverTs: number, event: D1AuditEventInput) {
  return db.insert(orgAuditEvents).values(rowOf(event, serverTs));
}

/**
 * The recording cap for auth.login_failed (AUDIT_SPEC §3.1). login_failed
 * is the only D1 write reachable over the unauthenticated path; to bound
 * the write amplification from a flood of invalid requests (an
 * availability / cost attack), excess over a fixed-window cap is not
 * recorded. The cap is counted in buckets of `auth_method + reason`: a
 * single window or a method-only window would let a flood from a different
 * path or for a different reason erase even the reason of a targeted
 * failure.
 */
export const LOGIN_FAILED_WINDOW_MS = 60 * 60 * 1000;
export const LOGIN_FAILED_WINDOW_LIMIT = 100;

interface LoginFailedBucket {
  readonly authMethod: string;
  readonly reason: string;
}

/** The mutable counter's primary key. No external ID / IP — only the classification the audit row itself carries. */
function loginFailedBucketKey(bucket: LoginFailedBucket): string {
  return JSON.stringify([bucket.authMethod, bucket.reason]);
}

/**
 * The aggregation marker left on a window that reached its cap
 * (AUDIT_SPEC §3.1). To make not only the **fact** of suppression but also
 * its **volume** observable, one row is left whenever the bucket's
 * suppressed count reaches a power of ten (1, 10, 100, …) — writes are
 * logarithmic in the suppressed count (a few rows per window even under a
 * flood). As on the individual rows, actor is type=user with no user_id
 * (no external provider ID or IP on an append-only actor — §1-2).
 */
const LOGIN_FAILED_SUPPRESSED_EVENT = "auth.login_failed_suppressed";

/**
 * The suppression marker for auth.signup_denied (AUDIT_SPEC §3.1). Same
 * fixed-window / power-of-ten discipline as login_failed; the bucket is
 * event name + reason.
 */
const SIGNUP_DENIED_SUPPRESSED_EVENT = "auth.signup_denied_suppressed";

/** Whether the count is one that leaves a suppression marker (1, 10, 100, … — see the doc above). */
function isSuppressionMilestone(suppressedCount: number): boolean {
  if (suppressedCount < 1) {
    return false;
  }
  // Exactly a decimal carry boundary (judged by integer division to avoid
  // log10 rounding error)
  let remaining = suppressedCount;
  while (remaining % 10 === 0) {
    remaining /= 10;
  }
  return remaining === 1;
}

// ---------------------------------------------------------------------------
// The read surface (AUDIT_SPEC §7). seq-cursor paging (newest first).
// ---------------------------------------------------------------------------

/**
 * A page specification (descending seq). beforeRowId is the row_id of the
 * previous page's last row (the §7 opaque cursor). Resolution happens under
 * each read's visibility predicate; an out-of-predicate or unknown id
 * behaves as an empty page (never an existence oracle).
 */
interface D1AuditReadPage {
  readonly beforeRowId: string | null;
  readonly limit: number;
}

/** The read shape of a D1 audit row (the common columns the §7 response carries; NULL is null). */
export interface D1StoredAuditEventRow {
  readonly seq: number;
  /** The wire row identifier (row_id — a 16-byte random hex). */
  readonly rowId: string;
  readonly serverTs: number;
  readonly event: string;
  readonly actorType: string;
  readonly actorUserId: string | null;
  readonly actorApiTokenId: string | null;
  readonly targetUserId: string | null;
  readonly orgId: string | null;
  readonly projectId: string | null;
  readonly payload: Readonly<Record<string, unknown>> | null;
}

/** The invite lifecycle's event names (§3.2). Org-family events are not mixed in. */
export const INVITE_AUDIT_EVENTS = ["invite.created", "invite.accepted", "invite.revoked"] as const;

interface D1AuditRepoShape {
  /** Append a standalone event (for events with no primary data write). */
  readonly appendUserEvent: (event: D1AuditEventInput, serverTs: number) => Effect.Effect<void>;
  /**
   * The append dedicated to auth.login_failed. Once the fixed-window (one
   * hour) recording cap is exceeded, individual rows are dropped and only
   * the suppression marker is kept (a SHOULD record — AUDIT_SPEC §3.1).
   *
   * `bucket` is the unit the cap counts in (auth_method + reason).
   * Do not pass a source identifier (the §1-2 line; the reason is §3.1).
   */
  readonly appendLoginFailed: (
    event: D1AuditEventInput,
    serverTs: number,
    bucket: LoginFailedBucket,
  ) => Effect.Effect<void>;
  /**
   * The append dedicated to auth.signup_denied (AUDIT_SPEC §3.1). Same
   * fixed-window cap discipline as login_failed; the bucket is per reason
   * (an independent window per denial reason — a flood for one reason must
   * not erase a targeted denial for another). Do not pass the presented
   * external provider ID (§1-2).
   */
  readonly appendSignupDenied: (
    event: D1AuditEventInput,
    serverTs: number,
    reason: string,
  ) => Effect.Effect<void>;
  /**
   * The project_id-scoped read of invite.* (the §7 exception clause). The
   * permission axis (chain role admin-or-above on the project × token scope
   * admin) is enforced by the worker-side handler — this layer carries only
   * the predicate.
   */
  readonly readProjectInviteEvents: (
    projectId: string,
    page: D1AuditReadPage,
  ) => Effect.Effect<readonly D1StoredAuditEventRow[]>;
  /**
   * The self-axis read of user-family events (§3.1) (§6: self only).
   * Returns only rows whose actor or target is the user. auth.login_failed
   * carries no actor user_id (§3.1), so it appears on no self axis (the
   * operator view's remit — L-4).
   */
  readonly readUserEventsFor: (
    userId: string,
    page: D1AuditReadPage,
  ) => Effect.Effect<readonly D1StoredAuditEventRow[]>;
}

export class D1AuditRepo extends Context.Service<D1AuditRepo, D1AuditRepoShape>()("D1AuditRepo") {}

/** Defensive parse of the payload column (JSON) — a corrupted row is treated as null so the read is not turned into a defect. */
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

/** One raw read of selectAuditPage. */
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
      // org_id is always NULL on this PR's two paths (invite.*
      // intentionally does not carry it, and the user family has no
      // writer), but this helper is generic over both tables, so do not
      // drop it from the projection — it must not silently go missing when
      // the future org admin axis arrives
      orgId: table.orgId,
      projectId: table.projectId,
      payload: table.payload,
    })
    .from(table)
    .where(where)
    .orderBy(desc(table.seq))
    .limit(page.limit);
}

/**
 * Read with the page condition (descending seq + a row_id cursor) composed
 * into the predicate. The cursor's row_id → seq resolution happens under
 * **the same visibility predicate** (pointing at a row outside the
 * predicate is identical to "unknown" = an empty page. Never an existence
 * oracle — AUDIT_SPEC §7).
 */
async function selectAuditPage(
  db: Db,
  table: D1AuditTable,
  predicate: SQL | undefined,
  page: D1AuditReadPage,
): Promise<readonly D1StoredAuditEventRow[]> {
  const rows = await readAuditPageRows(db, table, predicate, page);
  return rows.map((row) => ({ ...row, payload: parseStoredPayload(row.payload) }));
}

/**
 * A fixed-window-capped append for unauthenticated events (AUDIT_SPEC
 * §3.1 — the shared mechanism of auth.login_failed and
 * auth.signup_denied).
 *
 * Window counting uses a dedicated counter row, not a scan of the audit
 * log: scanning the ever-growing append-only user_audit_events on every
 * unauthenticated-path append would make the very flood we want to bound
 * into a cost amplifier. Window reset, increment, and cap judgment are
 * folded into one conditional UPSERT statement, and the decision is
 * derived from RETURNING's new counts (the same shape as the recovery
 * fetch count — recovery.ts). The counter table loginFailedWindows is shared
 * (bucketKey separates the namespaces — it is mutable state, not an audit
 * row; the table name is the historical name of the introducing event).
 */
async function appendWithFixedWindow(
  db: Db,
  event: D1AuditEventInput,
  serverTs: number,
  spec: {
    readonly bucketKey: string;
    readonly markerEvent: string;
    /** The classification part of the marker payload (window length, cap, and suppressed count are added here). */
    readonly markerBasePayload: Readonly<Record<string, unknown>>;
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
  // Within a window, recorded grows to the cap before suppressed grows
  // (the two never advance together). So "the cap is reached and
  // suppressed is at least 1" is a sufficient condition for a suppressed
  // request — the **last allowed** one at exactly the cap still passes
  // with suppressed = 0
  const recorded = counted?.recordedCount ?? 1;
  const suppressed = counted?.suppressedCount ?? 0;
  if (recorded >= LOGIN_FAILED_WINDOW_LIMIT && suppressed >= 1) {
    // The individual row is dropped, but suppression does not happen
    // silently: a marker row is left whenever the suppressed count reaches
    // a power of ten. The rows' density and the last count reveal the
    // suppression's scale, and writes stay logarithmically bounded in the
    // count
    if (isSuppressionMilestone(suppressed)) {
      await userAuditInsert(db, serverTs, {
        event: spec.markerEvent,
        actor: {},
        // The individual row's payload is not carried (AUDIT_SPEC §3.1:
        // a marker's payload is only the classification part, the window
        // length, the cap, and the suppressed count). A marker describes
        // the window's state, not this one request, so the last individual
        // row does not represent it
        payload: {
          ...spec.markerBasePayload,
          windowMs: LOGIN_FAILED_WINDOW_MS,
          limit: LOGIN_FAILED_WINDOW_LIMIT,
          suppressedCount: suppressed,
        },
      });
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
          markerEvent: LOGIN_FAILED_SUPPRESSED_EVENT,
          markerBasePayload: { authMethod: bucket.authMethod, reason: bucket.reason },
        }),
      ).pipe(Effect.orDie),
    appendSignupDenied: (event, serverTs, reason) =>
      tryD1(() =>
        appendWithFixedWindow(db, event, serverTs, {
          // The bucket namespaces are separated by event name (cannot
          // collide with login_failed's [authMethod, reason] key)
          bucketKey: JSON.stringify(["auth.signup_denied", reason]),
          markerEvent: SIGNUP_DENIED_SUPPRESSED_EVENT,
          markerBasePayload: { authMethod: "github_oauth", reason },
        }),
      ).pipe(Effect.orDie),
    readProjectInviteEvents: (projectId, page) =>
      tryD1(() =>
        selectAuditPage(
          db,
          orgAuditEvents,
          // The event-name narrowing is invite.* only (§7): org-family
          // events with the same project_id (org.project_created etc.) are
          // the org admin axis's remit and must not leak into the project
          // audit path
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
