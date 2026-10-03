// Repository of the org-attribution metadata and the §11-5 membership
// projection (AUTH_SPEC §11-3, §11-5 — never an authorization table).

import { and, count, eq, gt, inArray } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import { type D1AuditActor, orgAuditInsert } from "./audit.ts";
import { isUniqueConflict } from "./errors.ts";
import { projectMembers, projects } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

const run = <T>(evaluate: () => Promise<T>): Effect.Effect<T> => Effect.promise(evaluate);

// ---------------------------------------------------------------------------
// ProjectRepo (§11-3. The org-attribution metadata + the §11-5
// membership projection. Neither is an authorization table — the
// projection is a discovery-only candidate index and is never used in
// an authorization decision. The source of truth is the membership
// chain — CRYPTO_SPEC §6.4)
// ---------------------------------------------------------------------------

interface ProjectRepoShape {
  /**
   * An idempotent insert (§11-3 including the repair path). An existing
   * row is left as-is. Records org.project_created (AUDIT_SPEC §3.2) and
   * the genesis actor's (owner's) membership projection row (§11-5) in
   * the same batch. By the batch's atomicity, when the insert does not
   * go through because of a conflict with an existing row, the audit
   * row is rolled back too (a whiffed insert never duplicates just the
   * event). The projection row's insert is onConflictDoNothing: on the
   * repair path (§11-3) a lazy upsert (§11-5's (4)) may have already
   * placed the row, and that conflict must not roll back even the
   * projects row's insert.
   */
  readonly insertIfAbsent: (
    projectId: string,
    orgId: string,
    ownerUserId: string,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<void>;
  readonly exists: (projectId: string) => Effect.Effect<boolean>;
  /**
   * The org's active project count (the decision input of AUTH_SPEC
   * §11-3's acceptance limit). In v1 it counts every `projects` row of
   * the org (there is no delete API and no tombstone — when deletion is
   * introduced an exclusion condition is added). A count on the
   * `proj_org` index. It is a best-effort judgment input with no
   * atomicity against DO acceptance (§11-3 — a slight excess from
   * concurrent inits is accepted).
   */
  readonly countInOrg: (orgId: string) => Effect.Effect<number>;
  /**
   * Maintaining the projection (§11-5): the row insert after an
   * add_member acceptance and the lazy insert on a successful chain
   * fetch (self-repair of a missing row + the unmanned backfill of
   * pre-projection projects). Idempotent (equivalent to INSERT OR
   * IGNORE).
   */
  readonly upsertMember: (projectId: string, userId: string, nowMs: number) => Effect.Effect<void>;
  /**
   * Maintaining the projection (§11-5): deletion of a stale row the DO
   * answered non-member on at list read-time verification, after a
   * remove_member acceptance (convergence toward the chain truth).
   * Idempotent.
   */
  readonly deleteMember: (projectId: string, userId: string) => Effect.Effect<void>;
  /**
   * The candidate enumeration of the list (§11-5): the project_ids of
   * the user's own projection rows, ascending, up to `limit` rows from
   * the exclusive cursor `afterProjectId` (null = from the head).
   * Candidates only — the caller's DO check decides whether they may go
   * on the response.
   *
   * `withinProjectIds` is the filter performing the intersection with
   * the token scope **at the candidate-index stage** (null = no
   * restriction). `nextAfter` comes off the tail of the candidate page,
   * so leaving the intersection to a later stage (narrowing the
   * response rows) would let an out-of-scope project_id ride the cursor
   * and leak — the candidate space itself is closed inside the scope.
   */
  readonly listMemberProjectIds: (
    userId: string,
    afterProjectId: string | null,
    limit: number,
    withinProjectIds: readonly string[] | null,
  ) => Effect.Effect<readonly string[]>;
}

export class ProjectRepo extends Context.Service<ProjectRepo, ProjectRepoShape>()("ProjectRepo") {}

/**
 * The chunk width of the scope-intersection IN (the §11-5 candidate
 * enumeration). Sized with headroom inside the budget left after
 * subtracting the 3 parameters userId / after / limit from D1's
 * per-query bound-parameter cap (100 — Cloudflare D1 limits). Pushing
 * the token scope's issuance-time cap (100 entries — AUTH_SPEC §6 /
 * api-schema) into a single IN would exceed the cap, so when changing
 * any of these limits, re-verify the consistency with this value.
 */
const SCOPE_FILTER_CHUNK_SIZE = 50;

export function makeProjectRepo(db: Db): ProjectRepoShape {
  return {
    insertIfAbsent: (projectId, orgId, ownerUserId, nowMs, actor) =>
      run(async () => {
        try {
          await db.batch([
            db.insert(projects).values({ id: projectId, orgId, createdAt: nowMs }),
            db
              .insert(projectMembers)
              .values({ projectId, userId: ownerUserId, createdAt: nowMs })
              .onConflictDoNothing(),
            orgAuditInsert(db, nowMs, {
              event: "org.project_created",
              actor,
              orgId,
              projectId,
            }),
          ]);
        } catch (error) {
          // A PK conflict = already created. The whole batch rolls back,
          // so both insert and audit are a no-op (idempotent). No
          // execution order exists where only the audit row survives.
          // A non-conflict is a defect
          if (!isUniqueConflict(error)) {
            throw error;
          }
        }
      }),
    exists: (projectId) =>
      run(async () => {
        const row = await db
          .select({ id: projects.id })
          .from(projects)
          .where(eq(projects.id, projectId))
          .get();
        return row !== undefined;
      }),
    countInOrg: (orgId) =>
      run(async () => {
        const row = await db
          .select({ n: count() })
          .from(projects)
          .where(eq(projects.orgId, orgId))
          .get();
        return row?.n ?? 0;
      }),
    upsertMember: (projectId, userId, nowMs) =>
      run(async () => {
        await db
          .insert(projectMembers)
          .values({ projectId, userId, createdAt: nowMs })
          .onConflictDoNothing();
      }),
    deleteMember: (projectId, userId) =>
      run(async () => {
        await db
          .delete(projectMembers)
          .where(and(eq(projectMembers.projectId, projectId), eq(projectMembers.userId, userId)));
      }),
    listMemberProjectIds: (userId, afterProjectId, limit, withinProjectIds) =>
      run(async () => {
        const pageQuery = (
          scopeChunk: readonly string[] | null,
        ): Promise<{ projectId: string }[]> => {
          const conditions = [eq(projectMembers.userId, userId)];
          if (afterProjectId !== null) {
            conditions.push(gt(projectMembers.projectId, afterProjectId));
          }
          if (scopeChunk !== null) {
            conditions.push(inArray(projectMembers.projectId, [...scopeChunk]));
          }
          return db
            .select({ projectId: projectMembers.projectId })
            .from(projectMembers)
            .where(and(...conditions))
            .orderBy(projectMembers.projectId)
            .limit(limit)
            .all();
        };
        if (withinProjectIds === null) {
          return (await pageQuery(null)).map((row) => row.projectId);
        }
        // The scope-intersection IN is issued chunked: D1's per-query
        // bound-parameter cap is 100 and the token scope's schema cap is
        // also 100 entries (api-schema auth-api.ts) — a single IN would
        // exceed the cap together with the 3 parameters userId / after
        // / limit, and a legitimately issued wide-scope token's list
        // would hard-fail. Each chunk returns an ascending run of up to
        // `limit` rows, so concatenate + sort-all + cut-at-limit gives
        // the same page as a single query (the chunks are disjoint ID
        // sets). The loop shape is also safe against old rows whose
        // stored scope exceeds the issuance-time cap
        const merged: string[] = [];
        for (let offset = 0; offset < withinProjectIds.length; offset += SCOPE_FILTER_CHUNK_SIZE) {
          const chunk = withinProjectIds.slice(offset, offset + SCOPE_FILTER_CHUNK_SIZE);
          merged.push(...(await pageQuery(chunk)).map((row) => row.projectId));
        }
        return merged.toSorted().slice(0, limit);
      }),
  };
}
