import type { OrgId, ProjectId, UserId } from "@maruhi/core";
import { and, count, eq, gt, inArray } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import { type D1AuditActor, orgAuditInsert } from "./audit.ts";
import { tryD1 } from "./errors.ts";
import { projectMembers, projects } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

interface ProjectRepoShape {
  readonly insertIfAbsent: (
    projectId: ProjectId,
    orgId: OrgId,
    ownerUserId: UserId,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<void>;
  readonly exists: (projectId: ProjectId) => Effect.Effect<boolean>;
  readonly countInOrg: (orgId: OrgId) => Effect.Effect<number>;
  readonly upsertMember: (
    projectId: ProjectId,
    userId: UserId,
    nowMs: number,
  ) => Effect.Effect<void>;
  readonly deleteMember: (projectId: ProjectId, userId: UserId) => Effect.Effect<void>;
  readonly listMemberProjectIds: (
    userId: UserId,
    afterProjectId: ProjectId | null,
    limit: number,
    withinProjectIds: readonly ProjectId[] | null,
  ) => Effect.Effect<readonly ProjectId[]>;
}

export class ProjectRepo extends Context.Service<ProjectRepo, ProjectRepoShape>()("ProjectRepo") {}

const SCOPE_FILTER_CHUNK_SIZE = 50;

export function makeProjectRepo(db: Db): ProjectRepoShape {
  return {
    insertIfAbsent: (projectId, orgId, ownerUserId, nowMs, actor) =>
      tryD1(() =>
        db.batch([
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
        ]),
      ).pipe(
        Effect.catchTag("D1UniqueConflict", () => Effect.void),
        Effect.asVoid,
        Effect.orDie,
      ),
    exists: (projectId) =>
      tryD1(async () => {
        const row = await db
          .select({ id: projects.id })
          .from(projects)
          .where(eq(projects.id, projectId))
          .get();
        return row !== undefined;
      }).pipe(Effect.orDie),
    countInOrg: (orgId) =>
      tryD1(async () => {
        const row = await db
          .select({ n: count() })
          .from(projects)
          .where(eq(projects.orgId, orgId))
          .get();
        return row?.n ?? 0;
      }).pipe(Effect.orDie),
    upsertMember: (projectId, userId, nowMs) =>
      tryD1(async () => {
        await db
          .insert(projectMembers)
          .values({ projectId, userId, createdAt: nowMs })
          .onConflictDoNothing();
      }).pipe(Effect.orDie),
    deleteMember: (projectId, userId) =>
      tryD1(async () => {
        await db
          .delete(projectMembers)
          .where(and(eq(projectMembers.projectId, projectId), eq(projectMembers.userId, userId)));
      }).pipe(Effect.orDie),
    listMemberProjectIds: (userId, afterProjectId, limit, withinProjectIds) =>
      tryD1(async () => {
        const pageQuery = (
          scopeChunk: readonly ProjectId[] | null,
        ): Promise<{ projectId: ProjectId }[]> => {
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
        const merged: ProjectId[] = [];
        for (let offset = 0; offset < withinProjectIds.length; offset += SCOPE_FILTER_CHUNK_SIZE) {
          const chunk = withinProjectIds.slice(offset, offset + SCOPE_FILTER_CHUNK_SIZE);
          merged.push(...(await pageQuery(chunk)).map((row) => row.projectId));
        }
        return merged.toSorted().slice(0, limit);
      }).pipe(Effect.orDie),
  };
}
