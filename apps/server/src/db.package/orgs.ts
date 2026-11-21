import type { OrgId, OrgRole, UserId } from "@maruhi/core";
import { and, eq } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import { tryD1 } from "./errors.ts";
import { memberships } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

interface OrgRepoShape {
  readonly roleOf: (orgId: OrgId, userId: UserId) => Effect.Effect<OrgRole | null>;
}

export class OrgRepo extends Context.Service<OrgRepo, OrgRepoShape>()("OrgRepo") {}

export function makeOrgRepo(db: Db): OrgRepoShape {
  return {
    roleOf: (orgId, userId) =>
      tryD1(async () => {
        const row = await db
          .select({ role: memberships.role })
          .from(memberships)
          .where(and(eq(memberships.orgId, orgId), eq(memberships.userId, userId)))
          .get();
        return row === undefined ? null : (row.role as OrgRole);
      }).pipe(Effect.orDie),
  };
}
