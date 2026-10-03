// Repository of org membership roles (AUTH_SPEC §9-1 — not involved
// in project access).

import type { OrgRole } from "@maruhi/core";
import { and, eq } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import { memberships } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

const run = <T>(evaluate: () => Promise<T>): Effect.Effect<T> => Effect.promise(evaluate);

// ---------------------------------------------------------------------------
// OrgRepo (§9-1 org roles. Not involved in project access)
// ---------------------------------------------------------------------------

interface OrgRepoShape {
  readonly roleOf: (orgId: string, userId: string) => Effect.Effect<OrgRole | null>;
}

export class OrgRepo extends Context.Service<OrgRepo, OrgRepoShape>()("OrgRepo") {}

export function makeOrgRepo(db: Db): OrgRepoShape {
  return {
    roleOf: (orgId, userId) =>
      run(async () => {
        const row = await db
          .select({ role: memberships.role })
          .from(memberships)
          .where(and(eq(memberships.orgId, orgId), eq(memberships.userId, userId)))
          .get();
        return row === undefined ? null : (row.role as OrgRole);
      }),
  };
}
