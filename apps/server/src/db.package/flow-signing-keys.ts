// Repository of the CLI login flow signing key (AUTH_SPEC §4-2 —
// at most one row).

import { eq } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import { flowSigningKeys } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

const run = <T>(evaluate: () => Promise<T>): Effect.Effect<T> => Effect.promise(evaluate);

// ---------------------------------------------------------------------------
// FlowSigningKeyRepo (AUTH_SPEC §4-2. The store of the CLI login flow
// signing key)
// ---------------------------------------------------------------------------

/** The fixed id of the signing-key row (at most one row). */
const FLOW_SIGNING_KEY_ID = "v1";

interface FlowSigningKeyRepoShape {
  /**
   * Auto-generation on first use (AUTH_SPEC §4-2 — does not add to the
   * self-host setup steps). Idempotent, first-one-wins: the candidate
   * key is INSERT OR IGNOREd and the stored row is always read back —
   * closing the branch where two simultaneous first-use requests write
   * different keys and invalidate an in-flight flow. The return value
   * is the winning key (hex).
   */
  readonly getOrCreate: (candidateKeyHex: string, nowMs: number) => Effect.Effect<string>;
}

export class FlowSigningKeyRepo extends Context.Service<
  FlowSigningKeyRepo,
  FlowSigningKeyRepoShape
>()("FlowSigningKeyRepo") {}

export function makeFlowSigningKeyRepo(db: Db): FlowSigningKeyRepoShape {
  return {
    getOrCreate: (candidateKeyHex, nowMs) =>
      run(async () => {
        await db
          .insert(flowSigningKeys)
          .values({ id: FLOW_SIGNING_KEY_ID, keyHex: candidateKeyHex, createdAt: nowMs })
          .onConflictDoNothing();
        const row = await db
          .select({ keyHex: flowSigningKeys.keyHex })
          .from(flowSigningKeys)
          .where(eq(flowSigningKeys.id, FLOW_SIGNING_KEY_ID))
          .get();
        if (row === undefined) {
          // An empty SELECT right after the INSERT OR IGNORE = a D1 failure (defect)
          throw new Error("flow signing key insert succeeded but the row is missing");
        }
        return row.keyHex;
      }),
  };
}
