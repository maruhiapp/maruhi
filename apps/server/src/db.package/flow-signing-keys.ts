// Repository of the CLI login flow signing key (AUTH_SPEC §4-2 —
// at most one row).

import { eq } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import { tryD1 } from "./errors.ts";
import { flowSigningKeys } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

// D1 access goes through the shared tryD1 adapter (errors.ts —
// ADR-0006). Every method pipes `Effect.orDie` at its boundary: the
// public repository types keep an empty error channel because the
// handlers turning D1FailureError into typed errors belong to other
// lanes. An unexpected D1 failure stays a defect = a 500, as before

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
      tryD1(async () => {
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
      }).pipe(Effect.orDie),
  };
}
