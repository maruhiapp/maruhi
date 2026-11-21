import { eq } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import { tryD1 } from "./errors.ts";
import { flowSigningKeys } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

const FLOW_SIGNING_KEY_ID = "v1";

interface FlowSigningKeyRepoShape {
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
          throw new Error("flow signing key insert succeeded but the row is missing");
        }
        return row.keyHex;
      }).pipe(Effect.orDie),
  };
}
