import type { UserId } from "@maruhi/core";
import { and, eq } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import type { RecoveryFetchDecision, RecoveryWrapRecord } from "../auth-domain.ts";
import { type D1AuditActor, userAuditInsert } from "./audit.ts";
import { tryD1 } from "./errors.ts";
import { KEY_BLOB_FETCH_LIMIT, type KeyWrapRepoShape } from "./key-wraps.ts";
import { keyWrapWindows, recoveryWraps } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

export const RECOVERY_FETCH_LIMIT = KEY_BLOB_FETCH_LIMIT;

interface RecoveryRepoShape {
  readonly upsert: (
    userId: UserId,
    wrap: { readonly suite: string; readonly nonceHex: string; readonly ciphertextHex: string },
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<void>;
  readonly find: (userId: UserId) => Effect.Effect<RecoveryWrapRecord | null>;
  readonly recordFetch: (
    userId: UserId,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<RecoveryFetchDecision>;
}

export class RecoveryRepo extends Context.Service<RecoveryRepo, RecoveryRepoShape>()(
  "RecoveryRepo",
) {}

export function makeRecoveryRepo(db: Db, keyWraps: KeyWrapRepoShape): RecoveryRepoShape {
  return {
    upsert: (userId, wrap, nowMs, actor) =>
      tryD1(async () => {
        await db.batch([
          db
            .delete(keyWrapWindows)
            .where(and(eq(keyWrapWindows.userId, userId), eq(keyWrapWindows.kind, "blob-fetch"))),
          db
            .insert(recoveryWraps)
            .values({
              userId,
              suite: wrap.suite,
              nonceHex: wrap.nonceHex,
              ciphertextHex: wrap.ciphertextHex,
              createdAt: nowMs,
              updatedAt: nowMs,
            })
            .onConflictDoUpdate({
              target: recoveryWraps.userId,
              set: {
                suite: wrap.suite,
                nonceHex: wrap.nonceHex,
                ciphertextHex: wrap.ciphertextHex,
                updatedAt: nowMs,
              },
            }),
          userAuditInsert(db, nowMs, { event: "auth.recovery_code_reissued", actor }),
        ]);
      }).pipe(Effect.orDie),
    find: (userId) =>
      tryD1(async () => {
        const row = await db
          .select({
            suite: recoveryWraps.suite,
            nonceHex: recoveryWraps.nonceHex,
            ciphertextHex: recoveryWraps.ciphertextHex,
            updatedAt: recoveryWraps.updatedAt,
          })
          .from(recoveryWraps)
          .where(eq(recoveryWraps.userId, userId))
          .get();
        return row === undefined
          ? null
          : {
              suite: row.suite,
              nonceHex: row.nonceHex,
              ciphertextHex: row.ciphertextHex,
              updatedAtMs: row.updatedAt,
            };
      }).pipe(Effect.orDie),
    recordFetch: (userId, nowMs, actor) =>
      keyWraps.consumeWindow({
        userId,
        kind: "blob-fetch",
        limit: RECOVERY_FETCH_LIMIT,
        nowMs,
        audit: { event: "auth.recovery_blob_fetched", actor },
      }),
  };
}
