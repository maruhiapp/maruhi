// Repository of the recovery-code wrap (AUTH_SPEC §13 — at most one
// blob per user).

import { and, eq } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import type { RecoveryFetchDecision, RecoveryWrapRecord } from "../auth-domain.ts";
import { type D1AuditActor, userAuditInsert } from "./audit.ts";
import { KEY_BLOB_FETCH_LIMIT, type KeyWrapRepoShape } from "./key-wraps.ts";
import { keyWrapWindows, recoveryWraps } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

const run = <T>(evaluate: () => Promise<T>): Effect.Effect<T> => Effect.promise(evaluate);

// ---------------------------------------------------------------------------
// RecoveryRepo (AUTH_SPEC §13. At most one blob per user)
// ---------------------------------------------------------------------------

/**
 * The blob-fetch rate limit (AUTH_SPEC §13-3: 5 per hour per user).
 * Since KL3 (§13-8) it is counted in one window **summed by kind** with
 * passkey / guardian-group wrap fetches (`key_wrap_windows` kind =
 * blob-fetch — KeyWrapRepo.consumeWindow). The limit value is
 * unchanged.
 */
export const RECOVERY_FETCH_LIMIT = KEY_BLOB_FETCH_LIMIT;

interface RecoveryRepoShape {
  /**
   * Registration / re-issuance = a replacing upsert (§13-1; the old
   * wrap disappears the moment the new one is accepted). Records
   * auth.recovery_code_reissued in the same batch (AUDIT_SPEC §3.1 /
   * AUTH_SPEC §13-5; the first registration is the same replacing
   * acceptance, hence the same event).
   */
  readonly upsert: (
    userId: string,
    wrap: { readonly suite: string; readonly nonceHex: string; readonly ciphertextHex: string },
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<void>;
  readonly find: (userId: string) => Effect.Effect<RecoveryWrapRecord | null>;
  /**
   * Advances the fixed-window count and returns whether the fetch is
   * allowed (§13-3). When no row exists it is allowed (a 404 is not
   * counted — the caller judges via find). A read → conditional-update
   * pair of statements, best-effort in that concurrent requests may
   * slightly exceed the count. When allowed, records
   * auth.recovery_blob_fetched (a watch-listed event — AUDIT_SPEC §3.1)
   * in the same batch as the count update (a denial = no distribution
   * is not recorded).
   */
  readonly recordFetch: (
    userId: string,
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
      run(async () => {
        await db.batch([
          // A re-issuance is a new blob, so the fetch window (the
          // summed window — §13-8) is reset too (the trial history
          // against the old blob is not carried over to the new one)
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
      }),
    find: (userId) =>
      run(async () => {
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
      }),
    // Since KL3 (§13-8) the fetch count is kept in the fixed window
    // summed with passkey / guardian-group wrap fetches
    // (KeyWrapRepo.consumeWindow — a single conditional UPSERT + a
    // changes() = 1 guarded audit bundled in). The caller judges the
    // 404 via find first, so an unregistered user does not consume the
    // window (the §13-3 line is unchanged)
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
