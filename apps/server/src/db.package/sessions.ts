// Repository of sessions (AUTH_SPEC §5 — the id is a hash; the raw
// value never reaches this layer).

import { eq, lte } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import type { SessionRecord } from "../auth-domain.ts";
import { userAuditInsert } from "./audit.ts";
import { sessions } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

const run = <T>(evaluate: () => Promise<T>): Effect.Effect<T> => Effect.promise(evaluate);

// ---------------------------------------------------------------------------
// SessionRepo (§5. The id is a hash; the raw value never reaches this
// layer)
// ---------------------------------------------------------------------------

export interface SessionRepoShape {
  readonly insert: (
    idHash: string,
    userId: string,
    authMethod: string,
    nowMs: number,
    expiresAtMs: number,
  ) => Effect.Effect<void>;
  readonly findByHash: (idHash: string) => Effect.Effect<SessionRecord | null>;
  /** The sliding update (§5): advances last_used_at and expires_at. */
  readonly touch: (idHash: string, nowMs: number, expiresAtMs: number) => Effect.Effect<void>;
  /**
   * Explicit revocation (logout / server-side revocation). Records
   * auth.session_revoked in the same batch (AUDIT_SPEC §3.1). Expired-row
   * cleanup uses deleteByHash / deleteExpired (not a revocation event,
   * so nothing is recorded).
   */
  readonly revokeByHash: (idHash: string, nowMs: number) => Effect.Effect<void>;
  readonly deleteByHash: (idHash: string) => Effect.Effect<void>;
  /** The bulk cleanup of expired rows (called from cron; a row never presented disappears only here). */
  readonly deleteExpired: (nowMs: number) => Effect.Effect<void>;
}

export class SessionRepo extends Context.Service<SessionRepo, SessionRepoShape>()("SessionRepo") {}

export function makeSessionRepo(db: Db): SessionRepoShape {
  return {
    // auth.login_succeeded is 1:1 with session creation (AUDIT_SPEC
    // §3.1 — auth.session_created is not an independent event), so it
    // is recorded in the same batch. The session id (= the same hash as
    // the stored id — not the raw value, AUTH_SPEC §10) is copied into
    // the payload for cross-checking against the revocation event
    insert: (idHash, userId, authMethod, nowMs, expiresAtMs) =>
      run(async () => {
        await db.batch([
          db.insert(sessions).values({
            id: idHash,
            userId,
            authMethod,
            createdAt: nowMs,
            expiresAt: expiresAtMs,
            lastUsedAt: nowMs,
          }),
          userAuditInsert(db, nowMs, {
            event: "auth.login_succeeded",
            actor: { userId, authMethod },
            payload: { sessionId: idHash },
          }),
        ]);
      }),
    findByHash: (idHash) =>
      run(async () => {
        const row = await db
          .select({
            userId: sessions.userId,
            authMethod: sessions.authMethod,
            expiresAt: sessions.expiresAt,
          })
          .from(sessions)
          .where(eq(sessions.id, idHash))
          .get();
        return row === undefined
          ? null
          : { userId: row.userId, authMethod: row.authMethod, expiresAtMs: row.expiresAt };
      }),
    touch: (idHash, nowMs, expiresAtMs) =>
      run(async () => {
        await db
          .update(sessions)
          .set({ lastUsedAt: nowMs, expiresAt: expiresAtMs })
          .where(eq(sessions.id, idHash));
      }),
    revokeByHash: (idHash, nowMs) =>
      run(async () => {
        // The event is written after observing the deletion's success
        // via returning (the actor is also copied from it). A read →
        // delete two-step would let two concurrent logouts both succeed
        // on the SELECT and record 2 rows for 1 revocation. Splitting
        // the delete and the append into 2 statements leaves a
        // theoretical window where "only the delete succeeded and the
        // event is missing", but we fall toward the missing side over
        // the duplicate side. No row = no-op (a nonexistent revocation
        // is not evented)
        const deleted = await db
          .delete(sessions)
          .where(eq(sessions.id, idHash))
          .returning({ userId: sessions.userId, authMethod: sessions.authMethod });
        const row = deleted[0];
        if (row === undefined) {
          return;
        }
        await userAuditInsert(db, nowMs, {
          event: "auth.session_revoked",
          actor: { userId: row.userId, authMethod: row.authMethod },
          payload: { sessionId: idHash },
        });
      }),
    deleteByHash: (idHash) =>
      run(async () => {
        await db.delete(sessions).where(eq(sessions.id, idHash));
      }),
    deleteExpired: (nowMs) =>
      run(async () => {
        await db.delete(sessions).where(lte(sessions.expiresAt, nowMs));
      }),
  };
}
