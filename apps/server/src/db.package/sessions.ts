import type { AuthMethod, UserId } from "@maruhi/core";
import { eq, lte } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import type { SessionRecord } from "../auth-domain.ts";
import { userAuditInsert } from "./audit.ts";
import { tryD1 } from "./errors.ts";
import { sessions } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

export interface SessionRepoShape {
  readonly insert: (
    idHash: string,
    userId: UserId,
    authMethod: AuthMethod,
    nowMs: number,
    expiresAtMs: number,
  ) => Effect.Effect<void>;
  readonly findByHash: (idHash: string) => Effect.Effect<SessionRecord | null>;
  readonly touch: (idHash: string, nowMs: number, expiresAtMs: number) => Effect.Effect<void>;
  readonly revokeByHash: (idHash: string, nowMs: number) => Effect.Effect<void>;
  readonly deleteByHash: (idHash: string) => Effect.Effect<void>;
  readonly deleteExpired: (nowMs: number) => Effect.Effect<void>;
}

export class SessionRepo extends Context.Service<SessionRepo, SessionRepoShape>()("SessionRepo") {}

export function makeSessionRepo(db: Db): SessionRepoShape {
  return {
    insert: (idHash, userId, authMethod, nowMs, expiresAtMs) =>
      tryD1(async () => {
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
      }).pipe(Effect.orDie),
    findByHash: (idHash) =>
      tryD1(async () => {
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
      }).pipe(Effect.orDie),
    touch: (idHash, nowMs, expiresAtMs) =>
      tryD1(async () => {
        await db
          .update(sessions)
          .set({ lastUsedAt: nowMs, expiresAt: expiresAtMs })
          .where(eq(sessions.id, idHash));
      }).pipe(Effect.orDie),
    revokeByHash: (idHash, nowMs) =>
      tryD1(async () => {
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
      }).pipe(Effect.orDie),
    deleteByHash: (idHash) =>
      tryD1(async () => {
        await db.delete(sessions).where(eq(sessions.id, idHash));
      }).pipe(Effect.orDie),
    deleteExpired: (nowMs) =>
      tryD1(async () => {
        await db.delete(sessions).where(lte(sessions.expiresAt, nowMs));
      }).pipe(Effect.orDie),
  };
}
