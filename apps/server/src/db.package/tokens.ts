import type { TokenScope, UserId } from "@maruhi/core";
import { parseTokenScopes } from "@maruhi/core";
import { and, eq, sql, type SQL } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import type { ApiTokenRecord, ApiTokenSummary } from "../auth-domain.ts";
import { type D1AuditActor, guardedAuditSelectColumns, userAuditInsert } from "./audit.ts";
import { tryD1 } from "./errors.ts";
import { apiTokens, userAuditEvents } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

export interface NewApiToken {
  readonly id: string;
  readonly userId: UserId;
  readonly name: string;
  readonly tokenHash: string;
  readonly tokenPrefix: string;
  readonly scopes: readonly TokenScope[];
  readonly expiresAtMs: number;
  readonly createdAtMs: number;
}

export interface TokenRepoShape {
  readonly issueForUserWithinLimit: (token: NewApiToken, limit: number) => Effect.Effect<boolean>;
  readonly findByHash: (tokenHash: string) => Effect.Effect<ApiTokenRecord | null>;
  readonly touchLastUsed: (id: string, nowMs: number) => Effect.Effect<void>;
  readonly listForUser: (userId: UserId) => Effect.Effect<readonly ApiTokenSummary[]>;
  readonly revokeById: (
    id: string,
    userId: UserId,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<boolean>;
}

export class TokenRepo extends Context.Service<TokenRepo, TokenRepoShape>()("TokenRepo") {}

function tokenInsertSelect(db: Db, token: NewApiToken, condition: SQL) {
  return db
    .insert(apiTokens)
    .select(
      db
        .select({
          id: sql<string>`${token.id}`.as("id"),
          userId: sql<string>`${token.userId}`.as("user_id"),
          name: sql<string>`${token.name}`.as("name"),
          tokenHash: sql<string>`${token.tokenHash}`.as("token_hash"),
          tokenPrefix: sql<string>`${token.tokenPrefix}`.as("token_prefix"),
          scopes: sql<string>`${JSON.stringify(token.scopes)}`.as("scopes"),
          expiresAt: sql<number>`${token.expiresAtMs}`.as("expires_at"),
          createdAt: sql<number>`${token.createdAtMs}`.as("created_at"),
          lastUsedAt: sql<number | null>`${null}`.as("last_used_at"),
        })
        .from(sql`(select 1)`)
        .where(condition),
    )
    .returning({ id: apiTokens.id });
}

function tokenCreatedAuditAfterInsert(db: Db, token: NewApiToken) {
  return db.insert(userAuditEvents).select(
    db
      .select(
        guardedAuditSelectColumns({
          event: "auth.token_created",
          actor: { userId: token.userId },
          nowMs: token.createdAtMs,
          payload: { tokenId: token.id, name: token.name, scopes: token.scopes },
        }),
      )
      .from(apiTokens)
      .where(and(eq(apiTokens.id, token.id), sql`changes() = 1`)),
  );
}

async function rotateExistingToken(db: Db, token: NewApiToken): Promise<boolean> {
  const sameTokenName = and(eq(apiTokens.userId, token.userId), eq(apiTokens.name, token.name));
  const results = await db.batch([
    db.insert(userAuditEvents).select(
      db
        .select(
          guardedAuditSelectColumns({
            event: "auth.token_created",
            actor: { userId: token.userId },
            nowMs: token.createdAtMs,
            payload: { tokenId: token.id, name: token.name, scopes: token.scopes },
            replacedTokenIdSql: sql<string>`${apiTokens.id}`,
          }),
        )
        .from(apiTokens)
        .where(sameTokenName),
    ),
    db
      .delete(apiTokens)
      .where(and(sameTokenName, sql`changes() = 1`))
      .returning({ id: apiTokens.id }),
    tokenInsertSelect(db, token, sql`changes() = 1`),
  ]);
  return results[2].length === 1;
}

async function createNewTokenWithinLimit(
  db: Db,
  token: NewApiToken,
  limit: number,
): Promise<boolean> {
  const underLimit = sql<boolean>`(
    select count(*) from ${apiTokens}
    where ${apiTokens.userId} = ${token.userId}
  ) < ${limit}`;
  const nameAvailable = sql<boolean>`not exists (
    select 1 from ${apiTokens}
    where ${apiTokens.userId} = ${token.userId}
      and ${apiTokens.name} = ${token.name}
  )`;
  const results = await db.batch([
    tokenInsertSelect(db, token, sql`${underLimit} and ${nameAvailable}`),
    tokenCreatedAuditAfterInsert(db, token),
  ]);
  return results[0].length === 1;
}

export function makeTokenRepo(db: Db): TokenRepoShape {
  return {
    issueForUserWithinLimit: (token, limit) =>
      tryD1(async () => {
        if (await rotateExistingToken(db, token)) {
          return true;
        }
        if (await createNewTokenWithinLimit(db, token, limit)) {
          return true;
        }
        return rotateExistingToken(db, token);
      }).pipe(Effect.orDie),
    findByHash: (tokenHash) => tryD1(() => findTokenByHash(db, tokenHash)).pipe(Effect.orDie),
    touchLastUsed: (id, nowMs) =>
      tryD1(async () => {
        await db.update(apiTokens).set({ lastUsedAt: nowMs }).where(eq(apiTokens.id, id));
      }).pipe(Effect.orDie),
    listForUser: (userId) =>
      tryD1(async () => {
        const rows = await db
          .select({
            id: apiTokens.id,
            name: apiTokens.name,
            tokenPrefix: apiTokens.tokenPrefix,
            scopes: apiTokens.scopes,
            createdAt: apiTokens.createdAt,
            lastUsedAt: apiTokens.lastUsedAt,
            expiresAt: apiTokens.expiresAt,
          })
          .from(apiTokens)
          .where(eq(apiTokens.userId, userId))
          .orderBy(apiTokens.createdAt, apiTokens.id)
          .all();
        return rows.map((row): ApiTokenSummary => {
          const scopes = parseTokenScopes(row.scopes);
          if (scopes === null) {
            throw new Error("stored token scopes are not a valid scope array");
          }
          return {
            id: row.id,
            name: row.name,
            tokenPrefix: row.tokenPrefix,
            scopes,
            createdAtMs: row.createdAt,
            lastUsedAtMs: row.lastUsedAt,
            expiresAtMs: row.expiresAt,
          };
        });
      }).pipe(Effect.orDie),
    revokeById: (id, userId, nowMs, actor) =>
      tryD1(async () => {
        const deleted = await db
          .delete(apiTokens)
          .where(and(eq(apiTokens.id, id), eq(apiTokens.userId, userId)))
          .returning({ id: apiTokens.id });
        if (deleted.length === 0) {
          return false;
        }
        await userAuditInsert(db, nowMs, {
          event: "auth.token_revoked",
          actor,
          payload: { tokenId: id },
        });
        return true;
      }).pipe(Effect.orDie),
  };
}

async function findTokenByHash(db: Db, tokenHash: string): Promise<ApiTokenRecord | null> {
  const row = await db
    .select({
      id: apiTokens.id,
      userId: apiTokens.userId,
      tokenHash: apiTokens.tokenHash,
      scopes: apiTokens.scopes,
      expiresAt: apiTokens.expiresAt,
      lastUsedAt: apiTokens.lastUsedAt,
    })
    .from(apiTokens)
    .where(eq(apiTokens.tokenHash, tokenHash))
    .get();
  if (row === undefined) {
    return null;
  }
  const scopes = parseTokenScopes(row.scopes);
  if (scopes === null) {
    throw new Error("stored token scopes are not a valid scope array");
  }
  return {
    id: row.id,
    userId: row.userId,
    tokenHash: row.tokenHash,
    scopes,
    expiresAtMs: row.expiresAt,
    lastUsedAtMs: row.lastUsedAt,
  };
}
