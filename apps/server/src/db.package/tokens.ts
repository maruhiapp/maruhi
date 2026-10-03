// Repository of API tokens (AUTH_SPEC §6 — token_hash additionally
// carries a timing-safe comparison at the service layer).

import type { TokenScope } from "@maruhi/core";
import { parseTokenScopes } from "@maruhi/core";
import { and, eq, sql, type SQL } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import type { ApiTokenRecord, ApiTokenSummary } from "../auth-domain.ts";
import { type D1AuditActor, guardedAuditSelectColumns, userAuditInsert } from "./audit.ts";
import { apiTokens, userAuditEvents } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

const run = <T>(evaluate: () => Promise<T>): Effect.Effect<T> => Effect.promise(evaluate);

// ---------------------------------------------------------------------------
// TokenRepo (§6. The token_hash comparison additionally uses a
// timing-safe comparison at the service layer)
// ---------------------------------------------------------------------------

export interface NewApiToken {
  readonly id: string;
  readonly userId: string;
  readonly name: string;
  readonly tokenHash: string;
  readonly tokenPrefix: string;
  readonly scopes: readonly TokenScope[];
  /** The validity period fixed at issuance (AUTH_SPEC §6's default TTL — W3a). */
  readonly expiresAtMs: number;
  readonly createdAtMs: number;
}

export interface TokenRepoShape {
  /**
   * The same (user, name) rotates while revoking the existing token; a
   * different name is conditionally issued only under `limit`. Each
   * path runs as a D1 atomic batch, so even concurrent issuance never
   * allows a duplicate name or an over-limit distinct name. false =
   * quota rejection.
   *
   * The replaced old token id rides on `auth.token_created`'s payload
   * as `replacedTokenId` (absent on a fresh issuance — AUDIT_SPEC §3.1).
   */
  readonly issueForUserWithinLimit: (token: NewApiToken, limit: number) => Effect.Effect<boolean>;
  readonly findByHash: (tokenHash: string) => Effect.Effect<ApiTokenRecord | null>;
  readonly touchLastUsed: (id: string, nowMs: number) => Effect.Effect<void>;
  /**
   * The user's own token list (AUTH_SPEC §6 — W3a). token_hash is not
   * among the selected columns (a distribution surface — it does not
   * even exist in ApiTokenSummary's structure). Expired rows are
   * returned too (inventory targets — only verification drops them to
   * 401). Ascending created_at; ties by id.
   */
  readonly listForUser: (userId: string) => Effect.Effect<readonly ApiTokenSummary[]>;
  /**
   * Explicit revocation. Enforces id × user ownership and records
   * auth.token_revoked (§3.1 / S8). actor is the principal that executed
   * the revocation (on a targeted revocation it may be a session /
   * another token — AUDIT_SPEC §2). The return value = whether a row
   * was actually deleted (false is how the caller derives the uniform
   * 404 — §6's existence concealment).
   */
  readonly revokeById: (
    id: string,
    userId: string,
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

/**
 * The rotation of an existing same-name token. Because the first audit
 * INSERT reads the old id, replacedTokenId matches the row that is
 * actually deleted in the same batch.
 */
async function rotateExistingToken(db: Db, token: NewApiToken): Promise<boolean> {
  const basePayload = JSON.stringify({
    tokenId: token.id,
    name: token.name,
    scopes: token.scopes,
  });
  const sameTokenName = and(eq(apiTokens.userId, token.userId), eq(apiTokens.name, token.name));
  const results = await db.batch([
    db.insert(userAuditEvents).select(
      db
        .select(
          guardedAuditSelectColumns({
            event: "auth.token_created",
            actor: { userId: token.userId },
            nowMs: token.createdAtMs,
            payloadSql: sql<string>`json_patch(${basePayload}, json_object('replacedTokenId', ${apiTokens.id}))`,
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

/** Folds the limit check + INSERT of a new-name token into one statement. */
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
    // The admission on the issuance limit is the job of the repo's
    // conditional INSERT. A service-layer count → insert would be a
    // separate D1 round-trip, and concurrent issuances under different
    // names could observe the same under-limit and exceed it. A
    // same-name rotation is allowed even at the limit and also keeps
    // the old id's audit in the same batch.
    issueForUserWithinLimit: (token, limit) =>
      run(async () => {
        if (await rotateExistingToken(db, token)) {
          return true;
        }
        if (await createNewTokenWithinLimit(db, token, limit)) {
          return true;
        }
        // A race where a same-name token appeared between the first
        // existence check and the new INSERT. To distinguish it from a
        // quota rejection of a new name, the rotation is retried last
        return rotateExistingToken(db, token);
      }),
    findByHash: (tokenHash) => run(() => findTokenByHash(db, tokenHash)),
    touchLastUsed: (id, nowMs) =>
      run(async () => {
        await db.update(apiTokens).set({ lastUsedAt: nowMs }).where(eq(apiTokens.id, id));
      }),
    listForUser: (userId) =>
      run(async () => {
        // token_hash is not among the selected columns (a distribution
        // surface — the note in auth-domain.ts). Expired rows are
        // returned too: the list is an inventory surface, and unlike
        // revocation (row deletion) an expired row stays visible as
        // stock (the user can clean it up with a targeted revocation)
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
            // The same discipline as findTokenByHash: a column only our
            // own write path can produce being broken = an
            // implementation bug / DB corruption (the row is never
            // silently dropped)
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
      }),
    revokeById: (id, userId, nowMs, actor) =>
      run(async () => {
        // The event is written after observing the deletion's success
        // via returning (same shape as revokeByHash). A concurrent
        // revoke can pass the caller's findByHash on both sides, so an
        // unconditional batch could record multiple token_revoked for 1
        // revocation (overcounting). We fall toward the missing side
        // over the duplicate side
        const deleted = await db
          .delete(apiTokens)
          // Deleting by id alone would let the token-id-addressed admin
          // API (W3a's targeted revocation) revoke another user's
          // token while mis-recording the audit actor as the calling
          // user. The ownership condition is enforced at the repo
          // boundary; 0 rows = the caller's uniform 404 (§6)
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
      }),
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
    // A column only our own write path can produce being broken = an
    // implementation bug / DB corruption
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
