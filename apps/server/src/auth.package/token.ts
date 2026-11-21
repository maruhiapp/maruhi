import type { Principal, TokenServiceShape } from "@maruhi/core";
import { anonymousPrincipal, TokenLimitReachedError } from "@maruhi/core";
import { Clock, Effect } from "effect";
import { Digest } from "effect/crypto";

import type { ApiTokenRecord } from "../auth-domain.ts";
import type { TokenRepoShape } from "../db.package/index.ts";
import { constantTimeEqual, randomBase62, sha256Hex, ulid } from "../ids.ts";

const TOKEN_PREFIX = "maruhi_pat_";

const MAX_TOKENS_PER_USER = 100;

function displayPrefix(rawToken: string): string {
  return rawToken.slice(0, TOKEN_PREFIX.length + 4);
}

const hashOf = (rawToken: string): Effect.Effect<string, never, Digest.Digest> =>
  Effect.orDie(sha256Hex(rawToken));

function toPrincipal(record: ApiTokenRecord | null, tokenHash: string, nowMs: number): Principal {
  if (record === null || !constantTimeEqual(tokenHash, record.tokenHash)) {
    return anonymousPrincipal;
  }
  const expiresAtMs = record.expiresAtMs;
  if (expiresAtMs <= nowMs) {
    return anonymousPrincipal;
  }
  return {
    kind: "token",
    userId: record.userId,
    tokenId: record.id,
    scopes: record.scopes,
    expiresAtMs,
  };
}

const TOUCH_INTERVAL_MS = 60 * 60 * 1000;

function resolveByHash(tokens: TokenRepoShape, tokenHash: string): Effect.Effect<Principal> {
  return Effect.flatMap(tokens.findByHash(tokenHash), (record) =>
    Effect.flatMap(Clock.currentTimeMillis, (now) => {
      const principal = toPrincipal(record, tokenHash, now);
      if (principal.kind !== "token" || record === null) {
        return Effect.succeed(anonymousPrincipal);
      }
      if (record.lastUsedAtMs !== null && now - record.lastUsedAtMs < TOUCH_INTERVAL_MS) {
        return Effect.succeed(principal);
      }
      return Effect.as(tokens.touchLastUsed(record.id, now), principal);
    }),
  );
}

export function makeTokenService(tokens: TokenRepoShape): TokenServiceShape {
  return {
    issueToken: Effect.fn("token.issueToken")(function* (userId, name, scopes, ttlMs) {
      const rawToken = TOKEN_PREFIX + (yield* randomBase62());
      const tokenHash = yield* hashOf(rawToken);
      const tokenId = yield* ulid();
      const createdAtMs = yield* Clock.currentTimeMillis;
      const expiresAtMs = createdAtMs + ttlMs;
      const admitted = yield* tokens.issueForUserWithinLimit(
        {
          id: tokenId,
          userId,
          name,
          tokenHash,
          tokenPrefix: displayPrefix(rawToken),
          scopes,
          expiresAtMs,
          createdAtMs,
        },
        MAX_TOKENS_PER_USER,
      );
      if (!admitted) {
        return yield* Effect.fail(new TokenLimitReachedError({ limit: MAX_TOKENS_PER_USER }));
      }
      return { rawToken, tokenId, expiresAtMs };
    }),
    resolveApiToken: (rawToken) => {
      if (!rawToken.startsWith(TOKEN_PREFIX)) {
        return Effect.succeed(anonymousPrincipal);
      }
      return Effect.flatMap(hashOf(rawToken), (tokenHash) => resolveByHash(tokens, tokenHash));
    },
    revokePresentedToken: (rawToken) =>
      Effect.flatMap(hashOf(rawToken), (tokenHash) =>
        Effect.flatMap(tokens.findByHash(tokenHash), (record) =>
          record === null || !constantTimeEqual(tokenHash, record.tokenHash)
            ? Effect.void
            : Effect.asVoid(
                Effect.flatMap(Clock.currentTimeMillis, (now) =>
                  tokens.revokeById(record.id, record.userId, now, {
                    userId: record.userId,
                    apiTokenId: record.id,
                  }),
                ),
              ),
        ),
      ),
  };
}
