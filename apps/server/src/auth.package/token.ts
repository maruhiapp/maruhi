// The actual implementation of TokenService (AUTH_SPEC §6).
//
// - Format: `maruhi_pat_` + Base62 random (256-bit equivalent, 43 chars)
// - Verification: the presented token's SHA-256 is checked against the DB
//   and confirmed with a timing-safe comparison
// - The only issuance path is CLI login (§4) (the v1 dividing line; the
//   management surface — revoking one's own token, listing, targeted
//   revocation — uses TokenRepo directly from the handlers)
// - expires_at is fixed at issuance (§6's default TTL). Expired / revoked /
//   unknown all fold uniformly into anonymous (= 401; no distinction on the
//   wire)
// - Raw values and hashes are never logged (AUTH_SPEC §10)

import type { Principal, TokenServiceShape } from "@maruhi/core";
import { anonymousPrincipal, TokenLimitReachedError } from "@maruhi/core";
import { Effect } from "effect";

import type { ApiTokenRecord } from "../auth-domain.ts";
import type { TokenRepoShape } from "../db.package/index.ts";
import { constantTimeEqual, randomBase62, sha256Hex, ulid } from "../ids.ts";

const TOKEN_PREFIX = "maruhi_pat_";

/** Per-user cap on the number of tokens (AUTH_SPEC §6). */
const MAX_TOKENS_PER_USER = 100;

/** Display prefix (e.g. `maruhi_pat_Ab12…`). Up to the raw value's first 4 characters. */
function displayPrefix(rawToken: string): string {
  return rawToken.slice(0, TOKEN_PREFIX.length + 4);
}

const hashOf = (rawToken: string): Effect.Effect<string> =>
  Effect.promise(() => sha256Hex(rawToken));

/** Maps a hash-matched record onto a principal (expired / mismatched become anonymous). */
function toPrincipal(record: ApiTokenRecord | null, tokenHash: string, nowMs: number): Principal {
  if (record === null || !constantTimeEqual(tokenHash, record.tokenHash)) {
    return anonymousPrincipal;
  }
  // Expiry check (AUTH_SPEC §6 — W3a ruling CE)
  const expiresAtMs = record.expiresAtMs;
  if (expiresAtMs <= nowMs) {
    return anonymousPrincipal;
  }
  // A principal that passed the check always carries a non-null expiry (W3a ruling CI — /auth/me self-disclosure)
  return {
    kind: "token",
    userId: record.userId,
    tokenId: record.id,
    scopes: record.scopes,
    expiresAtMs,
  };
}

/** Write-thinning for last_used_at (avoids a D1 UPDATE per request; granularity 1 hour). */
const TOUCH_INTERVAL_MS = 60 * 60 * 1000;

function resolveByHash(tokens: TokenRepoShape, tokenHash: string): Effect.Effect<Principal> {
  return Effect.flatMap(tokens.findByHash(tokenHash), (record) => {
    const now = Date.now();
    const principal = toPrincipal(record, tokenHash, now);
    if (principal.kind !== "token" || record === null) {
      return Effect.succeed(anonymousPrincipal);
    }
    if (record.lastUsedAtMs !== null && now - record.lastUsedAtMs < TOUCH_INTERVAL_MS) {
      return Effect.succeed(principal);
    }
    return Effect.as(tokens.touchLastUsed(record.id, now), principal);
  });
}

export function makeTokenService(tokens: TokenRepoShape): TokenServiceShape {
  return {
    issueToken: (userId, name, scopes, ttlMs) =>
      Effect.gen(function* () {
        const rawToken = TOKEN_PREFIX + randomBase62();
        const tokenHash = yield* hashOf(rawToken);
        const tokenId = ulid();
        const createdAtMs = Date.now();
        // expires_at is fixed at issuance (AUTH_SPEC §6 — deliberately
        // asymmetric to the session §5 sliding renewal: tokens are forced
        // through periodic re-authentication)
        const expiresAtMs = createdAtMs + ttlMs;
        // Same (user, name) = reissuance = rotation (the old row's
        // revocation and the new row's insertion happen in one atomic
        // batch). Fresh issuance under a different name is folded into the
        // same statement as the user cap via the repo's conditional INSERT:
        // a service-side count → insert could let concurrent differently
        // named issuances observe the same under-limit state and exceed it
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
                // In self-revocation (CLI logout) the actor's token = the revocation target itself
                tokens.revokeById(record.id, record.userId, Date.now(), {
                  userId: record.userId,
                  apiTokenId: record.id,
                }),
              ),
        ),
      ),
  };
}
