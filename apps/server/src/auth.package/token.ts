// TokenService の本実装(AUTH_SPEC §6)。
//
// - 形式: `maruhi_pat_` + Base62 乱数(256-bit 相当、43 文字)
// - 検証: 提示トークンの SHA-256 を DB と照合し、タイミング安全比較で確認する
// - 発行経路は device flow のみ・管理系は自トークンの失効まで(2026-08-02 v1 線引き)
// - 生値・ハッシュをログに出さない(AUTH_SPEC §10)

import type { Principal, TokenServiceShape } from "@maruhi/core";
import { anonymousPrincipal } from "@maruhi/core";
import { Effect } from "effect";

import type { ApiTokenRecord } from "../auth-domain.ts";
import type { TokenRepoShape } from "../db.package/index.ts";
import { constantTimeEqual, randomBase62, sha256Hex, ulid } from "../ids.ts";

const TOKEN_PREFIX = "maruhi_pat_";

/** 表示用プレフィックス(例: `maruhi_pat_Ab12…`)。生値の先頭 4 文字まで。 */
function displayPrefix(rawToken: string): string {
  return rawToken.slice(0, TOKEN_PREFIX.length + 4);
}

const hashOf = (rawToken: string): Effect.Effect<string> =>
  Effect.promise(() => sha256Hex(rawToken));

function isExpired(record: ApiTokenRecord, nowMs: number): boolean {
  return record.expiresAtMs !== null && record.expiresAtMs <= nowMs;
}

/** ハッシュ照合済みレコードを主体へ写す(期限切れ・不一致は匿名)。 */
function toPrincipal(record: ApiTokenRecord | null, tokenHash: string, nowMs: number): Principal {
  if (record === null || !constantTimeEqual(tokenHash, record.tokenHash)) {
    return anonymousPrincipal;
  }
  return isExpired(record, nowMs)
    ? anonymousPrincipal
    : { kind: "token", userId: record.userId, tokenId: record.id, scopes: record.scopes };
}

function resolveByHash(tokens: TokenRepoShape, tokenHash: string): Effect.Effect<Principal> {
  return Effect.flatMap(tokens.findByHash(tokenHash), (record) => {
    const principal = toPrincipal(record, tokenHash, Date.now());
    if (principal.kind !== "token" || record === null) {
      return Effect.succeed(anonymousPrincipal);
    }
    return Effect.as(tokens.touchLastUsed(record.id, Date.now()), principal);
  });
}

export function makeTokenService(tokens: TokenRepoShape): TokenServiceShape {
  return {
    issueToken: (userId, name, scopes) =>
      Effect.gen(function* () {
        const rawToken = TOKEN_PREFIX + randomBase62();
        const tokenHash = yield* hashOf(rawToken);
        const tokenId = ulid();
        yield* tokens.insert({
          id: tokenId,
          userId,
          name,
          tokenHash,
          tokenPrefix: displayPrefix(rawToken),
          scopes,
          createdAtMs: Date.now(),
        });
        return { rawToken, tokenId };
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
            : tokens.deleteById(record.id),
        ),
      ),
  };
}
