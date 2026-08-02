// SessionService の本実装(AUTH_SPEC §5)。
//
// - 生成: 256-bit 乱数(hex)。クライアントには生値、DB には SHA-256 ハッシュのみ
// - 有効期限 30 日のスライディング更新。resolve のたびに期限を進める
// - 失効: サーバー側の行削除で即時。resolve は失効・期限切れ・不明を匿名に畳む
// - 生値・ハッシュをログに出さない(AUTH_SPEC §10)

import type { Principal, SessionServiceShape } from "@maruhi/core";
import { anonymousPrincipal } from "@maruhi/core";
import { Effect } from "effect";

import type { SessionRepoShape } from "../db.package/index.ts";
import { randomHex, sha256Hex } from "../ids.ts";

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * スライディング更新の書き込み間引き: 前回の延長から 1 時間未満なら D1 UPDATE を
 * 省く(全リクエスト書き込みを避ける。30 日スライディングの意味論は保たれる)。
 */
const TOUCH_INTERVAL_MS = 60 * 60 * 1000;

const hashOf = (rawValue: string): Effect.Effect<string> =>
  Effect.promise(() => sha256Hex(rawValue));

function resolveRecord(sessions: SessionRepoShape, idHash: string): Effect.Effect<Principal> {
  return Effect.flatMap(sessions.findByHash(idHash), (record) => {
    const now = Date.now();
    if (record === null) {
      return Effect.succeed(anonymousPrincipal);
    }
    if (record.expiresAtMs <= now) {
      // 期限切れ行はここで掃除する(DB バックの失効可能性を保つ)
      return Effect.as(sessions.deleteByHash(idHash), anonymousPrincipal);
    }
    const principal = { kind: "session", userId: record.userId } satisfies Principal;
    const newExpiresAt = now + SESSION_TTL_MS;
    if (newExpiresAt - record.expiresAtMs < TOUCH_INTERVAL_MS) {
      return Effect.succeed(principal);
    }
    return Effect.as(sessions.touch(idHash, now, newExpiresAt), principal);
  });
}

export function makeSessionService(sessions: SessionRepoShape): SessionServiceShape {
  return {
    issueSession: (userId, authMethod) =>
      Effect.gen(function* () {
        const rawValue = randomHex(32);
        const idHash = yield* hashOf(rawValue);
        const now = Date.now();
        const expiresAtMs = now + SESSION_TTL_MS;
        yield* sessions.insert(idHash, userId, authMethod, now, expiresAtMs);
        return { rawValue, expiresAtMs };
      }),
    resolveSession: (rawValue) =>
      Effect.flatMap(hashOf(rawValue), (idHash) => resolveRecord(sessions, idHash)),
    revokeSession: (rawValue) =>
      Effect.flatMap(hashOf(rawValue), (idHash) => sessions.deleteByHash(idHash)),
  };
}
