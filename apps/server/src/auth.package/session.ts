// The actual implementation of SessionService (AUTH_SPEC §5).
//
// - Generation: 256-bit random (hex). The client gets the raw value; the DB
//   stores only the SHA-256 hash
// - 30-day expiry with sliding renewal: each resolve advances the expiry
// - Revocation: immediate via server-side row deletion; resolve folds
//   revoked / expired / unknown into anonymous
// - Raw values and hashes are never logged (AUTH_SPEC §10)

import type { Principal, SessionServiceShape } from "@maruhi/core";
import { anonymousPrincipal } from "@maruhi/core";
import { Effect } from "effect";

import type { SessionRepoShape } from "../db.package/index.ts";
import { randomHex, sha256Hex } from "../ids.ts";

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Write-thinning for the sliding renewal: when less than 1 hour has passed
 * since the last extension, the D1 UPDATE is skipped (avoids a write per
 * request; the 30-day sliding semantics are preserved).
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
      // Expired rows are swept here (keeps server-side revocability)
      return Effect.as(sessions.deleteByHash(idHash), anonymousPrincipal);
    }
    const principal = {
      kind: "session",
      userId: record.userId,
      authMethod: record.authMethod,
    } satisfies Principal;
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
    // Explicit revocation goes through revokeByHash, which carries the
    // audit event (distinct from the expiry sweep's deleteByHash —
    // AUDIT_SPEC §3.1's auth.session_revoked covers explicit revocation only)
    revokeSession: (rawValue) =>
      Effect.flatMap(hashOf(rawValue), (idHash) => sessions.revokeByHash(idHash, Date.now())),
  };
}
