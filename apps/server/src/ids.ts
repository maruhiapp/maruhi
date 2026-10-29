// Generation and comparison of identifiers and credential randomness
// (Web-standard crypto only; no Bun-specific APIs).
//
// This file holds only ID / randomness encodings, not cryptographic
// protocols. Cryptographic operations (hashes) are delegated to
// WebCrypto (CLAUDE.md: no hand-rolled primitives).
//
// Since the Effect 4.1 migration, the generators are Effects that draw
// from the `SecureRandom` / `Digest` services (@maruhi/core's
// crypto-services seam), so tests can substitute deterministic sources
// with `Layer.mock`. Output formats are unchanged: AUTH_SPEC §5 / §6
// byte lengths, encodings and shapes are exactly as before.
//
// The one exception is `randomHexSync`: the audit Durable Object's
// append API, Drizzle statement construction and the lease grant map
// are synchronous by design (the DO storage API and statement building
// cannot yield a service), so those call sites keep a plain synchronous
// draw. It is the same WebCrypto draw the service performs.

import { decodeOrgId, decodeUserId, ulid, type OrgId, type UserId } from "@maruhi/core";
import { encodeHex } from "@maruhi/crypto";
import { Effect } from "effect";
import type { CryptoError } from "effect/crypto";
import { Digest, SecureRandom } from "effect/crypto";

// ULID is @maruhi/core's shared implementation (the same one used for the CLI's ledger id assignment)
export { ulid } from "@maruhi/core";

/**
 * A fresh internal user id (AUTH_SPEC §2 — a ULID). Generation is a trust
 * boundary of the UserId brand, so this is where a new one is minted.
 */
export const newUserId = (nowMs: number): Effect.Effect<UserId, never, SecureRandom.SecureRandom> =>
  Effect.map(ulid(nowMs), (id) => decodeUserId(id));

/**
 * A fresh organization id (AUTH_SPEC §9 — a ULID). Generation is a trust
 * boundary of the OrgId brand, so this is where a new one is minted.
 */
export const newOrgId = (nowMs: number): Effect.Effect<OrgId, never, SecureRandom.SecureRandom> =>
  Effect.map(ulid(nowMs), (id) => decodeOrgId(id));

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/**
 * Base62 representation of a 256-bit nonce (43 chars fixed, the AUTH_SPEC §6 token body).
 */
export const randomBase62 = (): Effect.Effect<string, never, SecureRandom.SecureRandom> =>
  Effect.flatMap(SecureRandom.SecureRandom, (random) =>
    Effect.map(random.randomBytes(32), (bytes) => {
      let value = 0n;
      for (const byte of bytes) {
        value = (value << 8n) | BigInt(byte);
      }
      let out = "";
      while (value > 0n) {
        out = BASE62[Number(value % 62n)] + out;
        value /= 62n;
      }
      return out.padStart(43, "0");
    }),
  );

/** A random hex string (`byteLength` bytes). Used for session raw values and OAuth state. */
export const randomHex = (
  byteLength: number,
): Effect.Effect<string, never, SecureRandom.SecureRandom> =>
  Effect.flatMap(SecureRandom.SecureRandom, (random) =>
    Effect.map(random.randomBytes(byteLength), (bytes) => encodeHex(bytes)),
  );

/**
 * The synchronous counterpart of `randomHex`, for the call sites that
 * cannot run an Effect (see the file header). Same draw, same encoding.
 */
export function randomHexSync(byteLength: number): string {
  return encodeHex(crypto.getRandomValues(new Uint8Array(byteLength)));
}

/** SHA-256 in hex (lowercase). The storage hash for sessions / tokens (AUTH_SPEC §5 / §6). */
export const sha256Hex = (
  value: string,
): Effect.Effect<string, CryptoError.CryptoError, Digest.Digest> =>
  Effect.flatMap(Digest.Digest, (digest) =>
    digest.digestHex(Digest.sha256, new TextEncoder().encode(value)),
  );

/**
 * Timing-safe string comparison (AUTH_SPEC §6). Scans the full length
 * even when lengths differ before returning (all compared values are
 * fixed-length hash hex).
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const length = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < length; i += 1) {
    diff |= (a.charCodeAt(i) | 0) ^ (b.charCodeAt(i) | 0);
  }
  return diff === 0;
}
