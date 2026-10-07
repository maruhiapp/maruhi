// Generation and comparison of identifiers and credential randomness
// (Web-standard crypto only; no Bun-specific APIs).
//
// This file holds only ID / randomness encodings, not cryptographic
// protocols. Cryptographic operations (hashes) are delegated to
// WebCrypto (CLAUDE.md: no hand-rolled primitives).

import { decodeUserId, ulid, type UserId } from "@maruhi/core";
import { encodeHex } from "@maruhi/crypto";

// ULID is @maruhi/core's shared implementation (the same one used for the CLI's ledger id assignment)
export { ulid } from "@maruhi/core";

/**
 * A fresh internal user id (AUTH_SPEC §2 — a ULID). Generation is a trust
 * boundary of the UserId brand, so this is where a new one is minted.
 */
export function newUserId(nowMs: number): UserId {
  return decodeUserId(ulid(nowMs));
}

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/**
 * Base62 representation of a 256-bit nonce (43 chars fixed, the AUTH_SPEC §6 token body).
 */
export function randomBase62(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
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
}

/** A random hex string (`byteLength` bytes). Used for session raw values and OAuth state. */
export function randomHex(byteLength: number): string {
  return encodeHex(crypto.getRandomValues(new Uint8Array(byteLength)));
}

/** SHA-256 in hex (lowercase). The storage hash for sessions / tokens (AUTH_SPEC §5 / §6). */
export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return encodeHex(new Uint8Array(digest));
}

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
