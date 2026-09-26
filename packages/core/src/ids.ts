// Identifier generation (Web-standard crypto only — no Bun-specific
// APIs; runs on browsers / Bun / workerd). Only ID encodings live here,
// no cryptographic protocol.

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * ULID (48-bit time + 80-bit random, Crockford Base32, 26 chars).
 *
 * The server uses it for principal identifiers (the internal user_id
 * etc. of AUTH_SPEC §2); the client uses it for the wrap_id / group_id
 * of the master-key wrap ledger (AUTH_SPEC §13-9 — the AAD binds the
 * id, so the client assigns it before encrypting).
 */
export function ulid(nowMs: number = Date.now()): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let time = "";
  let t = nowMs;
  for (let i = 0; i < 10; i += 1) {
    time = CROCKFORD[t % 32] + time;
    t = Math.floor(t / 32);
  }
  let rand = "";
  for (let i = 0; i < 16; i += 1) {
    // 256 is divisible by 32, so the modulo has no bias
    rand += CROCKFORD[(bytes[i] ?? 0) % 32];
  }
  return time + rand;
}
