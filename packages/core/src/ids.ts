// Identifier generation (Web-standard crypto only — no Bun-specific
// APIs; runs on browsers / Bun / workerd). Only ID encodings live here,
// no cryptographic protocol.
//
// The randomness draw goes through the `SecureRandom` service
// (crypto-services.ts) so tests can substitute a deterministic source
// with `Layer.mock`; the ULID algorithm and output format are unchanged
// from the previous ambient-WebCrypto implementation.
//
// The service's own `ulid` is deliberately not used: it reads the
// ambient Clock and encodes a 10-byte draw as a bit stream, while this
// implementation takes the caller's explicit logical time (the db
// layer threads one `nowMs` through an operation, and the id embeds
// that same instant) and maps a 16-byte draw byte-by-byte — a mapping
// the format-invariance tests in core/test/ids.test.ts pin. Adopting
// it would desync id timestamps from row timestamps and change the
// byte→string mapping for the same draw, for the sole gain of
// same-millisecond monotonicity, which no consumer relies on.

import { Effect } from "effect";
import { SecureRandom } from "effect/crypto";

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * ULID (48-bit time + 80-bit random, Crockford Base32, 26 chars).
 *
 * The server uses it for principal identifiers (the internal user_id
 * etc. of AUTH_SPEC §2); the client uses it for the wrap_id / group_id
 * of the master-key wrap ledger (AUTH_SPEC §13-9 — the AAD binds the
 * id, so the client assigns it before encrypting).
 */
export const ulid = (
  nowMs: number = Date.now(),
): Effect.Effect<string, never, SecureRandom.SecureRandom> =>
  Effect.flatMap(SecureRandom.SecureRandom, (random) =>
    Effect.map(random.randomBytes(16), (bytes) => {
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
    }),
  );
