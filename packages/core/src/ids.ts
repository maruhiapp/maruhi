import { Effect } from "effect";
import { SecureRandom } from "effect/crypto";

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

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
        rand += CROCKFORD[(bytes[i] ?? 0) % 32];
      }
      return time + rand;
    }),
  );
