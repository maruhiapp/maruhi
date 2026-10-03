// Helpers shared by the mirror status/sync and mark/promote halves (discipline: see commands/index.ts).

import { Duration, Effect } from "effect";

import { makeApiClient } from "../api.ts";
import { type CliServices } from "../context.ts";

/**
 * Whether two origins publish one server key: equal strings, or equal
 * fingerprints from their public `/auth/config` (a deployment answers
 * under its workers.dev hostname and its custom domain alike — ruling C
 * revision, round 5). The fingerprint is self-reported, so equality only
 * ever refuses (a mirror of itself) or names a way out — never lifts a
 * guard (round 6). Without a fingerprint on either side the strings
 * decide; a config that does not answer within the probe's bound counts
 * as no fingerprint.
 */
export function sameDeployment(a: string, b: string): Effect.Effect<boolean, never, CliServices> {
  if (a === b) {
    return Effect.succeed(true);
  }
  return Effect.gen(function* () {
    const [fingerprintA, fingerprintB] = yield* Effect.all(
      [deploymentFingerprint(a), deploymentFingerprint(b)],
      { concurrency: 2 },
    );
    return fingerprintA !== null && fingerprintA === fingerprintB;
  });
}

/** The server key fingerprint a deployment publishes (null = none, or no answer within the probe's bound). */
function deploymentFingerprint(origin: string): Effect.Effect<string | null, never, CliServices> {
  return Effect.gen(function* () {
    const client = yield* makeApiClient({ baseUrl: origin, timeout: PROMOTE_PROBE_TIMEOUT });
    return yield* client.auth.authConfig({}).pipe(
      Effect.map((config) => config.serverKeyFingerprintHex ?? null),
      Effect.catch(() => Effect.succeed(null)),
    );
  });
}

/** How long the promotion waits for the source to answer its probe (a black-holed source must not hold a failover). */
export const PROMOTE_PROBE_TIMEOUT = Duration.seconds(10);
