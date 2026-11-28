import { Duration, Effect } from "effect";

import { makeApiClient } from "../api.ts";
import type { CliServices } from "../cli.ts";

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

const deploymentFingerprint = Effect.fn("mirror-deployment.deploymentFingerprint")(function* (
  origin: string,
): Effect.fn.Return<string | null, never, CliServices> {
  const client = yield* makeApiClient({ baseUrl: origin, timeout: PROMOTE_PROBE_TIMEOUT });
  return yield* client.auth.authConfig({}).pipe(
    Effect.map((config) => config.serverKeyFingerprintHex ?? null),
    Effect.orElseSucceed(() => null),
  );
});

export const PROMOTE_PROBE_TIMEOUT = Duration.seconds(10);
