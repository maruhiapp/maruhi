import { type KeyFingerprintHex, type ProjectId, userKeyFingerprintHex } from "@maruhi/core";
import { decodeHex } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { CliError } from "./errors.ts";
import { fetchProjectMemberships } from "./project.package/index.ts";
import { compareCodePoints } from "./scope.ts";

export interface RegistryRow {
  readonly keyFingerprintHex: KeyFingerprintHex;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly label: string;
  readonly tokenId?: string | undefined;
  readonly createdAtMs: number;
}

export const FULL_FINGERPRINT = /^[0-9a-f]{32}$/;
export const FINGERPRINT_PREFIX = /^[0-9a-f]{8,32}$/;
export const WORD_COUNT = 12;

export function recomputeFingerprint(
  encPubHex: string,
  sigPubHex: string,
): Effect.Effect<KeyFingerprintHex | null, CliError> {
  const enc = decodeHex(encPubHex);
  const sig = decodeHex(sigPubHex);
  if (enc === null || sig === null) {
    return Effect.succeed(null);
  }
  return userKeyFingerprintHex(enc, sig).pipe(
    Effect.catchTag("CryptoInvalidInput", () => Effect.succeed(null)),
    Effect.orDie,
  );
}

export function fetchRegistry(
  client: MaruhiClient,
): Effect.Effect<readonly RegistryRow[] | null, never> {
  return client.devices.list({}).pipe(
    Effect.map((response): readonly RegistryRow[] => response.devices),
    Effect.orElseSucceed(() => null),
  );
}

export function resolveProjectIds(
  client: MaruhiClient,
  project: ProjectId | undefined,
): Effect.Effect<readonly ProjectId[], CliError> {
  return project === undefined
    ? fetchProjectMemberships(client).pipe(
        Effect.map((rows) => rows.map((row) => row.projectId).toSorted(compareCodePoints)),
      )
    : Effect.succeed([project]);
}
