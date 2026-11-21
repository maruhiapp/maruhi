import { type EnvironmentId, type UserId, type VariableId } from "@maruhi/core";
import type { ChainMember, SigningKeyPair } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import { requireWritingMember } from "../dek-wrap.ts";
import { type DekRecipient, requireChainEnvironment } from "../deks.ts";
import { CliError } from "../errors.ts";
import type { FloorHandle } from "../floor-check.ts";
import type { VerifiedPulledValue } from "../values-verify.ts";

export const MAX_REENCRYPT_PASSES = 3;

export interface RotateInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly reason: string | undefined;
  readonly forceNewEpoch: boolean;
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
}

export interface ReencryptTarget {
  readonly value: VerifiedPulledValue;
  readonly plaintext: Redacted.Redacted<Uint8Array>;
}

export interface ConflictedTarget {
  readonly variableId: VariableId;
  readonly known: VerifiedPulledValue;
  readonly currentVersion: number;
}

export function dedupeWarnings(warnings: readonly string[]): readonly string[] {
  return [...new Set(warnings)];
}

export const ensureRotatable = Effect.fn("env-rotate-shared.ensureRotatable")(function* (
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  signerUserId: UserId,
  signingKeyPair: SigningKeyPair,
): Effect.fn.Return<ChainMember, CliError> {
  const { member } = yield* requireWritingMember({
    verified,
    environmentId,
    target: "existing",
    signerUserId,
    signingKeyPair,
    operation: "rotate the epoch",
    forbidden:
      "A reader cannot rotate the epoch (rotate_epoch and value pushes require the member role or above — CRYPTO_SPEC §6.2)",
  });
  yield* requireChainEnvironment(verified, environmentId);
  return member;
});

export interface ReencryptContext {
  readonly client: MaruhiClient;
  readonly environmentId: EnvironmentId;
  readonly floor: FloorHandle;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly epoch: number;
  readonly dek: Redacted.Redacted<Uint8Array>;
  readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  readonly writerUserId: UserId;
  readonly writerKeyFingerprintHex: string;
  readonly signingKey: CryptoKey;
}

export function asOutcome<A, E, R>(
  effect: Effect.Effect<A, E, R>,
): Effect.Effect<
  { readonly kind: "ok"; readonly value: A } | { readonly kind: "failed"; readonly error: E },
  never,
  R
> {
  return effect.pipe(
    Effect.map((value) => ({ kind: "ok", value }) as const),
    Effect.catch((error) => Effect.succeed({ kind: "failed", error } as const)),
  );
}
