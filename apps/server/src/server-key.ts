import type { EnvironmentId, ProjectId } from "@maruhi/core";
import { cryptoEffect, cryptoPromise, serverKeyFingerprintHex } from "@maruhi/core";
import {
  decodeHex,
  deriveEncryptionKeyPair,
  encodeHex,
  type EncryptionKeyPair,
  exportEncryptionPublicKey,
  importEncryptionPublicKey,
  type KeyFingerprintHex,
  type LeaseWrapContext,
  unwrapDek,
  wrapLeaseDek,
} from "@maruhi/crypto";
import { Context, Data, Effect, Redacted } from "effect";

import type { WireSuite } from "./data.package/index.ts";
import { readWorkerSecret, type SecretBindingValue } from "./worker-env.ts";

const IKM_BYTES = 32;

export interface ServerKeyInfo {
  readonly serverEncPubHex: string;
  readonly serverKeyFingerprintHex: KeyFingerprintHex;
}

export interface StoredServerWrap {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

export interface LeaseWrapOutput {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

export type ResealFailure = "not-configured" | "unwrap-failed" | "wrap-failed";

export interface ServerKeyShape {
  readonly info: Effect.Effect<ServerKeyInfo | null>;
  readonly reseal: (input: {
    readonly projectId: ProjectId;
    readonly environmentId: EnvironmentId;
    readonly claimsDigestHex: string;
    readonly workloadPubHex: string;
    readonly wraps: readonly StoredServerWrap[];
  }) => Effect.Effect<readonly LeaseWrapOutput[], ResealFailure>;
}

export class ServerKey extends Context.Service<ServerKey, ServerKeyShape>()("ServerKey") {}

interface DerivedServerKey {
  readonly info: ServerKeyInfo;
  readonly keyPair: EncryptionKeyPair;
}

class ServerKeyUnusableError extends Data.TaggedError("ServerKeyUnusable")<object> {}
const unusable = new ServerKeyUnusableError();

const derive: (
  ikmHex: Redacted.Redacted<string> | undefined,
) => Effect.Effect<DerivedServerKey | null> = Effect.fn("server-key.derive")(
  function* (ikmHex: Redacted.Redacted<string> | undefined) {
    if (ikmHex === undefined) {
      return null;
    }
    const ikm = decodeHex(Redacted.value(ikmHex));
    if (ikm === null || ikm.length !== IKM_BYTES) {
      return null;
    }
    const pair = yield* cryptoEffect(() => deriveEncryptionKeyPair({ ikm }));
    const publicKey = yield* cryptoPromise("exportEncryptionPublicKey", () =>
      exportEncryptionPublicKey(pair.publicKey),
    ).pipe(Effect.orDie);
    const fingerprint = yield* serverKeyFingerprintHex(publicKey);
    return {
      info: {
        serverEncPubHex: encodeHex(publicKey),
        serverKeyFingerprintHex: fingerprint,
      },
      keyPair: pair,
    };
  },
  Effect.mapError(() => unusable),
  Effect.catchTag("ServerKeyUnusable", () => Effect.succeed(null)),
);

function zeroize(bytes: Uint8Array): void {
  bytes.fill(0);
}

export function makeServerKeyFromEnv(
  raw: SecretBindingValue | undefined,
): Effect.Effect<ServerKeyShape> {
  return readWorkerSecret(raw, "SERVER_ENC_KEY_IKM").pipe(Effect.map(makeServerKey));
}

export function makeServerKey(ikmHex: Redacted.Redacted<string> | undefined): ServerKeyShape {
  const derived = Effect.runSync(Effect.cached(derive(ikmHex)));
  const shared = Effect.uninterruptible(derived);
  return {
    info: Effect.map(shared, (key) => key?.info ?? null),
    reseal: Effect.fn("server-key.reseal")(function* (input) {
      const key = yield* shared;
      if (key === null) {
        return yield* Effect.fail<ResealFailure>("not-configured");
      }
      const workloadPubBytes = decodeHex(input.workloadPubHex);
      if (workloadPubBytes === null) {
        return yield* Effect.fail<ResealFailure>("wrap-failed");
      }
      const workloadPublicKey = yield* cryptoEffect(() =>
        importEncryptionPublicKey(workloadPubBytes),
      ).pipe(Effect.mapError(() => "wrap-failed" as const));
      const leases: LeaseWrapOutput[] = [];
      for (const wrap of input.wraps) {
        const enc = decodeHex(wrap.encHex);
        const ciphertext = decodeHex(wrap.ciphertextHex);
        if (enc === null || ciphertext === null) {
          return yield* Effect.fail<ResealFailure>("unwrap-failed");
        }
        const context: LeaseWrapContext = {
          projectId: input.projectId,
          environmentId: input.environmentId,
          epoch: wrap.epoch,
          claimsDigestHex: input.claimsDigestHex,
        };
        const leased = yield* Effect.acquireUseRelease(
          cryptoEffect(() =>
            unwrapDek({
              recipientKeyPair: key.keyPair,
              wrapped: { enc, ciphertext },
              context: {
                projectId: input.projectId,
                environmentId: input.environmentId,
                epoch: wrap.epoch,
                recipientUserId: key.info.serverKeyFingerprintHex,
              },
            }),
          ).pipe(Effect.mapError(() => "unwrap-failed" as const)),
          (dek) =>
            cryptoEffect(() => wrapLeaseDek({ workloadPublicKey, dek, context })).pipe(
              Effect.mapError(() => "wrap-failed" as const),
            ),
          (dek) => Effect.sync(() => zeroize(dek)),
        );
        leases.push({
          suite: wrap.suite,
          epoch: wrap.epoch,
          encHex: encodeHex(leased.enc),
          ciphertextHex: encodeHex(leased.ciphertext),
        });
      }
      return leases;
    }),
  };
}
