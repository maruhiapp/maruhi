import { cryptoEffect, cryptoPromise, type EnvironmentId } from "@maruhi/core";
import type { ChainEntry, ChainMember, EnvValuesDigestEntry } from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeEnvValuesDigest,
  signChainEntry,
  SUITE_ID,
} from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import type { VerifiedProject } from "../chain-sync.ts";
import { ownDeviceOrFail } from "../device-key.ts";
import { cliError, type CliError } from "../errors.ts";

export const signBoundaryCheckpoint = Effect.fn("boundary-checkpoint.signBoundaryCheckpoint")(
  function* (input: {
    readonly compositeEntry: ChainEntry;
    readonly environmentId: EnvironmentId;
    readonly epoch: number;
    readonly manifestVersion: number;
    readonly manifestSigHashHex: string;
    readonly values: readonly EnvValuesDigestEntry[];
    readonly verified: VerifiedProject;
    readonly member: ChainMember;
    readonly deviceFingerprintHex: string;
    readonly signingKey: CryptoKey;
  }): Effect.fn.Return<ChainEntry & { readonly op: "checkpoint" }, CliError> {
    const digest = yield* cryptoEffect(() => computeEnvValuesDigest(SUITE_ID, input.values)).pipe(
      Effect.mapError(() => cliError("Failed to compute the checkpoint values digest")),
    );
    const prevHashHex = yield* cryptoPromise("computeChainEntryHash", () =>
      computeChainEntryHash(input.compositeEntry),
    ).pipe(Effect.mapError(() => cliError("Failed to sign the boundary checkpoint entry")));
    const device = yield* ownDeviceOrFail(input.verified, input.member, {
      keyFingerprintHex: input.deviceFingerprintHex,
    });
    const timestampMs = yield* Clock.currentTimeMillis;
    const signed = yield* cryptoEffect(() =>
      signChainEntry({
        entry: {
          suite: SUITE_ID,
          seq: input.compositeEntry.seq + 1,
          prevHashHex,
          op: "checkpoint",
          actor: { userId: input.member.userId, keyFingerprintHex: device.keyFingerprintHex },
          payload: {
            environments: [
              {
                environmentId: input.environmentId,
                epoch: input.epoch,
                manifestVersion: input.manifestVersion,
                manifestSigHashHex: input.manifestSigHashHex,
                valuesDigestHex: digest,
              },
            ],
            auditHeadHashHex: "",
          },
          timestampMs,
        },
        signingKey: input.signingKey,
      }),
    ).pipe(Effect.mapError(() => cliError("Failed to sign the boundary checkpoint entry")));
    if (signed.op !== "checkpoint") {
      return yield* Effect.fail(cliError("Failed to sign the boundary checkpoint entry"));
    }
    return signed;
  },
);
