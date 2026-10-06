// Building and signing a boundary checkpoint (AUTH_SPEC §12-4 /
// CRYPTO_SPEC §6.3 — session-33 = the owner-approved plan 2-G′).
//
// An environment-creation or rotation composite must embed, at the seq
// right after H+1 (create / rotate) — H+2 — a `checkpoint` entry covering
// only the one tuple of that environment. The tuple binds the embedded
// manifest's (epoch, manifestVersion, signed_bytes hash) and the
// values_digest derived from the verified view (creation = the empty
// variable set; rotate = the current values actually read for
// re-encryption — no extra read occurs. session-32 §5-1). It does not
// notarize the audit head (empty string — acquiring the declaration [§16-2]
// and standalone acceptance are outside this path's scope).
//
// On a CAS retry this entry is re-signed together with the entry,
// statements, and manifest (because prev = the H+1 entry's hash changes).

import { cryptoEffect, cryptoPromise } from "@maruhi/core";
import type { ChainEntry, ChainMember, EnvValuesDigestEntry } from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeEnvValuesDigest,
  signChainEntry,
  SUITE_ID,
} from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { ownDeviceOrFail } from "./device-key.ts";
import { cliError, type CliError } from "./errors.ts";

/**
 * Signs the boundary checkpoint (H+2) that follows the H+1 composite entry.
 * values is the latest value-level shape of the verified view (active
 * variables only — the §6.2 values_digest definition).
 */
export const signBoundaryCheckpoint = Effect.fn("boundary-checkpoint.signBoundaryCheckpoint")(
  function* (input: {
    /** The just-signed composite entry (create / rotate — the anchor for seq / prev). */
    readonly compositeEntry: ChainEntry;
    readonly environmentId: string;
    /** The epoch the composite establishes (creation = 1, rotate = new_epoch). */
    readonly epoch: number;
    /** The embedded manifest's version and signed_bytes hash (the binding target — §4.3 (2)). */
    readonly manifestVersion: number;
    readonly manifestSigHashHex: string;
    readonly values: readonly EnvValuesDigestEntry[];
    /** The verified view used to resolve the signing device (message when the key at hand is missing — DK K13-5). */
    readonly verified: VerifiedProject;
    readonly member: ChainMember;
    /** FP of the signing device (the key at hand — the same device as the composite entry). */
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
