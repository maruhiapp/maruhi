// Shared implementation of chain-entry signing and append (CRYPTO_SPEC
// §6.1 / §6.4).
//
// Membership operations (add_member / remove_member / change_role —
// member.ts) and server-disclosure operations (grant_server /
// revoke_server — server-grant / server-revoke) share the same structure:
// "sign right after the current head → append under the parent-head CAS
// (a 409 goes to the caller's retryOnConflict as ChainHeadConflict)".
// The signing assembly and the append POST are unified here (per-op
// pre-checks and CAS-conflict recovery belong to each op).

import { ChainHeadConflictError } from "@maruhi/api-schema";
import type { ChainEntry, ChainOperation, SigningKeyPair } from "@maruhi/crypto";
import { signChainEntry, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { ownDeviceBySigningKey } from "./device-key.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";

/**
 * Signs one entry with the signer's key right after the verified view's
 * current head. The actor (user_id + key FP) is resolved from the
 * verified view's current member set (a non-member cannot sign).
 * `failureText` is the wording for a signing failure (the caller supplies
 * it, including the op name).
 */
export function signEntryAtHead(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly operation: ChainOperation;
  readonly signingKeyPair: SigningKeyPair;
  readonly failureText: string;
}): Effect.Effect<ChainEntry, CliError> {
  return Effect.gen(function* () {
    const actor = input.verified.state.members.get(input.signerUserId);
    if (actor === undefined) {
      return yield* Effect.fail(cliError("Not a chain-derived member"));
    }
    // The signing device = that person's valid device matching the signing key at hand (K4-16 — device-key.ts)
    const device = yield* ownDeviceBySigningKey(input.verified, actor, input.signingKeyPair);
    const signed = yield* Effect.tryPromise({
      try: () =>
        signChainEntry({
          entry: {
            suite: SUITE_ID,
            seq: input.verified.state.headSeq + 1,
            prevHashHex: input.verified.state.headHashHex,
            ...input.operation,
            actor: { userId: actor.userId, keyFingerprintHex: device.keyFingerprintHex },
            timestampMs: Date.now(),
          },
          signingKey: input.signingKeyPair.privateKey,
        }),
      catch: () => cliError(input.failureText),
    });
    if (!signed.ok) {
      return yield* Effect.fail(cliError(input.failureText));
    }
    return signed.value;
  });
}

/**
 * Append under the parent-head CAS. A head conflict is returned as
 * `ChainHeadConflictError` unchanged (the caller's retryOnConflict
 * classifies it). Anything else is mapped to a CliError.
 */
export function appendEntry(
  client: MaruhiClient,
  verified: VerifiedProject,
  entry: ChainEntry,
): Effect.Effect<void, ChainHeadConflictError | CliError> {
  return client.membership
    .append({
      params: { projectId: verified.projectId },
      payload: { parentHeadHashHex: verified.state.headHashHex, entry },
    })
    .pipe(
      Effect.asVoid,
      Effect.mapError((error) =>
        error instanceof ChainHeadConflictError ? error : toCliError(error),
      ),
    );
}
