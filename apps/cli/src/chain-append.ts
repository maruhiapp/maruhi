// Shared implementation of chain-entry signing and append (CRYPTO_SPEC
// §6.1 / §6.4).
//
// - signEntryAtHead signs an entry with a member's device key right after
//   the verified view's head. The ops that sign that way call it,
//   including the composite env create / rotate / rm and checkpoint, which
//   keep their own retries. device-ops.ts's add_device and revoke_device
//   are the exception: they resolve the actor device first, for their cap
//   and role checks, and sign with signChainEntry directly.
// - appendWithRetry is the loop of the ops that append one entry through
//   the chain-append API, checkpoint aside (it keeps its own retry):
//   membership (add_member / remove_member / change_role, through
//   member.ts's appendWithCas), devices (add_device / revoke_device —
//   device-ops.ts), server disclosure (grant_server / revoke_server —
//   server-grant / server-revoke) and four-eyes (propose / withdraw /
//   set_approval_policy — approval.ts; approve — approval-approve.ts).
//   "Sign right after the current head → append under the parent-head CAS
//   → on a head conflict (409), resync with the extension check, redo the
//   op's pre-checks and sign again" (retry.ts's retryOnConflict).
//   appendOperationWithRetry is that loop for an entry signEntryAtHead
//   signs. The pre-checks, and what a concurrent run's change means for
//   the op, belong to each op.

import { ChainHeadConflictError } from "@maruhi/api-schema";
import { cryptoEffect, type UserId } from "@maruhi/core";
import type { ChainEntry, ChainOperation, SigningKeyPair } from "@maruhi/crypto";
import { signChainEntry, SUITE_ID } from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { resyncExtended, type VerifiedProject } from "./chain-sync.ts";
import { ownDeviceBySigningKey } from "./device-key.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { retryOnConflict } from "./retry.ts";

/** The attempts of a chain append's head-conflict retry. */
const MAX_APPEND_ATTEMPTS = 5;

/**
 * Signs one entry with the signer's key right after the verified view's
 * current head. The actor (user_id + key FP) is resolved from the
 * verified view's current member set (a non-member cannot sign). A
 * signing failure reads "Failed to sign the <op> entry".
 */
export const signEntryAtHead = Effect.fn("chain-append.signEntryAtHead")(function* (input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: UserId;
  readonly operation: ChainOperation;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.fn.Return<ChainEntry, CliError> {
  const actor = input.verified.state.members.get(input.signerUserId);
  if (actor === undefined) {
    return yield* Effect.fail(cliError("Not a chain-derived member"));
  }
  // The signing device = that person's valid device matching the signing key at hand (K4-16 — device-key.ts)
  const device = yield* ownDeviceBySigningKey(input.verified, actor, input.signingKeyPair);
  const timestampMs = yield* Clock.currentTimeMillis;
  const signed = yield* cryptoEffect(() =>
    signChainEntry({
      entry: {
        suite: SUITE_ID,
        seq: input.verified.state.headSeq + 1,
        prevHashHex: input.verified.state.headHashHex,
        ...input.operation,
        actor: { userId: actor.userId, keyFingerprintHex: device.keyFingerprintHex },
        timestampMs,
      },
      signingKey: input.signingKeyPair.privateKey,
    }),
  ).pipe(Effect.mapError(() => cliError(`Failed to sign the ${input.operation.op} entry`)));
  return signed;
});

/**
 * Append under the parent-head CAS. A head conflict is returned as
 * `ChainHeadConflictError` unchanged (appendWithRetry's classify retries
 * it). Anything else is mapped to a CliError.
 */
function appendEntry(
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
      Effect.catchTag("ChainHeadConflict", Effect.fail, (error) => Effect.fail(toCliError(error))),
    );
}

/** The client an append goes through, and the resync a head conflict runs. */
interface AppendContext {
  readonly client: MaruhiClient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}

/** What an append's retry ends with: its last state, and the entry it appended (null when the last attempt appended none). */
interface AppendOutcome<S> {
  readonly state: S;
  readonly entry: ChainEntry | null;
}

/**
 * Appends one entry under the parent-head CAS, retrying on a head
 * conflict. Each attempt signs the state's entry at the state's view
 * (`sign`; null = nothing to append, so the attempt succeeds without one)
 * and appends it. After a head conflict the view is resynced with the
 * extension check (nothing is re-signed onto a shortened or forked chain —
 * chain-sync.ts's resyncExtended), and `recheck` redoes the op's
 * pre-checks on it and returns the next attempt's state. The resync and
 * `recheck` run after the last attempt's conflict too, so a definite
 * error they fail with is reported rather than the exhausted wording
 * (retry.ts).
 */
export function appendWithRetry<S extends { readonly verified: VerifiedProject }>(
  context: AppendContext,
  input: {
    /** The op name the exhausted wording uses (e.g. "remove_member"). */
    readonly op: string;
    readonly initial: S;
    readonly sign: (state: S) => Effect.Effect<ChainEntry | null, CliError>;
    readonly recheck: (resynced: VerifiedProject) => Effect.Effect<S, CliError>;
  },
): Effect.Effect<AppendOutcome<S>, CliError> {
  return retryOnConflict(input.initial, {
    maxAttempts: MAX_APPEND_ATTEMPTS,
    attempt: (state) =>
      Effect.gen(function* () {
        const entry = yield* input.sign(state);
        if (entry !== null) {
          yield* appendEntry(context.client, state.verified, entry);
        }
        return { state, entry };
      }),
    classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
    recover: (state) =>
      Effect.flatMap(resyncExtended(context.resync, state.verified), input.recheck),
    exhaustedMessage: `${input.op}'s chain-head conflict did not resolve (${MAX_APPEND_ATTEMPTS} attempts). Wait a moment and re-run`,
  });
}

/**
 * appendWithRetry for an entry signEntryAtHead signs: `operation`, signed
 * with the signer's key right after each attempt's view. A state for which
 * `settled` holds appends nothing (a concurrent run already made the
 * change, or closed what the op targets).
 */
export function appendOperationWithRetry<S extends { readonly verified: VerifiedProject }>(
  context: AppendContext & {
    readonly signerUserId: UserId;
    readonly signingKeyPair: SigningKeyPair;
  },
  input: {
    readonly operation: ChainOperation;
    readonly initial: S;
    readonly settled?: (state: S) => boolean;
    readonly recheck: (resynced: VerifiedProject) => Effect.Effect<S, CliError>;
  },
): Effect.Effect<AppendOutcome<S>, CliError> {
  return appendWithRetry(context, {
    op: input.operation.op,
    initial: input.initial,
    sign: (state) =>
      input.settled?.(state) === true
        ? Effect.succeed(null)
        : signEntryAtHead({
            verified: state.verified,
            signerUserId: context.signerUserId,
            operation: input.operation,
            signingKeyPair: context.signingKeyPair,
          }),
    recheck: input.recheck,
  });
}
