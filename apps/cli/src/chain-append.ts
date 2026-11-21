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

const MAX_APPEND_ATTEMPTS = 5;

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

interface AppendContext {
  readonly client: MaruhiClient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}

interface AppendOutcome<S> {
  readonly state: S;
  readonly entry: ChainEntry | null;
}

export function appendWithRetry<S extends { readonly verified: VerifiedProject }>(
  context: AppendContext,
  input: {
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
