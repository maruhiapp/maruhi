import { type WrappedDek } from "@maruhi/api-schema";
import { type EnvironmentId, type ProjectId, type UserId } from "@maruhi/core";
import type { SigningKeyPair, WrapRecipient } from "@maruhi/crypto";
import { Effect, type Redacted } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { wrapAndSignFor } from "./dek-wrap.ts";
import { type DekRecipient, environmentKeysFor } from "./deks.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";

export type RegisterOutcome =
  | { readonly kind: "ok" }
  | { readonly kind: "exists"; readonly storedRecipientEncPubHex: string };

type SlotConflictResolution = "already-registered" | "repaired";

export interface BackfillEnvironmentOutcome {
  readonly registered: number;
  readonly alreadyRegistered: number;
  readonly repaired: number;
}

interface BackfillAggregate {
  readonly registered: number;
  readonly alreadyRegistered: number;
  readonly repaired: number;
  readonly failed: readonly { readonly environmentId: EnvironmentId; readonly message: string }[];
}

export const backfillEachEnvironment = Effect.fn("backfill.backfillEachEnvironment")(function* <R>(
  environments: readonly EnvironmentId[],
  run: (environmentId: EnvironmentId) => Effect.Effect<BackfillEnvironmentOutcome, CliError, R>,
): Effect.fn.Return<BackfillAggregate, never, R> {
  let registered = 0;
  let alreadyRegistered = 0;
  let repaired = 0;
  const failed: { readonly environmentId: EnvironmentId; readonly message: string }[] = [];
  for (const environmentId of environments) {
    const result = yield* run(environmentId).pipe(
      Effect.map((outcome) => ({ kind: "ok", outcome }) as const),
      Effect.catch((error) => Effect.succeed({ kind: "failed", message: error.message } as const)),
    );
    if (result.kind === "ok") {
      registered += result.outcome.registered;
      alreadyRegistered += result.outcome.alreadyRegistered;
      repaired += result.outcome.repaired;
    } else {
      failed.push({ environmentId, message: result.message });
    }
  }
  return { registered, alreadyRegistered, repaired, failed };
});

export const backfillEnvironmentFor = Effect.fn("backfill.backfillEnvironmentFor")(
  function* (input: {
    readonly client: MaruhiClient;
    readonly verified: VerifiedProject;
    readonly environmentId: EnvironmentId;
    readonly recipient: DekRecipient;
    readonly wrapRecipient: WrapRecipient;
    readonly recipientLabel: string;
    readonly signerUserId: UserId;
    readonly signingKeyPair: SigningKeyPair;
    readonly onSlotConflict?: (
      wrap: WrappedDek,
      storedRecipientEncPubHex: string,
    ) => Effect.Effect<SlotConflictResolution, CliError>;
    readonly epochs?: readonly number[];
    readonly cached?: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  }): Effect.fn.Return<BackfillEnvironmentOutcome, CliError> {
    const keys = yield* environmentKeysFor({
      client: input.client,
      verified: input.verified,
      environmentId: input.environmentId,
      recipient: input.recipient,
      cached: input.cached,
    });
    const wraps: WrappedDek[] = [];
    for (const epoch of epochsToWrap(input.epochs, keys.currentEpoch)) {
      const dek = keys.deksByEpoch.get(epoch);
      if (dek === undefined) {
        return yield* Effect.fail(
          cliError(
            `No DEK wrap addressed to you exists for epoch ${epoch} of environment ${input.environmentId} (contradicts the all-epoch distribution of §7). Have another member who holds wraps for every epoch run this operation, or fill the gap via the repair path (re-registering wraps addressed to you) and re-run`,
          ),
        );
      }
      const built = yield* Effect.tryPromise({
        try: () =>
          wrapAndSignFor({
            projectId: input.verified.projectId,
            environmentId: input.environmentId,
            epoch,
            dek,
            recipient: input.wrapRecipient,
            signerUserId: input.signerUserId,
            signingKeyPair: input.signingKeyPair,
          }),
        catch: () =>
          cliError(`Failed to build the ${input.recipientLabel} DEK wrap (crypto error)`),
      });
      if (built.kind === "failed") {
        return yield* Effect.fail(
          cliError(`Failed to build the ${input.recipientLabel} DEK wrap (${built.reason})`),
        );
      }
      wraps.push(built.wrap);
    }

    const register = registerWraps(input.client, input.verified.projectId, input.environmentId);

    const batch = yield* register(wraps);
    if (batch.kind === "ok") {
      return { registered: wraps.length, alreadyRegistered: 0, repaired: 0 };
    }
    let registered = 0;
    let alreadyRegistered = 0;
    let repaired = 0;
    for (const wrap of wraps) {
      const single = yield* register([wrap]);
      if (single.kind === "ok") {
        registered += 1;
        continue;
      }
      const resolution =
        input.onSlotConflict === undefined
          ? ("already-registered" as const)
          : yield* input.onSlotConflict(wrap, single.storedRecipientEncPubHex);
      if (resolution === "repaired") {
        repaired += 1;
      } else {
        alreadyRegistered += 1;
      }
    }
    return { registered, alreadyRegistered, repaired };
  },
);

function epochsToWrap(
  epochs: readonly number[] | undefined,
  currentEpoch: number,
): readonly number[] {
  return epochs ?? Array.from({ length: currentEpoch }, (_, index) => index + 1);
}

export function registerWraps(
  client: MaruhiClient,
  projectId: ProjectId,
  environmentId: EnvironmentId,
): (deks: readonly WrappedDek[]) => Effect.Effect<RegisterOutcome, CliError> {
  return (deks) =>
    client.deks.register({ params: { projectId, environmentId }, payload: { deks } }).pipe(
      Effect.map((): RegisterOutcome => ({ kind: "ok" })),
      Effect.catchTag(
        "DekWrapExists",
        (error) =>
          Effect.succeed<RegisterOutcome>({
            kind: "exists",
            storedRecipientEncPubHex: error.storedRecipientEncPubHex,
          }),
        (error) => Effect.fail(toCliError(error)),
      ),
    );
}
