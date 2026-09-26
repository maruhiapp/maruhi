// The shared core of backfill (CRYPTO_SPEC §7 / AUTH_SPEC §12-6).
//
// The structure — "verify and unwrap every epoch's DEK (1 through the
// current epoch) of one environment from the wraps addressed to me, re-wrap
// for the target recipient, and register; converge a 409 (an occupied
// slot) by dropping from bulk to per-epoch" — is identical between the
// server-directed backfill right after a grant (server-grant) and the
// new-member-directed backfill after add_member (member). Only the
// resolution of a per-epoch 409 differs (treat as registered / replace via
// the repair path), so that is the injection point.

import { DekWrapExistsError, type WrappedDek } from "@maruhi/api-schema";
import type { SigningKeyPair } from "@maruhi/crypto";
import { Effect, type Redacted } from "effect";

import type { MaruhiClient } from "./api.ts";
import { wrapAndSignFor, type WrapRecipient } from "./dek-wrap.ts";
import { type DekRecipient, environmentKeysFor } from "./deks.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { VerifiedProject } from "./sync.ts";

/**
 * Result of a registration attempt (409 = existing slot).
 * `storedRecipientEncPubHex` is the stored recipient enc public key of the
 * occupying wrap carried by the 409 (AUTH_SPEC §12-6; servers from before
 * the supplement do not carry it = null).
 */
export type RegisterOutcome =
  | { readonly kind: "ok" }
  | { readonly kind: "exists"; readonly storedRecipientEncPubHex: string | null };

/** Resolution of a per-epoch 409 (the caller's semantics). */
export type SlotConflictResolution = "already-registered" | "repaired";

export interface BackfillEnvironmentOutcome {
  readonly registered: number;
  readonly alreadyRegistered: number;
  /** How many times `onSlotConflict` returned "repaired" (member add's repair path). */
  readonly repaired: number;
}

/** Aggregate of a multi-environment backfill (one environment's failure does not stop the rest — §7). */
export interface BackfillAggregate {
  readonly registered: number;
  readonly alreadyRegistered: number;
  readonly repaired: number;
  readonly failed: readonly { readonly environmentId: string; readonly message: string }[];
}

/**
 * Runs the backfill per environment and aggregates (the aggregation shape
 * shared by member add / change-role widenings / device addition).
 * Failures are collected per environment and the run continues.
 */
export function backfillEachEnvironment<R>(
  environments: readonly string[],
  run: (environmentId: string) => Effect.Effect<BackfillEnvironmentOutcome, CliError, R>,
): Effect.Effect<BackfillAggregate, never, R> {
  return Effect.gen(function* () {
    let registered = 0;
    let alreadyRegistered = 0;
    let repaired = 0;
    const failed: { readonly environmentId: string; readonly message: string }[] = [];
    for (const environmentId of environments) {
      const result = yield* run(environmentId).pipe(
        Effect.map((outcome) => ({ kind: "ok", outcome }) as const),
        Effect.catch((error) =>
          Effect.succeed({ kind: "failed", message: error.message } as const),
        ),
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
}

/**
 * Wraps every epoch's DEK of one environment for the target recipient and
 * registers them. Verify & unwrap the wraps addressed to me (§5.1 + §5.2)
 * → re-wrap + sign the registration (§5.1) → bulk register → on 409 drop
 * to per-epoch (because a batch is accepted atomically, a re-run after a
 * partial registration gets a 409 for the bulk). A per-epoch 409 is
 * resolved by `onSlotConflict` (default = treat as registered).
 */
export function backfillEnvironmentFor(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  /** Recipient info of myself (the DEK holder = the one performing the wrap — §7). */
  readonly recipient: DekRecipient;
  /** The wrap's destination (a server key / a new member). */
  readonly wrapRecipient: WrapRecipient;
  /** Destination label used in the wrap-generation failure message (e.g. "for the server"). */
  readonly recipientLabel: string;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  /**
   * Resolution of a per-epoch 409 (omitted = treat as registered). member
   * add's re-add repair performs delete → re-register here (the §12-6
   * repair path). The second argument is the stored recipient enc public
   * key of the occupying wrap carried by the 409 (null on old servers —
   * input to fallback detection).
   */
  readonly onSlotConflict?: (
    wrap: WrappedDek,
    storedRecipientEncPubHex: string | null,
  ) => Effect.Effect<SlotConflictResolution, CliError>;
  /**
   * The epochs to wrap (omitted = all of 1 through the current epoch).
   * Device gap filling (device-gaps.ts — DK K11-1) passes only the missing
   * epochs it could open.
   */
  readonly epochs?: readonly number[];
  /** My-addressed DEKs already verified and unwrapped in this session (the `cached` of `environmentKeysFor`). */
  readonly cached?: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
}): Effect.Effect<BackfillEnvironmentOutcome, CliError> {
  return Effect.gen(function* () {
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
        // §7: every member receives every epoch's DEK. A gap is a sign of a
        // poisoned wrap or a loss, so it is not silently skipped (guide the
        // §12-6 repair path). A plain re-run does not fix it (it hits the
        // same gap every time unless a wrap addressed to me exists), so do
        // not say "please re-run"
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

    // Bulk → on 409, drop to per-epoch to converge
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
  });
}

/** Epochs to wrap: the given ones, or 1 through the current epoch (the backfill default). */
function epochsToWrap(
  epochs: readonly number[] | undefined,
  currentEpoch: number,
): readonly number[] {
  return epochs ?? Array.from({ length: currentEpoch }, (_, index) => index + 1);
}

/**
 * Attempt to register DEK wraps (409 = DekWrapExists is returned as the
 * value "existing slot" — input to re-run convergence and repair
 * decisions).
 */
export function registerWraps(
  client: MaruhiClient,
  projectId: string,
  environmentId: string,
): (deks: readonly WrappedDek[]) => Effect.Effect<RegisterOutcome, CliError> {
  return (deks) =>
    client.deks.register({ params: { projectId, environmentId }, payload: { deks } }).pipe(
      Effect.map((): RegisterOutcome => ({ kind: "ok" })),
      Effect.catch((error) =>
        error instanceof DekWrapExistsError
          ? Effect.succeed<RegisterOutcome>({
              kind: "exists",
              storedRecipientEncPubHex: error.storedRecipientEncPubHex ?? null,
            })
          : Effect.fail(toCliError(error)),
      ),
    );
}
