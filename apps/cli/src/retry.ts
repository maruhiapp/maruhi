// Shared combinator for CAS-conflict retries (the retry procedure of
// AUTH_SPEC §12-4 / §12-5).
//
// The skeleton "attempt → classify conflict → recover (build re-sign
// material from a re-synced view) → re-attempt, and run recovery even
// on the final attempt to surface definite errors" is shared by
// push.ts / env-create.ts. Domain-specific recovery (adopting the
// winner, re-resolving, rebuilding wraps) stays in the caller's
// recover.

import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";

export interface ConflictRetryOptions<S, A, C> {
  readonly maxAttempts: number;
  /** One attempt (from the current state through signing and sending). Succeeds with the accepted value or fails with a raw error. */
  readonly attempt: (state: S) => Effect.Effect<A, unknown>;
  /** Classifies the failure: a classifiable value for a retryable conflict, null for a definite error (mapped to CliError and propagated). */
  readonly classify: (error: unknown) => C | null;
  /** Recovery from a conflict. A failure (definite error) propagates as is. */
  readonly recover: (state: S, conflict: C) => Effect.Effect<S, CliError>;
  /** Message for when every attempt is exhausted on conflicts. */
  readonly exhaustedMessage: string;
}

/**
 * Retries a CAS-style operation: run `attempt`, classify failures into
 * retryable conflicts, `recover` a fresh state (re-sync, re-resolve,
 * re-sign material) and try again, up to `maxAttempts`.
 *
 * Recovery runs even on the final attempt's conflict: definite
 * errors that become known through re-sync and re-resolution
 * (evidence of equivocation, a contradiction between the server's
 * response and the chain, a concurrent-create duplicate, etc.) are
 * more informative than a generic exhausted message. A definite
 * error propagates as is; only a returned retryable state is used on
 * the next round (unused on the final round).
 */
export function retryOnConflict<S, A, C>(
  initial: S,
  options: ConflictRetryOptions<S, A, C>,
): Effect.Effect<A, CliError> {
  return Effect.gen(function* () {
    let state = initial;
    for (let attempt = 1; attempt <= options.maxAttempts; attempt += 1) {
      const outcome = yield* options.attempt(state).pipe(
        Effect.map((value) => ({ kind: "accepted", value }) as const),
        Effect.catch(
          (
            error,
          ): Effect.Effect<
            | { readonly kind: "accepted"; readonly value: A }
            | { readonly kind: "conflict"; readonly conflict: C },
            CliError
          > => {
            const conflict = options.classify(error);
            return conflict === null
              ? Effect.fail(toCliError(error))
              : Effect.succeed({ kind: "conflict", conflict } as const);
          },
        ),
      );
      if (outcome.kind === "accepted") {
        return outcome.value;
      }
      state = yield* options.recover(state, outcome.conflict);
    }
    return yield* Effect.fail(cliError(options.exhaustedMessage));
  });
}
