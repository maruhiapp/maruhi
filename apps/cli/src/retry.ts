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

/** Every `_tag` literal carried by E's tagged members. */
type TagsOf<E> = E extends { readonly _tag: infer Tag extends string } ? Tag : never;

/** The members of E carrying `_tag` K (never when none do). */
type TaggedMember<E, K extends string> = E extends { readonly _tag: K } ? E : never;

export interface ConflictRetryOptions<S, A, C, E, R = never, K extends string = never> {
  readonly maxAttempts: number;
  /** One attempt (from the current state through signing and sending). Succeeds with the accepted value or fails with a typed error. */
  readonly attempt: (state: S) => Effect.Effect<A, E, R>;
  /** Classifies the failure: a classifiable value for a retryable conflict, null for a definite error (mapped to CliError and propagated). */
  readonly classify: (error: E) => C | null;
  /** Recovery from a conflict. A failure (definite error) propagates as is. */
  readonly recover: (state: S, conflict: C) => Effect.Effect<S, CliError, R>;
  /** Message for when every attempt is exhausted on conflicts. */
  readonly exhaustedMessage: string;
  /**
   * A failure `_tag` that bypasses classification and propagates as its
   * own tagged error (an outer retry's signal — the unclassified path's
   * toCliError mapping would erase the distinction the caller branches
   * on). Everything else is classified or mapped, as without the option.
   * A `_tag` E does not carry is not a compile error — it simply never
   * matches, degrading that error to the toCliError path.
   */
  readonly passthrough?: K;
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
export function retryOnConflict<S, A, C, E, R = never, K extends string = never>(
  initial: S,
  options: ConflictRetryOptions<S, A, C, E, R, K>,
): Effect.Effect<A, CliError | TaggedMember<E, K>, R> {
  return Effect.gen(function* () {
    const unclassified = (
      error: E,
    ): Effect.Effect<
      | { readonly kind: "accepted"; readonly value: A }
      | { readonly kind: "conflict"; readonly conflict: C },
      CliError
    > => {
      const conflict = options.classify(error);
      return conflict === null
        ? Effect.fail(toCliError(error))
        : Effect.succeed({ kind: "conflict", conflict } as const);
    };
    let state = initial;
    for (let attempt = 1; attempt <= options.maxAttempts; attempt += 1) {
      const outcome = yield* options.attempt(state).pipe(
        Effect.map((value) => ({ kind: "accepted", value }) as const),
        options.passthrough === undefined
          ? Effect.catch(unclassified)
          : // The option documents "a tag E carries"; the cast is contained
            // inside this abstraction (catchTag's K must be provably a tag
            // of E, while the option's K infers from the caller's literal)
            Effect.catchTag(options.passthrough as string as TagsOf<E>, Effect.fail, unclassified),
      );
      if (outcome.kind === "accepted") {
        return outcome.value;
      }
      state = yield* options.recover(state, outcome.conflict);
    }
    return yield* Effect.fail(cliError(options.exhaustedMessage));
  });
}
