import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";

type TaggedMember<E, K extends string> = E extends { readonly _tag: K } ? E : never;

interface ConflictRetryOptions<S, A, C, E, R = never, K extends string = never> {
  readonly maxAttempts: number;
  readonly attempt: (state: S) => Effect.Effect<A, E, R>;
  readonly classify: (error: E) => C | null;
  readonly recover: (state: S, conflict: C) => Effect.Effect<S, CliError, R>;
  readonly exhaustedMessage: string;
  readonly passthrough?: abstract new (...args: never) => { readonly _tag: K };
}

export const retryOnConflict = Effect.fn("retry.retryOnConflict")(function* <
  S,
  A,
  C,
  E,
  R = never,
  K extends string = never,
>(
  initial: S,
  options: ConflictRetryOptions<S, A, C, E, R, K>,
): Effect.fn.Return<A, CliError | TaggedMember<E, K>, R> {
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
  const passthrough = options.passthrough;
  for (let attempt = 1; attempt <= options.maxAttempts; attempt += 1) {
    const outcome = yield* options.attempt(state).pipe(
      Effect.map((value) => ({ kind: "accepted", value }) as const),
      passthrough === undefined
        ? Effect.catch(unclassified)
        : Effect.catch(
            (
              error: E,
            ): Effect.Effect<
              | { readonly kind: "accepted"; readonly value: A }
              | { readonly kind: "conflict"; readonly conflict: C },
              CliError | TaggedMember<E, K>
            > =>
              error instanceof passthrough
                ? Effect.fail(error as TaggedMember<E, K>)
                : unclassified(error),
          ),
    );
    if (outcome.kind === "accepted") {
      return outcome.value;
    }
    state = yield* options.recover(state, outcome.conflict);
  }
  return yield* Effect.fail(cliError(options.exhaustedMessage));
});
