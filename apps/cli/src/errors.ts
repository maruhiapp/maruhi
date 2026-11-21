import { Data, Effect, Runtime } from "effect";

export class CliError extends Data.TaggedError("CliError")<{
  readonly message: string;
  readonly usage?: boolean;
  readonly evidence?: boolean;
  readonly unreachable?: boolean;
}> {
  override get [Runtime.errorExitCode](): number {
    return this.usage === true ? 2 : 1;
  }
}

export function cliError(message: string): CliError {
  return new CliError({ message });
}

export function evidenceError(message: string): CliError {
  return new CliError({ message, evidence: true });
}

export function usageError(message: string): CliError {
  return new CliError({ message, usage: true });
}

export function asCleanupOutcome<A, R>(
  effect: Effect.Effect<A, CliError, R>,
): Effect.Effect<
  | { readonly kind: "ok"; readonly value: A }
  | { readonly kind: "failed"; readonly error: CliError },
  CliError,
  R
> {
  return effect.pipe(
    Effect.map((value) => ({ kind: "ok", value }) as const),
    Effect.catch((error: CliError) =>
      error.evidence === true
        ? Effect.fail(error)
        : Effect.succeed({ kind: "failed", error } as const),
    ),
  );
}
