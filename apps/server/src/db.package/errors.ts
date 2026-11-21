import { Data, Effect } from "effect";

export class D1UniqueConflictError extends Data.TaggedError("D1UniqueConflict")<{
  readonly cause: unknown;
  readonly constraint: string | null;
}> {}

export class D1FailureError extends Data.TaggedError("D1Failure")<{
  readonly cause: unknown;
}> {}

export type D1Error = D1UniqueConflictError | D1FailureError;

export const tryD1 = <A>(
  thunk: () => Promise<A>,
): Effect.Effect<A, D1UniqueConflictError | D1FailureError> =>
  Effect.tryPromise({
    try: thunk,
    catch: (error) =>
      isUniqueConflict(error)
        ? new D1UniqueConflictError({ cause: error, constraint: conflictTargetOf(error) })
        : new D1FailureError({ cause: error }),
  });

function isUniqueConflict(error: unknown): boolean {
  for (let current = error; current instanceof Error; current = current.cause) {
    if (current.message.includes("UNIQUE constraint failed")) {
      return true;
    }
  }
  return false;
}

function conflictTargetOf(error: unknown): string | null {
  for (let current = error; current instanceof Error; current = current.cause) {
    const target = /UNIQUE constraint failed: ([^:]+)/.exec(current.message)?.[1]?.trim();
    if (target) {
      return target;
    }
  }
  return null;
}
