// Shared D1 access adapter and error classification (ADR-0006's "thin
// tryPromise adapter") used by every repository file in db.package
// (inside the db.package boundary — a leaf with no inbound edges so
// repo files and the assembly in repos.ts never form an import cycle).

import { Data, Effect } from "effect";

/**
 * A D1 failure classified as a UNIQUE-constraint violation — the only
 * domain-expected branch a caller may recover from via
 * `Effect.catchTag("D1UniqueConflict", ...)`. `constraint` is the
 * violated target text the message carried (e.g.
 * "invitations.link_pub"), so a caller with several unique
 * constraints can tell which one lost without matching raw text
 * again; null when the message named none.
 */
export class D1UniqueConflictError extends Data.TaggedError("D1UniqueConflict")<{
  readonly cause: unknown;
  readonly constraint: string | null;
}> {}

/** A D1 failure that is not a domain-expected unique conflict. */
export class D1FailureError extends Data.TaggedError("D1Failure")<{
  readonly cause: unknown;
}> {}

/** The D1 failure family a `tryD1` call can raise. */
export type D1Error = D1UniqueConflictError | D1FailureError;

/**
 * The thin tryPromise adapter of ADR-0006, shared by every repository
 * method: a UNIQUE violation is classified as D1UniqueConflictError
 * (the only domain-expected branch — callers recover with
 * `Effect.catchTag("D1UniqueConflict", ...)`) and everything else is
 * D1FailureError, which each repository method turns into a defect
 * with `Effect.orDie` at its boundary. The public repository types
 * keep an empty error channel because the handlers that would turn
 * these into typed errors belong to other lanes; an unexpected D1
 * failure is still a defect, so it surfaces as a 500 exactly as
 * before.
 */
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

/**
 * Judges from the D1 error message whether a failure is a unique
 * constraint violation. Distinguished because misclassifying a
 * non-conflict failure (a transient outage, an FK violation, etc.) as
 * a "conflict" would make the re-lookup come up empty and misdirect
 * the incident investigation with a defect message that does not
 * match reality. drizzle wraps the error into `cause` depending on
 * the path (a batch passes it through; a single query wraps it in
 * DrizzleQueryError), so the cause chain is walked too.
 */
function isUniqueConflict(error: unknown): boolean {
  for (let current = error; current instanceof Error; current = current.cause) {
    if (current.message.includes("UNIQUE constraint failed")) {
      return true;
    }
  }
  return false;
}

/**
 * The violated constraint's target text from the same cause-chain
 * walk as isUniqueConflict ("UNIQUE constraint failed:
 * <table>.<column>"), null when the message carried none. The real
 * workerd shape appends a SQLite code tail — `: SQLITE_CONSTRAINT
 * (extended: SQLITE_CONSTRAINT_*)` — and the target list (one or
 * comma-joined columns) never contains a colon, so the capture stops
 * at the first one (or the end of the message). An empty capture
 * keeps the walk going to the next cause.
 */
function conflictTargetOf(error: unknown): string | null {
  for (let current = error; current instanceof Error; current = current.cause) {
    const target = /UNIQUE constraint failed: ([^:]+)/.exec(current.message)?.[1]?.trim();
    if (target) {
      return target;
    }
  }
  return null;
}
