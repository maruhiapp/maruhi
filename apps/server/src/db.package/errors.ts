// Shared D1 error classifiers used by multiple repository files (inside the
// db.package boundary — a leaf with no inbound edges so repo files and the
// assembly in repos.ts never form an import cycle).

/**
 * Judges from the D1 error message whether a failure is a unique
 * constraint violation. Distinguished because misclassifying a
 * non-conflict failure (a transient outage, an FK violation, etc.) as a
 * "conflict" would make the re-lookup come up empty and misdirect the
 * incident investigation with a defect message that does not match
 * reality. drizzle wraps the error into `cause` depending on the path
 * (a batch passes it through; a single query wraps it in
 * DrizzleQueryError), so the cause chain is walked too. Exposed for
 * tests.
 */
export function isUniqueConflict(error: unknown): boolean {
  for (let current = error; current instanceof Error; current = current.cause) {
    if (current.message.includes("UNIQUE constraint failed")) {
      return true;
    }
  }
  return false;
}
