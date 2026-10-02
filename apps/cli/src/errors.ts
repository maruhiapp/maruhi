// User-facing CLI errors.
//
// Absolute rule (the CLAUDE.md diskless invariant): message must not
// contain plaintext secret values, key material, or raw token values.
// Context is expressed only via identifiers (project ID, variable
// names, epochs, key fingerprints, etc.).

import { Data, Effect, Runtime } from "effect";

/** A user-facing CLI failure. The message never carries secret material. */
export class CliError extends Data.TaggedError("CliError")<{
  readonly message: string;
  /** Whether the error is a misuse of the arguments (a usage error = exit code 2). */
  readonly usage?: boolean;
  /**
   * Whether the failure carries cryptographic evidence (a
   * contradiction between signature-verified data and the chain
   * attestation / floor — one a re-run does not resolve). rotate's
   * per-leg classification (settlePass in env-rotate.ts) reads it to
   * avoid downgrading to "re-run to fix" guidance.
   */
  readonly evidence?: boolean;
  /**
   * Whether the failure is the server being unreachable (no response,
   * or a gateway error in front of it) rather than an answer. The
   * read-only fallback to a configured mirror (PF2 — AUTH_SPEC §11-7)
   * fires on this and on nothing else: an answer from the primary (a
   * 403, a 404, a conflict) is never retried against a replica.
   */
  readonly unreachable?: boolean;
}> {
  /**
   * The exit code is **carried by the error type itself** (ADR-0016
   * decision 4). An Effect mechanism to keep a "usage = 2, failure =
   * 1" mapping table off the runner; `Runtime.defaultTeardown` (=
   * `runMain`'s default teardown) reads it.
   */
  override get [Runtime.errorExitCode](): number {
    return this.usage === true ? 2 : 1;
  }
}

/** Builds a {@link CliError} from a user-facing message. */
export function cliError(message: string): CliError {
  return new CliError({ message });
}

/**
 * Builds a {@link CliError} carrying cryptographic evidence (a contradiction
 * between verified data and the chain's notarization or the local floor —
 * a failure re-running cannot resolve).
 */
export function evidenceError(message: string): CliError {
  return new CliError({ message, evidence: true });
}

/**
 * Builds a {@link CliError} for a malformed invocation (exit code 2).
 *
 * For the "the word refers to nothing" shape that the parser layer
 * cannot drop — unknown operation / unknown config key / malformed
 * ID. Without distinguishing it from an execution failure (1), a
 * script would treat a typo as an execution failure.
 */
export function usageError(message: string): CliError {
  return new CliError({ message, usage: true });
}

/**
 * Sorts a cleanup step's failure (`env rotate --config` / `push` cleanup —
 * sync-rotate.ts / sync-push.ts): evidence (a contradiction re-running cannot
 * resolve) keeps failing, everything else comes back as a value so the caller
 * can warn without changing the exit code of the work already reported.
 */
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
