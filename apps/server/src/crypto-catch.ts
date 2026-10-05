// Exhaustive handling of a crypto call's typed error channel
// (`WrappedCryptoError`, the @maruhi/core bridge).
//
// A data-first `Effect.catchTag(effect, tag, f, orElse)` whose `orElse`
// dies accepts every other kind, so a new `WrappedCryptoError` member
// would silently become a defect (a 500) at each such site. The table
// below has one required key per kind instead: adding a member fails
// typecheck at every call site until that site decides what the new
// kind means there.

import type { WrappedCryptoError } from "@maruhi/core";
import { Effect } from "effect";

/**
 * One entry per `WrappedCryptoError` kind. An entry is either a handler
 * (a refusal the site maps onto its own typed error) or `"die"` — the
 * kind is unreachable at this site, so it is an implementation bug and
 * becomes a defect carrying the error value (which holds identifiers
 * only — field / seq / reason codes — never secrets).
 */
export type CryptoErrorCases<E> = {
  readonly [Tag in WrappedCryptoError["_tag"]]:
    | "die"
    | ((error: Extract<WrappedCryptoError, { readonly _tag: Tag }>) => Effect.Effect<never, E>);
};

/**
 * Handles every `WrappedCryptoError` kind of `self` through `cases`.
 * The success value passes through unchanged.
 */
export const catchCryptoErrors = <A, E, R>(
  self: Effect.Effect<A, WrappedCryptoError, R>,
  cases: CryptoErrorCases<E>,
): Effect.Effect<A, E, R> =>
  Effect.catch(self, (error) => {
    const handle = cases[error["_tag"]];
    if (handle === "die") {
      return Effect.die(error);
    }
    // `cases` pairs each tag with a handler for that tag's member, and
    // `error["_tag"]` selected the entry, so the argument matches it (the
    // compiler cannot correlate the index with the narrowed parameter)
    return (handle as (error: WrappedCryptoError) => Effect.Effect<never, E>)(error);
  });
