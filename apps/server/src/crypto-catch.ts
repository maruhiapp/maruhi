import type { WrappedCryptoError } from "@maruhi/core";
import { Effect } from "effect";

export type CryptoErrorCases<E> = {
  readonly [Tag in WrappedCryptoError["_tag"]]:
    | "die"
    | ((error: Extract<WrappedCryptoError, { readonly _tag: Tag }>) => Effect.Effect<never, E>);
};

export const catchCryptoErrors = <A, E, R>(
  self: Effect.Effect<A, WrappedCryptoError, R>,
  cases: CryptoErrorCases<E>,
): Effect.Effect<A, E, R> =>
  Effect.catch(self, (error) => {
    const handle = cases[error["_tag"]];
    if (handle === "die") {
      return Effect.die(error);
    }
    return (handle as (error: WrappedCryptoError) => Effect.Effect<never, E>)(error);
  });
