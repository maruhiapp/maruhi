import { Cause, Exit, Runtime } from "effect";
import { CliError } from "effect/cli";

const USAGE_EXIT_CODE = 2;

export function maruhiTeardown(infoRequested: boolean): Runtime.Teardown {
  return <E, A>(exit: Exit.Exit<E, A>, onExit: (code: number) => void): void => {
    if (Exit.isFailure(exit)) {
      const failure: unknown = Cause.squash(exit.cause);
      if (failure instanceof CliError.ShowHelp) {
        if (failure.errors.length > 0 || !infoRequested) {
          onExit(USAGE_EXIT_CODE);
          return;
        }
      }
    }
    Runtime.defaultTeardown(exit, onExit);
  };
}
