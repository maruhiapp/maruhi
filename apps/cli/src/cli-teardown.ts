// Expresses maruhi's exit-code convention **as a `runMain` teardown**
// (ADR-0016 decision 4).
//
// Convention: 0 = success / 1 = execution failure / **2 = usage error**.
// These three values cannot be broken, or a script would read a typo as
// "the operation failed".
//
// For execution failures the error type itself carries
// `Runtime.errorExitCode` (errors.ts's `CliError` returns 2 / 1 by whether
// it is a usage error), so no mapping table is needed. The only exception
// is `ShowHelp`: upstream declares
// `ShowHelp[Runtime.errorExitCode] = this.errors.length ? 1 : 0`, which
// makes **a usage error exit 1**. The only hook upstream provides is
// `makeRunMain({ teardown })` (`CliConfig` holds only builtIns), so the
// reinterpretation happens here. Computing exit codes by hand in the
// harness would stop testing the production startup path — tests and
// production both pass through this teardown via the single cli.ts path.

import { Cause, Exit, Runtime } from "effect";
import { CliError } from "effect/cli";

/** Usage error. If indistinguishable from an execution failure (1), a typo cannot be fixed. */
const USAGE_EXIT_CODE = 2;

/**
 * Builds the teardown that maps CLI usage errors to exit code 2 and defers
 * everything else to {@link Runtime.defaultTeardown}.
 *
 * `infoRequested` = whether the launch argv (before `--`) contained
 * `--help` / `-h` / `--version` / `-v`. Upstream uses **`ShowHelp` with
 * empty errors** for two meanings — an explicit help/version display (not
 * an error = 0) and invoking a subcommand-required parent command alone
 * (`maruhi env` — a usage error = 2). The upstream error type alone
 * cannot distinguish them, so they are told apart by whether such a
 * request was made at launch.
 *
 * Being `(exit, onExit) => void`, it judges the same whether passed to
 * `BunRuntime.runMain({ teardown })` or applied directly to an
 * `Effect.exit` result (cli.ts does the latter — to keep bin.ts's
 * explicit `process.exit`: a pending `Bun.secrets` native call
 * interrupted by the keychain-operation timeout was observed to keep the
 * event loop alive and prevent the process from exiting).
 */
export function maruhiTeardown(infoRequested: boolean): Runtime.Teardown {
  return <E, A>(exit: Exit.Exit<E, A>, onExit: (code: number) => void): void => {
    if (Exit.isFailure(exit)) {
      const failure: unknown = Cause.squash(exit.cause);
      if (failure instanceof CliError.ShowHelp) {
        // errors present = a usage error. Even with empty errors, a run
        // that did not explicitly ask for help/version (a parent command
        // alone with no subcommand) is a usage error
        if (failure.errors.length > 0 || !infoRequested) {
          onExit(USAGE_EXIT_CODE);
          return;
        }
      }
    }
    Runtime.defaultTeardown(exit, onExit);
  };
}
