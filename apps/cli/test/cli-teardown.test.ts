// Unit tests for the exit codes: the error types carry
// Runtime.errorExitCode (errors.ts), and maruhiTeardown (cli-teardown.ts)
// maps ShowHelp so that a usage mistake exits 2.

import { Exit, Runtime } from "effect";
import { CliError as EffectCliError } from "effect/cli";
import { describe, expect, it } from "vitest";

import { maruhiTeardown } from "../src/cli-teardown.ts";
import { cliError, usageError } from "../src/errors.ts";

describe("exit codes ride Effect's mechanism", () => {
  it("the error types carry Runtime.errorExitCode (no mapping table written on the runner)", () => {
    // Runtime.defaultTeardown = the default teardown BunRuntime.runMain uses
    const failure: number[] = [];
    Runtime.defaultTeardown(Exit.fail(cliError("the run failed")), (code) => failure.push(code));
    expect(failure).toEqual([1]);

    const usage: number[] = [];
    Runtime.defaultTeardown(Exit.fail(usageError("invalid usage")), (code) => usage.push(code));
    expect(usage).toEqual([2]);
  });

  it("ShowHelp declares exit 1 upstream, so teardown remaps it to 2", () => {
    // Upstream: ShowHelp[Runtime.errorExitCode] = errors.length ? 1 : 0.
    // Left at the default teardown, **a usage mistake becomes exit 1** and
    // maruhi's 0/1/2 contract breaks
    const withErrors = Exit.fail(
      new EffectCliError.ShowHelp({
        commandPath: ["maruhi", "pull"],
        errors: [new EffectCliError.UnrecognizedOption({ option: "--shwo", suggestions: [] })],
      }),
    );
    const defaultCodes: number[] = [];
    Runtime.defaultTeardown(withErrors, (code) => defaultCodes.push(code));
    expect(defaultCodes).toEqual([1]);

    const codes: number[] = [];
    maruhiTeardown(false)(withErrors, (code) => codes.push(code));
    expect(codes).toEqual([2]);

    // A run that explicitly asked for `--help` / `--version` (errors empty) is not a mistake
    const helpCodes: number[] = [];
    maruhiTeardown(true)(
      Exit.fail(new EffectCliError.ShowHelp({ commandPath: ["maruhi"], errors: [] })),
      (code) => helpCodes.push(code),
    );
    expect(helpCodes).toEqual([0]);

    // A run with errors empty but no explicit help / version = a bare parent
    // command that requires a subcommand (`maruhi env`). A usage mistake (2)
    const bareCodes: number[] = [];
    maruhiTeardown(false)(
      Exit.fail(new EffectCliError.ShowHelp({ commandPath: ["maruhi", "env"], errors: [] })),
      (code) => bareCodes.push(code),
    );
    expect(bareCodes).toEqual([2]);
  });
});
