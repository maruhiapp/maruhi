import { Exit, Runtime } from "effect";
import { CliError as EffectCliError } from "effect/cli";
import { describe, expect, it } from "vite-plus/test";

import { maruhiTeardown } from "../src/cli-teardown.ts";
import { cliError, usageError } from "../src/errors.ts";

describe("exit codes ride Effect's mechanism", () => {
  it("the error types carry Runtime.errorExitCode (no mapping table written on the runner)", () => {
    const failure: number[] = [];
    Runtime.defaultTeardown(Exit.fail(cliError("the run failed")), (code) => failure.push(code));
    expect(failure).toEqual([1]);

    const usage: number[] = [];
    Runtime.defaultTeardown(Exit.fail(usageError("invalid usage")), (code) => usage.push(code));
    expect(usage).toEqual([2]);
  });

  it("ShowHelp declares exit 1 upstream, so teardown remaps it to 2", () => {
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

    const helpCodes: number[] = [];
    maruhiTeardown(true)(
      Exit.fail(new EffectCliError.ShowHelp({ commandPath: ["maruhi"], errors: [] })),
      (code) => helpCodes.push(code),
    );
    expect(helpCodes).toEqual([0]);

    const bareCodes: number[] = [];
    maruhiTeardown(false)(
      Exit.fail(new EffectCliError.ShowHelp({ commandPath: ["maruhi", "env"], errors: [] })),
      (code) => bareCodes.push(code),
    );
    expect(bareCodes).toEqual([2]);
  });
});
