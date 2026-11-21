import { CliError as EffectCliError } from "effect/cli";
import { describe, expect, it } from "vite-plus/test";

import { describeError } from "../src/cli-formatter.ts";

describe("the diagnostic mapping (rebuilt from structured fields)", () => {
  it("InvalidValue never shows the typed value", () => {
    const message = describeError(
      new EffectCliError.InvalidValue({
        option: "limit",
        value: "SUPER_SECRET_VALUE",
        expected: "integer",
        kind: "flag",
      }),
      "pull",
      { pull: { flags: ["limit"], positionals: [] } },
    );
    expect(message).toContain("Unacceptable value for flag --limit");
    expect(message).not.toContain("SUPER_SECRET_VALUE");
  });

  it("a value embedded in **expected** is never shown either (the leak via filter's onNone)", () => {
    const message = describeError(
      new EffectCliError.InvalidValue({
        option: "env",
        value: "SUPER_SECRET_VALUE",
        expected: "Expected even number, got SUPER_SECRET_VALUE",
        kind: "flag",
      }),
      "pull",
      { pull: { flags: ["env"], positionals: [] } },
    );
    expect(message).toBe("Unacceptable value for flag --env");
    expect(message).not.toContain("SUPER_SECRET_VALUE");
  });

  it("run's command missing (0 args) as a MissingArgument gets the execution-target wording", () => {
    const missing = describeError(
      new EffectCliError.MissingArgument({ argument: "command" }),
      "run",
      { run: { flags: [], positionals: ["command"] } },
    );
    expect(missing).toContain("Specify the command to run after `--`");
    const other = describeError(
      new EffectCliError.MissingArgument({ argument: "environment-id" }),
      "run",
      { run: { flags: [], positionals: ["environment-id"] } },
    );
    expect(other).toBe("Missing positional argument environment-id");
  });

  it("UnexpectedArgument shows only the count", () => {
    const message = describeError(
      new EffectCliError.UnexpectedArgument({ arguments: ["SECRET_A", "SECRET_B"] }),
      "pull",
      { pull: { flags: [], positionals: [] } },
    );
    expect(message).toContain("(2;");
    expect(message).not.toContain("SECRET_A");
    expect(message).not.toContain("SECRET_B");
  });

  it("ValidationError (a Command.validate rule) shows the rule's own fixed message", () => {
    const message = describeError(
      new EffectCliError.ValidationError({
        message: "--required and --optional are mutually exclusive (specify at most one)",
      }),
      "schema set",
      { "schema set": { flags: ["required", "optional"], positionals: ["name"] } },
    );
    expect(message).toBe("--required and --optional are mutually exclusive (specify at most one)");
  });
});
