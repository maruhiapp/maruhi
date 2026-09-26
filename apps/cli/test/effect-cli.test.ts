// Conformance checks for the argument layer (`effect/unstable/cli` — pull /
// run / env create / env rotate / env diff).
//
// Drives the parser's 12 pitfall shapes (docs/notes/cli-parser-alternatives.md)
// through the same argv and pins that maruhi's discipline holds: a usage
// mistake = exit 2 / diagnostics go to stderr / stdout stays clean / typed
// values never appear in diagnostics / values are shown only on a human's
// interactive terminal. Operations are never stubbed — everything goes through **the real runCli**.

import { Exit, Runtime } from "effect";
import { CliError as EffectCliError } from "effect/unstable/cli";
import { afterEach, describe, expect, it, vi } from "vitest";

import { describeError } from "../src/cli-formatter.ts";
import { maruhiTeardown } from "../src/cli-teardown.ts";
import { runCli } from "../src/cli.ts";
import { cliError, usageError } from "../src/errors.ts";
import { makeTestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { MockServer } from "./support/server.ts";

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
  vi.restoreAllMocks();
});

/**
 * An environment that is logged in with the default project / environment.
 * The server **never responds** (every request is 404), but it does record —
 * to confirm via "zero requests" that the rejection happened before the
 * command body ran.
 */
async function startEnv(): Promise<{ env: TestEnv; server: MockServer }> {
  const owner = await makeTestUser("user-owner-1111");
  const server = await MockServer.start([]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: "1111111111111111111111111111111111111111111111111111111111111111",
    defaultEnvironment: "prod",
  });
  return { env, server };
}

/** The shared check that no plaintext is mixed into a diagnostic (a typed value never becomes vocabulary). */
function expectNoLeak(env: TestEnv, secrets: readonly string[]): void {
  const output = [...env.logs, ...env.errors].join("\n");
  for (const secret of secrets) {
    expect(output).not.toContain(secret);
  }
}

describe("the parser's 12 pitfall shapes fail at the argument layer", () => {
  it("an undeclared option fails before execution", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["pull", "--shwo"], env.layer)).toBe(2);
    // Candidates come from **declared names** (the typed spelling is never
    // returned). Pinned to exact matching because a partial match would miss
    // `----show` (a doubled prefix)
    expect(env.errors.join("\n")).toContain("maruhi: Unknown flag (did you mean --show?)");
    expectNoLeak(env, ["--shwo"]);
    expect(server.requests).toHaveLength(0);
  });

  it("a value for a boolean is read as written", async () => {
    // To measure `--show=false` / `--show false` before any communication, the
    // environment ID is broken to force a fail (pull-run.test.ts pins that it
    // never reached value display)
    for (const argv of [
      ["pull", "--show=false", "--env", "!bad"],
      ["pull", "--show", "false", "--env", "!bad"],
    ]) {
      const { env, server } = await startEnv();
      // It passes the argument layer and fails at the environment-ID format
      // check (the command body) = `--show` was read as a value-taking option
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n")).toContain("Invalid environment ID");
      expect(server.requests).toHaveLength(0);
    }
  });

  it("a duplicated option fails (refused without naming the winning side)", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["pull", "--env", "prod", "--env", "dev"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Flag --env was specified more than once");
    expectNoLeak(env, ["prod", "dev"]);
    expect(server.requests).toHaveLength(0);
  });

  it("a duplicated boolean also fails (never depends on order)", async () => {
    // `maruhi pull --no-show $FLAGS` (with --show inside $FLAGS) = showing all
    // secrets. A bare Flag.Boolean resolves duplicates silently and **the
    // result depends on the order typed**
    for (const argv of [
      ["pull", "--show", "--no-show"],
      ["pull", "--no-show", "--show"],
      ["pull", "--show", "--show"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n")).toContain("Flag --show was specified more than once");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("an empty string after `--` does not fail", async () => {
    // The target is preserved and it reaches communication (pull) = the argument layer accepted it
    const { env, server } = await startEnv();

    expect(await runCli(["run", "--", "printenv", "", "x"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).not.toContain("Specify the command to run");
    expect(server.requests.length).toBeGreaterThan(0);
  });

  it("a leading empty positional arg fails", async () => {
    const { env, server } = await startEnv();

    // It fails while resolving the empty token as the command name (never
    // skipped and executed with the levels shifted)
    expect(await runCli(["", "pull"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Unknown subcommand");
    expect(env.logs).toEqual([]);
    expect(server.requests).toHaveLength(0);
  });

  it("never resolves a command across `--`", async () => {
    const { env, server } = await startEnv();

    // Resolving it across `--` as `run` would hand the first token after `--`
    // (= the command name itself) over as the execution target
    expect(await runCli(["--", "run", "printenv"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Write the command name before `--`");
    expect(env.runnerCalls).toHaveLength(0);
    expect(server.requests).toHaveLength(0);
  });

  it("a missing required positional arg fails", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["env", "create"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Missing positional argument environment-id");
    expect(server.requests).toHaveLength(0);
  });

  it("a positional-arg name written as an option gets guidance all the way to the fix", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["env", "create", "dev", "--environment-id", "prod"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("--environment-id is a positional argument");
    expect(errors).toContain("Write the value as a positional argument instead");
    expectNoLeak(env, ["prod"]);
    expect(server.requests).toHaveLength(0);
  });

  it("when the level's second token sits behind `--`, no diagnostic pretending it resolved is emitted", async () => {
    // `maruhi env -- create dev`: the upstream lexer cuts at the first `--`,
    // so `create` is never resolved as a subcommand (= it is the `env`
    // level's leftover). If dispatch decided "env create" across `--`, the
    // diagnostic would be a **lie** that "the operation was recognized and there are too many positional args"
    const { env, server } = await startEnv();
    expect(await runCli(["env", "--", "create", "dev"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    // It states the actual shape (an argument the `env` level does not take)
    expect(errors).toContain("maruhi env takes no positional arguments");
    // It never lies that "the operation was recognized"
    expect(errors).not.toContain("maruhi env create");
    expect(server.requests).toHaveLength(0);
  });

  it("an empty / whitespace-only value for an option fails (never silently falls to the default)", async () => {
    // Same shape as the accident where `maruhi push API_KEY --env "$ENV"` with
    // ENV unset silently writes to the default environment. One Schema
    // declaration rejects both
    const empty = await startEnv();
    expect(await runCli(["pull", "--env", ""], empty.env.layer)).toBe(2);
    expect(empty.env.errors.join("\n")).toContain("Unacceptable value for flag --env");
    expect(empty.server.requests).toHaveLength(0);

    const blank = await startEnv();
    expect(await runCli(["pull", "--env", "  "], blank.env.layer)).toBe(2);
    // Also pin on the **positive side** that the allowlist (SAFE_EXPECTATIONS)
    // is alive: fixing the wording on only one side would leave the
    // parenthetical silently dropped — a quiet degradation of the diagnostic
    expect(blank.env.errors.join("\n")).toContain(
      "Unacceptable value for flag --env (expected: a non-empty value",
    );
    // The typed value (whitespace) never appears in the diagnostic
    expect(blank.env.errors.join("\n")).not.toContain('"  "');
  });

  it("extra positional args state only the count, never their contents", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["pull", "SUPER_SECRET_VALUE"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unexpected extra arguments (1;");
    expect(errors).toContain("contents not shown");
    expect(errors).toContain("maruhi pull takes no positional arguments");
    expectNoLeak(env, ["SUPER_SECRET_VALUE"]);
    expect(server.requests).toHaveLength(0);
  });
});

describe("maruhi-specific discipline", () => {
  it("undeclared built-in flags are never grown (--wizard / --completions / --log-level)", async () => {
    // effect/unstable/cli's default adds help / version / wizard /
    // completions / log-level to every command. `maruhi pull --wizard`
    // **launches an interactive wizard** (measured). CliConfig narrows it to
    // just help / version so a secrets tool never carries an undeclared
    // interactive or output path
    for (const argv of [
      ["pull", "--wizard"],
      ["pull", "--completions", "bash"],
      ["pull", "--log-level", "all"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n")).toContain("Unknown flag");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("help and diagnostics never pollute stdout (a separate path from the command's output)", async () => {
    const { env } = await startEnv();
    // Catches any code that bypasses Console / CliIo and writes to the real stdout
    const stdout = vi.spyOn(console, "log").mockImplementation(() => {});

    // `--help` is not a mistake (exit 0). The point is that the body never
    // reaches stdout — blocking the same shape as the accident where
    // `V=$(maruhi config get server)` caught the banner
    expect(await runCli(["pull", "--help"], env.layer)).toBe(0);
    expect(env.logs).toEqual([]);
    expect(env.errors.join("\n")).toContain("maruhi pull");
    expect(stdout).not.toHaveBeenCalled();

    const rejected = await startEnv();
    expect(await runCli(["pull", "--shwo"], rejected.env.layer)).toBe(2);
    expect(rejected.env.logs).toEqual([]);
    expect(rejected.env.errors.length).toBeGreaterThan(0);
    expect(stdout).not.toHaveBeenCalled();
  });

  it("the safety net for **bypassed writes** (real-fd writes that go through neither Console nor CliIo)", async () => {
    // A `console.log` spy alone cannot catch a path that writes to the real fd
    // without going through `Console` (upstream adding a render method, or
    // Stdio's Sink grabbing the real stdout). collectingConsole is designed to
    // stub **every method** of Console, but a net that confirms it is blocked is needed here too
    const bypassed: string[] = [];
    // Stash **the original methods themselves**, not bound wrappers (`bind`):
    // restoring a bound one stacks one level per call and hides the write on the prototype
    const realWrite = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array): boolean => {
      bypassed.push(typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      // The real fd is untouched on all 3 paths: diagnostics (exit 2), help
      // (exit 0), and run failure (exit 1 — this harness's server responds to nothing)
      const rejected = await startEnv();
      expect(await runCli(["pull", "--shwo"], rejected.env.layer)).toBe(2);
      const help = await startEnv();
      expect(await runCli(["pull", "--help"], help.env.layer)).toBe(0);
      const failed = await startEnv();
      expect(await runCli(["pull"], failed.env.layer)).toBe(1);
    } finally {
      process.stdout.write = realWrite;
    }
    // This window also mixes in vitest's reporter output (because an await
    // intervenes). Judge by **no maruhi word appearing on the real fd** — that
    // is the property under test, not "nobody writes"
    const written = bypassed.join("");
    for (const marker of ["Usage: maruhi", "Unknown flag", "FLAGS", "maruhi:"]) {
      expect(written, marker).not.toContain(marker);
    }
  });

  it("the help attached to an error is just the one-line usage (--help is the full text)", async () => {
    const { env } = await startEnv();
    expect(await runCli(["pull", "--shwo"], env.layer)).toBe(2);
    const brief = env.errors.join("\n");
    expect(brief).toContain("Usage: maruhi pull");
    // Sections that appear only in the full text (FLAGS etc.) are never mixed into the error diagnostic
    expect(brief).not.toContain("FLAGS");

    const help = await startEnv();
    expect(await runCli(["pull", "--help"], help.env.layer)).toBe(0);
    const full = help.env.errors.join("\n");
    expect(full).toContain("FLAGS");
    // The declarations' description text appears in help (dropping it would
    // thin the help to a list of just names and types)
    expect(full).toContain("Server URL (defaults to config server)");
    expect(full).toContain("Print the values");
  });

  it("`-h` after `--` is the child process's argument (not read as a help request)", async () => {
    // If all of argv were examined, a flag **meant for the child process**
    // mixed into a maruhi usage mistake would surface the full help and bury
    // the actual diagnostic
    const { env } = await startEnv();
    expect(await runCli(["run", "stray", "--", "printenv", "-h"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unexpected extra arguments (1;");
    expect(errors).not.toContain("FLAGS");
  });

  it("an internal error (defect) never shows the message — it attaches only the type's name", async () => {
    // An upstream / unknown Error's message can arrive carrying wording with a
    // typed value embedded (`Invalid value: <plaintext>`). Neutralizing
    // control characters alone cannot keep the discipline, so it is never
    // passed through. It is not silently swallowed either (the type's name is
    // vocabulary argv cannot produce)
    const { env } = await startEnv();
    env.breakConfigLoadWithDefect();
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("maruhi: internal error (Error)");
    expect(errors).not.toContain("config load defect");
  });

  it("`maruhi run` takes its execution target only from behind `--`", async () => {
    const missing = await startEnv();
    expect(await runCli(["run"], missing.env.layer)).toBe(2);
    expect(missing.env.errors.join("\n")).toContain("Specify the command to run after `--`");
    expect(missing.server.requests).toHaveLength(0);

    // `--` is present but the target is empty (the unset form of `maruhi run -- "$CMD"`)
    const empty = await startEnv();
    expect(await runCli(["run", "--", ""], empty.env.layer)).toBe(2);
    expect(empty.env.runnerCalls).toHaveLength(0);
    expect(empty.server.requests).toHaveLength(0);

    // Even when the first token after `--` is empty, report the **written**
    // mistake — an extra positional arg — first (never overwritten by the
    // generic "no execution target")
    const strayWithEmpty = await startEnv();
    expect(await runCli(["run", "stray", "--", "", "printenv"], strayWithEmpty.env.layer)).toBe(2);
    const strayErrors = strayWithEmpty.env.errors.join("\n");
    expect(strayErrors).toContain("Unexpected extra arguments (1;");
    expect(strayErrors).not.toContain("Specify the command to run after `--`");
    expect(strayWithEmpty.env.runnerCalls).toHaveLength(0);
    expect(strayWithEmpty.server.requests).toHaveLength(0);

    // A forgotten `--`. The count comes from the array the parser resolved
    // (it keeps no copy of the declarations), so flag values are not counted
    // and the count is the same wherever they sit
    for (const argv of [
      ["run", "npm", "test"],
      ["run", "--env", "prod", "npm", "test"],
      ["run", "npm", "test", "--env", "prod"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n")).toContain("Unexpected extra arguments (2;");
      expect(env.errors.join("\n")).toContain("Write the command to run after `--`");
      expectNoLeak(env, ["npm", "test", "prod"]);
      expect(env.runnerCalls, argv.join(" ")).toHaveLength(0);
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });
});

describe("the diagnostic mapping (rebuilt from structured fields)", () => {
  it("InvalidValue never shows the typed value", () => {
    // effect/unstable/cli's default wording contains the value (`Invalid
    // value ...`). maruhi emits only the declared name and the expected type
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
    // Upstream's Param.filter builds `expected: onNone(a)`, so writing an
    // onNone like `(n) => \`Expected even number, got ${n}\`` leaks plaintext
    // from the expectation side. An expected that does not match the wording we wrote is never shown
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
    // rc.117 makes 0 of `Argument.atLeast(1)` a MissingArgument rather than
    // InvalidValue("at least"). The wording for other missing args is unchanged
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
});

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

describe("env's nested subcommands (ADR-0016 decision 6 — stage 2)", () => {
  it("a flag the operation does not have fails with a usage error (2)", async () => {
    // Because declarations are split per operation, it fails structurally as an undeclared flag
    for (const argv of [
      ["env", "rotate", "dev", "--name", "x"],
      ["env", "diff", "dev", "prod", "--reason", "x"],
      ["env", "diff", "dev", "prod", "--new-epoch"],
      ["env", "diff", "dev", "prod", "--no-new-epoch"],
      ["env", "create", "dev", "--reason", "x"],
    ]) {
      const { env, server } = await startEnv();
      // Mixed with a run failure (1), a script would treat a typo as an execution failure
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain("Unknown flag");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("an unknown operation lists the possible operations or candidates (the typed word is never shown)", async () => {
    const bogus = await startEnv();
    expect(await runCli(["env", "bogus", "dev"], bogus.env.layer)).toBe(2);
    expect(bogus.env.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: create | rotate | diff)",
    );
    expectNoLeak(bogus.env, ["bogus"]);
    expect(bogus.server.requests).toHaveLength(0);

    const typo = await startEnv();
    expect(await runCli(["env", "rotat", "dev"], typo.env.layer)).toBe(2);
    expect(typo.env.errors.join("\n")).toContain("Unknown subcommand (did you mean rotate?)");
    expect(typo.server.requests).toHaveLength(0);
  });

  it("rotate: duplicated options fail (values and booleans alike — never order-dependent)", async () => {
    for (const argv of [
      ["env", "rotate", "dev", "--reason", "reason-alpha", "--reason", "reason-beta"],
      ["env", "rotate", "dev", "--new-epoch", "--no-new-epoch"],
      ["env", "rotate", "dev", "--no-new-epoch", "--new-epoch"],
      ["env", "rotate", "dev", "--new-epoch", "--new-epoch"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain("was specified more than once");
      expectNoLeak(env, ["reason-alpha", "reason-beta"]);
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("rotate: an empty / whitespace-only --reason fails instead of collapsing to the default (the typed value is never shown)", async () => {
    // The unset form of `--reason "$REASON"`. The declaration (NonBlank)
    // handles it — blocking the shape where an empty reason reaches the chain
    for (const reason of ["", "  "]) {
      const { env, server } = await startEnv();
      expect(await runCli(["env", "rotate", "dev", "--reason", reason], env.layer)).toBe(2);
      expect(env.errors.join("\n")).toContain(
        "Unacceptable value for flag --reason (expected: a non-empty value",
      );
      expect(server.requests).toHaveLength(0);
    }
  });

  it("rotate: a positional arg placed behind a boolean flag is not consumed (order pinning)", async () => {
    // Upstream consumes the token right after a boolean **only when it is a
    // boolean literal** (asBooleanLiteral). A normal environment ID stays on
    // the stream, so the flag-first form also passes the argument layer
    const ordered = await startEnv();
    expect(
      await runCli(["env", "rotate", "--new-epoch", "dev", "--reason", "x"], ordered.env.layer),
    ).toBe(1);
    expect(ordered.env.errors.join("\n")).not.toContain("Missing positional argument");
    expect(ordered.server.requests.length).toBeGreaterThan(0);

    // Residual: an environment ID shaped like a boolean literal (`on` / `off`
    // etc.) is consumed as the boolean's value and fails **loudly** as a
    // missing required positional arg (exit 2 rather than silently rotating another environment)
    const literal = await startEnv();
    expect(
      await runCli(["env", "rotate", "--new-epoch", "on", "--reason", "x"], literal.env.layer),
    ).toBe(2);
    expect(literal.env.errors.join("\n")).toContain("Missing positional argument environment-id");
    expect(literal.server.requests).toHaveLength(0);
  });

  it("rotate: a value for a boolean is read as written", async () => {
    // `--new-epoch=false` is **interpreted as false** in effect (#2 of the 12
    // shapes). It passes the argument layer and reaches the command body
    // (communication) = correct interpretation, not a refusal
    const { env, server } = await startEnv();
    expect(await runCli(["env", "rotate", "dev", "--new-epoch=false"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).not.toContain("Unknown flag");
    expect(server.requests.length).toBeGreaterThan(0);

    // The negated form (`--no-new-epoch`) is also a declared spelling (the guidance target exists)
    const negated = await startEnv();
    expect(await runCli(["env", "rotate", "dev", "--no-new-epoch"], negated.env.layer)).toBe(1);
    expect(negated.env.errors.join("\n")).not.toContain("Unknown flag");
    expect(negated.server.requests.length).toBeGreaterThan(0);
  });

  it("rotate: a positional-arg name written as an option gets guidance all the way to the fix", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["env", "rotate", "--environment-id", "prod"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("--environment-id is a positional argument");
    expectNoLeak(env, ["prod"]);
    expect(server.requests).toHaveLength(0);
  });

  it("the environment-ID format check fails without showing the given value (shared by create / rotate)", async () => {
    for (const argv of [
      ["env", "create", "sk-live-topsecret!"],
      ["env", "rotate", "sk-live-topsecret!"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      const errors = env.errors.join("\n");
      expect(errors).toContain("Invalid environment ID");
      expect(errors).not.toContain("topsecret");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("diff: the second environment ID is required", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["env", "diff", "dev"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Missing positional argument other-environment-id");
    expect(server.requests).toHaveLength(0);
  });

  it("diff: an empty positional arg / comparing an environment to itself fails", async () => {
    const blank = await startEnv();
    expect(await runCli(["env", "diff", "dev", ""], blank.env.layer)).toBe(2);
    expect(blank.env.errors.join("\n")).toContain(
      "Unacceptable value for positional argument other-environment-id",
    );
    expect(blank.server.requests).toHaveLength(0);

    const same = await startEnv();
    expect(await runCli(["env", "diff", "dev", "dev"], same.env.layer)).toBe(2);
    expect(same.env.errors.join("\n")).toContain("The same environment ID was written twice");
    expect(same.server.requests).toHaveLength(0);
  });

  it("a leading empty arg fails as an unknown command and never stacks unrelated flag complaints", async () => {
    // The leading "" cannot be resolved as a command name (root's
    // UnknownSubcommand). At that point the flags have been matched against
    // root's declarations, so the following flags are not piled on as unknown
    // (formatErrors' folding — stage 3 ④. An empty token counts as one argument too)
    const { env } = await startEnv();
    expect(await runCli(["", "env", "create", "dev", "--environment-id", "prod"], env.layer)).toBe(
      2,
    );
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unknown subcommand");
    expect(errors).not.toContain("Unknown flag");
    expectNoLeak(env, ["prod"]);
  });

  it("bare `maruhi env` is a usage error (2) and writes the env level's usage to stderr", async () => {
    // Upstream makes "no subcommand given" a ShowHelp with empty errors (exit
    // 0); for maruhi it is a usage mistake (exit 2). teardown distinguishes by
    // "no explicit help / version" (cli-teardown.ts). stdout stays clean
    // (command output only — decision 9)
    const { env, server } = await startEnv();
    expect(await runCli(["env"], env.layer)).toBe(2);
    expect(env.logs).toEqual([]);
    expect(env.errors.join("\n")).toContain("maruhi env");
    expect(server.requests).toHaveLength(0);

    // An explicit `--help` is not a mistake (stays exit 0)
    const help = await startEnv();
    expect(await runCli(["env", "--help"], help.env.layer)).toBe(0);
    expect(help.env.errors.join("\n")).toContain("maruhi env");
    expect(help.server.requests).toHaveLength(0);
  });

  it("a flag written at the parent level fails with guidance on where it belongs (behind the subcommand)", async () => {
    // Under nesting, a parent-level flag is undeclared — it never lies that
    // "the flag does not exist"; it says how to fix it
    const { env, server } = await startEnv();
    expect(
      await runCli(["server", "--project", "abc", "grant", "--environments", "dev"], env.layer),
    ).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("write the subcommand first and its flags after it");
    expect(errors).toContain("maruhi server grant");
    expect(server.requests).toHaveLength(0);
  });

  it("even on a run dispatch resolved down to the leaf, a parent-level flag gets where-it-belongs guidance", async () => {
    // `--new-epoch rotate` / `--project=abc grant` leave the subcommand name in
    // argv, so the diagnostic's destination (commandKey) resolves to the leaf.
    // Choosing declarations by commandKey would produce a self-contradicting
    // diagnostic that lists the refused flag among "what this command accepts"
    // — pinned to choosing by the level upstream reports (UnrecognizedOption.command)
    const envRotate = await startEnv();
    expect(await runCli(["env", "--new-epoch", "rotate", "dev"], envRotate.env.layer)).toBe(2);
    const rotateErrors = envRotate.env.errors.join("\n");
    expect(rotateErrors).toContain("write the subcommand first and its flags after it");
    expect(rotateErrors).not.toContain("flags this command accepts");
    expect(envRotate.server.requests).toHaveLength(0);

    const grant = await startEnv();
    expect(
      await runCli(["server", "--project=abc", "grant", "--environments", "dev"], grant.env.layer),
    ).toBe(2);
    const grantErrors = grant.env.errors.join("\n");
    expect(grantErrors).toContain("write the subcommand first and its flags after it");
    expect(grantErrors).not.toContain("flags this command accepts");
    expect(grant.server.requests).toHaveLength(0);
  });
});

describe("server's nested subcommands (ADR-0016 decision 6 — stage 2 ②)", () => {
  it("a flag the operation does not have fails with a usage error (2)", async () => {
    for (const argv of [
      ["server", "revoke", "--environments", "dev"],
      ["server", "revoke", "--lease-policy", "policy.json"],
      ["server", "revoke", "--expect-fingerprint", "aaaabbbbccccddddeeeeffff00001111"],
      [
        "server",
        "grant",
        "--environments",
        "dev",
        "--fingerprint",
        "aaaabbbbccccddddeeeeffff00001111",
      ],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain("Unknown flag");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("an unknown operation lists the possible operations", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["server", "bogus"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Unknown subcommand (expected one of: grant | revoke)");
    expect(server.requests).toHaveLength(0);
  });

  it("duplicated options / empty or whitespace-only values fail (rejected by declaration)", async () => {
    for (const argv of [
      ["server", "grant", "--environments", "dev", "--environments", "prod"],
      ["server", "revoke", "--fingerprint", "aaaa", "--fingerprint", "bbbb"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain("was specified more than once");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
    for (const value of ["", "  "]) {
      const { env, server } = await startEnv();
      expect(await runCli(["server", "grant", "--environments", value], env.layer)).toBe(2);
      expect(env.errors.join("\n")).toContain(
        "Unacceptable value for flag --environments (expected: a non-empty value",
      );
      expect(server.requests).toHaveLength(0);
    }
  });

  it("grant requires --environments · the FP flag fails on the format check (the value is never shown)", async () => {
    const missing = await startEnv();
    expect(await runCli(["server", "grant"], missing.env.layer)).toBe(2);
    expect(missing.env.errors.join("\n")).toContain("grant requires --environments");
    expect(missing.server.requests).toHaveLength(0);

    // The FP format check is the shared parser (fingerprint-flag.ts), run
    // after the declaration (NonBlank) passes. The typed value itself never appears in the diagnostic
    const badFp = await startEnv();
    expect(
      await runCli(
        ["server", "grant", "--environments", "dev", "--expect-fingerprint", "sk-live-hunter2"],
        badFp.env.layer,
      ),
    ).toBe(2);
    const errors = badFp.env.errors.join("\n");
    expect(errors).toContain("--expect-fingerprint is malformed");
    expectNoLeak(badFp.env, ["sk-live-hunter2"]);
    expect(badFp.server.requests).toHaveLength(0);

    const badRevoke = await startEnv();
    expect(
      await runCli(["server", "revoke", "--fingerprint", "sk-live-hunter2"], badRevoke.env.layer),
    ).toBe(2);
    expect(badRevoke.env.errors.join("\n")).toContain("--fingerprint is malformed");
    expectNoLeak(badRevoke.env, ["sk-live-hunter2"]);
    expect(badRevoke.server.requests).toHaveLength(0);
  });

  it("the --environments format check fails before any communication", async () => {
    for (const value of ["dev,,prod", "dev,!bad"]) {
      const { env, server } = await startEnv();
      expect(await runCli(["server", "grant", "--environments", value], env.layer), value).toBe(2);
      expect(server.requests, value).toHaveLength(0);
    }
  });

  it("server takes no positional args", async () => {
    const { env, server } = await startEnv();
    // `server grant extra` = an extra positional arg at the grant level
    expect(await runCli(["server", "grant", "extra", "--environments", "dev"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unexpected extra arguments (1;");
    expect(errors).toContain("maruhi server grant takes no positional arguments");
    expect(server.requests).toHaveLength(0);
  });
});

describe("invite's nested subcommands (ADR-0016 decision 6 — stage 2 ③)", () => {
  it("a flag the operation does not have fails with a usage error (2)", async () => {
    for (const argv of [
      ["invite", "list", "--role", "member"],
      ["invite", "create", "--inviter-fingerprint", "aaaabbbbccccddddeeeeffff00001111"],
      ["invite", "revoke", "inv-1", "--role", "member"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain("Unknown flag");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("an unknown operation lists the possible operations", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["invite", "bogus"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: create | accept | list | revoke)",
    );
    expect(server.requests).toHaveLength(0);
  });

  it("create requires --role · duplicated options fail", async () => {
    const missing = await startEnv();
    expect(await runCli(["invite", "create"], missing.env.layer)).toBe(2);
    expect(missing.env.errors.join("\n")).toContain("Specify --role");
    expect(missing.server.requests).toHaveLength(0);

    const dup = await startEnv();
    expect(
      await runCli(["invite", "create", "--role", "member", "--role", "admin"], dup.env.layer),
    ).toBe(2);
    expect(dup.env.errors.join("\n")).toContain("Flag --role was specified more than once");
    expect(dup.server.requests).toHaveLength(0);
  });

  it("accept's target is required, and uninterpretable input fails without showing its contents", async () => {
    const missing = await startEnv();
    expect(await runCli(["invite", "accept"], missing.env.layer)).toBe(2);
    expect(missing.env.errors.join("\n")).toContain("Missing positional argument target");
    expect(missing.server.requests).toHaveLength(0);

    // Input that is neither a link nor a token (could be a plaintext value)
    // never appears in the diagnostic. The target is taken as Argument.Redacted
    // (it can contain a raw token)
    const garbage = await startEnv();
    const typed = "sk-live-hunter2-plaintext";
    expect(await runCli(["invite", "accept", typed], garbage.env.layer)).toBe(2);
    const errors = garbage.env.errors.join("\n");
    expect(errors).toContain("Specify an invite link");
    expectNoLeak(garbage.env, [typed]);
    expect(garbage.server.requests).toHaveLength(0);
  });

  it("the old format (a raw token / a v=1 link) fails with no compat path, contents never shown", async () => {
    const raw = await startEnv();
    const token = "maruhi_inv_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9xY01";
    expect(await runCli(["invite", "accept", token], raw.env.layer)).toBe(2);
    expect(raw.env.errors.join("\n")).toContain("Specify an invite link (…/invite#v=2&…)");
    // A raw token never appears in the diagnostic
    expectNoLeak(raw.env, [token]);
    expect(raw.server.requests).toHaveLength(0);

    const old = await startEnv();
    const link = `https://maruhi.example/invite#v=1&t=${token}&p=${"ab".repeat(32)}`;
    expect(await runCli(["invite", "accept", link], old.env.layer)).toBe(2);
    expect(old.env.errors.join("\n")).toContain("format version is not supported");
    expectNoLeak(old.env, [token, link]);
    expect(old.server.requests).toHaveLength(0);
  });

  it("revoke's invite id is required and never accepts empty", async () => {
    const missing = await startEnv();
    expect(await runCli(["invite", "revoke"], missing.env.layer)).toBe(2);
    expect(missing.env.errors.join("\n")).toContain("Missing positional argument invite-id");
    expect(missing.server.requests).toHaveLength(0);

    const blank = await startEnv();
    expect(await runCli(["invite", "revoke", "  "], blank.env.layer)).toBe(2);
    expect(blank.env.errors.join("\n")).toContain(
      "Unacceptable value for positional argument invite-id",
    );
    expect(blank.server.requests).toHaveLength(0);
  });
});

describe("member's nested subcommands (ADR-0016 decision 6 — stage 2 ④)", () => {
  it("a flag the operation does not have fails with a usage error (2)", async () => {
    for (const argv of [
      ["member", "remove", "user-1", "--role", "member"],
      ["member", "remove", "user-1", "--expect-fingerprint", "aaaabbbbccccddddeeeeffff00001111"],
      [
        "member",
        "change-role",
        "user-1",
        "--expect-fingerprint",
        "aaaabbbbccccddddeeeeffff00001111",
      ],
      ["member", "add", "--role", "member"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain("Unknown flag");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("an unknown operation lists the possible operations", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["member", "bogus"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: add | remove | change-role | list)",
    );
    expect(server.requests).toHaveLength(0);
  });

  it("remove / change-role's target user_id is required and never accepts empty", async () => {
    for (const argv of [
      ["member", "remove"],
      ["member", "change-role", "--role", "member"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain(
        "Missing positional argument user-id",
      );
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
    const blank = await startEnv();
    expect(await runCli(["member", "remove", "  "], blank.env.layer)).toBe(2);
    expect(blank.env.errors.join("\n")).toContain(
      "Unacceptable value for positional argument user-id",
    );
    expect(blank.server.requests).toHaveLength(0);
  });

  it("change-role requires one of --role / --env / --all-envs · duplicates and the FP format fail via the declaration and the shared parser", async () => {
    const missing = await startEnv();
    expect(await runCli(["member", "change-role", "user-1"], missing.env.layer)).toBe(2);
    expect(missing.env.errors.join("\n")).toContain("Specify what to change: --role");
    expect(missing.server.requests).toHaveLength(0);

    const dup = await startEnv();
    expect(
      await runCli(
        ["member", "change-role", "user-1", "--role", "admin", "--role", "reader"],
        dup.env.layer,
      ),
    ).toBe(2);
    expect(dup.env.errors.join("\n")).toContain("Flag --role was specified more than once");
    expect(dup.server.requests).toHaveLength(0);

    // The FP format check is the shared parser (fingerprint-flag.ts). The typed value is never shown
    const badFp = await startEnv();
    expect(
      await runCli(["member", "add", "--expect-fingerprint", "sk-live-hunter2"], badFp.env.layer),
    ).toBe(2);
    expect(badFp.env.errors.join("\n")).toContain("--expect-fingerprint is malformed");
    expectNoLeak(badFp.env, ["sk-live-hunter2"]);
    expect(badFp.server.requests).toHaveLength(0);
  });

  it("add's invite id is optional · two or more fail as extra arguments", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["member", "add", "inv-1", "inv-2"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unexpected extra arguments (1;");
    expect(server.requests).toHaveLength(0);
  });
});

describe("key / project nested subcommands (ADR-0016 stage 3 ②)", () => {
  it("an unknown operation lists the possible operations and fails before login / server contact", async () => {
    // Put behind session resolution, `key bogus` would fail as "Not logged in"
    // and the typo would never be conveyed (at exit 1, no less). In effect,
    // subcommand resolution runs before the handler = it structurally never reaches the session
    const key = await makeTestEnv();
    expect(await runCli(["key", "bogus"], key.layer)).toBe(2);
    expect(key.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: generate | show | publish | recover | recovery | seal | reserve)",
    );
    expect(key.errors.join("\n")).not.toContain("Not logged in");

    const project = await makeTestEnv();
    expect(await runCli(["project", "bogus"], project.layer)).toBe(2);
    expect(project.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: init | list | verify | anchor | checkpoint | policy)",
    );
  });

  it("the operation name never returns the typed word (neither control chars nor the value reach the terminal)", async () => {
    // A word carrying ANSI sequences that erase lines and write a fake success
    // line. The wording is only the list of possible operations — the typed
    // word is never shown (a positional arg could carry a value)
    const evil = "[2K\rmaruhi: OK";
    for (const command of ["key", "project"]) {
      const { env } = await startEnv();
      expect(await runCli([command, evil], env.layer), command).toBe(2);
      const output = [...env.logs, ...env.errors].join("\n");
      expect(output, command).toContain("Unknown subcommand");
      expect(output, command).not.toContain("");
      expect(output, command).not.toContain("\r");
    }
  });

  it("the leaves take no positional args (`key generate extra` fails as an extra argument)", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["key", "generate", "extra"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unexpected extra arguments (1;");
    expect(errors).toContain("maruhi key generate takes no positional arguments");
    expect(server.requests).toHaveLength(0);
  });

  it("bare `maruhi key` / `maruhi project` is a usage error (2)", async () => {
    for (const command of ["key", "project"]) {
      const { env, server } = await startEnv();
      expect(await runCli([command], env.layer), command).toBe(2);
      expect(env.logs, command).toEqual([]);
      expect(env.errors.join("\n"), command).toContain(`maruhi ${command}`);
      expect(server.requests, command).toHaveLength(0);
    }
  });
});

describe("diagnosing an unknown command (stage 3 ④ — root's UnknownSubcommand)", () => {
  it("a misspelled command name never treats correctly spelled options as unknown", async () => {
    // On an unresolved command, flags are matched against root's declarations,
    // so a correctly spelled --show would be listed as unknown too (never make
    // them hunt — formatErrors folds a simultaneous UnrecognizedOption into UnknownSubcommand)
    const { env } = await startEnv();
    expect(await runCli(["pul", "--show"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unknown subcommand (did you mean pull?)");
    expect(errors).not.toContain("Unknown flag");
  });

  it("an unknown command lists the possible commands", async () => {
    const { env } = await startEnv();
    expect(await runCli(["bogus"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: login | logout | pull | run | push | env | server | invite | member | approval | key | device | token | guardian | project | ci | agent | rotation | audit | config | schema | var | sync)",
    );
  });

  it("a value written in the command-name position also never shows its spelling", async () => {
    const { env } = await startEnv();
    expect(await runCli(["s3cr3t/value=with-symbols"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unknown subcommand");
    expect(errors).not.toContain("s3cr3t");
  });

  it("a flag written before the command name gets where-it-belongs guidance without self-contradiction", async () => {
    // `maruhi --show pull`. Building the diagnostic from the leaf (pull)'s
    // declarations would self-contradict — "refusing --show while listing it
    // among what it accepts" — so it is built from root's declarations (the where-it-belongs guidance)
    const { env, server } = await startEnv();
    expect(await runCli(["--show", "pull"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("write the subcommand first and its flags after it");
    expect(errors).not.toContain("flags this command accepts");
    expect(server.requests).toHaveLength(0);
  });

  it("`--version` output goes to stdout; combined with `--help`, help wins and goes to stderr", async () => {
    // `V=$(maruhi --version)` is the command's output. Under `--help
    // --version`, Help wins upstream = the collected lines are the help body,
    // so they never go to stdout (decision 9 / ADR-0016 addendum 2)
    const version = await startEnv();
    expect(await runCli(["--version"], version.env.layer)).toBe(0);
    expect(version.env.logs.join("\n")).toMatch(/^\d+\.\d+\.\d+/);
    expect(version.env.errors).toEqual([]);

    const both = await startEnv();
    expect(await runCli(["--help", "--version"], both.env.layer)).toBe(0);
    expect(both.env.logs).toEqual([]);
    expect(both.env.errors.join("\n")).toContain("maruhi");

    // Built-ins short-circuit first (upstream spec) = a usage mistake on the
    // same argv is never reported. Accepted because the value-writing path is
    // never reached, and pinned as behavior (ADR-0016 addendum 7)
    const swallowed = await startEnv();
    expect(await runCli(["--version", "--bogus"], swallowed.env.layer)).toBe(0);
    expect(swallowed.env.logs.join("\n")).toMatch(/^\d+\.\d+\.\d+/);
    expect(swallowed.server.requests).toHaveLength(0);
  });

  it("the entry command's doubled name (`maruhi maruhi`) is never suggested as a command", async () => {
    // There is no `maruhi` subcommand under root = just an unknown command
    // (the entry command is never registered under its own name)
    const { env } = await startEnv();
    expect(await runCli(["maruhi", "extra"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unknown subcommand");
    expect(errors).not.toContain("maruhi maruhi");
  });
});

describe("the login / logout argument layer (ADR-0016 stage 3 ④)", () => {
  it("a type-mismatched value is refused without showing the given value", async () => {
    // The expected type may be shown since it comes from the declaration,
    // but the given value could contain plaintext, so it is never shown
    const { env, server } = await startEnv();
    expect(await runCli(["login", "--poll-interval", "s3cr3t"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unacceptable value for flag --poll-interval");
    expectNoLeak(env, ["s3cr3t"]);
    expect(server.requests).toHaveLength(0);
  });

  it("a valueless number becomes a usage error (2)", async () => {
    // A number option with no value is an InvalidValue = a usage mistake
    // (exit 2). Never reported as an internal error (exit 1)
    const { env, server } = await startEnv();
    expect(await runCli(["login", "--token-ttl-days"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Unacceptable value for flag --token-ttl-days");
    expect(server.requests).toHaveLength(0);
  });

  it("a mistyped long option name is also suggested as a candidate", async () => {
    const { env } = await startEnv();
    expect(await runCli(["login", "--token-namee", "x"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Unknown flag (did you mean --token-name?)");
  });

  it("hidden options appear in neither help nor candidates", async () => {
    // The internal-facing spelling (--poll-interval) is not spread around.
    // Upstream's typo candidates exclude hidden (measured), and our own list (specOf) excludes it too
    const typo = await startEnv();
    expect(await runCli(["login", "--poll-intervall", "3"], typo.env.layer)).toBe(2);
    const errors = typo.env.errors.join("\n");
    expect(errors).not.toContain("--poll-interval");
    expect(errors).toContain("Unknown flag");

    const help = await startEnv();
    expect(await runCli(["login", "--help"], help.env.layer)).toBe(0);
    const full = help.env.errors.join("\n");
    expect(full).toContain("--token-name");
    expect(full).not.toContain("--poll-interval");
  });

  it("logout takes no positional args", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["logout", "extra"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("maruhi logout takes no positional arguments");
    expect(server.requests).toHaveLength(0);
  });
});

describe("rotation / audit nested subcommands (ADR-0016 stage 3 ③)", () => {
  it("bare `maruhi audit` runs as list (keeping current behavior)", async () => {
    // A parent with a handler (measured): the bare parent runs list and
    // reaches the command body (communication) = never becomes a usage error (2)
    const { env, server } = await startEnv();
    expect(await runCli(["audit"], env.layer)).toBe(1);
    expect(server.requests.length).toBeGreaterThan(0);
  });

  it("list's flags work under bare `maruhi audit` (`audit --limit 5`)", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["audit", "--limit", "5"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).not.toContain("Unknown flag");
    expect(server.requests.length).toBeGreaterThan(0);
  });

  it("`audit --help` usage draws the subcommand as optional (`[subcommand]`)", async () => {
    // Since bare `maruhi audit` runs list, upstream's uniform `<subcommand>`
    // (required) would be a lie. The decision is declaration-driven — only a
    // level holding both flags and subcommands (a parent with a handler) is fixed
    const help = await startEnv();
    expect(await runCli(["audit", "--help"], help.env.layer)).toBe(0);
    const full = help.env.errors.join("\n");
    expect(full).toContain("maruhi audit [subcommand]");
    expect(full).not.toContain("<subcommand>");

    // A normal parent (a level where bare is an error) still draws it as required
    const env = await startEnv();
    expect(await runCli(["env", "--help"], env.env.layer)).toBe(0);
    expect(env.env.errors.join("\n")).toContain("maruhi env <subcommand>");
  });

  it("a usage mistake on audit fails before any communication (out of range · wrong type · unknown operation)", async () => {
    const range = await startEnv();
    expect(await runCli(["audit", "--limit", "0"], range.env.layer)).toBe(2);
    expect(range.env.errors.join("\n")).toContain("--limit must be an integer between 1 and 200");
    expect(range.server.requests).toHaveLength(0);

    // A number with no value / unreadable as a number is an InvalidValue = a usage error (exit 2)
    const typed = await startEnv();
    expect(await runCli(["audit", "--limit", "s3cr3t"], typed.env.layer)).toBe(2);
    const typedErrors = typed.env.errors.join("\n");
    expect(typedErrors).toContain("Unacceptable value for flag --limit");
    expectNoLeak(typed.env, ["s3cr3t"]);
    expect(typed.server.requests).toHaveLength(0);

    const bogus = await startEnv();
    expect(await runCli(["audit", "bogus"], bogus.env.layer)).toBe(2);
    expect(bogus.env.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: list | invites | self | verify | reconcile)",
    );
    expect(bogus.server.requests).toHaveLength(0);
  });

  it("an own-level flag written before the subcommand gets where-it-belongs guidance without self-contradiction", async () => {
    // `audit --limit 5 list`. Upstream does not inherit the parent's local
    // flags into the subcommand = it reports it as undeclared, but the bare
    // parent's (= list) declarations hold the same flag, so listing it under
    // "accepted" would self-contradict
    const { env, server } = await startEnv();
    expect(await runCli(["audit", "--limit", "5", "list"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("--limit belongs after the subcommand");
    expect(errors).not.toContain("flags this command accepts");
    expect(server.requests).toHaveLength(0);
  });

  it("a flag the operation does not have fails with a usage error (2)", async () => {
    // Because declarations are split per operation, it fails structurally as an undeclared flag
    for (const argv of [
      ["audit", "verify", "--limit", "5"],
      ["audit", "self", "--project", "x"],
      ["audit", "invites", "--event", "var.version_pushed"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain("Unknown flag");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("the audit list filter's format check fails before any communication", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["audit", "--env", "!bad"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Invalid environment ID for --env");
    expect(server.requests).toHaveLength(0);
  });

  it("bare `maruhi rotation` / an unknown operation is a usage error (2)", async () => {
    const bare = await startEnv();
    expect(await runCli(["rotation"], bare.env.layer)).toBe(2);
    expect(bare.env.logs).toEqual([]);
    expect(bare.env.errors.join("\n")).toContain("maruhi rotation");

    const bogus = await startEnv();
    expect(await runCli(["rotation", "bogus"], bogus.env.layer)).toBe(2);
    expect(bogus.env.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: list | dismiss)",
    );
  });

  it("rotation dismiss's boolean (--all) refuses duplicates and reads a value as written", async () => {
    // `--all=false` is read as false exactly as written (#2 of the 12 shapes —
    // reading it as true regardless would turn it into a withdrawal of every
    // flag). A duplicate is rejected by atMost(1)
    for (const argv of [
      ["rotation", "dismiss", "--all", "--no-all"],
      ["rotation", "dismiss", "--all", "--all"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain(
        "Flag --all was specified more than once",
      );
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }

    // `--all=false` is read as a run "without --all" and passes the argument
    // layer (a missing target is reported by the command body at exit 1 — the
    // opposite of what was written). Since the regression (turning into true)
    // and resolveAllTargets both always communicate, distinguish via "missing-target guidance + zero communication"
    const explicit = await startEnv();
    expect(await runCli(["rotation", "dismiss", "--all=false"], explicit.env.layer)).toBe(1);
    expect(explicit.env.errors.join("\n")).not.toContain("Unknown flag");
    expect(explicit.env.errors.join("\n")).toContain("Specify what to dismiss");
    expect(explicit.server.requests).toHaveLength(0);
  });

  it("a missing rotation-dismiss target / a contradiction with --all fails before any communication", async () => {
    // Put behind the prelude's sync, the guidance would be hidden behind a
    // connection error (this harness's server only ever returns 404) and the round trip would be wasted
    const missing = await startEnv();
    expect(await runCli(["rotation", "dismiss"], missing.env.layer)).toBe(1);
    expect(missing.env.errors.join("\n")).toContain("Specify what to dismiss");
    expect(missing.server.requests).toHaveLength(0);

    const contradictory = await startEnv();
    expect(
      await runCli(
        ["rotation", "dismiss", "--all", "va1234567890123456789012", "--env", "prod"],
        contradictory.env.layer,
      ),
    ).toBe(1);
    expect(contradictory.env.errors.join("\n")).toContain(
      "--all cannot be combined with a variableId",
    );
    expect(contradictory.server.requests).toHaveLength(0);
  });

  it("the rotation-dismiss target's format check fails before any communication (the value is never shown)", async () => {
    const env1 = await startEnv();
    expect(
      await runCli(["rotation", "dismiss", "sk-live-x!", "--env", "prod"], env1.env.layer),
    ).toBe(2);
    expect(env1.env.errors.join("\n")).toContain("Invalid variableId");
    expectNoLeak(env1.env, ["sk-live-x!"]);
    expect(env1.server.requests).toHaveLength(0);

    const env2 = await startEnv();
    expect(await runCli(["rotation", "dismiss", "--all", "--env", "!bad"], env2.env.layer)).toBe(2);
    expect(env2.env.errors.join("\n")).toContain("Invalid environment ID for --env");
    expect(env2.server.requests).toHaveLength(0);
  });
});

describe("the push argument layer (ADR-0016 stage 3 ①)", () => {
  it("extra arguments never show their contents and always attach how to pass the value (stdin)", async () => {
    // `maruhi push API_KEY "$SECRET"` is the most likely typo. The refused
    // argument's contents are never shown (it could be plaintext) — instead
    // the fix is always attached, since otherwise there is no way to fix it
    const secret = "hunter2-plaintext-value";
    for (const argv of [
      ["push", "API_KEY", secret],
      // After `--` too, push never reads it (only run does). Rejected, not silently dropped
      ["push", "API_KEY", "--", secret],
      ["push", "API_KEY", "--", ""],
    ]) {
      const { env, server } = await startEnv();
      env.setStdin(new TextEncoder().encode("secret-value"));
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      const errors = env.errors.join("\n");
      expect(errors).toContain("Unexpected extra arguments (1;");
      expect(errors).toContain("contents not shown");
      expect(errors).toContain("Values are read from stdin");
      expectNoLeak(env, [secret]);
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("a missing variable name / an empty or whitespace-only one fails at the declaration", async () => {
    const missing = await startEnv();
    expect(await runCli(["push"], missing.env.layer)).toBe(2);
    expect(missing.env.errors.join("\n")).toContain("Missing positional argument name");
    expect(missing.server.requests).toHaveLength(0);

    const blank = await startEnv();
    expect(await runCli(["push", "  "], blank.env.layer)).toBe(2);
    expect(blank.env.errors.join("\n")).toContain(
      "Unacceptable value for positional argument name",
    );
    expect(blank.server.requests).toHaveLength(0);
  });

  it("a positional-arg name written as an option (`--name`) gets guidance all the way to the fix", async () => {
    const { env, server } = await startEnv();
    env.setStdin(new TextEncoder().encode("secret-value"));
    expect(await runCli(["push", "--name", "API_KEY"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--name is a positional argument");
    expect(server.requests).toHaveLength(0);
  });

  it("an empty / whitespace-only option value fails instead of collapsing to the default (the write-to-default-environment accident)", async () => {
    // Collapsing an empty value into "unspecified" would turn the unset form
    // of `--env "$ENV"` into **a write to the default environment** (un-undoable). The declaration (NonBlank) blocks it
    for (const argv of [
      ["push", "API_KEY", "--env", ""],
      ["push", "API_KEY", "--env", "  "],
      ["push", "API_KEY", "--project="],
    ]) {
      const { env, server } = await startEnv();
      env.setStdin(new TextEncoder().encode("secret-value"));
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n")).toContain("Unacceptable value for flag");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("a value that morphed into an option is never spelled back out (a plaintext leak path)", async () => {
    // "Words meant as a value" like `-hunter2` (a short group),
    // `--sk_live_ab12`, or `-----BEGIN...` (a long spelling) are never written
    // out by the refusal diagnostic. Candidates come only from **declared
    // names** (cli-formatter.ts's discipline). `-hunter2` is not used: the
    // short group's leading `-h` resolves to the built-in help and shows help
    // (exit 0) — nothing leaks, but it is no refusal check either, so the same
    // shape is pinned with a leading character that does not hit help
    for (const [typed, fragment] of [
      ["-xunter2", "unter2"],
      ["--sk_live_ab12", "sk_live"],
      ["-----BEGIN-RSA-PRIVATE-KEY-hunter2", "BEGIN"],
      ["--constructor=x", "constructor"],
    ] as const) {
      const { env, server } = await startEnv();
      env.setStdin(new TextEncoder().encode("secret-value"));
      expect(await runCli(["push", "API_KEY", typed], env.layer), typed).toBe(2);
      const errors = env.errors.join("\n");
      expect(errors, typed).toContain("Unknown flag");
      expect(errors, typed).not.toContain(fragment);
      expect(server.requests, typed).toHaveLength(0);
    }
  });
});

describe("config's nested subcommands (ADR-0016 stage 3 ①)", () => {
  it("an unknown operation / bare `maruhi config` is a usage error (2)", async () => {
    const bogus = await startEnv();
    expect(await runCli(["config", "bogus"], bogus.env.layer)).toBe(2);
    expect(bogus.env.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: get | set)",
    );

    const bare = await startEnv();
    expect(await runCli(["config"], bare.env.layer)).toBe(2);
    expect(bare.env.logs).toEqual([]);
    expect(bare.env.errors.join("\n")).toContain("maruhi config");
  });

  it("an unknown config key never returns the typed word and lists the possible keys", async () => {
    // A word carrying ANSI sequences that erase lines and write a fake success
    // line. The wording is only the list of possible values — the typed word
    // is never shown (a positional arg could carry a value)
    const evil = "[2K\rmaruhi: OK";
    const get = await startEnv();
    expect(await runCli(["config", "get", evil], get.env.layer)).toBe(2);
    const getOutput = [...get.env.logs, ...get.env.errors].join("\n");
    expect(getOutput).toContain("Unknown config key (server | defaultProject");
    expect(getOutput).not.toContain("");
    expect(getOutput).not.toContain("\r");

    // A word written in the operation-name position is never returned either (the unknown-subcommand diagnostic)
    const action = await startEnv();
    expect(await runCli(["config", evil, "server"], action.env.layer)).toBe(2);
    const actionOutput = [...action.env.logs, ...action.env.errors].join("\n");
    expect(actionOutput).toContain("Unknown subcommand");
    expect(actionOutput).not.toContain("");
    expect(actionOutput).not.toContain("\r");
  });

  it("an empty / whitespace-only `config set` value fails without overwriting the existing setting", async () => {
    // The accident where the unset form of `config set defaultProject "$PROJ"`
    // overwrites the existing setting with empty and reports success (the declaration blocks it)
    for (const value of ["", "  "]) {
      const { env } = await startEnv();
      expect(await runCli(["config", "set", "defaultEnvironment", value], env.layer)).toBe(2);
      expect(env.errors.join("\n")).toContain("Unacceptable value for positional argument value");
      expect(await runCli(["config", "get", "defaultEnvironment"], env.layer)).toBe(0);
      expect(env.logs).toContain("prod");
    }
  });

  it("a valueless `config set` fails at the declaration (required positional arg)", async () => {
    const { env } = await startEnv();
    expect(await runCli(["config", "set", "defaultEnvironment"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Missing positional argument value");
  });

  it("tokens behind `--` fill the positional-arg slots (ADR-0016 addendum 8)", async () => {
    // Upstream, the parser folds positional args before and after `--` into
    // one array. It works as the POSIX escape hatch for writing a `-`-leading
    // value as a positional arg, and no token is silently dropped (anything
    // past the slots stays an extra positional arg = exit 2)
    const { env } = await startEnv();
    expect(await runCli(["config", "set", "--", "defaultEnvironment", "dev"], env.layer)).toBe(0);
    expect(env.logs).toContain("Set defaultEnvironment");
    expect(await runCli(["config", "get", "defaultEnvironment"], env.layer)).toBe(0);
    expect(env.logs).toContain("dev");
  });

  it("`config get`'s extra arguments fail, breaking neither the setting nor the read", async () => {
    const single = await startEnv();
    expect(await runCli(["config", "get", "defaultEnvironment", "dev"], single.env.layer)).toBe(2);
    const errors = single.env.errors.join("\n");
    expect(errors).toContain("Unexpected extra arguments (1;");
    expect(errors).toContain("maruhi config get only takes these positional arguments: key");
    expect(single.env.logs).toHaveLength(0);

    // The count is never underreported (never let an optional slot absorb it)
    const multiple = await startEnv();
    expect(
      await runCli(["config", "get", "defaultEnvironment", "a", "b"], multiple.env.layer),
    ).toBe(2);
    expect(multiple.env.errors.join("\n")).toContain("Unexpected extra arguments (2;");

    // set's extra arguments never rewrite the setting either
    const set = await startEnv();
    expect(
      await runCli(["config", "set", "defaultEnvironment", "dev", "extra"], set.env.layer),
    ).toBe(2);
    expect(set.env.errors.join("\n")).toContain("Unexpected extra arguments (1;");
    expect(await runCli(["config", "get", "defaultEnvironment"], set.env.layer)).toBe(0);
    expect(set.env.logs).toContain("prod");
  });

  it("a successful run's stdout is only the command's output (the value)", async () => {
    const { env } = await startEnv();
    const stdout = vi.spyOn(console, "log").mockImplementation(() => {});

    // `V=$(maruhi config get server)` must never catch anything but the value
    expect(await runCli(["config", "get", "defaultEnvironment"], env.layer)).toBe(0);
    expect(stdout).not.toHaveBeenCalled();
    expect(env.logs).toEqual(["prod"]);
  });
});
