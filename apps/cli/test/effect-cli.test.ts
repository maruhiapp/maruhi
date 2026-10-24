// Conformance checks for the argument layer (`effect/cli`) as a whole.
//
// Drives 12 argv pitfall shapes a CLI parser commonly gets wrong and
// pins that maruhi's discipline holds: a usage mistake = exit 2 /
// diagnostics go to stderr / stdout stays clean / typed values never
// appear in diagnostics. Operations are never stubbed — everything goes
// through **the real runCli**. Also here: the diagnosis of an unknown
// command, the combination rules (`Command.validate`), and the split
// between a usage mistake (2) and a failed run or a defect (1).
//
// The argument layers of env, server, invite, member, push and config
// are pinned in env-command.test.ts, server-command.test.ts,
// invite-command.test.ts, member-command.test.ts, push-command.test.ts
// and config-command.test.ts, and those of key / project, login /
// logout and rotation / audit in key-project-command.test.ts,
// login-logout-command.test.ts and rotation-audit-command.test.ts.
// describeError is pinned in cli-formatter.test.ts, the exit-code
// teardown in cli-teardown.test.ts, and that values are shown only on a
// human's interactive terminal in display.test.ts,
// redacted-display-gate.test.ts and pull-run-pull.test.ts.

import { describe, expect, it, vi } from "vitest";

import { runCli } from "../src/cli.ts";
import { expectNoLeak, startEnv } from "./support/argument-layer.ts";
import { makeTestEnv, seedConfig } from "./support/env.ts";

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
    // environment ID is broken to force a fail (pull-run-pull.test.ts pins that it
    // never reached value display)
    for (const argv of [
      ["pull", "--show=false", "--env", "!bad"],
      ["pull", "--show", "false", "--env", "!bad"],
    ]) {
      const { env, server } = await startEnv();
      // It fails at the flag's brand schema (the environment id mints at the
      // flag declaration) = `--show` was read as a value-taking option
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n")).toContain("Unacceptable value for flag --env");
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
    // is alive: the flag's brand schema's authored `expected` annotation is
    // echoed in the parenthetical (the Schema machinery's "Expected" render
    // prefix is stripped) — a rewording in project.ts drops it, so this side
    // keeps the diagnostic honest rather than silently suppressed
    expect(blank.env.errors.join("\n")).toContain(
      "Unacceptable value for flag --env (expected: environment id",
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
    // effect/cli's default adds help / version / wizard /
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
      "Unknown subcommand (expected one of: login | logout | pull | run | push | mcp | env | server | mirror | invite | member | approval | key | device | token | guardian | project | ci | agent | rotation | audit | config | schema | var | sync | proxy)",
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

describe("contradictory and dependent flags (Command.validate rules)", () => {
  // A rule runs after parsing and before the handler, so its refusal reads
  // like a parse error (the usage line plus the rule's fixed message, exit
  // 2), and the command never reaches the session or the network
  async function refusal(argv: readonly string[]): Promise<{
    readonly code: number;
    readonly errors: readonly string[];
    readonly requests: number;
  }> {
    const { env, server } = await startEnv();
    const code = await runCli([...argv], env.layer);
    expect(env.logs).toEqual([]);
    return { code, errors: env.errors, requests: server.requests.length };
  }

  it("member change-role / device approve: at most one of --env, --all-envs and --no-envs", async () => {
    const message = "maruhi: --env, --all-envs and --no-envs cannot be combined";
    for (const flags of [
      ["--env", "prod", "--all-envs"],
      ["--env", "prod", "--no-envs"],
      ["--all-envs", "--no-envs"],
    ]) {
      expect(await refusal(["member", "change-role", "user-target-2222", ...flags])).toEqual({
        code: 2,
        errors: ["Usage: maruhi member change-role [flags] <user-id>", message],
        requests: 0,
      });
      expect(
        await refusal(["device", "approve", "0123456789abcdef0123456789abcdef", ...flags]),
      ).toEqual({
        code: 2,
        errors: ["Usage: maruhi device approve [flags] <fp-or-words>", message],
        requests: 0,
      });
    }
  });

  it("invite create: --env and --no-envs (an invite has no --all-envs)", async () => {
    expect(
      await refusal(["invite", "create", "--role", "member", "--env", "prod", "--no-envs"]),
    ).toEqual({
      code: 2,
      errors: [
        "Usage: maruhi invite create [flags]",
        "maruhi: --env and --no-envs cannot be combined",
      ],
      requests: 0,
    });
  });

  it("key recover: --handoff and --passkey", async () => {
    expect(await refusal(["key", "recover", "--handoff", "--passkey"])).toEqual({
      code: 2,
      errors: [
        "Usage: maruhi key recover [flags]",
        "maruhi: Choose one of --handoff and --passkey",
      ],
      requests: 0,
    });
  });

  it("key recovery: --passkey with --replace is refused before asking the server whether a reserve key exists", async () => {
    // Checked after that request before, so with no reserve key yet the pair
    // was silently ignored and a new reserve key was created
    expect(await refusal(["key", "recovery", "--passkey", "--replace"])).toEqual({
      code: 2,
      errors: [
        "Usage: maruhi key recovery [flags]",
        "maruhi: --passkey cannot be combined with --replace: --replace never opens the ledger. If you still have a passkey, run `maruhi key recovery --passkey` (without --replace) to reissue the recovery code for the same reserve key",
      ],
      requests: 0,
    });
  });

  it("push / var rollback / var rotate: --no-sync and --config", async () => {
    const message = "maruhi: --no-sync and --config cannot be combined (drop one of them)";
    const sync = ["--no-sync", "--config", "maruhi.sync.json"];
    expect(await refusal(["push", "API_KEY", ...sync])).toEqual({
      code: 2,
      errors: ["Usage: maruhi push [flags] <name>", message],
      requests: 0,
    });
    expect(await refusal(["var", "rollback", "API_KEY", "--to", "1", ...sync])).toEqual({
      code: 2,
      errors: ["Usage: maruhi var rollback [flags] <name>", message],
      requests: 0,
    });
    expect(await refusal(["var", "rotate", "API_KEY", ...sync])).toEqual({
      code: 2,
      errors: ["Usage: maruhi var rotate [flags] <name>", message],
      requests: 0,
    });
  });

  it("var rotate: --previous without --finalize; under --finalize the sync flags are not read", async () => {
    expect(await refusal(["var", "rotate", "API_KEY", "--previous", "1"])).toEqual({
      code: 2,
      errors: [
        "Usage: maruhi var rotate [flags] <name>",
        "maruhi: --previous applies to --finalize only",
      ],
      requests: 0,
    });
    // --finalize syncs nothing, so the pair passes the rules as before and
    // the run stops at the next check (the missing rotation config, still
    // before any network)
    const finalize = await refusal([
      "var",
      "rotate",
      "API_KEY",
      "--finalize",
      "--no-sync",
      "--config",
      "maruhi.sync.json",
      "--rotate-config",
      "missing.rotate.json",
    ]);
    expect(finalize.code).toBe(1);
    expect(finalize.errors.join("\n")).toContain(
      "Cannot read the rotation config missing.rotate.json",
    );
    expect(finalize.requests).toBe(0);
  });

  it("rotation list: --due-within without --fail-on-due / --fail-on-pending", async () => {
    expect(await refusal(["rotation", "list", "--due-within", "7"])).toEqual({
      code: 2,
      errors: [
        "Usage: maruhi rotation list [flags]",
        "maruhi: --due-within applies to --fail-on-due / --fail-on-pending only",
      ],
      requests: 0,
    });
  });

  it("env rotate: --new-epoch without --reason is refused before the session and the chain sync", async () => {
    // Checked inside the rotation before, after the session was opened and
    // the chain synced
    expect(await refusal(["env", "rotate", "dev", "--new-epoch"])).toEqual({
      code: 2,
      errors: [
        "Usage: maruhi env rotate [flags] <environment-id>",
        "maruhi: Specify the rotation reason with --reason (it is recorded on the chain's rotate_epoch entry and cannot be rewritten later)",
      ],
      requests: 0,
    });
  });

  it("rotation dismiss: --all with a variable ID is a usage error (exit 2)", async () => {
    expect(
      await refusal(["rotation", "dismiss", "--all", "va1234567890123456789012", "--env", "prod"]),
    ).toEqual({
      code: 2,
      errors: [
        "Usage: maruhi rotation dismiss [flags] [<variable...>]",
        "maruhi: --all cannot be combined with a variableId (use one or the other)",
      ],
      requests: 0,
    });
  });

  it("rotation dismiss: a variable ID without --env, and --env without a variable ID", async () => {
    // Both reached the command body before and failed there with exit 1 and
    // the missing-target guidance, which a bare `rotation dismiss` still gets
    const usage = "Usage: maruhi rotation dismiss [flags] [<variable...>]";
    expect(await refusal(["rotation", "dismiss", "va1234567890123456789012"])).toEqual({
      code: 2,
      errors: [usage, "maruhi: A variableId requires --env <environmentId>"],
      requests: 0,
    });
    expect(await refusal(["rotation", "dismiss", "--env", "prod"])).toEqual({
      code: 2,
      errors: [
        usage,
        "maruhi: --env requires a variableId (or --all to dismiss every flag in that environment)",
      ],
      requests: 0,
    });
  });

  it("project policy approvals: --off with --required / --ops, and --ops without --required", async () => {
    const usage = "Usage: maruhi project policy approvals [flags]";
    for (const flags of [
      ["--off", "--required", "2"],
      ["--off", "--ops", "remove_member"],
    ]) {
      expect(await refusal(["project", "policy", "approvals", ...flags])).toEqual({
        code: 2,
        errors: [usage, "maruhi: --off cannot be combined with --required / --ops"],
        requests: 0,
      });
    }
    expect(await refusal(["project", "policy", "approvals", "--ops", "remove_member"])).toEqual({
      code: 2,
      errors: [usage, "maruhi: --ops requires --required <n>"],
      requests: 0,
    });
  });

  it("a rule's refusal comes before the command body's own checks", async () => {
    // --role is checked in the command body, which reported it first before
    expect(
      await refusal([
        "member",
        "change-role",
        "user-target-2222",
        "--role",
        "bogus",
        "--env",
        "prod",
        "--all-envs",
      ]),
    ).toEqual({
      code: 2,
      errors: [
        "Usage: maruhi member change-role [flags] <user-id>",
        "maruhi: --env, --all-envs and --no-envs cannot be combined",
      ],
      requests: 0,
    });
  });
});

describe("input validation and defect handling", () => {
  it("invalid project / environment IDs error early", async () => {
    const env = await makeTestEnv();
    await seedConfig(env, { server: "https://maruhi.example", defaultEnvironment: "dev" });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    // A usage mistake is a usage error (2). The supplied value itself is not echoed
    expect(await runCli(["pull", "--project", "not-hex"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Unacceptable value for flag --project");
    expect(env.errors.join("\n")).not.toContain("not-hex");
    const env2 = await makeTestEnv();
    await seedConfig(env2, {
      server: "https://maruhi.example",
      defaultProject: "ab".repeat(32),
    });
    env2.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    // The environment ID format check runs before any network access (session resolution)
    expect(await runCli(["pull", "--env", "!bad"], env2.layer)).toBe(2);
    expect(env2.errors.join("\n")).toContain("Unacceptable value for flag --env");
    expect(env2.errors.join("\n")).not.toContain("!bad");
  });

  it("a config-sourced invalid ID is not a typo — it names the fix target and exits 1", async () => {
    const env = await makeTestEnv();
    // Nothing was typed on the command line, so reporting it as 2 (usage error)
    // would be "a usage error with nothing to fix"
    await seedConfig(env, { server: "https://maruhi.example", defaultProject: "not-hex" });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    expect(await runCli(["pull", "--env", "dev"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("fix defaultProject in your config");
  });

  it("a defect (bug-sourced throw) is reported as 1, not a usage error (2)", async () => {
    const env = await makeTestEnv();
    env.breakConfigLoadWithDefect();
    expect(await runCli(["config", "get", "server"], env.layer)).toBe(1);
    // Pin the "only the type name is attached" shape **strictly** (a partial
    // match would still pass after regressing to `internal error: <upstream message>` — the rule would lose its teeth)
    expect(env.errors.join("\n")).toContain("maruhi: internal error (Error)");
    // A defect's message is not shown — even wording embedding the typed value could reach here
    expect(env.errors.join("\n")).not.toContain("config load defect");
  });
});
