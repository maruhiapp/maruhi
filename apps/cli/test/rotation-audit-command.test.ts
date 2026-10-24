// The argument layer of `maruhi rotation` and `maruhi audit`
// (commands/rotation.ts and audit.package/command.ts): their nested
// subcommands (ADR-0016 stage 3), driven through the real runCli as in
// effect-cli.test.ts. The two groups share one describe, kept whole.

import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { expectNoLeak, startEnv } from "./support/argument-layer.ts";

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
    expect(env.errors.join("\n")).toContain(
      "Unacceptable value for flag --env (expected: environment id (1-64 chars of [A-Za-z0-9_-], starting alphanumeric))",
    );
    expect(server.requests).toHaveLength(0);

    const badVar = await startEnv();
    expect(await runCli(["audit", "list", "--var", "sk-live-x!"], badVar.env.layer)).toBe(2);
    expect(badVar.env.errors.join("\n")).toContain(
      "Unacceptable value for flag --var (expected: variable id (1-64 chars of [A-Za-z0-9_-], starting alphanumeric))",
    );
    expectNoLeak(badVar.env, ["sk-live-x!"]);
    expect(badVar.server.requests).toHaveLength(0);
  });

  it("bare `maruhi rotation` / an unknown operation is a usage error (2)", async () => {
    const bare = await startEnv();
    expect(await runCli(["rotation"], bare.env.layer)).toBe(2);
    expect(bare.env.logs).toEqual([]);
    expect(bare.env.errors.join("\n")).toContain("maruhi rotation");

    const bogus = await startEnv();
    expect(await runCli(["rotation", "bogus"], bogus.env.layer)).toBe(2);
    expect(bogus.env.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: list | dismiss | proposals | accept | reject)",
    );
  });

  it("rotation dismiss's boolean (--all) refuses duplicates and reads a value as written", async () => {
    // `--all=false` is read as false exactly as written (#2 of
    // effect-cli.test.ts's 12 shapes — reading it as true regardless would
    // turn it into a withdrawal of every flag). A duplicate is rejected by
    // atMost(1)
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

  it("a missing rotation-dismiss target fails before any communication", async () => {
    // Put behind the prelude's sync, the guidance would be hidden behind a
    // connection error (this harness's server only ever returns 404) and the round trip would be wasted
    // (the contradiction with --all and half a single target are Command.validate
    // rules — effect-cli.test.ts's Command.validate block)
    const missing = await startEnv();
    expect(await runCli(["rotation", "dismiss"], missing.env.layer)).toBe(1);
    expect(missing.env.errors.join("\n")).toContain("Specify what to dismiss");
    expect(missing.server.requests).toHaveLength(0);
  });

  it("rotation dismiss's and proposals' format checks fail before any communication (the value is never shown)", async () => {
    const env1 = await startEnv();
    expect(
      await runCli(["rotation", "dismiss", "sk-live-x!", "--env", "prod"], env1.env.layer),
    ).toBe(2);
    expect(env1.env.errors.join("\n")).toContain(
      "Unacceptable value for positional argument variable (expected: variable id (1-64 chars of [A-Za-z0-9_-], starting alphanumeric))",
    );
    expectNoLeak(env1.env, ["sk-live-x!"]);
    expect(env1.server.requests).toHaveLength(0);

    const env2 = await startEnv();
    expect(await runCli(["rotation", "dismiss", "--all", "--env", "!bad"], env2.env.layer)).toBe(2);
    expect(env2.env.errors.join("\n")).toContain(
      "Unacceptable value for flag --env (expected: environment id (1-64 chars of [A-Za-z0-9_-], starting alphanumeric))",
    );
    expectNoLeak(env2.env, ["!bad"]);
    expect(env2.server.requests).toHaveLength(0);

    const env3 = await startEnv();
    expect(await runCli(["rotation", "proposals", "--env", "!bad"], env3.env.layer)).toBe(2);
    expect(env3.env.errors.join("\n")).toContain(
      "Unacceptable value for flag --env (expected: environment id (1-64 chars of [A-Za-z0-9_-], starting alphanumeric))",
    );
    expectNoLeak(env3.env, ["!bad"]);
    expect(env3.server.requests).toHaveLength(0);
  });
});
