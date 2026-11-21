import { describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { expectNoLeak, startEnv } from "./support/argument-layer.ts";

describe("env's nested subcommands (ADR-0016 decision 6 — stage 2)", () => {
  it("a flag the operation does not have fails with a usage error (2)", async () => {
    for (const argv of [
      ["env", "rotate", "dev", "--name", "x"],
      ["env", "diff", "dev", "prod", "--reason", "x"],
      ["env", "diff", "dev", "prod", "--new-epoch"],
      ["env", "diff", "dev", "prod", "--no-new-epoch"],
      ["env", "create", "dev", "--reason", "x"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain("Unknown flag");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("an unknown operation lists the possible operations or candidates (the typed word is never shown)", async () => {
    const bogus = await startEnv();
    expect(await runCli(["env", "bogus", "dev"], bogus.env.layer)).toBe(2);
    expect(bogus.env.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: create | list | rename | rm | rotate | diff)",
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
    const ordered = await startEnv();
    expect(
      await runCli(["env", "rotate", "--new-epoch", "dev", "--reason", "x"], ordered.env.layer),
    ).toBe(1);
    expect(ordered.env.errors.join("\n")).not.toContain("Missing positional argument");
    expect(ordered.server.requests.length).toBeGreaterThan(0);

    const literal = await startEnv();
    expect(
      await runCli(["env", "rotate", "--new-epoch", "on", "--reason", "x"], literal.env.layer),
    ).toBe(2);
    expect(literal.env.errors.join("\n")).toContain("Missing positional argument environment-id");
    expect(literal.server.requests).toHaveLength(0);
  });

  it("rotate: a value for a boolean is read as written", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["env", "rotate", "dev", "--new-epoch=false"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).not.toContain("Unknown flag");
    expect(server.requests.length).toBeGreaterThan(0);

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
      expect(errors).toContain(
        "Unacceptable value for positional argument environment-id (expected: environment id (1-64 chars of [A-Za-z0-9_-], starting alphanumeric))",
      );
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
    const { env, server } = await startEnv();
    expect(await runCli(["env"], env.layer)).toBe(2);
    expect(env.logs).toEqual([]);
    expect(env.errors.join("\n")).toContain("maruhi env");
    expect(server.requests).toHaveLength(0);

    const help = await startEnv();
    expect(await runCli(["env", "--help"], help.env.layer)).toBe(0);
    expect(help.env.errors.join("\n")).toContain("maruhi env");
    expect(help.server.requests).toHaveLength(0);
  });

  it("a flag written at the parent level fails with guidance on where it belongs (behind the subcommand)", async () => {
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
