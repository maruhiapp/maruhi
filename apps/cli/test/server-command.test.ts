// The argument layer of `maruhi server` (server.package/command.ts): its
// nested subcommands (ADR-0016 decision 6), driven through the real runCli
// as in effect-cli.test.ts.

import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { expectNoLeak, startEnv } from "./support/argument-layer.ts";

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
