// The argument layer of `maruhi member` (member.package/command.ts): its
// nested subcommands (ADR-0016 decision 6), driven through the real runCli
// as in effect-cli.test.ts.

import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { expectNoLeak, startEnv } from "./support/argument-layer.ts";

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
