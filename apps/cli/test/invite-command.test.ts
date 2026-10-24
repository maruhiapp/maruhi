// The argument layer of `maruhi invite` (invite.package/command.ts): its
// nested subcommands (ADR-0016 decision 6), driven through the real runCli
// as in effect-cli.test.ts.

import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { expectNoLeak, startEnv } from "./support/argument-layer.ts";

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
