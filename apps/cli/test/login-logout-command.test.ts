// The argument layer of `maruhi login` and `maruhi logout`
// (commands/login-logout.ts, ADR-0016 stage 3), driven through the real
// runCli as in effect-cli.test.ts.

import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { expectNoLeak, startEnv } from "./support/argument-layer.ts";

describe("the login / logout argument layer (ADR-0016 stage 3 ④)", () => {
  it("a type-mismatched value is refused without showing the given value", async () => {
    // The expected type may be shown since it comes from the declaration,
    // but the given value could contain plaintext, so it is never shown
    const { env, server } = await startEnv();
    expect(await runCli(["login", "--token-ttl-days", "s3cr3t"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unacceptable value for flag --token-ttl-days");
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

  it("--poll-interval no longer exists and is refused as an unknown flag", async () => {
    // The hidden test-only shortcut was removed with the polling rewrite
    // (the schedule now drives the waits; tests drive a virtual clock). An
    // unknown flag is a usage error (2), and the given value is never echoed
    const { env, server } = await startEnv();
    expect(await runCli(["login", "--poll-interval", "sentinel-value-0x"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unknown flag");
    expect(errors).not.toContain("--poll-interval");
    expectNoLeak(env, ["sentinel-value-0x"]);
    expect(server.requests).toHaveLength(0);
  });

  it("logout takes no positional args", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["logout", "extra"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("maruhi logout takes no positional arguments");
    expect(server.requests).toHaveLength(0);
  });
});
