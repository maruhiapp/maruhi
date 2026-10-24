// The argument layer of `maruhi push` (push.package/command.ts, ADR-0016
// stage 3), driven through the real runCli as in effect-cli.test.ts.

import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { expectNoLeak, startEnv } from "./support/argument-layer.ts";

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
