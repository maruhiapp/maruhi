// Tests for pull (§5.1 distribution-time verification + §12-7 all-epoch DEKs)
// and run (memory injection), and for the AI-agent-detection boundary
// (value display is refused / run is allowed).

import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { chainHandler, pullHandler, servers, startEnv } from "./support/pull-run.ts";

describe("maruhi run", () => {
  it("injects decrypted values as child-process environment variables (memory injection)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "printenv", "ALPHA"], env.layer)).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
    expect(env.runnerCalls[0]?.command).toEqual(["printenv", "ALPHA"]);
    expect(env.runnerCalls[0]?.extraEnv).toEqual({
      ALPHA: "alpha-value",
      BETA: "beta-value",
    });
  });

  it("hands the runner the values to redact when an agent is detected or the output is not a terminal, and nothing on a human terminal (ROADMAP Phase 3 ⑤)", async () => {
    const decode = (fragments: readonly Uint8Array[] | undefined) =>
      fragments?.map((bytes) => new TextDecoder().decode(bytes)).toSorted();
    // A human terminal (stdin / stdout / stderr all terminals): stdio inherited, no redaction
    const terminal = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "true"], terminal.layer)).toBe(0);
    expect(terminal.runnerCalls[0]?.redact).toBeUndefined();
    // A known agent on a PTY (stdout is a terminal): the secondary layer triggers
    const agent = await startEnv([chainHandler(), pullHandler()]);
    agent.setAgent({ isAgent: true, name: "claude-code" });
    expect(await runCli(["run", "--", "true"], agent.layer)).toBe(0);
    expect(decode(agent.runnerCalls[0]?.redact)).toEqual(["alpha-value", "beta-value"]);
    // stderr redirected to a file (stdout still a terminal): triggers
    const stderrPiped = await startEnv([chainHandler(), pullHandler()]);
    stderrPiped.setTerminal({ stderr: false });
    expect(await runCli(["run", "--", "true"], stderrPiped.layer)).toBe(0);
    expect(decode(stderrPiped.runnerCalls[0]?.redact)).toEqual(["alpha-value", "beta-value"]);
    // stdin from a heredoc alone does not trigger (the child's TTY is kept)
    const heredoc = await startEnv([chainHandler(), pullHandler()]);
    heredoc.setTerminal({ stdin: false });
    expect(await runCli(["run", "--", "true"], heredoc.layer)).toBe(0);
    expect(heredoc.runnerCalls[0]?.redact).toBeUndefined();
  });

  it("run is allowed even when an AI agent is detected (the boundary)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: true, name: "cursor" });
    // It passes without a terminal (CI / pipe). run is not a path that *shows*
    // the value but a consumption path injecting it into the child's
    // environment variables — outside the TTY boundary
    env.setTerminal({ stdin: false, stdout: false });
    expect(await runCli(["run", "--", "true"], env.layer)).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
  });

  it("the value appears only in the child-process environment, never in terminal output", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "true"], env.layer)).toBe(0);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).not.toContain("alpha-value");
    expect(output).not.toContain("beta-value");
    expect(env.runnerCalls[0]?.extraEnv["ALPHA"]).toBe("alpha-value");
  });

  it("propagates the child process's exit code", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setRunnerExitCode(3);
    expect(await runCli(["run", "--", "false"], env.layer)).toBe(3);
  });

  it("no command specified errors without pulling or decrypting", async () => {
    // A run with nothing to execute is a usage mistake (usage error). Letting
    // it through would fetch the distribution and decrypt every variable
    // before saying the same thing = producing plaintext that is never used
    const env = await startEnv([chainHandler(), pullHandler()]);
    const server = servers[servers.length - 1];
    expect(await runCli(["run"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify the command to run after `--`");
    expect(server?.requests).toHaveLength(0);
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("the same when `--` is given but nothing follows it", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    const server = servers[servers.length - 1];
    expect(await runCli(["run", "--"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify the command to run after `--`");
    expect(server?.requests).toHaveLength(0);
  });

  it("passes empty-string arguments after `--` through without dropping them", async () => {
    // Dropping an empty-string argument on a truthiness check silently shrinks
    // the child's argv by one and misfires the argument check too. Everything
    // after `--` is passed through as an argv token verbatim
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "printenv", "", "ALPHA"], env.layer)).toBe(0);
    expect(env.runnerCalls[0]?.command).toEqual(["printenv", "", "ALPHA"]);
  });

  it("catches an empty argument before `--` even when the child side has a whitespace argument", async () => {
    // The tokens before and after `--` merge into one array (the upstream
    // parser), so a leading empty string lands in the executable position.
    // `Argument.filter` rejects it as "nothing to execute" — a whitespace-only
    // child argument (`" "`) is not rejected (the second onward pass through as-is)
    const env = await startEnv([chainHandler(), pullHandler()]);
    const server = servers[servers.length - 1];
    expect(await runCli(["run", "", "--", "printenv", " "], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify the command to run after `--`");
    expect(server?.requests).toHaveLength(0);
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("an executable placed **before** `--` never becomes the child process (only what follows `--` is taken)", async () => {
    // Because the upstream parser merges the positional args around `--` into
    // one array, `maruhi run stray -- printenv` would morph into **running
    // stray** on declaration alone. It is rejected by matching `--`'s position
    // and count in `Stdio.args` (ADR-0016 decision 8)
    const env = await startEnv([chainHandler(), pullHandler()]);
    const server = servers[servers.length - 1];
    expect(await runCli(["run", "stray", "--", "printenv"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unexpected extra arguments (1;");
    expect(errors).toContain("Write the command to run after `--`");
    // Never print the contents (a positional arg could contain plaintext)
    expect(errors).not.toContain("stray");
    expect(env.runnerCalls).toHaveLength(0);
    expect(server?.requests).toHaveLength(0);
  });

  it("a nested `--` (`npm test -- --watch`) also passes through to the child verbatim", async () => {
    // Only the first `--` is treated as maruhi's terminator; inner `--`s stay
    // as child arguments (dropping them would break npm / cargo / docker-style argument forwarding)
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "npm", "test", "--", "--watch"], env.layer)).toBe(0);
    expect(env.runnerCalls[0]?.command).toEqual(["npm", "test", "--", "--watch"]);
  });

  it("everything after `--` skips maruhi's argument checks and passes to the child verbatim", async () => {
    // If the strict argument-usage check reached the child's arguments,
    // `maruhi run -- <cmd>` could no longer run arbitrary commands. Everything
    // past `--` is never interpreted as a maruhi flag or positional arg, so it is outside the check's scope
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(
      await runCli(["run", "--", "printenv", "--show=false", "--shwo", "extra"], env.layer),
    ).toBe(0);
    expect(env.runnerCalls[0]?.command).toEqual(["printenv", "--show=false", "--shwo", "extra"]);
  });
});
