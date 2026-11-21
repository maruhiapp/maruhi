import { describe, expect, it } from "vite-plus/test";

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
    const terminal = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "true"], terminal.layer)).toBe(0);
    expect(terminal.runnerCalls[0]?.redact).toBeUndefined();
    const agent = await startEnv([chainHandler(), pullHandler()]);
    agent.setAgent({ isAgent: true, name: "claude-code" });
    expect(await runCli(["run", "--", "true"], agent.layer)).toBe(0);
    expect(decode(agent.runnerCalls[0]?.redact)).toEqual(["alpha-value", "beta-value"]);
    const stderrPiped = await startEnv([chainHandler(), pullHandler()]);
    stderrPiped.setTerminal({ stderr: false });
    expect(await runCli(["run", "--", "true"], stderrPiped.layer)).toBe(0);
    expect(decode(stderrPiped.runnerCalls[0]?.redact)).toEqual(["alpha-value", "beta-value"]);
    const heredoc = await startEnv([chainHandler(), pullHandler()]);
    heredoc.setTerminal({ stdin: false });
    expect(await runCli(["run", "--", "true"], heredoc.layer)).toBe(0);
    expect(heredoc.runnerCalls[0]?.redact).toBeUndefined();
  });

  it("run is allowed even when an AI agent is detected (the boundary)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: true, name: "cursor" });
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
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "printenv", "", "ALPHA"], env.layer)).toBe(0);
    expect(env.runnerCalls[0]?.command).toEqual(["printenv", "", "ALPHA"]);
  });

  it("catches an empty argument before `--` even when the child side has a whitespace argument", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    const server = servers[servers.length - 1];
    expect(await runCli(["run", "", "--", "printenv", " "], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify the command to run after `--`");
    expect(server?.requests).toHaveLength(0);
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("an executable placed **before** `--` never becomes the child process (only what follows `--` is taken)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    const server = servers[servers.length - 1];
    expect(await runCli(["run", "stray", "--", "printenv"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unexpected extra arguments (1;");
    expect(errors).toContain("Write the command to run after `--`");
    expect(errors).not.toContain("stray");
    expect(env.runnerCalls).toHaveLength(0);
    expect(server?.requests).toHaveLength(0);
  });

  it("a nested `--` (`npm test -- --watch`) also passes through to the child verbatim", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "npm", "test", "--", "--watch"], env.layer)).toBe(0);
    expect(env.runnerCalls[0]?.command).toEqual(["npm", "test", "--", "--watch"]);
  });

  it("everything after `--` skips maruhi's argument checks and passes to the child verbatim", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(
      await runCli(["run", "--", "printenv", "--show=false", "--shwo", "extra"], env.layer),
    ).toBe(0);
    expect(env.runnerCalls[0]?.command).toEqual(["printenv", "--show=false", "--shwo", "extra"]);
  });
});
