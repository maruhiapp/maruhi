import { spawnSync } from "node:child_process";
import { join } from "node:path";

import { describe, expect, it } from "vite-plus/test";

const PROBE = join(import.meta.dirname, "support", "exec-probe.ts");

interface ProbeResult {
  readonly exitCode: number;
  readonly output: string;
  readonly missing: string;
  readonly badCwd: string;
  readonly capturedBytes: number;
  readonly capturedStderr: string;
  readonly flooded: string;
  readonly floodedStderr: string;
  readonly floodedStderrStdout: number;
  readonly leftoverStdout: string;
  readonly leftoverStderr: string;
  readonly leftoverMs: number;
  readonly stubborn: string;
  readonly stubbornMs: number;
  readonly polluted: string;
  readonly floodedAfterExit: string;
  readonly failedItselfCode: number;
  readonly failedItselfStderr: string;
}

describe("ProcessRunner.exec (live — Bun.spawn)", () => {
  it("the value reaches stdin whole, the child's environment carries telemetry-off and no MARUHI_*, output is captured, and the exit code comes back", () => {
    const result = spawnSync("bun", [PROBE], {
      encoding: "utf8",
      timeout: 60_000,
    });
    expect(result.status, result.stderr).toBe(0);
    const lines = result.stdout.trim().split("\n");
    expect(lines).toHaveLength(1);
    const probe = JSON.parse(lines[0] ?? "") as ProbeResult;
    expect(probe.exitCode).toBe(3);
    expect(probe.output).toContain("len=16384 telemetry=false maruhi=unset");
    expect(probe.output).toContain("x".repeat(70_000));
    expect(probe.output).toContain("to-stderr");
    expect(probe.missing).toContain("Cannot start maruhi-probe-not-installed-9f3c");
    expect(probe.missing).toContain("maruhi never downloads a vendor CLI");
    expect(probe.missing).toContain("(ENOENT)");
    expect(probe.badCwd).toContain(
      "the target's working directory does not exist or is not a directory (/nonexistent-maruhi-probe-dir)",
    );
    expect(probe.capturedBytes).toBe(300_000);
    expect(probe.capturedStderr).toBe("note\n");
    expect(probe.flooded).toContain(
      "sh wrote more than 1 MiB to stdout (a credential is small; commentary belongs on stderr): it was stopped and nothing it wrote was read",
    );
    expect(probe.floodedStderr).toBe(
      "(the script wrote more than 1 MiB to stderr; none of it is shown)",
    );
    expect(probe.floodedStderrStdout).toBe("value\n".length);
    expect(probe.leftoverStdout).toBe("value\n");
    expect(probe.leftoverStderr).toContain("a process the script started still held its output");
    expect(probe.leftoverMs).toBeLessThan(15_000);
    expect(probe.stubborn).toContain("wrote more than 1 MiB to stdout");
    expect(probe.stubbornMs).toBeLessThan(15_000);
    expect(probe.polluted).toContain(
      "ScriptLeftoverError: sh exited (code 0) while a process it started kept writing to its stdout",
    );
    expect(probe.floodedAfterExit).toContain("ScriptLeftoverError: sh exited (code 0)");
    expect(probe.floodedAfterExit).not.toContain("it was stopped");
    expect(probe.failedItselfCode).toBe(7);
    expect(probe.failedItselfStderr).toContain("issuer said no");
  }, 60_000);
});
