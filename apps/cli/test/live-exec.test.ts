// Pins the production ProcessRunner's `exec` (live.ts — the child-process
// boundary of `maruhi sync`'s exec driver) with a real process. Since
// vitest runs under Node, the Bun.spawn-using implementation is exercised
// via a probe launched under `bun` (support/exec-probe.ts).

import { spawnSync } from "node:child_process";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

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
}

describe("ProcessRunner.exec (live — Bun.spawn)", () => {
  it("the value reaches stdin whole, the child's environment carries telemetry-off and no MARUHI_*, output is captured, and the exit code comes back", () => {
    const result = spawnSync("bun", [PROBE], {
      encoding: "utf8",
      // spawnSync blocks the event loop — keep it below vitest's hook
      // timeout
      timeout: 60_000,
    });
    expect(result.status, result.stderr).toBe(0);
    // The parent's stdout is just the probe's single JSON line (the
    // child's output doesn't pass straight through)
    const lines = result.stdout.trim().split("\n");
    expect(lines).toHaveLength(1);
    const probe = JSON.parse(lines[0] ?? "") as ProbeResult;
    expect(probe.exitCode).toBe(3);
    expect(probe.output).toContain("len=16384 telemetry=false maruhi=unset");
    // The output comes back whole, uncut (cutting happens after the
    // redaction — sync-exec.ts)
    expect(probe.output).toContain("x".repeat(70_000));
    expect(probe.output).toContain("to-stderr");
    // An uninstalled command is a typed error (doesn't go fetch it)
    expect(probe.missing).toContain("Cannot start maruhi-probe-not-installed-9f3c");
    expect(probe.missing).toContain("maruhi never downloads a vendor CLI");
    expect(probe.missing).toContain("(ENOENT)");
    // A missing cwd is named distinctly from a missing executable
    expect(probe.badCwd).toContain(
      "the target's working directory does not exist or is not a directory (/nonexistent-maruhi-probe-dir)",
    );
    // captureScript: stdout whole (300,000 bytes) and stderr as text; a
    // flood past 1 MiB is refused with the script stopped (the probe does
    // not wait out its sleep)
    expect(probe.capturedBytes).toBe(300_000);
    expect(probe.capturedStderr).toBe("note\n");
    expect(probe.flooded).toContain(
      "sh wrote more than 1 MiB to stdout (a credential is small; commentary belongs on stderr): it was stopped and nothing it wrote was read",
    );
    expect(probe.floodedStderr).toBe(
      "(the script wrote more than 1 MiB to stderr; none of it is shown)",
    );
    // … and the script ran on: its value arrived whole (D-10)
    expect(probe.floodedStderrStdout).toBe("value\n".length);
    // A process the script left behind (`… &`) holds the pipes; the capture
    // ends after the grace with the script's answer and says so (D-12)
    expect(probe.leftoverStdout).toBe("value\n");
    expect(probe.leftoverStderr).toContain("a process the script started still held its output");
    expect(probe.leftoverMs).toBeLessThan(15_000);
    // A script that ignores the stop is killed after the grace (D-13)
    expect(probe.stubborn).toContain("wrote more than 1 MiB to stdout");
    expect(probe.stubbornMs).toBeLessThan(15_000);
  }, 60_000);
});
