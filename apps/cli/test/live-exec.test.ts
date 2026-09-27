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
  });
});
