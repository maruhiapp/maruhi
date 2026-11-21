import { spawnSync } from "node:child_process";
import { join } from "node:path";

import { describe, expect, it } from "vite-plus/test";

const PROBE = join(import.meta.dirname, "support", "run-probe.ts");
const PIPE_PROBE = join(import.meta.dirname, "support", "pipe-probe.ts");

describe("ProcessRunner.run with redaction (live — Bun.spawn, piped)", () => {
  it("scrubs the value from stdout and stderr, keeps binary bytes intact, and returns the exit code", () => {
    const result = spawnSync("bun", [PROBE], { timeout: 60_000 });
    expect(result.status, result.stderr.toString()).toBe(0);
    const stdout = result.stdout;
    const text = stdout.toString("latin1");
    expect(text).not.toContain("hunter2-probe-secret-value");
    expect(text).not.toContain("line-one-of-pem");
    expect(result.stderr.toString()).not.toContain("hunter2-probe-secret-value");
    expect(text).toContain("token=[redacted] done\n");
    expect(text).toContain('{"key":"[redacted]"}\n');
    expect(text).toContain("\n[redacted]\n");
    expect(result.stderr.toString()).toContain("err=[redacted]\n");
    const start = stdout.indexOf("BIN:") + 4;
    const end = stdout.indexOf(":END", start);
    const bytes = stdout.subarray(start, end);
    expect(bytes.length).toBe(256);
    for (let i = 0; i < 256; i++) {
      expect(bytes[i], `byte ${i}`).toBe(i);
    }
    const last = text.trim().split("\n").at(-1) ?? "";
    expect(JSON.parse(last)).toEqual({ exitCode: 4 });
  }, 60_000);

  it("keeps pipe semantics: when our stdout closes (| head), the child is ended and run exits (§19 C-1)", () => {
    const result = spawnSync("sh", ["-c", `bun "${PIPE_PROBE}" flood | head -c 200 >/dev/null`], {
      encoding: "utf8",
      timeout: 20_000,
    });
    expect(result.signal, "the probe did not finish in time").toBeNull();
    const marker = JSON.parse(result.stderr.trim().split("\n").at(-1) ?? "{}") as {
      exitCode: number;
      elapsedMs: number;
    };
    expect(marker.exitCode).not.toBe(0);
    expect(marker.elapsedMs).toBeLessThan(10_000);
    expect(result.stderr).not.toContain("hunter2-pipe-probe");
  }, 60_000);

  it("does not wait for a grandchild that keeps the pipes open after the child exits (§19 C-1)", () => {
    const result = spawnSync("bun", [PIPE_PROBE, "grandchild"], {
      encoding: "utf8",
      timeout: 20_000,
    });
    expect(result.signal).toBeNull();
    expect(result.stdout).toContain("done");
    const marker = JSON.parse(result.stderr.trim().split("\n").at(-1) ?? "{}") as {
      exitCode: number;
      elapsedMs: number;
    };
    expect(marker.exitCode).toBe(0);
    expect(marker.elapsedMs).toBeLessThan(5_000);
  }, 60_000);
});
