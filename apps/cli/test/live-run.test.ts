// Pins the run-output redaction of the production ProcessRunner (live.ts
// relayRedacted — ROADMAP Phase 3 ⑤) with a real child under Bun: the
// injected value is scrubbed from stdout and stderr by exact match (whole,
// per line, JSON-escaped), across a chunk boundary, while bytes that match
// nothing pass through unchanged and the exit code comes back. Since
// vitest runs under Node, the Bun.spawn implementation is exercised via a
// probe launched under `bun` (support/run-probe.ts).

import { spawnSync } from "node:child_process";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const PROBE = join(import.meta.dirname, "support", "run-probe.ts");

describe("ProcessRunner.run with redaction (live — Bun.spawn, piped)", () => {
  it("scrubs the value from stdout and stderr, keeps binary bytes intact, and returns the exit code", () => {
    const result = spawnSync("bun", [PROBE], { timeout: 60_000 });
    expect(result.status, result.stderr.toString()).toBe(0);
    const stdout = result.stdout;
    const text = stdout.toString("latin1");
    // Never the secret, in any of its forms
    expect(text).not.toContain("hunter2-probe-secret-value");
    expect(text).not.toContain("line-one-of-pem");
    expect(result.stderr.toString()).not.toContain("hunter2-probe-secret-value");
    // Each form scrubbed
    expect(text).toContain("token=[redacted] done\n");
    expect(text).toContain('{"key":"[redacted]"}\n');
    // Across the two writes (the carry-over): the whole value is one match
    expect(text).toContain("\n[redacted]\n");
    expect(result.stderr.toString()).toContain("err=[redacted]\n");
    // Binary transparency: the 256 byte values arrive as written
    const start = stdout.indexOf("BIN:") + 4;
    const end = stdout.indexOf(":END", start);
    const bytes = stdout.subarray(start, end);
    expect(bytes.length).toBe(256);
    for (let i = 0; i < 256; i++) {
      expect(bytes[i], `byte ${i}`).toBe(i);
    }
    // The probe's own JSON marker is the last stdout line
    const last = text.trim().split("\n").at(-1) ?? "";
    expect(JSON.parse(last)).toEqual({ exitCode: 4 });
  }, 60_000);
});
