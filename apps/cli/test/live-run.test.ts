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
const PIPE_PROBE = join(import.meta.dirname, "support", "pipe-probe.ts");

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

  it("keeps pipe semantics: when our stdout closes (| head), the child is ended and run exits (§19 C-1)", () => {
    // The probe's stdout is read by `head -c 200` and then closed; without
    // the EPIPE handling the relay would read the flooding child forever
    const result = spawnSync("sh", ["-c", `bun "${PIPE_PROBE}" flood | head -c 200 >/dev/null`], {
      encoding: "utf8",
      timeout: 20_000,
    });
    expect(result.signal, "the probe did not finish in time").toBeNull();
    const marker = JSON.parse(result.stderr.trim().split("\n").at(-1) ?? "{}") as {
      exitCode: number;
      elapsedMs: number;
    };
    // The child died of SIGPIPE (sh reports 141 — 128 + 13) or was ended; never hung
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
    // The child itself returns at once; the relay waits at most the grace, not the grandchild's 20 s
    expect(marker.elapsedMs).toBeLessThan(5_000);
  }, 60_000);
});
