// Unit tests for live.ts's interactive-input primitives.
//
// - makeStdinLineReader: retains unconsumed lines across prompts (the
//   close-readline-each-time shape was dropping the next line), CRLF,
//   newline-less termination, EOF
// - readHiddenLine: termination handling of raw-mode input (no hang on
//   end/error), Ctrl+D abort, ignoring escape sequences (arrow keys) and
//   control characters, Backspace
//
// Driven by adding a TTY stub (setRawMode / isRaw) onto PassThrough.

import { spawnSync } from "node:child_process";
import { closeSync, openSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";

import { describe, expect, it } from "vitest";

import { makeStdinLineReader, readHiddenLine, writeLine } from "../src/live.ts";

/** A pseudo stdin with a raw-mode stub. */
function fakeTty(): PassThrough & { isRaw: boolean; setRawMode: (raw: boolean) => void } {
  const stream = new PassThrough();
  return Object.assign(stream, {
    isRaw: false,
    setRawMode(raw: boolean) {
      this.isRaw = raw;
      return this;
    },
  });
}

function asStdin(stream: PassThrough): NodeJS.ReadStream {
  return stream as unknown as NodeJS.ReadStream;
}

describe("makeStdinLineReader (the shared non-TTY line reader)", () => {
  it("lets later prompts receive the remaining lines when one chunk carries several", async () => {
    const stream = new PassThrough();
    const readLine = makeStdinLineReader(asStdin(stream));
    stream.write("WRONG\nAAAA-BBBB\n");
    // The first prompt gets line 1; the second (a retry) gets line 2
    expect(await readLine()).toBe("WRONG");
    expect(await readLine()).toBe("AAAA-BBBB");
  });

  it("strips CRLF line endings and also returns a final line ended without a newline", async () => {
    const stream = new PassThrough();
    const readLine = makeStdinLineReader(asStdin(stream));
    stream.write("first\r\nlast-without-newline");
    stream.end();
    expect(await readLine()).toBe("first");
    expect(await readLine()).toBe("last-without-newline");
    await expect(readLine()).rejects.toThrow("eof");
  });

  it("fails with eof when the input ends empty (never hangs)", async () => {
    const stream = new PassThrough();
    const readLine = makeStdinLineReader(asStdin(stream));
    stream.end();
    await expect(readLine()).rejects.toThrow("eof");
  });
});

describe("readHiddenLine (raw-mode non-echo input)", () => {
  it("Backspace deletes the tail and Enter commits", async () => {
    const tty = fakeTty();
    const pending = readHiddenLine(asStdin(tty));
    tty.write("ABCX\u007fD\r");
    expect(await pending).toBe("ABCD");
    // Raw mode is restored
    expect(tty.isRaw).toBe(false);
  });

  it("escape sequences like arrow keys and tabs never mix into the input (prevents invisible corruption)", async () => {
    const tty = fakeTty();
    const pending = readHiddenLine(asStdin(tty));
    // Sandwiched between a left arrow (ESC [ D) and a tab, only printable
    // characters remain
    tty.write("AB\u001b[D\tCD\n");
    expect(await pending).toBe("ABCD");
  });

  it("Ctrl+C / Ctrl+D are treated as aborts", async () => {
    const byCtrlC = fakeTty();
    const pendingC = readHiddenLine(asStdin(byCtrlC));
    byCtrlC.write("AB\u0003");
    await expect(pendingC).rejects.toThrow("interrupted");

    const byCtrlD = fakeTty();
    const pendingD = readHiddenLine(asStdin(byCtrlD));
    byCtrlD.write("AB\u0004");
    await expect(pendingD).rejects.toThrow("interrupted");
  });

  it("does not hang when the stream ends mid-input — fails with eof", async () => {
    const tty = fakeTty();
    const pending = readHiddenLine(asStdin(tty));
    tty.write("AB");
    tty.end();
    await expect(pending).rejects.toThrow("eof");
  });
});

describe("writeLine (synchronous writes and closed pipes)", () => {
  it("writes one line + newline fully to the fd (a file)", () => {
    const path = join(tmpdir(), `maruhi-writeline-${process.pid}.txt`);
    const fd = openSync(path, "w");
    try {
      writeLine(fd, "first");
      writeLine(fd, "second");
    } finally {
      closeSync(fd);
    }
    expect(readFileSync(path, "utf8")).toBe("first\nsecond\n");
  });

  it("writes to a pipe closed by the reader first (EPIPE) are not defects — the process exits 0", () => {
    // The `maruhi … | head -1` shape. writeSync throws EPIPE on the second
    // line onward, but like console.log it swallows silently. Verify with a
    // real process: run the writer under bun and watch the exit code after
    // the reader head closes at 1 line
    const script =
      'import { writeLine } from "./apps/cli/src/live.ts"; for (let i = 0; i < 200000; i += 1) writeLine(1, `line${i}`); process.exit(0);';
    const result = spawnSync(
      "bash",
      ["-c", `bun -e '${script}' | head -1; echo "writer-exit=\${PIPESTATUS[0]}"`],
      { cwd: new URL("../../..", import.meta.url).pathname, encoding: "utf8" },
    );
    // stderr is attached so a failure's cause (bun missing, script syntax)
    // is readable (the bash side's exit code is always 0 due to the
    // trailing echo, so assertions go on the writer's exit code =
    // writer-exit plus the first line arriving)
    expect(result.stdout, result.stderr).toContain("line0");
    expect(result.stdout, result.stderr).toContain("writer-exit=0");
    expect(result.stderr).not.toContain("EPIPE");
  });
});
