// Unit tests for display.ts: the total timestamp formatters, showValues
// (the post-decryption defense line) and decodeValueText (the unified
// value-decoding policy).

import { Effect, Exit, Layer, Stdio } from "effect";
import { describe, expect, it } from "vitest";

import { AgentProfileRef } from "../src/agent-gate.ts";
import {
  decodeValueText,
  formatUtcDate,
  formatUtcMinutes,
  formatUtcSeconds,
  showValues,
} from "../src/display.ts";
import { CliIo } from "../src/io.ts";
import { variable } from "./support/variable.ts";

describe("total timestamp formatters", () => {
  it("degrades to an explicit display — no RangeError — for out-of-Date-range or non-finite input", () => {
    expect(formatUtcSeconds(0)).toBe("1970-01-01 00:00:00 UTC");
    expect(formatUtcMinutes(0)).toBe("1970-01-01 00:00 UTC");
    expect(formatUtcDate(0)).toBe("1970-01-01");
    // Even inside the Date range, years outside 0-9999 (where toISOString
    // returns an expanded-year form) silently shift a fixed slice — degrade explicitly instead
    expect(formatUtcSeconds(Date.UTC(9999, 11, 31, 23, 59, 59))).toBe("9999-12-31 23:59:59 UTC");
    for (const bad of [
      253_402_300_800_000, // year 10000
      -62_167_219_200_001, // year -1
      8_640_000_000_000_000,
      -1e300,
      Number.POSITIVE_INFINITY,
      Number.NaN,
    ]) {
      expect(formatUtcSeconds(bad)).toContain("invalid timestamp");
      expect(formatUtcMinutes(bad)).toContain("invalid timestamp");
      expect(formatUtcDate(bad)).toContain("invalid timestamp");
    }
  });
});

describe("showValues (the post-decryption defense line)", () => {
  /** A CliIo that discards output (this check only observes "display is never reached"). */
  const silentIo = Layer.succeed(CliIo, {
    log: () => Effect.void,
    logError: () => Effect.void,
    readStdin: Effect.succeed(new Uint8Array(0)),
    promptLine: () => Effect.succeed(""),
    envVar: () => undefined,
    agentProfile: () => ({ isAgent: false }),
    stderrIsTerminal: () => true,
    colorEnabled: () => false,
    openBrowser: () => Effect.succeed(false),
  });

  const showOne = (input: {
    readonly agent?: { readonly isAgent: boolean; readonly name?: string };
    readonly stdinIsTerminal: boolean;
    readonly stdoutIsTerminal: boolean;
  }) =>
    Effect.runPromiseExit(
      showValues([variable("SECRET", "plaintext-value")]).pipe(
        Effect.provide(
          Layer.mergeAll(
            silentIo,
            Layer.succeed(AgentProfileRef, input.agent ?? { isAgent: false }),
            Stdio.layerTest({
              stdinIsTerminal: Effect.succeed(input.stdinIsTerminal),
              stdoutIsTerminal: Effect.succeed(input.stdoutIsTerminal),
            }),
          ),
        ),
      ),
    );

  it("does not display off-terminal even for a direct call that bypasses the entry check", async () => {
    // The main path is pull's entry point (before decryption). This defense line
    // keeps a future direct showValues caller from reaching display without the
    // entry check — pins **both layers using the same decision** (primary = TTY, secondary = agent detection)
    const piped = await showOne({ stdinIsTerminal: true, stdoutIsTerminal: false });
    expect(Exit.isFailure(piped)).toBe(true);
    expect(JSON.stringify(piped)).toContain("stdout is not an interactive terminal");
    expect(JSON.stringify(piped)).not.toContain("plaintext-value");

    const headless = await showOne({ stdinIsTerminal: false, stdoutIsTerminal: true });
    expect(Exit.isFailure(headless)).toBe(true);
    expect(JSON.stringify(headless)).toContain("stdin is not an interactive terminal");

    // The most common shape in CI / non-interactive shells = both non-terminal (pins all 3 branches)
    const detached = await showOne({ stdinIsTerminal: false, stdoutIsTerminal: false });
    expect(Exit.isFailure(detached)).toBe(true);
    expect(JSON.stringify(detached)).toContain(
      "neither stdin nor stdout is an interactive terminal",
    );
    expect(JSON.stringify(detached)).not.toContain("plaintext-value");

    const agent = await showOne({
      agent: { isAgent: true, name: "claude" },
      stdinIsTerminal: true,
      stdoutIsTerminal: true,
    });
    expect(Exit.isFailure(agent)).toBe(true);
    expect(JSON.stringify(agent)).toContain("AI agent environment was detected");
  });

  it("displays on a human interactive terminal (positive control that the checks are not vacuous)", async () => {
    const allowed = await showOne({ stdinIsTerminal: true, stdoutIsTerminal: true });
    expect(Exit.isSuccess(allowed)).toBe(true);
  });

  it("cannot forge a `NAME=value` line via a newline in the value", async () => {
    // Values can be written by co-editors. Streaming a newline verbatim would let
    // them fabricate a line for a nonexistent variable on screen (deceiving a user who copies from pull --show)
    const logs: string[] = [];
    const capturingIo = Layer.succeed(CliIo, {
      log: (line: string) => {
        logs.push(line);
        return Effect.void;
      },
      logError: () => Effect.void,
      readStdin: Effect.succeed(new Uint8Array(0)),
      promptLine: () => Effect.succeed(""),
      envVar: () => undefined,
      agentProfile: () => ({ isAgent: false }),
      stderrIsTerminal: () => true,
      colorEnabled: () => false,
      openBrowser: () => Effect.succeed(false),
    });
    const exit = await Effect.runPromiseExit(
      showValues([variable("SECRET", "x\nDATABASE_URL=postgres://attacker/")]).pipe(
        Effect.provide(
          Layer.mergeAll(
            capturingIo,
            Layer.succeed(AgentProfileRef, { isAgent: false }),
            Stdio.layerTest({
              stdinIsTerminal: Effect.succeed(true),
              stdoutIsTerminal: Effect.succeed(true),
            }),
          ),
        ),
      ),
    );
    expect(Exit.isSuccess(exit)).toBe(true);
    // A forged line never appears in `NAME=value` form (it carries a marker)
    expect(logs).not.toContain("DATABASE_URL=postgres://attacker/");
    expect(logs).toContain("| DATABASE_URL=postgres://attacker/");
  });

  it("a trailing newline does not add to the line count; it is only reported as present", async () => {
    // "a\nb\n" is 2 lines + a trailing newline. A naive split would fabricate an
    // empty third line and shift the reported count by one (the trailing newline is part of the value, so it is not dropped either)
    const logs: string[] = [];
    const capturingIo = Layer.succeed(CliIo, {
      log: (line: string) => {
        logs.push(line);
        return Effect.void;
      },
      logError: () => Effect.void,
      readStdin: Effect.succeed(new Uint8Array(0)),
      promptLine: () => Effect.succeed(""),
      envVar: () => undefined,
      agentProfile: () => ({ isAgent: false }),
      stderrIsTerminal: () => true,
      colorEnabled: () => false,
      openBrowser: () => Effect.succeed(false),
    });
    const exit = await Effect.runPromiseExit(
      showValues([variable("SECRET", "a\nb\n")]).pipe(
        Effect.provide(
          Layer.mergeAll(
            capturingIo,
            Layer.succeed(AgentProfileRef, { isAgent: false }),
            Stdio.layerTest({
              stdinIsTerminal: Effect.succeed(true),
              stdoutIsTerminal: Effect.succeed(true),
            }),
          ),
        ),
      ),
    );
    expect(Exit.isSuccess(exit)).toBe(true);
    expect(logs[0]).toContain("2-line value with a trailing newline");
    expect(logs).toEqual([logs[0], "| a", "| b"]);
  });

  it("neutralizes order-breaking characters even in displayed values (same treatment as the name side)", async () => {
    // Values are written by co-editors, so a malicious value could fake another
    // member's terminal display. Killing ANSI alone leaves bidi overrides and
    // zero-width chars — pin that the same list as the name side (displayText) neutralizes them (never add coverage to only one side)
    const logs: string[] = [];
    const errors: string[] = [];
    const capturingIo = Layer.succeed(CliIo, {
      log: (line: string) => {
        logs.push(line);
        return Effect.void;
      },
      logError: (line: string) => {
        errors.push(line);
        return Effect.void;
      },
      readStdin: Effect.succeed(new Uint8Array(0)),
      promptLine: () => Effect.succeed(""),
      envVar: () => undefined,
      agentProfile: () => ({ isAgent: false }),
      stderrIsTerminal: () => true,
      colorEnabled: () => false,
      openBrowser: () => Effect.succeed(false),
    });
    const exit = await Effect.runPromiseExit(
      showValues([variable("SECRET", "a\u202Eb\u200Bc\u2028d\u200Ce\nf")]).pipe(
        Effect.provide(
          Layer.mergeAll(
            capturingIo,
            Layer.succeed(AgentProfileRef, { isAgent: false }),
            Stdio.layerTest({
              stdinIsTerminal: Effect.succeed(true),
              stdoutIsTerminal: Effect.succeed(true),
            }),
          ),
        ),
      ),
    );
    expect(Exit.isSuccess(exit)).toBe(true);
    // ZWNJ (needed for some scripts) and newlines (legitimate values like PEMs)
    // are kept. A value containing newlines is printed with a marker on the second line onward (so the value side cannot forge a `NAME=value` line)
    expect(logs).toEqual([
      'SECRET= (a 2-line value; the leading "| " on each line below is a marker added by maruhi)',
      "| a\uFFFDb\uFFFDc\uFFFDd\u200Ce",
      "| f",
    ]);
    // Neutralization is not silent: name that the display differs from the actual
    // value (without putting the value itself in the warning)
    expect(errors.join("\n")).toContain("SECRET");
    expect(errors.join("\n")).toContain("do not match the actual values");
  });
});

describe("decodeValueText (unified value-decoding policy)", () => {
  it("returns valid UTF-8 as-is (including newlines / tabs) and null for invalid UTF-8", () => {
    expect(decodeValueText(new TextEncoder().encode("multi\nline\tvalue"))).toBe(
      "multi\nline\tvalue",
    );
    // The fatal policy shared by --show / run: no substitution-character camouflage — the caller raises an explicit error
    expect(decodeValueText(new Uint8Array([0xff, 0xfe]))).toBeNull();
  });
});
