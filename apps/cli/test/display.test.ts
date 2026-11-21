import { Effect, Exit, Layer, Stdio } from "effect";
import { describe, expect, it } from "vite-plus/test";

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
    expect(formatUtcSeconds(Date.UTC(9999, 11, 31, 23, 59, 59))).toBe("9999-12-31 23:59:59 UTC");
    for (const bad of [
      253_402_300_800_000,
      -62_167_219_200_001,
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
    const piped = await showOne({ stdinIsTerminal: true, stdoutIsTerminal: false });
    expect(Exit.isFailure(piped)).toBe(true);
    expect(JSON.stringify(piped)).toContain("stdout is not an interactive terminal");
    expect(JSON.stringify(piped)).not.toContain("plaintext-value");

    const headless = await showOne({ stdinIsTerminal: false, stdoutIsTerminal: true });
    expect(Exit.isFailure(headless)).toBe(true);
    expect(JSON.stringify(headless)).toContain("stdin is not an interactive terminal");

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
    expect(logs).not.toContain("DATABASE_URL=postgres://attacker/");
    expect(logs).toContain("| DATABASE_URL=postgres://attacker/");
  });

  it("a trailing newline does not add to the line count; it is only reported as present", async () => {
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
    expect(logs).toEqual([
      'SECRET= (a 2-line value; the leading "| " on each line below is a marker added by maruhi)',
      "| a\uFFFDb\uFFFDc\uFFFDd\u200Ce",
      "| f",
    ]);
    expect(errors.join("\n")).toContain("SECRET");
    expect(errors.join("\n")).toContain("do not match the actual values");
  });
});

describe("decodeValueText (unified value-decoding policy)", () => {
  it("returns valid UTF-8 as-is (including newlines / tabs) and null for invalid UTF-8", () => {
    expect(decodeValueText(new TextEncoder().encode("multi\nline\tvalue"))).toBe(
      "multi\nline\tvalue",
    );
    expect(decodeValueText(new Uint8Array([0xff, 0xfe]))).toBeNull();
  });
});
