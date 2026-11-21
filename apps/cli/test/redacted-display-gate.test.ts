import { Effect, Exit, Layer, Redacted, Stdio } from "effect";
import { describe, expect, it } from "vite-plus/test";

import { AgentProfileRef } from "../src/agent-gate.ts";
import { type DisplayableVariable, showValues } from "../src/display.ts";
import { CliIo } from "../src/io.ts";

function wipedVariable(): DisplayableVariable {
  const value = Redacted.make(new TextEncoder().encode("plaintext-value"), {
    label: "variable-value",
  });
  Redacted.wipeUnsafe(value);
  return { name: "SECRET", version: 1, epoch: 1, value };
}

describe("unwrapping decrypted values sits behind the display gate", () => {
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

  const showWiped = (input: {
    readonly isAgent: boolean;
    readonly stdinIsTerminal: boolean;
    readonly stdoutIsTerminal: boolean;
  }) =>
    Effect.runPromiseExit(
      showValues([wipedVariable()]).pipe(
        Effect.provide(
          Layer.mergeAll(
            silentIo,
            Layer.succeed(AgentProfileRef, { isAgent: input.isAgent }),
            Stdio.layerTest({
              stdinIsTerminal: Effect.succeed(input.stdinIsTerminal),
              stdoutIsTerminal: Effect.succeed(input.stdoutIsTerminal),
            }),
          ),
        ),
      ),
    );

  it("on non-TTY / a known agent it fails with a typed error before unwrapping", async () => {
    for (const rejected of [
      { isAgent: false, stdinIsTerminal: true, stdoutIsTerminal: false },
      { isAgent: false, stdinIsTerminal: false, stdoutIsTerminal: true },
      { isAgent: true, stdinIsTerminal: true, stdoutIsTerminal: true },
    ]) {
      const exit = await showWiped(rejected);
      expect(Exit.isFailure(exit)).toBe(true);
      const dump = JSON.stringify(exit);
      expect(dump).toContain('"_tag":"Fail"');
      expect(dump).not.toContain('"_tag":"Die"');
      expect(dump).not.toContain("plaintext-value");
    }
  });

  it("only a human's interactive terminal reaches the unwrap (the positive control — the gate is not swinging at air)", async () => {
    const exit = await showWiped({
      isAgent: false,
      stdinIsTerminal: true,
      stdoutIsTerminal: true,
    });
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain('"_tag":"Die"');
  });
});
