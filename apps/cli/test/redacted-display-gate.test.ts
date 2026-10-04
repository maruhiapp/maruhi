// The regression that secret material is wrapped in `Redacted` (the 4th layer after ADR-0016's display gate).
//
// Following display.ts (terminal neutralization), failure.ts (error mapping),
// and "internal errors get only the type name", this 4th layer: tokens can
// never yield their raw value without unwrapping `Redacted` at the type level.
//
// The threefold list of what these tests pin is split across
// redacted-output.test.ts (#1), redacted-keychain.test.ts (#2), and
// redacted.test.ts (#3); this file holds section 2b.

import { Effect, Exit, Layer, Redacted, Stdio } from "effect";
import { describe, expect, it } from "vitest";

import { AgentProfileRef } from "../src/agent-gate.ts";
import { type DisplayableVariable, showValues } from "../src/display.ts";
import { CliIo } from "../src/io.ts";

// ---------------------------------------------------------------------------
// 2b. Decrypted values are unwrapped only "behind" the display gate
// ---------------------------------------------------------------------------

/**
 * Makes one variable whose unwrap is **observable**.
 *
 * After `Redacted.wipeUnsafe`, `Redacted.value` throws a defect (the upstream
 * spec). That lets the test tell from outside "was it unwrapped": refused at
 * the gate fails as a typed error (CliError); past the gate it fails as a
 * defect. Used only inside the test — as handle invalidation, not zeroing
 * (production code never uses wipeUnsafe, so it never builds a defect path).
 */
function wipedVariable(): DisplayableVariable {
  const value = Redacted.make(new TextEncoder().encode("plaintext-value"), {
    label: "variable-value",
  });
  Redacted.wipeUnsafe(value);
  return { name: "SECRET", version: 1, epoch: 1, value };
}

describe("unwrapping decrypted values sits behind the display gate", () => {
  /** A CliIo that discards output (here we only check "it never reached display"). */
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
    // Unwrapped, it would defect (Unable to get redacted value). Failing as a
    // CliError instead = the decision settled before the gate
    for (const rejected of [
      { isAgent: false, stdinIsTerminal: true, stdoutIsTerminal: false },
      { isAgent: false, stdinIsTerminal: false, stdoutIsTerminal: true },
      { isAgent: true, stdinIsTerminal: true, stdoutIsTerminal: true },
    ]) {
      const exit = await showWiped(rejected);
      expect(Exit.isFailure(exit)).toBe(true);
      const dump = JSON.stringify(exit);
      // Failing as a typed error (Fail) = it settled at the gate. Had the
      // unwrap been reached, the wiped handle would throw a defect (Die) and this would change
      expect(dump).toContain('"_tag":"Fail"');
      expect(dump).not.toContain('"_tag":"Die"');
      expect(dump).not.toContain("plaintext-value");
    }
  });

  it("only a human's interactive terminal reaches the unwrap (the positive control — the gate is not swinging at air)", async () => {
    // With the same input through the gate, it now reaches the unwrap and
    // defects. Without this, the test above would also pass on an implementation that never unwraps at all
    const exit = await showWiped({
      isAgent: false,
      stdinIsTerminal: true,
      stdoutIsTerminal: true,
    });
    expect(Exit.isFailure(exit)).toBe(true);
    // Evidence the unwrap on the wiped handle was reached (defect = Die)
    expect(JSON.stringify(exit)).toContain('"_tag":"Die"');
  });
});
