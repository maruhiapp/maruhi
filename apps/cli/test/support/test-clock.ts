// Driving the CLI's Effect Clock with `TestClock` in integration tests.
//
// `runCli` provides its service layer once at the run's root
// (cli-runner.ts), so a `Layer.succeed(Clock.Clock, testClock)` merged
// into the test env's layer overrides the clock for the whole command
// tree — `Clock.currentTimeMillis` and every `Effect.sleep` resolve
// against it. The run itself is a plain `Promise` (cli.ts), so the
// test advances the clock from outside: the driver loop adjusts the
// clock and yields real event-loop turns for the mock server's I/O,
// until the run's promise settles.
//
// The clock is anchored at wall time (`at` defaults to `Date.now()`),
// so fixtures that build deadlines from `Date.now()` (FAR_FUTURE_MS
// etc.) stay consistent.

import { Clock, Duration, Effect, Layer } from "effect";
import { TestClock } from "effect/testing";

import type { CliServices } from "../../src/cli.ts";
import { runCli } from "../../src/cli.ts";

/** A `runCli` layer with a `TestClock` in place of the live clock. */
export interface ClockedLayer {
  readonly layer: Layer.Layer<CliServices>;
  readonly testClock: TestClock.TestClock;
}

/**
 * Injects a fresh `TestClock` (started at `at`, default wall-now) into
 * the env layer. The returned `testClock` is shared with the run, so the
 * test can `setTime` / `adjust` it while the run is pending.
 */
export async function withTestClock(
  envLayer: Layer.Layer<CliServices>,
  options?: { readonly at?: number | undefined },
): Promise<ClockedLayer> {
  const testClock = await Effect.runPromise(Effect.scoped(TestClock.make()));
  await Effect.runPromise(testClock.setTime(options?.at ?? Date.now()));
  return {
    testClock,
    layer: Layer.mergeAll(envLayer, Layer.succeed(Clock.Clock, testClock)),
  };
}

/**
 * Advances the test clock in `stepMs` steps until `run` settles, yielding
 * a real event-loop turn per step so the pending run's I/O (the mock
 * server, keychain writes, …) progresses between advances. Sleeps
 * registered after a step are caught by the next one, so the driver
 * needs no signal that a sleep exists.
 */
export async function advanceUntilSettled(
  testClock: TestClock.TestClock,
  run: Promise<number>,
  options?: {
    readonly stepMs?: number;
    /** Bounds test-time spent before giving up (iterations × stepMs). */
    readonly maxIterations?: number;
  },
): Promise<number> {
  const stepMs = options?.stepMs ?? 3_000;
  const maxIterations = options?.maxIterations ?? 1_000;
  const settled: { code: number | undefined } = { code: undefined };
  const tracked = run.then(
    (code) => {
      settled.code = code;
      return code;
    },
    (error: unknown) => {
      throw error;
    },
  );
  for (let i = 0; i < maxIterations && settled.code === undefined; i++) {
    await Effect.runPromise(testClock.adjust(Duration.millis(stepMs)));
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  if (settled.code === undefined) {
    throw new Error(`run did not settle within ${maxIterations} clock steps of ${stepMs}ms`);
  }
  return tracked;
}

/**
 * `runCli` under a `TestClock` with an auto-advancing driver: every poll
 * interval the program waits is fast-forwarded until the run settles.
 * Use for commands whose whole wait should elapse instantly in test-time.
 */
export async function runCliWithClock(
  argv: readonly string[],
  envLayer: Layer.Layer<CliServices>,
  options?: Parameters<typeof advanceUntilSettled>[2] & {
    readonly at?: number;
  },
): Promise<number> {
  const { layer, testClock } = await withTestClock(envLayer, { at: options?.at });
  return advanceUntilSettled(testClock, runCli(argv, layer), options);
}

/**
 * Real-time wait for a side-effect to appear (an emitted line, a keychain
 * write). This waits on program output, not on clock semantics, so it is
 * a bounded real poll — the wait the program itself is in is what
 * `TestClock` fast-forwards.
 */
export async function waitFor<T>(
  probe: () => T | undefined,
  options?: { readonly timeoutMs?: number; readonly stepMs?: number },
): Promise<T> {
  const timeoutMs = options?.timeoutMs ?? 10_000;
  const stepMs = options?.stepMs ?? 10;
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const found = probe();
    if (found !== undefined) {
      return found;
    }
    if (Date.now() >= deadline) {
      throw new Error("waitFor: condition was not met before the timeout");
    }
    await new Promise((resolve) => setTimeout(resolve, stepMs));
  }
}
