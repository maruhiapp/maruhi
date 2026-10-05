// Driving the CLI's Effect Clock in integration tests.
//
// `runCli` provides its service layer once at the run's root
// (cli-runner.ts), so a `Layer.succeed(Clock.Clock, …)` merged into the
// test env's layer overrides the clock for the whole command tree —
// `Clock.currentTimeMillis` and every `Effect.sleep` (which delegates to
// `Clock.sleep`) resolve against it.
//
// Two clocks, two needs:
//
// - `withVirtualClock` (used by `runCliWithClock`) makes test time move
//   ONLY when the program actually waits: `sleep(d)` advances `now` by d
//   and yields one fiber turn. No driver loop — real I/O (the mock
//   server, keychain writes) can never consume test time, so how slow a
//   runner is cannot change the outcome.
// - `withTestClock` + `advanceUntilSettled` is for tests that must act
//   between the wait's rounds (place a registry row mid-wait): the test
//   waits on program output first, then pushes the clock.
//
// Clocks are anchored at wall time (`at` defaults to `Date.now()`), so
// fixtures that build deadlines from `Date.now()` (FAR_FUTURE_MS etc.)
// stay consistent.

import { Clock, Duration, Effect, Layer } from "effect";
import { TestClock } from "effect/testing";

import type { CliServices } from "../../src/cli.ts";
import { runCli } from "../../src/cli.ts";

/** A `runCli` layer with a virtual clock in place of the live clock. */
interface ClockedLayer {
  readonly layer: Layer.Layer<CliServices>;
  /** Reads the clock's current test time. */
  readonly now: () => number;
}

/**
 * The waits/bounds split: a program wait shorter than this is virtual —
 * it resolves instantly and `now` advances by the full duration; a wait
 * of 10 s or more sleeps in real time (the client's 30 s request
 * timeout — a bound on real work that must never be virtualized into
 * cancelling in-flight I/O). A future test whose program waits 10 s or
 * more per round therefore knowingly costs real time; keep poll
 * intervals under this bound.
 */
const REAL_WAIT_BOUND_MS = 10_000;

/**
 * A `Clock` (used by `runCliWithClock`) whose wall time advances
 * exactly by the waits the program asks for (`sleep(d)` does `now += d`
 * for waits below {@link REAL_WAIT_BOUND_MS}). Time therefore moves
 * only on the program's own poll intervals — never while it is doing
 * real I/O — and bounds on that I/O keep their real duration.
 */
async function withVirtualClock(
  envLayer: Layer.Layer<CliServices>,
  options?: { readonly at?: number | undefined },
): Promise<ClockedLayer> {
  let now = options?.at ?? Date.now();
  let monotonicNanos = BigInt(0);
  const clock: Clock.Clock = {
    currentTimeMillisUnsafe: () => now,
    currentTimeMillis: Effect.sync(() => now),
    currentTimeNanosUnsafe: () => BigInt(Math.round(now)) * 1_000_000n,
    currentTimeNanos: Effect.sync(() => BigInt(Math.round(now)) * 1_000_000n),
    monotonicTimeNanosUnsafe: () => monotonicNanos,
    monotonicTimeNanos: Effect.sync(() => monotonicNanos),
    sleep: (duration) =>
      Effect.suspend(() => {
        const millis = Duration.toMillis(duration);
        if (!Number.isFinite(millis)) {
          // An unbounded wait stays a wait
          return Effect.never;
        }
        if (millis >= REAL_WAIT_BOUND_MS) {
          return Effect.callback<void>((resume) => {
            const timer = setTimeout(() => resume(Effect.void), millis);
            return Effect.sync(() => clearTimeout(timer));
          });
        }
        now += millis;
        monotonicNanos += BigInt(Math.round(millis)) * 1_000_000n;
        return Effect.yieldNow;
      }),
  };
  return {
    now: () => now,
    layer: Layer.mergeAll(envLayer, Layer.succeed(Clock.Clock, clock)),
  };
}

/**
 * `runCli` under the virtual clock: every interval the program waits
 * elapses instantly and deterministically. Use for commands whose whole
 * wait should pass in test-time — there is no driver loop, so the run's
 * real I/O finishes at whatever speed the runner gives it.
 */
export async function runCliWithClock(
  argv: readonly string[],
  envLayer: Layer.Layer<CliServices>,
  options?: { readonly at?: number },
): Promise<number> {
  const { layer } = await withVirtualClock(envLayer, options);
  return runCli(argv, layer);
}

/** A `runCli` layer with a `TestClock` in place of the live clock. */
export interface TestClockedLayer {
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
): Promise<TestClockedLayer> {
  const testClock = await Effect.runPromise(Effect.scoped(TestClock.make()));
  await Effect.runPromise(testClock.setTime(options?.at ?? Date.now()));
  return {
    testClock,
    layer: Layer.mergeAll(envLayer, Layer.succeed(Clock.Clock, testClock)),
  };
}

/**
 * Advances the test clock in `stepMs` steps until `run` settles (on
 * either outcome), yielding a real event-loop turn per step so the
 * pending run's I/O (the mock server, keychain writes, …) progresses
 * between advances. Sleeps registered after a step are caught by the
 * next one, so the driver needs no signal that a sleep exists. Use it
 * only once the run is already parked in its wait — the steps move test
 * time whether or not the program is sleeping.
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
  const settled: { outcome: "done" | "failed" | undefined } = { outcome: undefined };
  const tracked = run.then(
    (code) => {
      settled.outcome = "done";
      return code;
    },
    (error: unknown) => {
      settled.outcome = "failed";
      throw error;
    },
  );
  for (let i = 0; i < maxIterations && settled.outcome === undefined; i++) {
    await Effect.runPromise(testClock.adjust(Duration.millis(stepMs)));
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  if (settled.outcome === undefined) {
    throw new Error(`run did not settle within ${maxIterations} clock steps of ${stepMs}ms`);
  }
  return tracked;
}

/**
 * Real-time wait for a side-effect to appear (an emitted line, a keychain
 * write). This waits on program output, not on clock semantics, so it is
 * a bounded real poll — the wait the program itself is in is what the
 * test clocks fast-forward.
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
