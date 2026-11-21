import { Clock, Duration, Effect, Layer } from "effect";
import { TestClock } from "effect/testing";

import type { CliServices } from "../../src/cli.ts";
import { runCli } from "../../src/cli.ts";

interface ClockedLayer {
  readonly layer: Layer.Layer<CliServices>;
  readonly now: () => number;
}

const REAL_WAIT_BOUND_MS = 10_000;

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

export async function runCliWithClock(
  argv: readonly string[],
  envLayer: Layer.Layer<CliServices>,
  options?: { readonly at?: number },
): Promise<number> {
  const { layer } = await withVirtualClock(envLayer, options);
  return runCli(argv, layer);
}

export interface TestClockedLayer {
  readonly layer: Layer.Layer<CliServices>;
  readonly testClock: TestClock.TestClock;
}

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

export async function advanceUntilSettled(
  testClock: TestClock.TestClock,
  run: Promise<number>,
  options?: {
    readonly stepMs?: number;
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
