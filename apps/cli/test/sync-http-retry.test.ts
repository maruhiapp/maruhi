// Tests for the retry policy of the sync http send (sync-http-send.ts):
// the schedule's waits, the attempt count, the Retry-After cap, and both
// Retry-After forms (seconds and HTTP-date). Time is driven by TestClock,
// so no real time passes.

import { Cause, Clock, Duration, Effect, Exit, Fiber, Layer, Redacted } from "effect";
import { HttpClient, HttpClientError, HttpClientRequest, HttpClientResponse } from "effect/http";
import { TestClock } from "effect/testing";
import { describe, expect, it } from "vitest";

import type { CliError } from "../src/errors.ts";
import { HTTP_PRESETS } from "../src/sync.package/sync-http-presets.ts";
import { send } from "../src/sync.package/sync-http-send.ts";
import type {
  HttpOutcome,
  HttpRetryPolicy,
  HttpTargetInput,
} from "../src/sync.package/sync-http.ts";

type Step =
  | { readonly status: number; readonly retryAfter?: string }
  | { readonly transport: string };

const DEFAULT_RETRY: HttpRetryPolicy = {
  attempts: 3,
  baseDelay: Duration.millis(100),
  maxDelay: Duration.seconds(30),
};

/**
 * Runs `send` against a scripted client under TestClock and returns the
 * exit plus the timestamps of every request the client saw.
 */
async function run(
  script: readonly Step[],
  retry: HttpRetryPolicy = DEFAULT_RETRY,
  now = 0,
): Promise<{ readonly exit: Exit.Exit<HttpOutcome, CliError>; readonly calls: number[] }> {
  const calls: number[] = [];
  let next = 0;
  const client = HttpClient.make((request) =>
    Effect.flatMap(Clock.currentTimeMillis, (at) => {
      calls.push(at);
      const step = script[next];
      next += 1;
      if (step === undefined) {
        return Effect.die(new Error("the scripted responses ran out"));
      }
      if ("transport" in step) {
        return Effect.fail(
          new HttpClientError.HttpClientError({
            reason: new HttpClientError.TransportError({
              request,
              description: step.transport,
            }),
          }),
        );
      }
      return Effect.succeed(
        HttpClientResponse.fromWeb(
          request,
          new Response("{}", {
            status: step.status,
            headers: step.retryAfter === undefined ? {} : { "retry-after": step.retryAfter },
          }),
        ),
      );
    }),
  );
  const input: HttpTargetInput = {
    preset: HTTP_PRESETS.vercel,
    options: {},
    token: Redacted.make("vercel-token-test"),
    retry,
  };
  const exit = await Effect.runPromise(
    Effect.gen(function* () {
      yield* TestClock.setTime(now);
      const fiber = yield* Effect.forkChild(
        Effect.exit(send(input, HttpClientRequest.get("https://api.vercel.com/test"))),
      );
      yield* TestClock.adjust(Duration.days(1));
      return yield* Fiber.join(fiber);
    }).pipe(
      Effect.provide(
        Layer.mergeAll(TestClock.layer(), Layer.succeed(HttpClient.HttpClient, client)),
      ),
    ),
  );
  return { exit, calls };
}

function messageOf(exit: Exit.Exit<HttpOutcome, CliError>): string {
  if (!Exit.isFailure(exit)) {
    throw new Error("expected a failure exit");
  }
  const squashed: unknown = Cause.squash(exit.cause);
  return squashed instanceof Error ? squashed.message : String(squashed);
}

describe("sync http send retry policy", () => {
  it("waits out the doubling backoff between attempts and fails with the last response", async () => {
    const { exit, calls } = await run([{ status: 503 }, { status: 503 }, { status: 503 }]);
    expect(calls).toEqual([0, 100, 300]);
    expect(messageOf(exit)).toBe(
      "the Vercel API answered 503 (3 attempts). Check the network and retry",
    );
  });

  it("returns the response when a retry succeeds", async () => {
    const { exit, calls } = await run([{ status: 429 }, { status: 200 }]);
    expect(calls).toEqual([0, 100]);
    if (!Exit.isSuccess(exit)) {
      throw new Error("expected a success exit");
    }
    expect(exit.value.status).toBe(200);
  });

  it("sends nothing and reports an exhausted policy when attempts is zero", async () => {
    const { exit, calls } = await run([], { ...DEFAULT_RETRY, attempts: 0 });
    expect(calls).toEqual([]);
    expect(messageOf(exit)).toBe(" (0 attempts). Check the network and retry");
  });

  it("runs exactly one request when attempts is one", async () => {
    const { exit, calls } = await run([{ status: 503 }], { ...DEFAULT_RETRY, attempts: 1 });
    expect(calls).toEqual([0]);
    expect(messageOf(exit)).toBe(
      "the Vercel API answered 503 (1 attempts). Check the network and retry",
    );
  });

  it("honors Retry-After seconds over the backoff", async () => {
    const { exit, calls } = await run([
      { status: 429, retryAfter: "2" },
      { status: 503, retryAfter: "5" },
      { status: 503 },
    ]);
    expect(calls).toEqual([0, 2000, 7000]);
    expect(messageOf(exit)).toBe(
      "the Vercel API answered 503 (3 attempts). Check the network and retry",
    );
  });

  it("honors an HTTP-date Retry-After read from the clock", async () => {
    const t0 = Date.parse("2026-10-05T00:00:00Z");
    const retryAfter = new Date(t0 + 8_000).toUTCString();
    const { exit, calls } = await run(
      [{ status: 503, retryAfter }, { status: 503 }],
      { ...DEFAULT_RETRY, attempts: 2 },
      t0,
    );
    expect(calls).toEqual([t0, t0 + 8_000]);
    expect(messageOf(exit)).toBe(
      "the Vercel API answered 503 (2 attempts). Check the network and retry",
    );
  });

  it("fails instead of waiting when Retry-After asks for longer than the cap", async () => {
    const { exit, calls } = await run([{ status: 429, retryAfter: "60" }]);
    expect(calls).toEqual([0]);
    expect(messageOf(exit)).toBe(
      "the Vercel API asked to retry after 60 seconds (Retry-After), longer than maruhi waits. Run `maruhi sync apply` again later",
    );
  });

  it("does not apply the cap to the last attempt", async () => {
    const { exit, calls } = await run([{ status: 503 }, { status: 429, retryAfter: "60" }], {
      ...DEFAULT_RETRY,
      attempts: 2,
    });
    expect(calls).toEqual([0, 100]);
    expect(messageOf(exit)).toBe(
      "the Vercel API answered 429 (2 attempts). Check the network and retry",
    );
  });

  it("fails instead of waiting when the backoff itself exceeds the cap", async () => {
    const { exit, calls } = await run([{ status: 503 }], {
      ...DEFAULT_RETRY,
      baseDelay: Duration.seconds(40),
    });
    expect(calls).toEqual([0]);
    expect(messageOf(exit)).toBe(
      "the Vercel API asked to retry after 40 seconds (Retry-After), longer than maruhi waits. Run `maruhi sync apply` again later",
    );
  });

  it("retries transport failures on the same schedule", async () => {
    const { exit, calls } = await run([{ transport: "boom" }, { transport: "boom" }], {
      ...DEFAULT_RETRY,
      attempts: 2,
    });
    expect(calls).toEqual([0, 100]);
    expect(messageOf(exit)).toBe(
      "Could not reach the vendor API (HttpClientError) (2 attempts). Check the network and retry",
    );
  });
});
