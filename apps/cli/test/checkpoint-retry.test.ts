// Tests for the AuditHeadNotReady (503) retry of fetchAuditHead
// (checkpoint.ts): the exponential-backoff waits between attempts, the
// unchanged 10-attempt budget, and the exhaustion message. Time is
// driven by TestClock — no real time passes.

import { AuditHeadNotReadyError } from "@maruhi/api-schema";
import { Cause, Clock, Duration, Effect, Exit, Fiber, Layer } from "effect";
import { TestClock } from "effect/testing";
import { describe, expect, it } from "vitest";

import type { MaruhiClient } from "../src/api.ts";
import { fetchAuditHead } from "../src/checkpoint.ts";
import type { CliError } from "../src/errors.ts";
import { CliIo } from "../src/io.ts";

type Step = "ready" | "not-ready";

const READY_HASH = "cd".repeat(32);

/**
 * Runs fetchAuditHead against a scripted client under TestClock and
 * returns the exit, the timestamp of every auditHead call, and the
 * retry lines logged between attempts.
 */
async function run(script: readonly Step[]): Promise<{
  readonly exit: Exit.Exit<string, CliError>;
  readonly calls: number[];
  readonly lines: string[];
}> {
  const calls: number[] = [];
  const lines: string[] = [];
  let next = 0;
  const client = {
    audit: {
      auditHead: () =>
        Effect.flatMap(Clock.currentTimeMillis, (at) => {
          calls.push(at);
          const step = script[next];
          next += 1;
          if (step === undefined) {
            return Effect.die(new Error("the scripted responses ran out"));
          }
          return step === "ready"
            ? Effect.succeed({ auditHeadHashHex: READY_HASH })
            : Effect.fail(new AuditHeadNotReadyError());
        }),
    },
  } as unknown as MaruhiClient;
  const io = Layer.succeed(CliIo, {
    log: (line) =>
      Effect.sync(() => {
        lines.push(line);
      }),
    logError: () => Effect.void,
    readStdin: Effect.succeed(new Uint8Array()),
    promptLine: () => Effect.die(new Error("promptLine unused")),
    envVar: () => undefined,
    agentProfile: () => ({ isAgent: false }),
    stderrIsTerminal: () => false,
    colorEnabled: () => false,
    openBrowser: () => Effect.succeed(false),
  });
  const exit = await Effect.runPromise(
    Effect.gen(function* () {
      const fiber = yield* Effect.forkChild(Effect.exit(fetchAuditHead(client, "proj-1")));
      yield* TestClock.adjust(Duration.seconds(30));
      return yield* Fiber.join(fiber);
    }).pipe(Effect.provide(Layer.mergeAll(TestClock.layer(), io))),
  );
  return { exit, calls, lines };
}

function messageOf(exit: Exit.Exit<string, CliError>): string {
  if (!Exit.isFailure(exit)) {
    throw new Error("expected a failure exit");
  }
  const squashed: unknown = Cause.squash(exit.cause);
  return squashed instanceof Error ? squashed.message : String(squashed);
}

describe("fetchAuditHead AuditHeadNotReady retry", () => {
  it("waits an exponential backoff between attempts and stops at the 10-attempt budget with the exhaustion guidance", async () => {
    const { exit, calls, lines } = await run(Array.from({ length: 10 }, () => "not-ready"));
    // Waits of 5, 10, 20, ..., 1280 ms between calls (total ~2.5 s over
    // the whole budget — the acceptance path's retry shares the same base)
    expect(calls).toEqual([0, 5, 15, 35, 75, 155, 315, 635, 1275, 2555]);
    expect(lines).toEqual(
      Array.from(
        { length: 9 },
        (_, i) =>
          `The server is materializing the audit-head hash column — retrying (attempt ${i + 2} of 10)`,
      ),
    );
    expect(messageOf(exit)).toBe(
      "The server is still materializing the audit-head hash column after 10 attempts (this happens once, on the first audit-head access of a project with a very large existing audit log). Progress is saved server-side and every attempt advances it — re-run the command to continue where it left off",
    );
  });

  it("returns the attestation once a retry succeeds", async () => {
    const { exit, calls, lines } = await run(["not-ready", "not-ready", "ready"]);
    expect(calls).toEqual([0, 5, 15]);
    expect(lines).toEqual([
      "The server is materializing the audit-head hash column — retrying (attempt 2 of 10)",
      "The server is materializing the audit-head hash column — retrying (attempt 3 of 10)",
    ]);
    if (!Exit.isSuccess(exit)) {
      throw new Error("expected a success exit");
    }
    expect(exit.value).toBe(READY_HASH);
  });
});
