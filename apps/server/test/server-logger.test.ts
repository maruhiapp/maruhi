// The server logger (server-logger.ts): Effect log calls reach the console
// exactly as the plain console.warn / console.error lines they replace —
// WARN on console.warn, ERROR / FATAL on console.error, the message parts as
// the console arguments, and nothing else (no date / level / fiber prefix,
// no annotations, no spans, no Cause). INFO and below are dropped.

import { Cause, Effect } from "effect";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CAUSE_ONLY_LINE, ServerLoggerLive } from "../src/server-logger.ts";

const CONSOLE_METHODS = ["log", "info", "warn", "error", "debug"] as const;
type ConsoleMethod = (typeof CONSOLE_METHODS)[number];

/** Spies on every console method; the returned function reads each method's recorded calls. */
function spyConsole(): () => Record<ConsoleMethod, unknown[][]> {
  const spies = CONSOLE_METHODS.map(
    (method) => [method, vi.spyOn(console, method).mockImplementation(() => {})] as const,
  );
  return () =>
    Object.fromEntries(spies.map(([method, spy]) => [method, spy.mock.calls])) as Record<
      ConsoleMethod,
      unknown[][]
    >;
}

const run = (program: Effect.Effect<void>): Promise<void> =>
  Effect.runPromise(program.pipe(Effect.provide(ServerLoggerLive)));

describe("server logger (server-logger.ts)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("writes a WARN to console.warn with exactly the message", async () => {
    const collect = spyConsole();
    await run(Effect.logWarning("static warning line"));
    expect(collect().warn).toEqual([["static warning line"]]);
    expect(collect().error).toEqual([]);
    expect(collect().log).toEqual([]);
    expect(collect().info).toEqual([]);
    expect(collect().debug).toEqual([]);
  });

  it("writes an ERROR and a FATAL to console.error with exactly the message", async () => {
    const collect = spyConsole();
    await run(
      Effect.logError("static error line").pipe(Effect.andThen(Effect.logFatal("fatal line"))),
    );
    expect(collect().error).toEqual([["static error line"], ["fatal line"]]);
    expect(collect().warn).toEqual([]);
    expect(collect().log).toEqual([]);
  });

  it("passes several message parts as the console arguments, in order", async () => {
    const collect = spyConsole();
    const detail = { count: 3 };
    await run(Effect.logWarning("text", "TypeError", detail));
    // The same arguments console.warn("text", "TypeError", detail) received
    expect(collect().warn).toEqual([["text", "TypeError", detail]]);
  });

  it("drops INFO, DEBUG and TRACE", async () => {
    const collect = spyConsole();
    await run(
      Effect.log("default level").pipe(
        Effect.andThen(Effect.logInfo("info line")),
        Effect.andThen(Effect.logDebug("debug line")),
        Effect.andThen(Effect.logTrace("trace line")),
      ),
    );
    for (const method of CONSOLE_METHODS) {
      expect(collect()[method]).toEqual([]);
    }
  });

  it("never prints annotations, log spans, or a Cause (they can carry identifiers or error text)", async () => {
    const collect = spyConsole();
    const projectId = "ab".repeat(32);
    await run(
      Effect.logError("failure line", Cause.fail(new Error(`DO error about ${projectId}`))).pipe(
        Effect.annotateLogs("projectId", projectId),
        Effect.withLogSpan(`span-${projectId}`),
      ),
    );
    expect(collect().error).toEqual([["failure line"]]);
    expect(JSON.stringify(collect())).not.toContain(projectId);
  });

  it("prints a fixed line, not a blank one, for a Cause-only log call (and never the Cause)", async () => {
    const collect = spyConsole();
    const projectId = "cd".repeat(32);
    await run(Effect.logError(Cause.fail(new Error(`DO error about ${projectId}`))));
    expect(collect().error).toEqual([[CAUSE_ONLY_LINE]]);
    expect(JSON.stringify(collect())).not.toContain(projectId);
  });

  it("replaces the default logger (nothing reaches console.log through the default formatter)", async () => {
    const collect = spyConsole();
    await run(Effect.logWarning("only once"));
    expect(collect().warn).toHaveLength(1);
    expect(collect().log).toEqual([]);
  });
});
