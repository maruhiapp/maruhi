import { Effect, Redacted } from "effect";

import { liveLayer } from "../../src/live.ts";
import { ProcessRunner } from "../../src/run.ts";

const value = "v".repeat(16 * 1024);
process.env["MARUHI_TOKEN"] = "maruhi_pat_probe_dummy";
process.env["MARUHI_TOKEN_ORIGIN"] = "https://probe.invalid";

const script =
  'head -c 70000 /dev/zero | tr "\\0" x; echo; input=$(cat); printf "len=%s telemetry=%s maruhi=%s\\n" "${#input}" "${WRANGLER_SEND_METRICS:-unset}" "${MARUHI_TOKEN:-unset}"; echo "to-stderr" >&2; exit 3';

const program = Effect.gen(function* () {
  const runner = yield* ProcessRunner;
  const outcome = yield* runner.exec({
    command: ["sh", "-c", script],
    cwd: process.cwd(),
    extraEnv: { WRANGLER_SEND_METRICS: "false" },
    stdin: Redacted.make(new TextEncoder().encode(value), { label: "sync-stdin" }),
  });
  const failedSpawnMessage = (input: { command: readonly string[]; cwd: string }) =>
    runner
      .exec({
        command: input.command,
        cwd: input.cwd,
        extraEnv: {},
        stdin: Redacted.make(new Uint8Array(0), { label: "sync-stdin" }),
      })
      .pipe(
        Effect.map(() => "unexpectedly started"),
        Effect.catch((error) => Effect.succeed(error.message)),
      );
  const missing = yield* failedSpawnMessage({
    command: ["maruhi-probe-not-installed-9f3c"],
    cwd: process.cwd(),
  });
  const badCwd = yield* failedSpawnMessage({
    command: ["sh", "-c", "true"],
    cwd: "/nonexistent-maruhi-probe-dir",
  });
  const captured = yield* Effect.promise(() =>
    runner.captureScript({
      command: ["sh", "-c", 'head -c 300000 /dev/zero | tr "\\0" y; printf "note\\n" >&2'],
      cwd: process.cwd(),
      extraEnv: {},
    }),
  );
  const refusal = (shell: string) =>
    Effect.promise(() =>
      runner.captureScript({ command: ["sh", "-c", shell], cwd: process.cwd(), extraEnv: {} }).then(
        () => "unexpectedly captured",
        (error: unknown) =>
          error instanceof Error ? `${error.name}: ${error.message}` : String(error),
      ),
    );
  const flooded = yield* refusal("head -c 3000000 /dev/zero; sleep 5; echo late");
  const floodedStderr = yield* Effect.promise(() =>
    runner.captureScript({
      command: ["sh", "-c", "head -c 3000000 /dev/zero >&2; echo value"],
      cwd: process.cwd(),
      extraEnv: {},
    }),
  );
  const leftoverStart = Date.now();
  const leftover = yield* Effect.promise(() =>
    runner.captureScript({
      command: ["sh", "-c", "sleep 20 & echo value"],
      cwd: process.cwd(),
      extraEnv: {},
    }),
  );
  const leftoverMs = Date.now() - leftoverStart;
  const stubbornStart = Date.now();
  const stubborn = yield* refusal("trap '' TERM; head -c 3000000 /dev/zero; sleep 20");
  const stubbornMs = Date.now() - stubbornStart;
  const polluted = yield* refusal("(sleep 1; echo junk) & echo value");
  const failedItself = yield* Effect.promise(() =>
    runner.captureScript({
      command: ["sh", "-c", "(sleep 0.3; echo junk) & echo 'issuer said no' >&2; exit 7"],
      cwd: process.cwd(),
      extraEnv: {},
    }),
  );
  const floodedAfterExit = yield* refusal(
    "(sleep 0.5; head -c 3000000 /dev/zero | tr '\\0' z; sleep 10) & echo value",
  );
  return {
    exitCode: outcome.exitCode,
    output: outcome.output,
    leftoverStdout: new TextDecoder().decode(leftover.stdout),
    leftoverStderr: leftover.stderr,
    leftoverMs,
    stubborn,
    stubbornMs,
    polluted,
    floodedAfterExit,
    failedItselfCode: failedItself.exitCode,
    failedItselfStderr: failedItself.stderr,
    missing,
    badCwd,
    capturedBytes: captured.stdout.length,
    capturedStderr: captured.stderr,
    flooded,
    floodedStderr: floodedStderr.stderr,
    floodedStderrStdout: floodedStderr.stdout.length,
  };
});

const result = await Effect.runPromise(program.pipe(Effect.provide(liveLayer())));
console.log(JSON.stringify(result));
