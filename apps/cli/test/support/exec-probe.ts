// Probe that exercises the production ProcessRunner's `exec` (live.ts —
// Bun.spawn) with a real process. vitest runs on Node where `Bun` doesn't
// exist, so live-exec.test.ts launches this script with `bun` and reads the
// result JSON from stdout.
//
// Under test: the value arrives on stdin **whole** (16 KiB — Vercel's limit),
// the child's env has the telemetry-off var but no MARUHI_*, output is
// captured (does not leak to the parent's stdout), output is returned
// **untruncated and whole** (truncating before redacting would leak the value's
// tail), a non-zero exit code comes back, and an unspawnable command is a
// typed error. The child is a one-line sh script (reads the value from stdin
// and reports only its length and env presence — never the value itself).

import { Effect, Redacted } from "effect";

import { liveLayer } from "../../src/live.ts";
import { ProcessRunner } from "../../src/run.ts";

const value = "v".repeat(16 * 1024);
// Place the namespace that must not reach the child on the parent
process.env["MARUHI_TOKEN"] = "maruhi_pat_probe_dummy";
process.env["MARUHI_TOKEN_ORIGIN"] = "https://probe.invalid";

// Emit a 70,000-char line first (evidence there is no 64K-char truncation)
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
  const missing = yield* runner
    .exec({
      command: ["maruhi-probe-not-installed-9f3c"],
      cwd: process.cwd(),
      extraEnv: {},
      stdin: Redacted.make(new Uint8Array(0), { label: "sync-stdin" }),
    })
    .pipe(
      Effect.map(() => "unexpectedly started"),
      Effect.catch((error) => Effect.succeed(error.message)),
    );
  const badCwd = yield* runner
    .exec({
      command: ["sh", "-c", "true"],
      cwd: "/nonexistent-maruhi-probe-dir",
      extraEnv: {},
      stdin: Redacted.make(new Uint8Array(0), { label: "sync-stdin" }),
    })
    .pipe(
      Effect.map(() => "unexpectedly started"),
      Effect.catch((error) => Effect.succeed(error.message)),
    );
  // The rotation connector's script capture (captureScript): stdout is
  // the credential and is read whole up to 1 MiB; past that the script is
  // stopped and nothing of it is kept (D-6)
  const captured = yield* Effect.promise(() =>
    runner.captureScript({
      command: ["sh", "-c", 'head -c 300000 /dev/zero | tr "\\0" y; printf "note\\n" >&2'],
      cwd: process.cwd(),
      extraEnv: {},
    }),
  );
  /** A capture expected to reject: its error's name and message. */
  const refusal = (shell: string) =>
    Effect.promise(() =>
      runner.captureScript({ command: ["sh", "-c", shell], cwd: process.cwd(), extraEnv: {} }).then(
        () => "unexpectedly captured",
        (error: unknown) =>
          error instanceof Error ? `${error.name}: ${error.message}` : String(error),
      ),
    );
  const flooded = yield* refusal("head -c 3000000 /dev/zero; sleep 5; echo late");
  // A flooded stderr is dropped whole (never cut — D-9) and drained: the
  // script runs on and its value is read (D-10 — a stopped script would
  // strand the credential it may have created)
  const floodedStderr = yield* Effect.promise(() =>
    runner.captureScript({
      command: ["sh", "-c", "head -c 3000000 /dev/zero >&2; echo value"],
      cwd: process.cwd(),
      extraEnv: {},
    }),
  );
  // A process the script left behind holds its pipes: the capture ends
  // after the grace with the script's own answer (D-12); a script that
  // ignores the stop is killed after the grace (D-13)
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
  // Bytes a leftover process writes after the script exited are never
  // silently the answer (D-14): a late line, or a flood past the cap after
  // the exit, is refused naming the script's own exit code
  const polluted = yield* refusal("(sleep 1; echo junk) & echo value");
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
// stdout is only this JSON (that no child output is mixed in is also under test)
console.log(JSON.stringify(result));
