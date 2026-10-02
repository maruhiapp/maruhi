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
  const flooded = yield* Effect.promise(() =>
    runner
      .captureScript({
        command: ["sh", "-c", "head -c 3000000 /dev/zero; sleep 5; echo late"],
        cwd: process.cwd(),
        extraEnv: {},
      })
      .then(
        () => "unexpectedly captured",
        (error: unknown) => (error instanceof Error ? error.message : String(error)),
      ),
  );
  return {
    exitCode: outcome.exitCode,
    output: outcome.output,
    missing,
    badCwd,
    capturedBytes: captured.stdout.length,
    capturedStderr: captured.stderr,
    flooded,
  };
});

const result = await Effect.runPromise(program.pipe(Effect.provide(liveLayer())));
// stdout is only this JSON (that no child output is mixed in is also under test)
console.log(JSON.stringify(result));
