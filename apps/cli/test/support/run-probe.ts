// Probe that exercises the production ProcessRunner's `run` with
// run-output redaction (live.ts's relayRedacted — ROADMAP Phase 3 ⑤)
// under Bun with a real child. vitest runs on Node, so live-run.test.ts
// launches this script with `bun` and reads its stdout and stderr as
// bytes: the child's output is relayed to this process's fds (scrubbed),
// and the last stdout line is a JSON marker with the exit code.
//
// The child prints: the secret in a line, the secret in a JSON-escaped
// body (a multi-line value), the secret split across a pipe boundary
// (`printf` in two writes), the secret on stderr, the bytes 0..255 (byte
// transparency), and exits 4.

import { Effect } from "effect";

import { liveLayer } from "../../src/live.ts";
import { ProcessRunner } from "../../src/run.ts";

const SECRET = "hunter2-probe-secret-value";
const MULTI = "line-one-of-pem\nline-two-of-pem";
const enc = new TextEncoder();

const script = [
  // 1. the value in a log line
  'printf "token=%s done\\n" "$SECRET"',
  // 2. a multi-line value echoed as a JSON string (escaped newline)
  `printf '{"key":"line-one-of-pem\\\\nline-two-of-pem"}\\n'`,
  // 3. the value cut in two writes (a pipe chunk boundary in the parent)
  'printf "%s" "hunter2-probe-"; sleep 0.2; printf "%s\\n" "secret-value"',
  // 4. stderr
  'printf "err=%s\\n" "$SECRET" >&2',
  // 5. every byte value once (binary transparency)
  'printf "BIN:"; i=0; while [ $i -lt 256 ]; do printf "\\\\$(printf "%03o" $i)"; i=$((i+1)); done; printf ":END\\n"',
  "exit 4",
].join("; ");

const program = Effect.gen(function* () {
  const runner = yield* ProcessRunner;
  return yield* runner.run({
    command: ["sh", "-c", script],
    extraEnv: { SECRET },
    redact: [enc.encode(SECRET), enc.encode(MULTI)],
  });
});

const exitCode = await Effect.runPromise(program.pipe(Effect.provide(liveLayer())));
console.log(JSON.stringify({ exitCode }));
