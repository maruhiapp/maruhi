// Probe for the pipe semantics of the redacted relay (live.ts
// startRedactedRelay — review finding pf4-design.md §19 C-1), run under Bun
// by live-run.test.ts:
//
//   mode "flood":      the child writes lines forever; the test pipes this
//                      probe into `head -c`, so our stdout closes early. The
//                      relay must then stop and the child must be ended
//                      (SIGPIPE), and this process must exit
//   mode "grandchild": the child starts a background grandchild that holds
//                      the pipes open for 20 s and exits at once. The relay
//                      must not wait for the grandchild
//
// Writes the exit code as a JSON line on stderr (stdout is the child's).

import { Effect } from "effect";

import { liveLayer } from "../../src/live.ts";
import { ProcessRunner } from "../../src/run.ts";

const mode = process.argv[2] ?? "flood";
const script =
  mode === "flood"
    ? 'i=0; while :; do echo "line $i token=$SECRET"; i=$((i+1)); done'
    : "sleep 20 & echo done";

const program = Effect.gen(function* () {
  const runner = yield* ProcessRunner;
  return yield* runner.run({
    command: ["sh", "-c", script],
    extraEnv: { SECRET: "hunter2-pipe-probe" },
    redact: [new TextEncoder().encode("hunter2-pipe-probe")],
  });
});

const started = Date.now();
const exitCode = await Effect.runPromise(program.pipe(Effect.provide(liveLayer())));
process.stderr.write(`${JSON.stringify({ exitCode, elapsedMs: Date.now() - started })}\n`);
