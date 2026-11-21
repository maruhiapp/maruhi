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
