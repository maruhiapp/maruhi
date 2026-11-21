import { Effect } from "effect";

import { liveLayer } from "../../src/live.ts";
import { ProcessRunner } from "../../src/run.ts";

const SECRET = "hunter2-probe-secret-value";
const MULTI = "line-one-of-pem\nline-two-of-pem";
const enc = new TextEncoder();

const script = [
  'printf "token=%s done\\n" "$SECRET"',
  `printf '{"key":"line-one-of-pem\\\\nline-two-of-pem"}\\n'`,
  'printf "%s" "hunter2-probe-"; sleep 0.2; printf "%s\\n" "secret-value"',
  'printf "err=%s\\n" "$SECRET" >&2',
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
