// The command runner: mounts argv and the unused Effect services, runs one command, reports the failure (discipline: see commands/index.ts).

import { Cause, Console, Effect, Exit, FileSystem, Layer, Path, Stdio, Terminal } from "effect";
import { CliConfig, Command, CliError as EffectCliError, GlobalFlag } from "effect/cli";
import { ChildProcessSpawner } from "effect/process";

import { formatterLayer } from "./cli-formatter.ts";
import { maruhiTeardown } from "./cli-teardown.ts";
import { COMMAND_SPECS, makeRootCommand } from "./commands/index.ts";
import { type CliServices } from "./context.ts";
import { CliError } from "./errors.ts";
import { internalErrorKind } from "./failure.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { NoticeLedger, formatNotice } from "./notice.ts";
import { CLI_VERSION } from "./version.ts";

/* -------------------------------------------------------------------------- */
/* Runner                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Of the Effect environments the argument layer uses, the ones **maruhi
 * never uses**. Files, the terminal, and child processes are carried by
 * maruhi's own services (ConfigStore / CliIo.promptLine / ProcessRunner).
 * Passing implementations to the argument layer would leave room for
 * undeclared interaction/output paths (Prompt / wizard) to move, so a
 * **dying implementation** is placed here (same reason as decision 5).
 */
const unusedEnvironment = Layer.mergeAll(
  FileSystem.layerNoop({}),
  Path.layer,
  Layer.succeed(
    Terminal.Terminal,
    Terminal.make({
      columns: Effect.succeed(80),
      rows: Effect.succeed(24),
      readInput: Effect.die(
        "the argument layer must not read interactive input (interaction goes through CliIo.promptLine)",
      ),
      readLine: Effect.die(
        "the argument layer must not read interactive input (interaction goes through CliIo.promptLine)",
      ),
      display: () => Effect.void,
    }),
  ),
  Layer.succeed(
    ChildProcessSpawner.ChildProcessSpawner,
    ChildProcessSpawner.make(() =>
      Effect.die("child processes are spawned only through ProcessRunner (run.ts)"),
    ),
  ),
);

/**
 * The destination of help / diagnostics. **Every method** is bent toward
 * `CliIo.logError` (= stderr) (decision 9). A partial override of just
 * log / error would open a hole where a future upstream render method
 * passes through to the real stdout. Since `Console`'s methods are
 * synchronous (`void`), lines are accumulated here and flushed to `CliIo`
 * after the run (never interrupt an Effect via `runSync`).
 */
function collectingConsole(lines: string[]): Console.Console {
  const collect = (...args: ReadonlyArray<unknown>) => {
    lines.push(args.join(" "));
  };
  return {
    assert: collect,
    clear: collect,
    count: collect,
    countReset: collect,
    debug: collect,
    dir: collect,
    dirxml: collect,
    error: collect,
    group: collect,
    groupCollapsed: collect,
    groupEnd: collect,
    info: collect,
    log: collect,
    table: collect,
    time: collect,
    timeEnd: collect,
    timeLog: collect,
    trace: collect,
    warn: collect,
  };
}

/**
 * Re-mounts argv onto `Stdio`. runCli takes argv as an argument (a test
 * swaps argv per run), so the `Stdio.args` the `--` judgment
 * (`commandAfterTerminator`) reads is **the same array**. Production's
 * `Stdio.args` is `process.argv.slice(2)` = what bin.ts passes to runCli,
 * so the value never changes — only the source is unified.
 */
function withArgs(stdio: Stdio.Stdio, argv: readonly string[]): Stdio.Stdio {
  return Stdio.make({ ...stdio, args: Effect.succeed([...argv]) });
}

/** Puts a run failure into one line of maruhi vocabulary (never pass through an upstream English sentence raw). */
function reportFailure(io: CliIoShape, cause: Cause.Cause<unknown>): Effect.Effect<void> {
  const failure: unknown = Cause.squash(cause);
  // ShowHelp was already rendered by the effect side via Formatter (Console → stderr)
  if (failure instanceof EffectCliError.ShowHelp) {
    return Effect.void;
  }
  if (failure instanceof CliError) {
    return io.logError(formatNotice("error", failure.message, io.colorEnabled()));
  }
  // A defect (a bug) or an upstream unknown error. **The message is never
  // shown**: it could arrive embedding a typed-in value (`Invalid value:
  // <plaintext>`), so control-character neutralization alone cannot keep
  // the discipline (never surface a typed-in value in diagnostics). Never
  // swallowed silently (CLAUDE.md) — only the type's name is attached
  // (failure.ts's internalErrorKind — the same shape as cli.ts's defect
  // path)
  return io.logError(
    formatNotice("error", `internal error (${internalErrorKind(failure)})`, io.colorEnabled()),
  );
}

/**
 * Runs a command through `effect/cli` and returns the process exit code.
 *
 * `commandKey` is the **resolved command stage** decided by runCli's
 * dispatch, used as the diagnostics' destination (which declaration to
 * name).
 */
export async function runEffectCli(
  commandKey: string,
  argv: readonly string[],
  layer: Layer.Layer<CliServices>,
): Promise<number> {
  const diagnostics: string[] = [];
  let commandExitCode = 0;
  const root = makeRootCommand((code) => {
    commandExitCode = code;
  });
  // Decides only the amount of help (a run with an explicit `--help` gets
  // the full text; a misspelling gets a 1-line usage — decision 3). Never
  // used for any argument **check**. What follows `--` is **the child
  // process's arguments**, so it is not inspected: `maruhi run stray --
  // cmd -h`'s `-h` belongs to cmd, not a help request to maruhi
  const terminator = argv.indexOf("--");
  const ownArgs = terminator < 0 ? argv : argv.slice(0, terminator);
  // **Bare `maruhi` (no arguments) is treated as a help request** (the
  // stage-3 ruling — ADR-0016 appendix): usage + the command list with
  // exit 0. The destination is stderr (decision 9: stdout is for the
  // command's output only — the same treatment as `maruhi --help`). A
  // bare **subcommand stage** (`maruhi env` alone) is not covered: that
  // is a misspelling (exit 2), and the teardown tells them apart
  const bareRoot = ownArgs.length === 0;
  const helpRequested = bareRoot || ownArgs.includes("--help") || ownArgs.includes("-h");
  const versionRequested = ownArgs.includes("--version") || ownArgs.includes("-v");
  // The teardown's discrimination material (cli-teardown.ts): without an
  // explicit help / version, an errors-empty ShowHelp (a bare parent
  // command) is a misspelling (2)
  const infoRequested = helpRequested || versionRequested;

  const program = Effect.gen(function* () {
    const io = yield* CliIo;
    const stdio = yield* Stdio.Stdio;
    const exit = yield* Command.runWith(root, { version: CLI_VERSION })([...argv]).pipe(
      Effect.provideService(Stdio.Stdio, withArgs(stdio, argv)),
      Effect.provideService(Console.Console, collectingConsole(diagnostics)),
      Effect.provide(
        Layer.mergeAll(
          // Color applies only to stderr's prefixes and help headings (notice.ts — judged via CliIo)
          formatterLayer(commandKey, COMMAND_SPECS, helpRequested, io.colorEnabled()),
          // Built-in global flags are only --help / --version (decision 5)
          CliConfig.layer({ builtIns: [GlobalFlag.Help, GlobalFlag.Version] }),
          unusedEnvironment,
        ),
      ),
      Effect.exit,
    );
    for (const line of diagnostics) {
      // Only `--version`'s output is **the command's output** (stdout).
      // `V=$(maruhi --version)` is a legitimate script use, a different
      // role than help / diagnostics (stderr). A failed run (when written
      // alongside a misspelling) stays on stderr. A run where `--help` is
      // also given makes upstream's Help win = the collected lines are the
      // help body, so they are not flushed to stdout
      yield* versionRequested && !helpRequested && Exit.isSuccess(exit)
        ? io.log(line)
        : io.logError(line);
    }
    if (Exit.isFailure(exit)) {
      yield* reportFailure(io, exit.cause);
    }
    return exit;
  });

  const exit = await Effect.runPromise(
    program.pipe(
      // An identical-worded Note / Warning fires once per run (notice.ts — the ledger is per-run)
      Effect.provideService(NoticeLedger, new Set<string>()),
      Effect.provide(layer),
    ),
  );

  let exitCode = 0;
  // Production and tests go through the same teardown (never build a
  // shape where ShowHelp's exit 1 → 2 re-read works on only one side —
  // cli-teardown.ts)
  maruhiTeardown(infoRequested)(exit, (code) => {
    exitCode = code;
  });
  // `maruhi run` inherits the child process's exit code. Since
  // `Command.runWith` discards the handler's return value, only a
  // successful run's exit code is carried out (not an error, so it cannot
  // ride Runtime.errorExitCode)
  return exitCode === 0 ? commandExitCode : exitCode;
}
