import { Cause, Console, Effect, Exit, FileSystem, Layer, Path, Stdio, Terminal } from "effect";
import { CliConfig, Command, CliError as EffectCliError, GlobalFlag } from "effect/cli";
import { ChildProcessSpawner } from "effect/process";

import { formatterLayer } from "./cli-formatter.ts";
import { maruhiTeardown } from "./cli-teardown.ts";
import type { CliServices } from "./cli.ts";
import { COMMAND_SPECS, makeRootCommand } from "./commands/index.ts";
import { CliError } from "./errors.ts";
import { internalErrorKind } from "./failure.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { NoticeLedger, formatNotice } from "./notice.ts";
import { CLI_VERSION } from "./version.ts";

const unusedEnvironment = Layer.mergeAll(
  FileSystem.layerNoop({}),
  Path.layer,
  Layer.succeed(
    Terminal.Terminal,
    Terminal.make({
      columns: Effect.succeed(80),
      rows: Effect.succeed(24),
      size: Effect.die(
        "the argument layer must not observe the terminal size (interaction goes through CliIo.promptLine)",
      ),
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

function withArgs(stdio: Stdio.Stdio, argv: readonly string[]): Stdio.Stdio {
  return Stdio.make({ ...stdio, args: Effect.succeed([...argv]) });
}

function reportFailure(io: CliIoShape, cause: Cause.Cause<unknown>): Effect.Effect<void> {
  const failure: unknown = Cause.squash(cause);
  if (failure instanceof EffectCliError.ShowHelp) {
    return Effect.void;
  }
  if (failure instanceof CliError) {
    return io.logError(formatNotice("error", failure.message, io.colorEnabled()));
  }
  return io.logError(
    formatNotice("error", `internal error (${internalErrorKind(failure)})`, io.colorEnabled()),
  );
}

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
  const terminator = argv.indexOf("--");
  const ownArgs = terminator < 0 ? argv : argv.slice(0, terminator);
  const bareRoot = ownArgs.length === 0;
  const helpRequested = bareRoot || ownArgs.includes("--help") || ownArgs.includes("-h");
  const versionRequested = ownArgs.includes("--version") || ownArgs.includes("-v");
  const infoRequested = helpRequested || versionRequested;

  const program = Effect.gen(function* () {
    const io = yield* CliIo;
    const stdio = yield* Stdio.Stdio;
    const exit = yield* Command.runWith(root, { version: CLI_VERSION })([...argv]).pipe(
      Effect.provideService(Stdio.Stdio, withArgs(stdio, argv)),
      Effect.provideService(Console.Console, collectingConsole(diagnostics)),
      Effect.provide(
        Layer.mergeAll(
          formatterLayer(commandKey, COMMAND_SPECS, helpRequested, io.colorEnabled()),
          CliConfig.layer({ builtIns: [GlobalFlag.Help, GlobalFlag.Version] }),
          unusedEnvironment,
        ),
      ),
      Effect.exit,
    );
    for (const line of diagnostics) {
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
    program.pipe(Effect.provideService(NoticeLedger, new Set<string>()), Effect.provide(layer)),
  );

  let exitCode = 0;
  maruhiTeardown(infoRequested)(exit, (code) => {
    exitCode = code;
  });
  return exitCode === 0 ? commandExitCode : exitCode;
}
