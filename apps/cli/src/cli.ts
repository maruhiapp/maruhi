// Entry of the maruhi CLI: the argument layer is `effect/cli`
// (commands/index.ts + cli-runner.ts).
//
// runCli holds only three things: (1) the dedicated diagnostic for a run
// with no command name before `--` (the effect side can only say "extra
// argument" and cannot say how to fix it), (2) resolving the diagnostic's
// destination (command level), (3) the final net for internal errors.
//
// Values are entered via stdin (plaintext values never go on argv), values
// are displayed only by pull --show, and anything but a human's
// interactive terminal is refused (agent-gate.ts). `maruhi run` is
// allowed.

import { Effect, type Layer } from "effect";

import { runEffectCli } from "./cli-runner.ts";
import { COMMAND_SPECS, ROOT_SPEC_KEY } from "./commands/index.ts";
import type { CliServices } from "./context.ts";
import { internalErrorKind } from "./failure.ts";
import { logFailure } from "./notice.ts";

export type { CliServices } from "./context.ts";

/**
 * The message for a run whose command name sits **after** `--`.
 * effect/cli does not resolve commands across `--` (shape #7 of
 * the 12), but its diagnostic can only be "extra argument" and cannot say
 * how to fix it (put the command name first). The only position able to
 * emit a dedicated message is here, before dispatch.
 */
const TERMINATOR_BEFORE_COMMAND =
  "Write the command name before `--` (everything after `--` is passed through as arguments)";

/**
 * Collects the positional arguments (command-name candidates) before `--`
 * from argv.
 *
 * A minimal hand-rolled lexer. This is not the "scan that **inspects**
 * arguments" ADR-0016 decision 2 forbids — it is **material for
 * dispatch** and does not appear in the declaration. Tokens starting
 * with `-` are options (or their misspellings); the rest are collected
 * as positionals. The value of an option that takes one also lands among
 * the positionals (a lex-only scan that does not know the argument
 * table), but the consumer only looks at "the first non-empty token"
 * and "whether a positional exists before `--`", so it cannot disagree
 * with the effect side's resolution.
 */
function positionalTokens(argv: readonly string[]): {
  readonly beforeTerminator: readonly string[];
  readonly afterTerminatorHasTokens: boolean;
} {
  const before: string[] = [];
  let terminated = false;
  let after = false;
  for (const token of argv) {
    if (!terminated && token === "--") {
      terminated = true;
      continue;
    }
    if (terminated) {
      after = after || token.length > 0;
      continue;
    }
    if (token === "" || !token.startsWith("-")) {
      before.push(token);
    }
  }
  return { beforeTerminator: before, afterTerminatorHasTokens: after };
}

/**
 * The diagnostic destination passed to `effect/cli` (the
 * resolved command level).
 *
 * Dispatches on the leading command name; when the second word is a known
 * subcommand, the diagnostic's destination is fixed to that level
 * (`env rotate`). An unknown command or no command name is root
 * (ROOT_SPEC_KEY) — diagnostics are carried by the effect side's
 * UnknownSubcommand / UnrecognizedOption. An empty token is not resolved
 * as a command name (the effect side does not resolve one either). The
 * level list is drawn from COMMAND_SPECS (no hand-written copy is kept).
 */
function commandKeyOf(tokens: readonly string[]): string {
  const named = tokens.filter((token) => token !== "");
  const head = named[0];
  if (head === undefined || !Object.hasOwn(COMMAND_SPECS, head)) {
    return ROOT_SPEC_KEY;
  }
  // Resolve as deep as known levels continue (down to the 3 levels of `key seal remove` — KL3 K5)
  let key = head;
  for (const token of named.slice(1)) {
    const nested = `${key} ${token}`;
    if (!Object.hasOwn(COMMAND_SPECS, nested)) {
      break;
    }
    key = nested;
  }
  return key;
}

/**
 * Runs the maruhi CLI against `argv` with the given service layer and
 * returns the process exit code (0 = success, 1 = failure, 2 = usage error,
 * 3 = `rotation list --fail-on-due` / `--fail-on-flags` found something due).
 */
export async function runCli(
  argv: readonly string[],
  layer: Layer.Layer<CliServices>,
): Promise<number> {
  /** Emits one or more diagnostics to stderr (the final net outside runEffectCli). */
  const reportError = async (messages: readonly string[]): Promise<void> => {
    await Effect.runPromise(
      Effect.forEach(messages, (message) => logFailure(message), { discard: true }).pipe(
        Effect.provide(layer),
      ),
    );
  };

  // A run whose command name sits **after** `--` (`maruhi -- run
  // printenv`) is dropped before deciding which command to dispatch to
  // (the dedicated diagnostic above). An empty token is not resolved as a
  // command name, so `maruhi "" -- run` is treated as the same shape
  const tokens = positionalTokens(argv);
  if (tokens.beforeTerminator.every((token) => token === "") && tokens.afterTerminatorHasTokens) {
    await reportError([TERMINATOR_BEFORE_COMMAND]);
    return 2;
  }

  // Defects in the command body are caught inside runEffectCli
  // (`Effect.exit` + reportFailure). What arrives here is only a reject =
  // a failure to build layers or of logError itself, but bin.ts only
  // awaits runCli, so un-caught would surface Bun's unhandled rejection
  // rather than a maruhi message. Do not emit the message (it could
  // embed a typed-in value and still arrive) — attach only the type's
  // name (failure.ts)
  try {
    return await runEffectCli(commandKeyOf(tokens.beforeTerminator), argv, layer);
  } catch (error) {
    await reportError([`internal error (${internalErrorKind(error)})`]);
    return 1;
  }
}
