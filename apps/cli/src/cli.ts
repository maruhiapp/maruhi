import { Effect, type Layer, type Stdio } from "effect";
import type { Digest, SecureRandom } from "effect/crypto";
import type { HttpClient } from "effect/http";

import { runEffectCli } from "./cli-runner.ts";
import { COMMAND_SPECS, ROOT_SPEC_KEY } from "./commands/index.ts";
import type { ConfigStore } from "./config.ts";
import type { SqlRunner } from "./connector.package/index.ts";
import { internalErrorKind } from "./failure.ts";
import type { FloorStore } from "./floor.ts";
import type { CliIo } from "./io.ts";
import type { Keychain } from "./keychain.ts";
import type { FingerprintBook } from "./known-fingerprints.ts";
import { logFailure } from "./notice.ts";
import type { OwnDeviceStore } from "./own-devices.ts";
import type { PinStore } from "./pins.ts";
import type { ProxyAcceptStore } from "./proxy.package/index.ts";
import type { ProcessRunner } from "./run.ts";

export type CliServices =
  | Keychain
  | ConfigStore
  | FloorStore
  | PinStore
  | FingerprintBook
  | CliIo
  | ProcessRunner
  | Stdio.Stdio
  | HttpClient.HttpClient
  | OwnDeviceStore
  | ProxyAcceptStore
  | SqlRunner
  | SecureRandom.SecureRandom
  | Digest.Digest;

const TERMINATOR_BEFORE_COMMAND =
  "Write the command name before `--` (everything after `--` is passed through as arguments)";

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

function commandKeyOf(tokens: readonly string[]): string {
  const named = tokens.filter((token) => token !== "");
  const head = named[0];
  if (head === undefined || !Object.hasOwn(COMMAND_SPECS, head)) {
    return ROOT_SPEC_KEY;
  }
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

export async function runCli(
  argv: readonly string[],
  layer: Layer.Layer<CliServices>,
): Promise<number> {
  const reportError = async (messages: readonly string[]): Promise<void> => {
    await Effect.runPromise(
      Effect.forEach(messages, (message) => logFailure(message), { discard: true }).pipe(
        Effect.provide(layer),
      ),
    );
  };

  const tokens = positionalTokens(argv);
  if (tokens.beforeTerminator.every((token) => token === "") && tokens.afterTerminatorHasTokens) {
    await reportError([TERMINATOR_BEFORE_COMMAND]);
    return 2;
  }

  try {
    return await runEffectCli(commandKeyOf(tokens.beforeTerminator), argv, layer);
  } catch (error) {
    await reportError([`internal error (${internalErrorKind(error)})`]);
    return 1;
  }
}
