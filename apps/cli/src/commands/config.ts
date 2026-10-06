// `maruhi config` (discipline: see commands/index.ts).

import { Effect } from "effect";
import { Argument, Command } from "effect/cli";

import {
  CONFIG_KEYS,
  type ConfigKey,
  ConfigStore,
  IDENTITY_BACKINGS,
  asConfigKey,
  asIdentityBacking,
  loadCliConfig,
} from "../config.ts";
import { CliError, usageError } from "../errors.ts";
import { CliIo } from "../io.ts";
import { logWarning } from "../notice.ts";
import { NonBlank } from "./flags.ts";
import { noteMirrorSession } from "./shared.ts";

/** The config key's positional argument (shared by config's subcommands). */
const configKeyArgument = () =>
  Argument.String("key").pipe(
    Argument.withDescription(`Config key (${CONFIG_KEYS.join(" | ")})`),
    Argument.withSchema(NonBlank),
  );

export const configGetConfig = {
  key: configKeyArgument(),
};

export const configSetConfig = {
  key: configKeyArgument(),
  // An empty / whitespace-only value is refused by the declaration
  // (NonBlank): blocks the accident where the unset shape of `config set
  // defaultProject "$PROJ"` overwrites the existing config with an empty
  // value and reports success
  value: Argument.String("value").pipe(
    Argument.withDescription("Value to set"),
    Argument.withSchema(NonBlank),
  ),
};

function requireConfigKey(value: string): Effect.Effect<ConfigKey, CliError> {
  const key = asConfigKey(value);
  return key === null
    ? Effect.fail(usageError(`Unknown config key (${CONFIG_KEYS.join(" | ")})`))
    : Effect.succeed(key);
}

export function makeConfigCommands() {
  const configGet = Command.make(
    "get",
    configGetConfig,
    Effect.fn("commands-config.configGet")(function* (values) {
      const io = yield* CliIo;
      const configKey = yield* requireConfigKey(values.key);
      const config = yield* loadCliConfig;
      // stdout is only the command's output (the value): `V=$(maruhi
      // config get server)` captures nothing besides the value (decision 9)
      yield* io.log(config[configKey] ?? "");
    }),
  ).pipe(Command.withDescription("Print one non-secret setting to stdout"));

  const configSet = Command.make(
    "set",
    configSetConfig,
    Effect.fn("commands-config.configSet")(function* (values) {
      const io = yield* CliIo;
      const store = yield* ConfigStore;
      const configKey = yield* requireConfigKey(values.key);
      // A key holding a closed-set value is checked at declaration (a typo is never silently stored)
      if (configKey === "identityBacking" && asIdentityBacking(values.value) === null) {
        return yield* Effect.fail(
          usageError(`identityBacking must be one of: ${IDENTITY_BACKINGS.join(" | ")}`),
        );
      }
      // A broken config file is recreatable via set (it holds only
      // non-secrets so it may be discarded — never make it unrecoverable
      // from inside the CLI). But since it loses the existing config, it is
      // never swallowed silently — a warning is emitted. Recreatable is
      // **content corruption** only: a read failure itself (EACCES /
      // EISDIR / EIO etc.) would silently replace an existing config that
      // merely could not be read, so it fails as-is
      const config = yield* store.load.pipe(
        Effect.catchTag("ConfigFileCorruptError", (error) =>
          Effect.gen(function* () {
            yield* logWarning(
              `${error.message} — discarding the existing config and recreating it with only this key`,
            );
            return {};
          }),
        ),
      );
      yield* store.save({ ...config, [configKey]: values.value });
      yield* io.log(`Set ${configKey}`);
      if (configKey === "mirror") {
        yield* noteMirrorSession(values.value);
      }
    }),
  ).pipe(Command.withDescription("Set one non-secret setting"));

  const config = Command.make("config").pipe(
    Command.withDescription(
      "Manage non-secret settings (get / set). Secrets are never stored here",
    ),
    Command.withSubcommands([configGet, configSet]),
  );

  return config;
}
