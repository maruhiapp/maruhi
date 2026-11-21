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
      if (configKey === "identityBacking" && asIdentityBacking(values.value) === null) {
        return yield* Effect.fail(
          usageError(`identityBacking must be one of: ${IDENTITY_BACKINGS.join(" | ")}`),
        );
      }
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
