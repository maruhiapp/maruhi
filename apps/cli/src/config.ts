import { homedir } from "node:os";
import { join } from "node:path";

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import { Context, Data, Effect, FileSystem, Result, Runtime, Schema } from "effect";

import { CliError, cliError } from "./errors.ts";
import { writeJsonFileAtomic } from "./json-record.ts";

export const IDENTITY_BACKINGS = ["github-signing-keys", "none"] as const;

export type IdentityBacking = (typeof IDENTITY_BACKINGS)[number];

export interface CliConfig {
  readonly server?: string;
  readonly mirror?: string;
  readonly defaultProject?: string;
  readonly defaultEnvironment?: string;
  readonly identityBacking?: IdentityBacking;
}

export const CONFIG_KEYS = [
  "server",
  "mirror",
  "defaultProject",
  "defaultEnvironment",
  "identityBacking",
] as const;

export function identityBackingOf(config: CliConfig): IdentityBacking {
  return config.identityBacking ?? "github-signing-keys";
}

export function asIdentityBacking(value: string): IdentityBacking | null {
  return (IDENTITY_BACKINGS as readonly string[]).includes(value)
    ? (value as IdentityBacking)
    : null;
}

export type ConfigKey = (typeof CONFIG_KEYS)[number];

export function asConfigKey(name: string): ConfigKey | null {
  return (CONFIG_KEYS as readonly string[]).includes(name) ? (name as ConfigKey) : null;
}

export interface ConfigStoreShape {
  readonly load: Effect.Effect<CliConfig, CliError | ConfigFileCorruptError>;
  readonly save: (config: CliConfig) => Effect.Effect<void, CliError>;
}

export class ConfigStore extends Context.Service<ConfigStore, ConfigStoreShape>()(
  "cli/ConfigStore",
) {}

export const loadCliConfig: Effect.Effect<CliConfig, CliError, ConfigStore> = Effect.gen(
  function* () {
    const store = yield* ConfigStore;
    return yield* store.load.pipe(
      Effect.catchTag("ConfigFileCorruptError", (error) => Effect.fail(cliError(error.message))),
    );
  },
);

export function defaultConfigPath(env: (name: string) => string | undefined): string {
  const explicit = env("MARUHI_CONFIG_DIR");
  if (explicit !== undefined && explicit.length > 0) {
    return join(explicit, "config.json");
  }
  const xdg = env("XDG_CONFIG_HOME");
  const base = xdg !== undefined && xdg.length > 0 ? xdg : join(homedir(), ".config");
  return join(base, "maruhi", "config.json");
}

const CliConfigSchema = Schema.Struct({
  server: Schema.optionalKey(Schema.String),
  mirror: Schema.optionalKey(Schema.String),
  defaultProject: Schema.optionalKey(Schema.String),
  defaultEnvironment: Schema.optionalKey(Schema.String),
  identityBacking: Schema.optionalKey(Schema.String),
});

function decodeConfig(json: string): CliConfig | null {
  const parsed = Schema.decodeUnknownResult(
    Schema.fromJsonString(Schema.Record(Schema.String, Schema.Unknown)),
  )(json);
  if (Result.isFailure(parsed)) {
    return null;
  }
  const strings: Record<string, string> = {};
  for (const [key, value] of Object.entries(parsed.success)) {
    if (typeof value === "string" && value.length > 0) {
      strings[key] = value;
    }
  }
  const decoded = Schema.decodeUnknownResult(CliConfigSchema)(strings);
  if (Result.isFailure(decoded)) {
    return null;
  }
  const { identityBacking: backing, ...config } = decoded.success;
  if (backing === undefined) {
    return config;
  }
  const identityBacking = asIdentityBacking(backing);
  return identityBacking === null ? config : { ...config, identityBacking };
}

class ConfigFileCorruptError extends Data.TaggedError("ConfigFileCorruptError")<{
  readonly message: string;
}> {
  override get [Runtime.errorExitCode](): number {
    return 1;
  }
}

export function makeFileConfigStore(path: string): ConfigStoreShape {
  return {
    load: Effect.gen(function* () {
      const fs = yield* FileSystem.FileSystem;
      const json = yield* fs.readFileString(path, "utf8").pipe(
        Effect.catchReason("PlatformError", "NotFound", () => Effect.succeed(null)),
        Effect.catch((error) => {
          const code =
            (error.reason.cause as NodeJS.ErrnoException | undefined)?.code ?? "unknown error";
          return Effect.fail(
            cliError(
              `Cannot read the config file (${code}). Fix the file's permissions or move it out of the way, then retry: ${path}`,
            ),
          );
        }),
      );
      if (json === null) {
        return {};
      }
      const config = decodeConfig(json);
      if (config === null) {
        return yield* new ConfigFileCorruptError({
          message: `Cannot read the config file (it is corrupt): ${path}`,
        });
      }
      return config;
    }).pipe(Effect.provide(BunFileSystem.layer)),
    save: (config) =>
      writeJsonFileAtomic(path, CliConfigSchema, config).pipe(
        Effect.mapError(() => cliError(`Cannot write the config file: ${path}`)),
        Effect.provide(BunFileSystem.layer),
      ),
  };
}
