// Storage for non-secret settings (server base URL, default project /
// environment).
//
// Format: one JSON file. Location: $MARUHI_CONFIG_DIR (an override for
// tests and advanced users) → $XDG_CONFIG_HOME/maruhi →
// ~/.config/maruhi. Secrets (tokens, key material) are never written
// here — they live only in the OS keychain (keychain.ts).
//
// The server URL has no default (self-hosted is the premise, so no hosted
// default exists — task ruling).

import { homedir } from "node:os";
import { join } from "node:path";

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import { Context, Data, Effect, FileSystem, Result, Runtime, Schema } from "effect";

import { CliError, cliError } from "./errors.ts";
import { writeJsonFileAtomic } from "./json-record.ts";

/**
 * Backing source (CRYPTO_SPEC §6.5 — IV2): the source that mechanically
 * cross-checks the other party's sig key against the IdP's public key
 * list during the invite mutual check. `github-signing-keys` (default) /
 * `none` (no check = always a ceremony). `org-directory` is reserved (not
 * implemented).
 */
export const IDENTITY_BACKINGS = ["github-signing-keys", "none"] as const;

export type IdentityBacking = (typeof IDENTITY_BACKINGS)[number];

/** Non-secret CLI configuration. */
export interface CliConfig {
  readonly server?: string;
  /**
   * The read-only mirror of `server` (PF2 — AUTH_SPEC §11-7): the origin
   * `run` / `pull` / `ci run` / `ci sync` fall back to when the server
   * is unreachable. Its session is the mirror's own (`maruhi login
   * --server <mirror>`).
   */
  readonly mirror?: string;
  readonly defaultProject?: string;
  readonly defaultEnvironment?: string;
  readonly identityBacking?: IdentityBacking;
}

/** Keys accepted by `maruhi config set` (all non-secret). */
export const CONFIG_KEYS = [
  "server",
  "mirror",
  "defaultProject",
  "defaultEnvironment",
  "identityBacking",
] as const;

/** The effective backing value (unset = `github-signing-keys` — supplement 21 ruling B). */
export function identityBackingOf(config: CliConfig): IdentityBacking {
  return config.identityBacking ?? "github-signing-keys";
}

/** Acceptance check for `config set identityBacking <value>` (invalid = null). */
export function asIdentityBacking(value: string): IdentityBacking | null {
  return (IDENTITY_BACKINGS as readonly string[]).includes(value)
    ? (value as IdentityBacking)
    : null;
}

/** A key accepted by `maruhi config set`. */
export type ConfigKey = (typeof CONFIG_KEYS)[number];

/** Returns the typed config key for `name`, or null when unknown. */
export function asConfigKey(name: string): ConfigKey | null {
  return (CONFIG_KEYS as readonly string[]).includes(name) ? (name as ConfigKey) : null;
}

/** Load / save boundary for the non-secret config file. */
export interface ConfigStoreShape {
  readonly load: Effect.Effect<CliConfig, CliError | ConfigFileCorruptError>;
  readonly save: (config: CliConfig) => Effect.Effect<void, CliError>;
}

export class ConfigStore extends Context.Service<ConfigStore, ConfigStoreShape>()(
  "cli/ConfigStore",
) {}

/**
 * `ConfigStore.load` for every caller other than `config set`'s
 * discard-and-recreate: a corrupt-content failure surfaces as a plain
 * CliError (the tag exists only for the one command allowed to rebuild
 * the file).
 */
export const loadCliConfig: Effect.Effect<CliConfig, CliError, ConfigStore> = Effect.gen(
  function* () {
    const store = yield* ConfigStore;
    return yield* store.load.pipe(
      Effect.catchTag("ConfigFileCorruptError", (error) => Effect.fail(cliError(error.message))),
    );
  },
);

/** Resolves the config file path (MARUHI_CONFIG_DIR → XDG_CONFIG_HOME → ~/.config). */
export function defaultConfigPath(env: (name: string) => string | undefined): string {
  const explicit = env("MARUHI_CONFIG_DIR");
  if (explicit !== undefined && explicit.length > 0) {
    return join(explicit, "config.json");
  }
  const xdg = env("XDG_CONFIG_HOME");
  const base = xdg !== undefined && xdg.length > 0 ? xdg : join(homedir(), ".config");
  return join(base, "maruhi", "config.json");
}

/**
 * The accepted config keys as a Struct: decoding shapes a record into
 * `CliConfig` (unknown keys drop out of the Struct result, and every
 * key stays optional so an absent key stays absent).
 */
const CliConfigSchema = Schema.Struct({
  server: Schema.optionalKey(Schema.String),
  mirror: Schema.optionalKey(Schema.String),
  defaultProject: Schema.optionalKey(Schema.String),
  defaultEnvironment: Schema.optionalKey(Schema.String),
  identityBacking: Schema.optionalKey(Schema.String),
});

/**
 * Decodes the config file's JSON, per-key tolerant as before: anything
 * that is not a JSON object is `null` (never throws), a key holding a
 * non-string (or empty) value is dropped rather than failing the whole
 * decode — one bad value must not take down the other settings.
 */
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
  // An unknown value falls back to the default (with check): never
  // fall toward a typo **removing** the check (`none` works only
  // when spelled out explicitly)
  const identityBacking = asIdentityBacking(backing);
  return identityBacking === null ? config : { ...config, identityBacking };
}

/**
 * A failure where the config file's **content** cannot be interpreted as
 * JSON — a tag of its own so `config set`'s "discard and recreate"
 * catches it by tag and nothing else does. A failure to read (EACCES /
 * EISDIR / EIO etc.) is not corrupt content, so it must not proceed to
 * replacing the existing settings. It becomes a plain {@link CliError}
 * with the same message wherever it leaves the code that handles it
 * (`config set` via the catchTag, every other consumer via
 * {@link loadCliConfig}).
 */
class ConfigFileCorruptError extends Data.TaggedError("ConfigFileCorruptError")<{
  readonly message: string;
}> {
  /** The same exit code CliError gives it (a failure, not a usage error). */
  override get [Runtime.errorExitCode](): number {
    return 1;
  }
}

/** File-backed config store at `path` (used by both production and tests). */
export function makeFileConfigStore(path: string): ConfigStoreShape {
  return {
    load: Effect.gen(function* () {
      const fs = yield* FileSystem.FileSystem;
      const json = yield* fs.readFileString(path, "utf8").pipe(
        // Treat **only** not-created (NotFound / ENOENT) as empty settings
        // (first run). Folding read failures like EACCES / EISDIR / EIO into
        // empty settings would let a later `config set` replace, without
        // warning, settings that merely failed to be read
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
      // temp + rename prevents torn writes (the last write among concurrent runs wins)
      writeJsonFileAtomic(path, CliConfigSchema, config).pipe(
        Effect.mapError(() => cliError(`Cannot write the config file: ${path}`)),
        Effect.provide(BunFileSystem.layer),
      ),
  };
}
