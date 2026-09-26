// Storage for non-secret settings (server base URL, default project /
// environment).
//
// Format: one JSON file. Location: $MARUHI_CONFIG_DIR (an override for
// tests and advanced users) → $XDG_CONFIG_HOME/maruhi →
// ~/.config/maruhi. Secrets (tokens, key material) are never written
// here — they live only in the OS keychain (keychain.ts).
//
// The server URL has no default (self-hosted is the premise, so no hosted
// default exists — task ruling). The old `githubClientId` was removed
// with its consumer by the AUTH_SPEC §4 revision (CLI client_id
// resolution was dropped) — if left in an existing file it is harmlessly
// ignored as an unknown key (decodeConfig picks up only allowed keys).

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import { Context, Effect } from "effect";

import { CliError, cliError } from "./errors.ts";

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
  readonly defaultProject?: string;
  readonly defaultEnvironment?: string;
  readonly identityBacking?: IdentityBacking;
}

/** Keys accepted by `maruhi config set` (all non-secret). */
export const CONFIG_KEYS = [
  "server",
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
  readonly load: Effect.Effect<CliConfig, CliError>;
  readonly save: (config: CliConfig) => Effect.Effect<void, CliError>;
}

export class ConfigStore extends Context.Service<ConfigStore, ConfigStoreShape>()(
  "cli/ConfigStore",
) {}

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

function pickString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function decodeConfig(json: string): CliConfig | null {
  try {
    const value: unknown = JSON.parse(json);
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return null;
    }
    const record = value as Record<string, unknown>;
    const config: { -readonly [K in keyof CliConfig]: CliConfig[K] } = {};
    for (const key of CONFIG_KEYS) {
      const picked = pickString(record, key);
      if (picked === undefined) {
        continue;
      }
      if (key === "identityBacking") {
        // An unknown value falls back to the default (with check): never
        // fall toward a typo **removing** the check (`none` works only
        // when spelled out explicitly)
        const backing = asIdentityBacking(picked);
        if (backing !== null) {
          config.identityBacking = backing;
        }
        continue;
      }
      config[key] = picked;
    }
    return config;
  } catch {
    return null;
  }
}

/** Internal marker distinguishing a read failure (other than ENOENT) from a parse failure. */
class ConfigUnreadableError extends Error {}

/**
 * A failure where the config file's **content** cannot be interpreted as
 * JSON (a subtype of CliError). Only for this case may `config set`
 * "discard and recreate" — a failure to read (EACCES / EISDIR / EIO
 * etc.) is not corrupt content, so it must not proceed to replacing the
 * existing settings.
 */
export class ConfigFileCorruptError extends CliError {}

/** File-backed config store at `path` (used by both production and tests). */
export function makeFileConfigStore(path: string): ConfigStoreShape {
  return {
    load: Effect.tryPromise({
      try: async () => {
        let json: string;
        try {
          json = await readFile(path, "utf8");
        } catch (error) {
          // Treat **only** not-created (ENOENT) as empty settings (first
          // run). Folding read failures like EACCES / EISDIR / EIO into
          // empty settings would let a later `config set` replace,
          // without warning, settings that merely failed to be read
          if ((error as NodeJS.ErrnoException).code === "ENOENT") {
            return {};
          }
          const code = (error as NodeJS.ErrnoException).code ?? "unknown error";
          throw new ConfigUnreadableError(code);
        }
        const config = decodeConfig(json);
        if (config === null) {
          throw new Error("corrupt");
        }
        return config;
      },
      catch: (error) =>
        error instanceof ConfigUnreadableError
          ? cliError(
              `Cannot read the config file (${error.message}). Fix the file's permissions or move it out of the way, then retry: ${path}`,
            )
          : new ConfigFileCorruptError({
              message: `Cannot read the config file (it is corrupt): ${path}`,
            }),
    }),
    save: (config) =>
      Effect.tryPromise({
        try: async () => {
          await mkdir(dirname(path), { recursive: true, mode: 0o700 });
          // temp + rename prevents torn writes (the last write among concurrent runs wins)
          const temp = `${path}.${process.pid}.tmp`;
          await writeFile(temp, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
          await rename(temp, path);
        },
        catch: () => cliError(`Cannot write the config file: ${path}`),
      }),
  };
}
