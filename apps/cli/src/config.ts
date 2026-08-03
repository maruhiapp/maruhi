// 非機密設定(サーバー base URL・GitHub OAuth App の client_id・既定の
// プロジェクト / 環境)の置き場所。
//
// 形式: JSON 1 ファイル。置き場所は $MARUHI_CONFIG_DIR(テスト・上級者向け
// オーバーライド)→ $XDG_CONFIG_HOME/maruhi → ~/.config/maruhi。
// シークレット(トークン・鍵素材)は絶対にここへ書かない — それらは
// OS キーチェーンのみ(keychain.ts)。
//
// サーバー URL に既定値はない(セルフホスト前提でホステッドのデフォルトが
// 存在しない — タスク裁定)。github client_id はサーバー側にも公開設定
// エンドポイントがないため、v1 はユーザーが設定で与える(要裁定: session-11.md)。

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import { Context, Effect, Layer } from "effect";

import { cliError, type CliError } from "./errors.ts";

/** Non-secret CLI configuration. */
export interface CliConfig {
  readonly server?: string;
  readonly githubClientId?: string;
  readonly defaultProject?: string;
  readonly defaultEnvironment?: string;
}

/** Keys accepted by `maruhi config set` (all non-secret). */
export const CONFIG_KEYS = [
  "server",
  "githubClientId",
  "defaultProject",
  "defaultEnvironment",
] as const;

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
    if (typeof value !== "object" || value === null) {
      return null;
    }
    const record = value as Record<string, unknown>;
    const config: { -readonly [K in keyof CliConfig]: CliConfig[K] } = {};
    for (const key of CONFIG_KEYS) {
      const picked = pickString(record, key);
      if (picked !== undefined) {
        config[key] = picked;
      }
    }
    return config;
  } catch {
    return null;
  }
}

/** File-backed config store at `path` (used by both production and tests). */
export function makeFileConfigStore(path: string): ConfigStoreShape {
  return {
    load: Effect.tryPromise({
      try: async () => {
        let json: string;
        try {
          json = await readFile(path, "utf8");
        } catch {
          // 未作成は空設定として扱う(初回実行)
          return {};
        }
        const config = decodeConfig(json);
        if (config === null) {
          throw new Error("corrupt");
        }
        return config;
      },
      catch: () => cliError(`設定ファイルを読み取れません(壊れています): ${path}`),
    }),
    save: (config) =>
      Effect.tryPromise({
        try: async () => {
          await mkdir(dirname(path), { recursive: true, mode: 0o700 });
          await writeFile(path, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
        },
        catch: () => cliError(`設定ファイルを書き込めません: ${path}`),
      }),
  };
}

/** Layer providing a file-backed {@link ConfigStore}. */
export function layerFileConfigStore(path: string): Layer.Layer<ConfigStore> {
  return Layer.succeed(ConfigStore, makeFileConfigStore(path));
}
