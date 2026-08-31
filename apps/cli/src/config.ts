// 非機密設定(サーバー base URL・既定のプロジェクト / 環境)の置き場所。
//
// 形式: JSON 1 ファイル。置き場所は $MARUHI_CONFIG_DIR(テスト・上級者向け
// オーバーライド)→ $XDG_CONFIG_HOME/maruhi → ~/.config/maruhi。
// シークレット(トークン・鍵素材)は絶対にここへ書かない — それらは
// OS キーチェーンのみ(keychain.ts)。
//
// サーバー URL に既定値はない(セルフホスト前提でホステッドのデフォルトが
// 存在しない — タスク裁定)。旧 `githubClientId` は 2026-08-31 の AUTH_SPEC §4
// 改訂(CLI の client_id 解決の廃止)で消費者ごと削除された — 既存ファイルに
// 残っていても未知キーとして無害に無視される(decodeConfig は許可キーのみ拾う)。

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import { Context, Effect } from "effect";

import { CliError, cliError } from "./errors.ts";

/** Non-secret CLI configuration. */
export interface CliConfig {
  readonly server?: string;
  readonly defaultProject?: string;
  readonly defaultEnvironment?: string;
}

/** Keys accepted by `maruhi config set` (all non-secret). */
export const CONFIG_KEYS = ["server", "defaultProject", "defaultEnvironment"] as const;

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
      if (picked !== undefined) {
        config[key] = picked;
      }
    }
    return config;
  } catch {
    return null;
  }
}

/** 読み取り失敗(ENOENT 以外)をパース失敗と区別するための内部マーカー。 */
class ConfigUnreadableError extends Error {}

/**
 * 設定ファイルの**内容**が JSON として解釈できない失敗(CliError の下位型)。
 * `config set` はこの場合のみ「破棄して作り直す」を許す — 読み取り自体の失敗
 * (EACCES / EISDIR / EIO 等)は内容の破損ではないため、既存設定の置換に
 * 進んではならない(deepsec B2)。
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
          // 未作成(ENOENT)**だけ**を空設定として扱う(初回実行)。EACCES /
          // EISDIR / EIO 等の読み取り失敗まで空設定に畳むと、読めなかっただけの
          // 既存設定を後続の `config set` が警告なしで置換する(deepsec B2)
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
          // temp + rename で torn write を防ぐ(同時実行の最後の書き込みが勝つ)
          const temp = `${path}.${process.pid}.tmp`;
          await writeFile(temp, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
          await rename(temp, path);
        },
        catch: () => cliError(`Cannot write the config file: ${path}`),
      }),
  };
}
