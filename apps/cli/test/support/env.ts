// テスト用のサービス層: インメモリキーチェーン・出力捕捉 CliIo・記録型
// ProcessRunner・一時ディレクトリの設定ストア・実 fetch の HttpClient。
// 実キーチェーン(Bun.secrets)は CI に存在しないため結合しない(タスク指示)。

import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Effect, Layer } from "effect";
import { FetchHttpClient } from "effect/unstable/http";

import type { CliServices } from "../../src/cli.ts";
import { ConfigStore, makeFileConfigStore } from "../../src/config.ts";
import { cliError } from "../../src/errors.ts";
import { type AgentProfile, CliIo } from "../../src/io.ts";
import {
  Keychain,
  masterKeyEntryName,
  type StoredMasterKey,
  type StoredToken,
  tokenEntryName,
} from "../../src/keychain.ts";
import { ProcessRunner } from "../../src/run.ts";
import type { TestUser } from "./crypto.ts";

/** One recorded child-process invocation. */
export interface RunnerCall {
  readonly command: readonly string[];
  readonly extraEnv: Readonly<Record<string, string>>;
}

/** A fully in-memory test environment for driving `runCli`. */
export interface TestEnv {
  readonly layer: Layer.Layer<CliServices>;
  readonly keychain: Map<string, string>;
  readonly logs: string[];
  readonly errors: string[];
  readonly runnerCalls: RunnerCall[];
  readonly configPath: string;
  setStdin(bytes: Uint8Array): void;
  setAgent(profile: AgentProfile): void;
  setEnvVar(name: string, value: string | undefined): void;
  setRunnerExitCode(code: number): void;
  /** キーチェーン書き込みを失敗させる(login の失効フォールバック検査用)。 */
  failKeychainWrites(): void;
  /** defect 経路の検査用: 設定読込を throw(非 CliError)にする。 */
  breakConfigLoadWithDefect(): void;
}

export async function makeTestEnv(): Promise<TestEnv> {
  const configDir = await mkdtemp(join(tmpdir(), "maruhi-cli-test-"));
  const configPath = join(configDir, "config.json");
  const keychain = new Map<string, string>();
  const logs: string[] = [];
  const errors: string[] = [];
  const runnerCalls: RunnerCall[] = [];
  const envVars = new Map<string, string>();
  let stdin: Uint8Array = new Uint8Array(0);
  let agent: AgentProfile = { isAgent: false };
  let runnerExitCode = 0;
  let keychainWritable = true;
  let configLoadDefect = false;

  const fileStore = makeFileConfigStore(configPath);
  const layer = Layer.mergeAll(
    Layer.succeed(Keychain, {
      get: (name) => Effect.sync(() => keychain.get(name) ?? null),
      set: (name, value) =>
        Effect.suspend(() => {
          if (!keychainWritable) {
            return Effect.fail(cliError("キーチェーンに書き込めません(テスト注入)"));
          }
          keychain.set(name, value);
          return Effect.void;
        }),
      remove: (name) =>
        Effect.sync(() => {
          keychain.delete(name);
        }),
    }),
    Layer.succeed(ConfigStore, {
      load: Effect.suspend(() => {
        if (configLoadDefect) {
          throw new Error("config load defect (test)");
        }
        return fileStore.load;
      }),
      save: (config) => fileStore.save(config),
    }),
    Layer.succeed(CliIo, {
      log: (line) =>
        Effect.sync(() => {
          logs.push(line);
        }),
      logError: (line) =>
        Effect.sync(() => {
          errors.push(line);
        }),
      readStdin: Effect.suspend(() => Effect.succeed(stdin)),
      envVar: (name) => envVars.get(name),
      agentProfile: () => agent,
    }),
    Layer.succeed(ProcessRunner, {
      run: ({ command, extraEnv }) =>
        Effect.sync(() => {
          runnerCalls.push({ command, extraEnv });
          return runnerExitCode;
        }),
    }),
    FetchHttpClient.layer,
  );

  return {
    layer,
    keychain,
    logs,
    errors,
    runnerCalls,
    configPath,
    setStdin(bytes) {
      stdin = bytes;
    },
    setAgent(profile) {
      agent = profile;
    },
    setEnvVar(name, value) {
      if (value === undefined) {
        envVars.delete(name);
      } else {
        envVars.set(name, value);
      }
    },
    setRunnerExitCode(code) {
      runnerExitCode = code;
    },
    failKeychainWrites() {
      keychainWritable = false;
    },
    breakConfigLoadWithDefect() {
      configLoadDefect = true;
    },
  };
}

/** ログイン済み + master 鍵保存済みの状態をキーチェーンへシードする。 */
export function seedSession(env: TestEnv, origin: string, user: TestUser): void {
  const token: StoredToken = {
    // 実サーバーの形式(maruhi_pat_ + Base62 乱数)に寄せたフィクスチャ
    token: "maruhi_pat_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9x123",
    userId: user.userId,
    tokenId: "tok_0001",
  };
  const master: StoredMasterKey = {
    suite: "maruhi/v1",
    encPubHex: user.encPubHex,
    encSkHex: user.encSkHex,
    sigPubHex: user.sigPubHex,
    sigSkSeedHex: user.sigSkSeedHex,
  };
  env.keychain.set(tokenEntryName(origin), JSON.stringify(token));
  env.keychain.set(masterKeyEntryName(origin, user.userId), JSON.stringify(master));
}

/** config.json に server(+ 任意の既定)を書いた状態を作る。 */
export async function seedConfig(
  env: TestEnv,
  config: Readonly<Record<string, string>>,
): Promise<void> {
  const { writeFile, mkdir } = await import("node:fs/promises");
  const { dirname } = await import("node:path");
  await mkdir(dirname(env.configPath), { recursive: true });
  await writeFile(env.configPath, JSON.stringify(config));
}
