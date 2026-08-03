// 本番サービス実装(Bun ランタイム。ADR-0004: CLI は Bun 固有 API 可)。
//
// - Keychain = Bun.secrets(macOS Keychain / Linux libsecret / Windows
//   Credential Manager)。キーチェーン不在環境では型付きエラーで案内し、
//   平文ファイルへのフォールバックは行わない(ディスクレス不変条件)
// - ProcessRunner = Bun.spawn(環境変数へのメモリ注入のみ。stdio は継承)
// - エージェント検出 = gunshi/agent の getAgentProfile

import { Duration, Effect, Layer } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { getAgentProfile } from "gunshi/agent";

import type { CliServices } from "./cli.ts";
import { ConfigStore, defaultConfigPath, makeFileConfigStore } from "./config.ts";
import { cliError } from "./errors.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { KEYCHAIN_SERVICE, Keychain, type KeychainShape } from "./keychain.ts";
import { ProcessRunner, type ProcessRunnerShape } from "./run.ts";

const keychainUnavailable = () =>
  cliError(
    "OS キーチェーンにアクセスできません(この環境ではトークン・鍵を保存できません)。平文ファイルへの保存は行いません — トークンは MARUHI_TOKEN 環境変数で渡せます",
  );

// keyring デーモン不在の headless Linux では Bun.secrets の書き込みが応答なしで
// ブロックすることを実測(Cursor Cloud 環境)。キーチェーンのロック解除
// プロンプト(ユーザー操作)を待つ余地を残しつつ、ハングは案内エラーに落とす
const KEYCHAIN_TIMEOUT = Duration.seconds(30);

function keychainOp<T>(run: () => Promise<T>): Effect.Effect<T, ReturnType<typeof cliError>> {
  return Effect.tryPromise({ try: run, catch: keychainUnavailable }).pipe(
    Effect.timeout(KEYCHAIN_TIMEOUT),
    Effect.catchTag("TimeoutError", () => Effect.fail(keychainUnavailable())),
  );
}

function makeBunKeychain(): KeychainShape {
  return {
    get: (name) => keychainOp(() => Bun.secrets.get({ service: KEYCHAIN_SERVICE, name })),
    set: (name, value) =>
      keychainOp(() => Bun.secrets.set({ service: KEYCHAIN_SERVICE, name, value })),
    remove: (name) =>
      keychainOp(async () => {
        await Bun.secrets.delete({ service: KEYCHAIN_SERVICE, name });
      }),
  };
}

function makeBunProcessRunner(): ProcessRunnerShape {
  return {
    run: ({ command, extraEnv }) =>
      Effect.tryPromise({
        try: async () => {
          // 値は子プロセスの環境変数へのメモリ注入のみ(ディスクレス不変条件)
          const child = Bun.spawn({
            cmd: [...command],
            env: { ...process.env, ...extraEnv },
            stdin: "inherit",
            stdout: "inherit",
            stderr: "inherit",
          });
          return await child.exited;
        },
        catch: () => cliError(`コマンドを起動できません: ${command[0] ?? ""}`),
      }),
  };
}

function makeLiveIo(): CliIoShape {
  return {
    log: (line) => Effect.sync(() => console.log(line)),
    logError: (line) => Effect.sync(() => console.error(line)),
    readStdin: Effect.tryPromise({
      try: async () => {
        const chunks: Uint8Array[] = [];
        for await (const chunk of process.stdin) {
          chunks.push(chunk as Uint8Array);
        }
        const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
        const merged = new Uint8Array(total);
        let offset = 0;
        for (const chunk of chunks) {
          merged.set(chunk, offset);
          offset += chunk.length;
        }
        return merged;
      },
      catch: () => cliError("stdin を読み取れません"),
    }),
    envVar: (name) => process.env[name],
    agentProfile: getAgentProfile,
  };
}

/** Production service layer for the maruhi CLI (Bun runtime). */
export function liveLayer(): Layer.Layer<CliServices> {
  return Layer.mergeAll(
    Layer.succeed(Keychain, makeBunKeychain()),
    Layer.succeed(ConfigStore, makeFileConfigStore(defaultConfigPath((name) => process.env[name]))),
    Layer.succeed(CliIo, makeLiveIo()),
    Layer.succeed(ProcessRunner, makeBunProcessRunner()),
    FetchHttpClient.layer,
  );
}
