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
import { floorDirOf, FloorStore, makeFileFloorStore } from "./floor.ts";
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

/** 対話入力の Ctrl+C / Ctrl+D による中断(EOF・読み取り不能と区別する)。 */
class PromptInterruptedError extends Error {}

const ENTER_CHARS = new Set(["\r", "\n"]);
const ERASE_CHARS = new Set(["\u007f", "\b"]);
const CTRL_C = "\u0003";
const CTRL_D = "\u0004";
const ESCAPE = "\u001b";
// CSI 等のエスケープ列の終端(英字と ~)。矢印キー等の断片を入力に混ぜない
const ESCAPE_END = /[A-Za-z~]/;

/**
 * TTY での非エコー入力(リカバリーコード等の秘密の 1 行)。raw mode で 1 文字
 * ずつ読み、端末には何も表示しない。Backspace は末尾削除、Ctrl+C / Ctrl+D は
 * 中断(raw mode では EOF もキー入力として届く)、矢印キー等のエスケープ列と
 * その他の制御文字は無視する(見えない入力を黙って壊さない)。ストリームの
 * 終端・エラーでも必ず settle する(ハングしない)。テスト用に公開する。
 */
export function readHiddenLine(stdin: NodeJS.ReadStream): Promise<string> {
  return new Promise((resolve, reject) => {
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();
    let line = "";
    let inEscape = false;
    const cleanup = () => {
      stdin.off("data", onData);
      stdin.off("end", onEnd);
      stdin.off("error", onError);
      stdin.setRawMode(wasRaw);
      stdin.pause();
    };
    const finish = (outcome: "done" | "interrupted" | "eof") => {
      cleanup();
      process.stderr.write("\n");
      if (outcome === "done") {
        resolve(line);
      } else if (outcome === "interrupted") {
        reject(new PromptInterruptedError("interrupted"));
      } else {
        reject(new Error(outcome));
      }
    };
    const endOutcome = (ch: string): "done" | "interrupted" | null => {
      if (ENTER_CHARS.has(ch)) {
        return "done";
      }
      if (ch === CTRL_C || ch === CTRL_D) {
        return "interrupted";
      }
      return null;
    };
    // 消去は末尾 1 文字、その他の制御文字(タブ等)は無視、印字可能文字のみ追加
    const applyChar = (ch: string) => {
      if (ERASE_CHARS.has(ch)) {
        line = line.slice(0, -1);
      } else if (ch >= " ") {
        line += ch;
      }
    };
    // 1 文字を処理し、入力が終端した(finish 済み)かを返す
    const handleChar = (ch: string): boolean => {
      if (inEscape) {
        inEscape = !ESCAPE_END.test(ch);
        return false;
      }
      if (ch === ESCAPE) {
        inEscape = true;
        return false;
      }
      const outcome = endOutcome(ch);
      if (outcome !== null) {
        finish(outcome);
        return true;
      }
      applyChar(ch);
      return false;
    };
    const onData = (chunk: Buffer) => {
      for (const ch of chunk.toString("utf8")) {
        if (handleChar(ch)) {
          return;
        }
      }
    };
    const onEnd = () => finish("eof");
    const onError = () => finish("eof");
    stdin.on("data", onData);
    stdin.once("end", onEnd);
    stdin.once("error", onError);
  });
}

/**
 * 非 TTY(パイプ)入力の共有行リーダー。readline を都度作って閉じる形は、
 * 閉じた時点でインスタンスがバッファ済みの次行を捨てるため、複数プロンプトの
 * フロー(復元コードの再入力等)で 2 行目以降が消える。未消費分を保持する
 * 単一のバッファから行を切り出す。テスト用に公開する。
 */
export function makeStdinLineReader(stdin: NodeJS.ReadStream): () => Promise<string> {
  let buffered = "";
  let ended = false;
  const takeLine = (): string | null => {
    const index = buffered.indexOf("\n");
    if (index < 0) {
      return null;
    }
    const line = buffered.slice(0, index);
    buffered = buffered.slice(index + 1);
    return line.endsWith("\r") ? line.slice(0, -1) : line;
  };
  // 改行なしで終端した残り(`printf` の最終行等)も 1 行として返す
  const drainTail = (): string => {
    if (buffered.length === 0) {
      throw new Error("eof");
    }
    const rest = buffered;
    buffered = "";
    return rest;
  };
  const refill = async (): Promise<void> => {
    const chunk = await nextChunk(stdin);
    if (chunk === null) {
      ended = true;
    } else {
      buffered += chunk;
    }
  };
  return async () => {
    for (;;) {
      const line = takeLine();
      if (line !== null) {
        return line;
      }
      if (ended) {
        return drainTail();
      }
      await refill();
    }
  };
}

/** stdin の次のチャンクを 1 つ読む(終端は null。エラーは reject)。 */
function nextChunk(stdin: NodeJS.ReadStream): Promise<string | null> {
  // 'end' は一度しか発火しない: 前回の読み取りでリスナーを外した後に終端して
  // いた場合、イベント待ちは永遠に解決しない。既終端はここで検出する
  if (stdin.readableEnded) {
    return Promise.resolve(null);
  }
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      stdin.off("data", onData);
      stdin.off("end", onEnd);
      stdin.off("error", onError);
      stdin.pause();
    };
    const onData = (chunk: Buffer) => {
      cleanup();
      resolve(chunk.toString("utf8"));
    };
    const onEnd = () => {
      cleanup();
      resolve(null);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    stdin.on("data", onData);
    stdin.once("end", onEnd);
    stdin.once("error", onError);
    stdin.resume();
  });
}

function makeLiveIo(): CliIoShape {
  // 非 TTY 入力の行リーダーはプロセスで 1 つ(プロンプト間で未消費行を保持する)
  const readPipedLine = makeStdinLineReader(process.stdin);
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
    promptLine: ({ prompt, secret }) =>
      Effect.tryPromise({
        try: async () => {
          // プロンプトは stderr へ(stdout をパイプしても対話が壊れない)
          process.stderr.write(prompt);
          const stdin = process.stdin;
          if (secret === true && stdin.isTTY) {
            return await readHiddenLine(stdin);
          }
          // 非 TTY(パイプ入力)ではエコー制御のしようがないためそのまま読む
          return await readPipedLine();
        },
        catch: (error) =>
          cliError(
            error instanceof PromptInterruptedError
              ? "入力が中断されました"
              : "対話入力を読み取れません(非対話環境では実行できない操作です)",
          ),
      }),
    envVar: (name) => process.env[name],
    agentProfile: getAgentProfile,
  };
}

/** Production service layer for the maruhi CLI (Bun runtime). */
export function liveLayer(): Layer.Layer<CliServices> {
  const configPath = defaultConfigPath((name) => process.env[name]);
  return Layer.mergeAll(
    Layer.succeed(Keychain, makeBunKeychain()),
    Layer.succeed(ConfigStore, makeFileConfigStore(configPath)),
    // ローカル床(§6.3)は設定と同系の非機密置き場(<config dir>/floor)
    Layer.succeed(FloorStore, makeFileFloorStore(floorDirOf(configPath))),
    Layer.succeed(CliIo, makeLiveIo()),
    Layer.succeed(ProcessRunner, makeBunProcessRunner()),
    FetchHttpClient.layer,
  );
}
