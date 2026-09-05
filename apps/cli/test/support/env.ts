// テスト用のサービス層: インメモリキーチェーン・出力捕捉 CliIo・記録型
// ProcessRunner・一時ディレクトリの設定ストア・実 fetch の HttpClient。
// 実キーチェーン(Bun.secrets)は CI に存在しないため結合しない(タスク指示)。

import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Effect, Layer, Redacted, Stdio } from "effect";
import { FetchHttpClient } from "effect/unstable/http";

import { AgentProfileRef } from "../../src/agent-gate.ts";
import type { CliServices } from "../../src/cli.ts";
import { ConfigStore, makeFileConfigStore } from "../../src/config.ts";
import { cliError } from "../../src/errors.ts";
import { makeFileFloorStore } from "../../src/floor-log.ts";
import { floorDirOf, FloorStore } from "../../src/floor.ts";
import { type AgentProfile, CliIo } from "../../src/io.ts";
import {
  Keychain,
  masterKeyEntryName,
  type StoredMasterKey,
  serializeStoredMasterKey,
  serializeStoredToken,
  type StoredToken,
  tokenEntryName,
} from "../../src/keychain.ts";
import { makeFilePinStore, PinStore, pinsDirOf } from "../../src/pins.ts";
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
  /** ローカル床(§6.3)のディレクトリ(<configDir>/floor)。 */
  readonly floorDir: string;
  /** 招待ピン(§6.3 (a) アンカー + 発行ピン)のディレクトリ(<configDir>/invites)。 */
  readonly pinsDir: string;
  /** promptLine に表示されたプロンプト文字列(検査用)。 */
  readonly prompts: string[];
  /** openBrowser に渡された URL(login のブラウザ自動起動分岐の検査用)。 */
  readonly browserOpens: string[];
  setStdin(bytes: Uint8Array): void;
  /**
   * 端末判定(`Stdio`)の偽装。値の表示可否の**一次境界**なので、既定は
   * 「人間の対話端末」= stdin / stdout / stderr が端末。パイプ・リダイレクト・
   * CI・未知のエージェントを再現するときに false を渡す。
   */
  setTerminal(input: {
    readonly stdin?: boolean;
    readonly stdout?: boolean;
    readonly stderr?: boolean;
  }): void;
  /**
   * promptLine が順に返す応答をキューする(枯渇後は失敗 = EOF 相当)。
   * 関数は応答時点で評価される(表示済みログから値を導く応答のため —
   * リカバリーコードの保存確認等)。
   */
  setPromptResponses(lines: readonly (string | (() => string))[]): void;
  setAgent(profile: AgentProfile): void;
  /** stderr の接頭辞の色(notice.ts)。既定は無色 — 断言を素の文字列で書けるように。 */
  setColor(enabled: boolean): void;
  setEnvVar(name: string, value: string | undefined): void;
  setRunnerExitCode(code: number): void;
  /** openBrowser の成否を偽装する(既定は成功)。 */
  setBrowserOpenSucceeds(succeeds: boolean): void;
  /** キーチェーン書き込みを失敗させる(login の失効フォールバック検査用)。 */
  failKeychainWrites(): void;
  /**
   * 受理された push の床コミットだけを失敗させる(読み取り・pull コミットは
   * 通す)。床は SHOULD であり、書けなかった場合でも検出が床だけに依存して
   * いないことを固定するために使う。
   */
  failFloorPushCommits(): void;
  /**
   * intent(3-F)の追記だけを失敗させる。journal-before-send は床の書き込みで
   * 唯一の fail-closed(永続化に失敗したら送信しない)であり、fail-open へ
   * 巻かれる退行を「サーバーへ 1 リクエストも飛ばないこと」で固定するために使う。
   */
  failFloorIntentAppends(): void;
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
  const prompts: string[] = [];
  const promptResponses: (string | (() => string))[] = [];
  const browserOpens: string[] = [];
  let browserOpenSucceeds = true;
  let stdin: Uint8Array = new Uint8Array(0);
  let agent: AgentProfile = { isAgent: false };
  let colorEnabled = false;
  // 既定は「人間が対話端末で実行した」形(値の表示が許される唯一の形)
  let stdinIsTerminal = true;
  let stdoutIsTerminal = true;
  let stderrIsTerminal = true;
  let runnerExitCode = 0;
  let keychainWritable = true;
  let floorPushCommittable = true;
  let floorIntentAppendable = true;
  let configLoadDefect = false;

  const fileStore = makeFileConfigStore(configPath);
  const floorDir = floorDirOf(configPath);
  const floorStore = makeFileFloorStore(floorDir);
  const pinsDir = pinsDirOf(configPath);
  const pinStore = makeFilePinStore(pinsDir);
  const layer = Layer.mergeAll(
    // argv は runCli が実行ごとに渡す(effect-cli.ts が Stdio へ載せ替える)。
    // ここで固定するのは端末判定 — 値の表示可否の一次境界(agent-gate.ts)
    Stdio.layerTest({
      stdinIsTerminal: Effect.sync(() => stdinIsTerminal),
      stdoutIsTerminal: Effect.sync(() => stdoutIsTerminal),
    }),
    // 二次層(既知エージェントの検出結果)。本番は live.ts が std-env から供給する
    Layer.sync(AgentProfileRef, () => agent),
    Layer.succeed(PinStore, pinStore),
    Layer.succeed(FloorStore, {
      load: (projectId) => floorStore.load(projectId),
      commitHead: (projectId, head) => floorStore.commitHead(projectId, head),
      commitPull: (projectId, commit) => floorStore.commitPull(projectId, commit),
      commitPush: (projectId, commit) =>
        Effect.suspend(() =>
          floorPushCommittable
            ? floorStore.commitPush(projectId, commit)
            : Effect.fail(cliError("ローカル床に書き込めません(テスト注入)")),
        ),
      commitMetadata: (projectId, commit) => floorStore.commitMetadata(projectId, commit),
      commitManifest: (projectId, commit) =>
        Effect.suspend(() =>
          floorPushCommittable
            ? floorStore.commitManifest(projectId, commit)
            : Effect.fail(cliError("ローカル床に書き込めません(テスト注入)")),
        ),
      appendIntent: (projectId, intent) =>
        Effect.suspend(() =>
          floorIntentAppendable
            ? floorStore.appendIntent(projectId, intent)
            : Effect.fail(cliError("ローカル床に intent を書き込めません(テスト注入)")),
        ),
      resolveIntent: (projectId, intentId, outcome) =>
        floorStore.resolveIntent(projectId, intentId, outcome),
      loadAttestedHead: (projectId) => floorStore.loadAttestedHead(projectId),
      saveAttestedHead: (projectId, head) => floorStore.saveAttestedHead(projectId, head),
      appendAttestationEvidence: (projectId, evidence) =>
        floorStore.appendAttestationEvidence(projectId, evidence),
    }),
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
      promptLine: ({ prompt }) =>
        Effect.suspend(() => {
          prompts.push(prompt);
          const next = promptResponses.shift();
          return next === undefined
            ? Effect.fail(cliError("対話入力を読み取れません(テスト: 応答キューが空)"))
            : Effect.succeed(typeof next === "function" ? next() : next);
        }),
      envVar: (name) => envVars.get(name),
      agentProfile: () => agent,
      stderrIsTerminal: () => stderrIsTerminal,
      colorEnabled: () => colorEnabled,
      openBrowser: (url) =>
        Effect.sync(() => {
          browserOpens.push(url);
          return browserOpenSucceeds;
        }),
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
    floorDir,
    pinsDir,
    prompts,
    browserOpens,
    setStdin(bytes) {
      stdin = bytes;
    },
    setTerminal({ stdin: isStdinTerminal, stdout: isStdoutTerminal, stderr: isStderrTerminal }) {
      stdinIsTerminal = isStdinTerminal ?? stdinIsTerminal;
      stdoutIsTerminal = isStdoutTerminal ?? stdoutIsTerminal;
      stderrIsTerminal = isStderrTerminal ?? stderrIsTerminal;
    },
    setPromptResponses(lines) {
      promptResponses.length = 0;
      promptResponses.push(...lines);
    },
    setAgent(profile) {
      agent = profile;
    },
    setColor(enabled) {
      colorEnabled = enabled;
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
    setBrowserOpenSucceeds(succeeds) {
      browserOpenSucceeds = succeeds;
    },
    failKeychainWrites() {
      keychainWritable = false;
    },
    failFloorPushCommits() {
      floorPushCommittable = false;
    },
    failFloorIntentAppends() {
      floorIntentAppendable = false;
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
    token: Redacted.make("maruhi_pat_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9x123"),
    userId: user.userId,
    tokenId: "tok_0001",
  };
  const master: StoredMasterKey = {
    suite: "maruhi/v1",
    encPubHex: user.encPubHex,
    encSkHex: Redacted.make(user.encSkHex),
    sigPubHex: user.sigPubHex,
    sigSkSeedHex: Redacted.make(user.sigSkSeedHex),
  };
  // JSON.stringify(token) は使えない — Redacted.toJSON() が伏字を返し、
  // 「シードしたのに認証できない」テストになる(本番の login.ts と同じ罠)
  env.keychain.set(tokenEntryName(origin), serializeStoredToken(token));
  // master 鍵も JSON.stringify は使えない(秘密側が伏字で保存され復号不能になる)
  env.keychain.set(masterKeyEntryName(origin, user.userId), serializeStoredMasterKey(master));
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
