// maruhi CLI のコマンド定義(Gunshi)と Effect 実行の結線。
//
// コマンド階層は 1 段(サブコマンド + positional の action)。値の入力は
// stdin(argv に平文値を載せない)、値の表示は pull --show のみで、AI
// エージェント検出時は拒否する(agent.ts)。`maruhi run` は許可される。

import { hostname } from "node:os";

import { Effect, Layer } from "effect";
import type { HttpClient } from "effect/unstable/http";
import { cli, define } from "gunshi";

import { ensureValueDisplayAllowed } from "./agent.ts";
import { makeApiClient, type MaruhiClient } from "./api.ts";
import { asConfigKey, type CliConfig, CONFIG_KEYS, ConfigStore } from "./config.ts";
import type { DekRecipient } from "./deks.ts";
import { displayText, displayValue } from "./display.ts";
import { envCreateOp } from "./env-create.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import { Keychain } from "./keychain.ts";
import { keyGenerateOp, keyShowOp } from "./keygen.ts";
import { loginOp, logoutOp } from "./login.ts";
import { projectInitOp } from "./project-init.ts";
import { type DecryptedVariable, type PulledVariables, pullVariables } from "./pull.ts";
import { pushVariable } from "./push.ts";
import { ProcessRunner, runOp } from "./run.ts";
import {
  type CliSession,
  loadMasterKeys,
  type MasterKeys,
  normalizeHttpOrigin,
  resolveServerOrigin,
  resolveSession,
} from "./session.ts";
import { syncProject, type VerifiedProject } from "./sync.ts";

/** Services every CLI command may need (production wiring lives in live.ts). */
export type CliServices = Keychain | ConfigStore | CliIo | ProcessRunner | HttpClient.HttpClient;

const CLI_VERSION = "0.0.0";

// AUTH_SPEC §12-1 の受理ポリシー形式(クライアント側の早期検証)
const RESOURCE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const PROJECT_ID_PATTERN = /^[0-9a-f]{64}$/;

interface CommonFlags {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly env?: string | undefined;
}

function resolveProjectId(
  flag: string | undefined,
  config: CliConfig,
): Effect.Effect<string, CliError> {
  const value = flag ?? config.defaultProject;
  if (value === undefined) {
    return Effect.fail(
      cliError(
        "プロジェクトが未指定です。--project <id> か `maruhi config set defaultProject <id>` を使ってください",
      ),
    );
  }
  if (!PROJECT_ID_PATTERN.test(value)) {
    return Effect.fail(cliError(`プロジェクト ID の形式が不正です: ${value}`));
  }
  return Effect.succeed(value);
}

function resolveEnvironmentId(
  flag: string | undefined,
  config: CliConfig,
): Effect.Effect<string, CliError> {
  const value = flag ?? config.defaultEnvironment;
  if (value === undefined) {
    return Effect.fail(
      cliError(
        "環境が未指定です。--env <id> か `maruhi config set defaultEnvironment <id>` を使ってください",
      ),
    );
  }
  if (!RESOURCE_ID_PATTERN.test(value)) {
    return Effect.fail(cliError(`環境 ID の形式が不正です: ${value}`));
  }
  return Effect.succeed(value);
}

interface SessionContext {
  readonly config: CliConfig;
  readonly origin: string;
  readonly session: CliSession;
  readonly client: MaruhiClient;
}

function openSession(
  serverFlag: string | undefined,
): Effect.Effect<SessionContext, CliError, CliServices> {
  return Effect.gen(function* () {
    const store = yield* ConfigStore;
    const config = yield* store.load;
    const origin = yield* resolveServerOrigin(serverFlag, config);
    const session = yield* resolveSession(origin);
    const client = yield* makeApiClient({ baseUrl: origin, token: session.token });
    return { config, origin, session, client };
  });
}

interface ProjectContext extends SessionContext {
  readonly masterKeys: MasterKeys;
  readonly recipient: DekRecipient;
  readonly projectId: string;
  readonly verified: VerifiedProject;
}

/** データ系コマンド共通の前段: ID 検証 → セッション → master 鍵 → §6.3 同期検査。 */
function openProject(flags: CommonFlags): Effect.Effect<ProjectContext, CliError, CliServices> {
  return Effect.gen(function* () {
    // プロジェクト ID の形式検証はネットワークアクセスより先に行う
    const store = yield* ConfigStore;
    const projectId = yield* resolveProjectId(flags.project, yield* store.load);
    const context = yield* openSession(flags.server);
    const masterKeys = yield* loadMasterKeys(context.session);
    const verified = yield* syncProject(context.client, projectId);
    const recipient: DekRecipient = {
      userId: context.session.userId,
      encPubHex: masterKeys.record.encPubHex,
      encKeyPair: masterKeys.encKeyPair,
    };
    return { ...context, masterKeys, recipient, projectId, verified };
  });
}

function formatPulledLine(variable: DecryptedVariable): string {
  return `${displayText(variable.name)}\tversion=${variable.version}\tepoch=${variable.epoch}\t(${variable.value.byteLength} bytes)`;
}

/** 検証中に収集した SHOULD 警告(非 NFC 名の配布等 — §12-1)を表示する。 */
function logWarnings(warnings: readonly string[]): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    for (const warning of warnings) {
      yield* io.logError(`警告: ${warning}`);
    }
  });
}

const displayDecoder = new TextDecoder("utf-8", { fatal: false });

/** 値の端末表示(pull --show)。エージェント検出時は agent.ts が拒否する。 */
function showValues(variables: readonly DecryptedVariable[]): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensureValueDisplayAllowed(io.agentProfile());
    for (const variable of variables) {
      yield* io.log(
        `${displayText(variable.name)}=${displayValue(displayDecoder.decode(variable.value))}`,
      );
    }
  });
}

/** stdin の値: 末尾の改行 1 つ(LF / CRLF)は落とす(`echo` 由来の混入対策)。 */
export function normalizeStdinValue(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0 && bytes[bytes.length - 1] === 0x0a) {
    const end = bytes.length > 1 && bytes[bytes.length - 2] === 0x0d ? -2 : -1;
    return bytes.slice(0, end);
  }
  return bytes;
}

type CliProgram = Effect.Effect<number | void, CliError, CliServices>;

/** コマンド本体(Effect プログラム)を実行し、終了コードを蓄積する。 */
type Execute = (program: CliProgram) => Promise<void>;

function loginCommand(execute: Execute) {
  return define({
    name: "login",
    description: "GitHub device flow でログインし、maruhi トークンを OS キーチェーンに保存する",
    args: {
      server: { type: "string", description: "サーバー URL(省略時は config の server)" },
      "github-client-id": {
        type: "string",
        description: "GitHub OAuth App の client_id(省略時は config の githubClientId)",
      },
      "token-name": {
        type: "string",
        description: "トークン名(同名の再ログインはローテーション。既定: cli:<hostname>)",
      },
      "github-base-url": {
        type: "string",
        description: "GitHub の base URL(テスト用)",
        hidden: true,
      },
      "github-poll-interval": {
        type: "number",
        description: "device flow ポーリング間隔の下限秒(テスト用)",
        hidden: true,
      },
    },
    run: (ctx) =>
      execute(
        Effect.gen(function* () {
          const store = yield* ConfigStore;
          const config = yield* store.load;
          const origin = yield* resolveServerOrigin(ctx.values.server, config);
          const clientId = ctx.values["github-client-id"] ?? config.githubClientId;
          if (clientId === undefined) {
            return yield* Effect.fail(
              cliError(
                "GitHub OAuth App の client_id が未設定です。--github-client-id を指定するか、`maruhi config set githubClientId <id>` で設定してください(セルフホストではサーバーと同じ OAuth App を使います)",
              ),
            );
          }
          // --github-base-url は GHES / テスト用の上書き。既定の GitHub から
          // 外す以上、http を任意ホストへ向ける経路を塞ぐ(https か loopback のみ)
          const githubBaseUrl =
            ctx.values["github-base-url"] === undefined
              ? undefined
              : yield* normalizeHttpOrigin(ctx.values["github-base-url"], "GitHub base URL");
          const minIntervalSeconds = ctx.values["github-poll-interval"];
          yield* loginOp({
            origin,
            clientId,
            tokenName: ctx.values["token-name"] ?? `cli:${hostname()}`,
            ...(githubBaseUrl === undefined ? {} : { githubBaseUrl }),
            ...(minIntervalSeconds === undefined ? {} : { minIntervalSeconds }),
          });
        }),
      ),
  });
}

function logoutCommand(execute: Execute) {
  return define({
    name: "logout",
    description: "自トークンを失効させ、OS キーチェーンから削除する",
    args: {
      server: { type: "string", description: "サーバー URL(省略時は config の server)" },
    },
    run: (ctx) =>
      execute(
        Effect.gen(function* () {
          const store = yield* ConfigStore;
          const config = yield* store.load;
          const origin = yield* resolveServerOrigin(ctx.values.server, config);
          yield* logoutOp({ origin });
        }),
      ),
  });
}

function keyCommand(execute: Execute) {
  return define({
    name: "key",
    description: "master keypair の管理(generate / show)",
    args: {
      action: { type: "positional", description: "generate | show" },
      server: { type: "string", description: "サーバー URL(省略時は config の server)" },
    },
    run: (ctx) =>
      execute(
        Effect.gen(function* () {
          const context = yield* openSession(ctx.values.server);
          if (ctx.values.action === "generate") {
            return yield* keyGenerateOp({ session: context.session });
          }
          if (ctx.values.action === "show") {
            return yield* keyShowOp({ session: context.session });
          }
          return yield* Effect.fail(
            cliError(`不明な操作です: ${ctx.values.action}(generate | show)`),
          );
        }),
      ),
  });
}

function projectCommand(execute: Execute) {
  return define({
    name: "project",
    description: "プロジェクトの管理(init / verify)",
    args: {
      action: { type: "positional", description: "init | verify" },
      server: { type: "string", description: "サーバー URL(省略時は config の server)" },
      org: { type: "string", description: "init 時の所属 org(複数所属時のみ必要)" },
      project: { type: "string", description: "verify 対象のプロジェクト ID" },
    },
    run: (ctx) =>
      execute(
        Effect.gen(function* () {
          if (ctx.values.action === "init") {
            const context = yield* openSession(ctx.values.server);
            const masterKeys = yield* loadMasterKeys(context.session);
            const org = ctx.values.org;
            yield* projectInitOp({
              client: context.client,
              session: context.session,
              masterKeys,
              ...(org === undefined ? {} : { orgFlag: org }),
            });
            return;
          }
          if (ctx.values.action === "verify") {
            const io = yield* CliIo;
            const context = yield* openSession(ctx.values.server);
            const projectId = yield* resolveProjectId(ctx.values.project, context.config);
            const verified = yield* syncProject(context.client, projectId);
            yield* io.log(`チェーン検証 OK(head seq=${verified.state.headSeq})`);
            yield* io.log(`head: ${verified.state.headHashHex}`);
            yield* io.log(`メンバー(${verified.state.members.size}):`);
            for (const member of verified.state.members.values()) {
              yield* io.log(
                `  ${displayText(member.userId)}\t${member.role}\tfp=${member.keyFingerprintHex}`,
              );
            }
            for (const [environmentId, environment] of verified.state.environments) {
              yield* io.log(
                `環境 ${environmentId}: epoch=${environment.currentEpoch}(作成 seq=${environment.createdAtSeq})`,
              );
            }
            return;
          }
          return yield* Effect.fail(
            cliError(`不明な操作です: ${ctx.values.action}(init | verify)`),
          );
        }),
      ),
  });
}

function envCommand(execute: Execute) {
  return define({
    name: "env",
    description: "環境の管理(create)",
    args: {
      action: { type: "positional", description: "create" },
      "environment-id": { type: "positional", description: "環境 ID(例: dev / prod)" },
      name: { type: "string", description: "表示名(省略時は環境 ID)" },
      server: { type: "string", description: "サーバー URL(省略時は config の server)" },
      project: {
        type: "string",
        description: "プロジェクト ID(省略時は config の defaultProject)",
      },
    },
    run: (ctx) =>
      execute(
        Effect.gen(function* () {
          if (ctx.values.action !== "create") {
            return yield* Effect.fail(cliError(`不明な操作です: ${ctx.values.action}(create)`));
          }
          const environmentId = ctx.values["environment-id"];
          // positional 未指定は undefined。RegExp.test は "undefined" に
          // 文字列化してパターンに通ってしまうため、型で明示的に弾く
          if (environmentId === undefined || !RESOURCE_ID_PATTERN.test(environmentId)) {
            return yield* Effect.fail(
              cliError(
                `環境 ID を指定してください(例: maruhi env create dev)。指定値: ${String(environmentId)}`,
              ),
            );
          }
          const io = yield* CliIo;
          const context = yield* openProject({
            server: ctx.values.server,
            project: ctx.values.project,
          });
          const created = yield* envCreateOp({
            client: context.client,
            verified: context.verified,
            environmentId,
            name: ctx.values.name ?? environmentId,
            signerUserId: context.session.userId,
            signingKeyPair: context.masterKeys.sigKeyPair,
            resync: syncProject(context.client, context.projectId),
          });
          yield* io.log(
            `環境を作成しました: ${environmentId}(epoch=${created.currentEpoch}、DEK を現メンバー ${context.verified.state.members.size} 名へラップ済み)`,
          );
        }),
      ),
  });
}

function pullCommand(execute: Execute) {
  return define({
    name: "pull",
    description: "同期検査(§6.3)+ 配布時検証(§5.1)+ 復号し、メタデータを表示する",
    args: {
      server: { type: "string", description: "サーバー URL(省略時は config の server)" },
      project: {
        type: "string",
        description: "プロジェクト ID(省略時は config の defaultProject)",
      },
      env: { type: "string", description: "環境 ID(省略時は config の defaultEnvironment)" },
      show: {
        type: "boolean",
        description: "値を端末に表示する(AI エージェント環境では拒否される)",
      },
    },
    run: (ctx) =>
      execute(
        Effect.gen(function* () {
          const io = yield* CliIo;
          const store = yield* ConfigStore;
          // 環境 ID の形式検証はネットワークアクセスより先に行う
          const environmentId = yield* resolveEnvironmentId(ctx.values.env, yield* store.load);
          const context = yield* openProject(ctx.values);
          const pulled: PulledVariables = yield* pullVariables({
            client: context.client,
            verified: context.verified,
            environmentId,
            recipient: context.recipient,
            resync: syncProject(context.client, context.projectId),
          });
          yield* logWarnings(pulled.warnings);
          yield* io.log(`同期・検証 OK: ${pulled.variables.length} 変数(環境 ${environmentId})`);
          for (const variable of pulled.variables) {
            yield* io.log(formatPulledLine(variable));
          }
          if (ctx.values.show === true) {
            yield* showValues(pulled.variables);
          }
        }),
      ),
  });
}

function pushCommand(execute: Execute) {
  return define({
    name: "push",
    description: "stdin から読んだ値を暗号化して push する(末尾の改行 1 つは除去)",
    args: {
      name: { type: "positional", description: "変数名(表示名。環境変数名になる)" },
      server: { type: "string", description: "サーバー URL(省略時は config の server)" },
      project: {
        type: "string",
        description: "プロジェクト ID(省略時は config の defaultProject)",
      },
      env: { type: "string", description: "環境 ID(省略時は config の defaultEnvironment)" },
    },
    run: (ctx) =>
      execute(
        Effect.gen(function* () {
          const io = yield* CliIo;
          const store = yield* ConfigStore;
          const environmentId = yield* resolveEnvironmentId(ctx.values.env, yield* store.load);
          const context = yield* openProject(ctx.values);
          const value = normalizeStdinValue(yield* io.readStdin);
          const pushed = yield* pushVariable({
            client: context.client,
            environmentId,
            recipient: context.recipient,
            name: ctx.values.name,
            value,
            verified: context.verified,
            resync: syncProject(context.client, context.projectId),
            // 値署名(§4.1)/ 作成時のステートメント著者署名(§4.2):
            // writer / author = 自分の内部 user_id、鍵 = master sig 鍵
            writerUserId: context.session.userId,
            signingKey: context.masterKeys.sigKeyPair.privateKey,
          });
          yield* logWarnings(pushed.warnings);
          yield* io.log(
            `push しました: ${ctx.values.name}(version=${pushed.version}, epoch=${pushed.epoch})`,
          );
        }),
      ),
  });
}

function runCommand(execute: Execute) {
  return define({
    name: "run",
    description: "pull + 復号した値を子プロセスの環境変数へメモリ注入してコマンドを実行する",
    args: {
      server: { type: "string", description: "サーバー URL(省略時は config の server)" },
      project: {
        type: "string",
        description: "プロジェクト ID(省略時は config の defaultProject)",
      },
      env: { type: "string", description: "環境 ID(省略時は config の defaultEnvironment)" },
    },
    run: (ctx) =>
      execute(
        Effect.gen(function* () {
          const store = yield* ConfigStore;
          const environmentId = yield* resolveEnvironmentId(ctx.values.env, yield* store.load);
          const context = yield* openProject(ctx.values);
          const pulled = yield* pullVariables({
            client: context.client,
            verified: context.verified,
            environmentId,
            recipient: context.recipient,
            resync: syncProject(context.client, context.projectId),
          });
          yield* logWarnings(pulled.warnings);
          // `maruhi run` の環境変数名は検証済みステートメント経由(§4.2 / §12-7)。
          // 実行制御系変数名 denylist(run.ts)は検証済み name に適用される防衛層
          return yield* runOp({ command: ctx.rest, variables: pulled.variables });
        }),
      ),
  });
}

function configCommand(execute: Execute) {
  return define({
    name: "config",
    description: "非機密設定の管理(get / set)。シークレットはここに保存されない",
    args: {
      action: { type: "positional", description: "get | set" },
      key: { type: "positional", description: `設定キー(${CONFIG_KEYS.join(" | ")})` },
      value: { type: "positional", description: "set 時の値", required: false },
    },
    run: (ctx) =>
      execute(
        Effect.gen(function* () {
          const io = yield* CliIo;
          const store = yield* ConfigStore;
          const key = asConfigKey(ctx.values.key);
          if (key === null) {
            return yield* Effect.fail(
              cliError(`不明な設定キーです: ${ctx.values.key}(${CONFIG_KEYS.join(" | ")})`),
            );
          }
          if (ctx.values.action === "get") {
            const config = yield* store.load;
            yield* io.log(config[key] ?? "");
            return;
          }
          if (ctx.values.action === "set") {
            const value = ctx.values.value;
            if (value === undefined) {
              return yield* Effect.fail(cliError("設定する値を指定してください"));
            }
            // 壊れた設定ファイルは set で作り直せるようにする(非機密のみの
            // ファイルなので破棄してよい — CLI 内から復旧不能にしない)
            const config = yield* store.load.pipe(
              Effect.catch(() => Effect.succeed<CliConfig>({})),
            );
            yield* store.save({ ...config, [key]: value });
            yield* io.log(`${key} を設定しました`);
            return;
          }
          return yield* Effect.fail(cliError(`不明な操作です: ${ctx.values.action}(get | set)`));
        }),
      ),
  });
}

function entryCommand(execute: Execute) {
  return define({
    name: "maruhi",
    description: "maruhi — ディスクレス secrets 管理 CLI",
    run: () =>
      execute(
        Effect.gen(function* () {
          const io = yield* CliIo;
          yield* io.log("使い方: maruhi <command> [options]");
          yield* io.log(
            "commands: login / logout / key / project / env / pull / push / run / config",
          );
          yield* io.log("詳細: maruhi <command> --help");
        }),
      ),
  });
}

/**
 * Runs the maruhi CLI against `argv` with the given service layer and
 * returns the process exit code (0 = success, 1 = failure, 2 = usage error).
 */
export async function runCli(
  argv: readonly string[],
  layer: Layer.Layer<CliServices>,
): Promise<number> {
  let exitCode = 0;

  const execute: Execute = async (program) => {
    const handled = program.pipe(
      Effect.map((code) => (typeof code === "number" ? code : 0)),
      Effect.catch((error) =>
        Effect.gen(function* () {
          const io = yield* CliIo;
          yield* io.logError(`maruhi: ${toCliError(error).message}`);
          return 1;
        }),
      ),
      // defect(バグ)を usage エラー(2)に化けさせない: runPromise の
      // reject → gunshi 経由で外側 catch へ落ちると exit 2 になってしまう
      Effect.catchDefect((defect) =>
        Effect.gen(function* () {
          const io = yield* CliIo;
          const message = defect instanceof Error ? defect.message : String(defect);
          yield* io.logError(`maruhi: 内部エラー: ${message}`);
          return 1;
        }),
      ),
      Effect.provide(layer),
    );
    exitCode = await Effect.runPromise(handled);
  };

  try {
    await cli([...argv], entryCommand(execute), {
      name: "maruhi",
      version: CLI_VERSION,
      description: "maruhi — ディスクレス secrets 管理 CLI",
      subCommands: {
        login: loginCommand(execute),
        logout: logoutCommand(execute),
        key: keyCommand(execute),
        project: projectCommand(execute),
        env: envCommand(execute),
        pull: pullCommand(execute),
        push: pushCommand(execute),
        run: runCommand(execute),
        config: configCommand(execute),
      },
    });
  } catch (error) {
    // 引数検証・未知コマンドは usage エラー(2)。メッセージは gunshi のものを使う
    const message = error instanceof Error ? error.message : "引数を解釈できません";
    await Effect.runPromise(
      Effect.gen(function* () {
        const io = yield* CliIo;
        yield* io.logError(`maruhi: ${message}`);
      }).pipe(Effect.provide(layer)),
    );
    return 2;
  }
  return exitCode;
}
