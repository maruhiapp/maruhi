// maruhi CLI のコマンド定義(Gunshi)と Effect 実行の結線。
//
// コマンド階層は 1 段(サブコマンド + positional の action)。値の入力は
// stdin(argv に平文値を載せない)、値の表示は pull --show のみで、AI
// エージェント検出時は拒否する(agent.ts)。`maruhi run` は許可される。

import { hostname } from "node:os";

import { type EnvironmentId, isEnvironmentId } from "@maruhi/core";
import { Effect, Layer } from "effect";
import { cli, define } from "gunshi";

import { ensureValueDisplayAllowed } from "./agent.ts";
import { asConfigKey, type CliConfig, CONFIG_KEYS, ConfigStore } from "./config.ts";
import type { CliServices, CommonFlags } from "./context.ts";
import {
  loadCheckedFloor,
  openEnvironment,
  openProject,
  openSession,
  resolveProjectId,
} from "./context.ts";
import { displayText, formatPulledLine, logWarnings, showValues } from "./display.ts";
import { envCreateOp } from "./env-create.ts";
import { envRotateOp, type RotationSummary } from "./env-rotate.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import { keyGenerateOp, keyShowOp } from "./keygen.ts";
import { loginOp, logoutOp, resolveClientId } from "./login.ts";
import { projectInitOp } from "./project-init.ts";
import { type PulledVariables, pullVariables } from "./pull.ts";
import { pushVariable } from "./push.ts";
import { issueRecoveryCodeOp, recoverMasterKeyOp } from "./recovery.ts";
import { runOp } from "./run.ts";
import { loadMasterKeys, normalizeHttpOrigin, resolveServerOrigin } from "./session.ts";
import { syncProject } from "./sync.ts";

export type { CliServices } from "./context.ts";

const CLI_VERSION = "0.0.0";

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
        description:
          "GitHub OAuth App の client_id(省略時は config の githubClientId → サーバーの /auth/config から自動解決)",
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
          // フラグ → config → サーバーの公開設定エンドポイント(AUTH_SPEC §4)
          const clientId = yield* resolveClientId({
            origin,
            explicit: ctx.values["github-client-id"],
            configured: config.githubClientId,
          });
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
    description: "master keypair の管理(generate / show / recover / recovery)",
    args: {
      action: {
        type: "positional",
        description: "generate | show | recover(コードから復元)| recovery(コードの発行・再発行)",
      },
      server: { type: "string", description: "サーバー URL(省略時は config の server)" },
    },
    run: (ctx) =>
      execute(
        Effect.gen(function* () {
          const context = yield* openSession(ctx.values.server);
          if (ctx.values.action === "generate") {
            return yield* keyGenerateOp({ session: context.session, client: context.client });
          }
          if (ctx.values.action === "show") {
            return yield* keyShowOp({ session: context.session, client: context.client });
          }
          if (ctx.values.action === "recover") {
            return yield* recoverMasterKeyOp({ session: context.session, client: context.client });
          }
          if (ctx.values.action === "recovery") {
            const masterKeys = yield* loadMasterKeys(context.session);
            return yield* issueRecoveryCodeOp({
              session: context.session,
              client: context.client,
              masterKeys,
            });
          }
          return yield* Effect.fail(
            cliError(`不明な操作です: ${ctx.values.action}(generate | show | recover | recovery)`),
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
            const synced = yield* syncProject(context.client, projectId);
            // チェーン床の検査(§6.3 規則 (a))も verify の一部
            const verified = (yield* loadCheckedFloor(
              projectId,
              synced,
              syncProject(context.client, projectId),
            )).verified;
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

/** `maruhi env create <id>`: 複合リクエストによる環境作成(§12-4)。 */
function envCreate(
  flags: CommonFlags & { readonly name?: string | undefined },
  environmentId: EnvironmentId,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const context = yield* openProject(flags);
    const created = yield* envCreateOp({
      client: context.client,
      verified: context.verified,
      environmentId,
      name: flags.name ?? environmentId,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
    });
    yield* io.log(
      `環境を作成しました: ${environmentId}(epoch=${created.currentEpoch}、DEK を現メンバー ${context.verified.state.members.size} 名へラップ済み)`,
    );
  });
}

/**
 * 部分完了 / 完了未検証の報告。エポックは進んでおり、旧エポックの DEK 保持者は
 * 未再暗号化の変数の現在値を読めるままである(§7)。「完了」の顔で終わらせず、
 * 成功終了にもしない。
 */
function reportPartialRotation(
  environmentId: EnvironmentId,
  summary: RotationSummary,
  scope: string,
  skipped: string,
): Effect.Effect<number, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // 中断した場合の残数は上限であって実測ではない(再走査へ到達していないため、
    // 競合分が既に他メンバーによって新エポックで書かれている可能性が残る)。
    // 断定せず「未確認を含む」と示す
    const scale =
      summary.remaining > 0
        ? `未完了 ${summary.remaining} 変数${summary.failure === null ? "" : "(未確認を含む)"}`
        : "完了を検証できませんでした";
    yield* io.log(`部分完了: ${scope}(再暗号化 ${summary.reencrypted} 変数${skipped}、${scale})`);
    // 中断原因がある場合はそれを明示する(エポックだけが進んだ事実を、生の
    // エラーだけ出して伝え損ねない)
    const cause =
      summary.failure === null
        ? "並行 push との競合が解消しませんでした"
        : `再暗号化が中断しました: ${summary.failure}`;
    yield* io.logError(
      `警告: 環境 ${environmentId} の再暗号化が完了していません(${cause})。未再暗号化の現在値は epoch ${summary.epoch} 未満の DEK のままです — 原因を解消したうえで maruhi env rotate ${environmentId} を再実行すると、エポックを進めずに残りから再開します(再実行は残りを再走査するため、実際の未完了数もそこで確定します)。ただし原因が検証失敗・ローカル床違反(= サーバー応答の矛盾)である場合、再実行では解消しません — 配布された証拠を調査してください`,
    );
    return 1;
  });
}

/**
 * ローテーション結果の報告と終了コード。完了サマリは再暗号化の実績を報告し、
 * 未完了分(部分完了)は警告として明示する — 「エポックだけ進んで再暗号化が
 * 残っている」状態を成功の顔で終わらせない。
 */
function reportRotation(
  environmentId: EnvironmentId,
  summary: RotationSummary,
): Effect.Effect<number, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* logWarnings(summary.warnings);
    const skipped =
      summary.alreadyCurrent === 0
        ? ""
        : `、並行更新により再暗号化不要 ${summary.alreadyCurrent} 変数`;
    if (summary.mode === "up-to-date") {
      // 確認のみ(未完了なし・新エポック未要求)。部分完了の案内が勧める
      // 再実行の着地点でもあるので、何もしなかったことを明示する
      yield* io.log(
        `確認完了: 環境 ${environmentId} のアクティブ変数はすべて epoch ${summary.epoch} で暗号化されています(未完了の再暗号化はありません)。新しいエポックを作るには --reason を指定してください`,
      );
      return 0;
    }
    const scope =
      summary.mode === "rotated"
        ? `環境 ${environmentId} を epoch ${summary.previousEpoch} → ${summary.epoch} へローテーション`
        : `環境 ${environmentId}(epoch ${summary.epoch})の再暗号化を再開`;
    if (summary.remaining > 0 || summary.failure !== null) {
      return yield* reportPartialRotation(environmentId, summary, `${scope}しました`, skipped);
    }
    if (summary.mode === "resumed") {
      // 再開は「要求されたローテーション」ではない: 新しいエポックは作られて
      // いないので、完了報告がローテーション成功に見えてはならない(退職者の
      // 削除に伴う実行が、新エポックなしで成功扱いになる形を塞ぐ。新エポックの
      // 存在を保証したい呼び出しは --new-epoch を使う)
      yield* io.log(
        `完了: ${scope}しました(再暗号化 ${summary.reencrypted} 変数${skipped})。**新しいエポックは作成していません**(epoch は ${summary.epoch} のまま)— 新しいローテーションが必要な場合はもう一度実行するか、--new-epoch を付けて実行してください`,
      );
      return 0;
    }
    yield* io.log(`完了: ${scope}しました(再暗号化 ${summary.reencrypted} 変数${skipped})`);
    return 0;
  });
}

/** `maruhi env rotate <id> [--reason <text>] [--new-epoch]`(§7 / §12-4)。 */
function envRotate(
  flags: CommonFlags & {
    readonly reason?: string | undefined;
    readonly newEpoch?: boolean | undefined;
  },
  environmentId: EnvironmentId,
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    // 環境床(§6.3)を使うため環境コンテキストで開く(env は positional 優先)
    const context = yield* openEnvironment({ ...flags, env: environmentId });
    const summary = yield* envRotateOp({
      client: context.client,
      verified: context.verified,
      environmentId,
      recipient: context.recipient,
      reason: flags.reason ?? "",
      forceNewEpoch: flags.newEpoch === true,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
      floor: context.floorHandle,
    });
    return yield* reportRotation(environmentId, summary);
  });
}

/** env コマンドが受け付けるオプション名(操作ごとの適用可否は下の表)。 */
const ENV_ACTION_FLAGS = {
  create: new Set(["name"]),
  rotate: new Set(["reason", "new-epoch"]),
} as const;
const ENV_COMMON_FLAGS = new Set(["server", "project"]);

/**
 * env のオプション検査。gunshi は 1 コマンド 1 引数表なので、`create` と
 * `rotate` の両方のフラグが常に受理される。**黙って捨てない**ために 2 つを
 * 検査する:
 *
 * 1. 未知のオプション(`--new-epochs` のような綴り間違い)。gunshi は未知の
 *    オプションを無視するため、放置すると「新エポックを必ず作る」つもりの
 *    実行が黙って弱い再開経路へ落ちる
 * 2. 操作に適用されないオプション(create への --reason 等)。指定した意図が
 *    無視されたことに気付けるようにする
 */
function checkEnvFlags(
  action: "create" | "rotate",
  tokens: readonly { readonly kind: string; readonly name?: string | undefined }[],
): Effect.Effect<void, CliError> {
  const applicable = ENV_ACTION_FLAGS[action];
  for (const token of tokens) {
    if (token.kind !== "option" || token.name === undefined) {
      continue;
    }
    const name = token.name;
    if (ENV_COMMON_FLAGS.has(name) || applicable.has(name)) {
      continue;
    }
    const other = action === "create" ? ENV_ACTION_FLAGS.rotate : ENV_ACTION_FLAGS.create;
    return Effect.fail(
      cliError(
        other.has(name)
          ? `--${displayText(name)} は env ${action} では使えません(${action === "create" ? "rotate" : "create"} 用のオプションです)`
          : `不明なオプションです: --${displayText(name)}`,
      ),
    );
  }
  return Effect.void;
}

function envCommand(execute: Execute) {
  return define({
    name: "env",
    description: "環境の管理(create / rotate)",
    args: {
      action: { type: "positional", description: "create | rotate" },
      "environment-id": { type: "positional", description: "環境 ID(例: dev / prod)" },
      name: { type: "string", description: "表示名(create のみ。省略時は環境 ID)" },
      reason: {
        type: "string",
        description: "ローテーションの理由(新しいエポックを作る場合は必須。チェーンに記録される)",
      },
      "new-epoch": {
        type: "boolean",
        description: "rotate: 未完了の再暗号化があっても再開で済ませず、必ず新しいエポックを作る",
      },
      server: { type: "string", description: "サーバー URL(省略時は config の server)" },
      project: {
        type: "string",
        description: "プロジェクト ID(省略時は config の defaultProject)",
      },
    },
    run: (ctx) =>
      execute(
        Effect.gen(function* () {
          const action = ctx.values.action;
          if (action !== "create" && action !== "rotate") {
            return yield* Effect.fail(cliError(`不明な操作です: ${action}(create | rotate)`));
          }
          const environmentId = ctx.values["environment-id"];
          // positional 未指定(undefined)は型で明示的に弾く
          if (environmentId === undefined || !isEnvironmentId(environmentId)) {
            return yield* Effect.fail(
              cliError(
                `環境 ID を指定してください(例: maruhi env ${action} dev)。指定値: ${String(environmentId)}`,
              ),
            );
          }
          yield* checkEnvFlags(action, ctx.tokens);
          const flags = { server: ctx.values.server, project: ctx.values.project };
          if (action === "rotate") {
            return yield* envRotate(
              { ...flags, reason: ctx.values.reason, newEpoch: ctx.values["new-epoch"] },
              environmentId,
            );
          }
          return yield* envCreate({ ...flags, name: ctx.values.name }, environmentId);
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
          // 値の表示拒否(AI エージェント検出)はコマンド入口 = 復号前に検査する。
          // 環境全体を復号してから拒否しない(復号された平文を作らない)
          if (ctx.values.show === true) {
            yield* ensureValueDisplayAllowed(io.agentProfile());
          }
          const context = yield* openEnvironment(ctx.values);
          const pulled: PulledVariables = yield* pullVariables({
            client: context.client,
            verified: context.verified,
            environmentId: context.environmentId,
            recipient: context.recipient,
            resync: context.resync,
            floor: context.floorHandle,
          });
          yield* logWarnings(pulled.warnings);
          yield* io.log(
            `同期・検証 OK: ${pulled.variables.length} 変数(環境 ${context.environmentId})`,
          );
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
          const context = yield* openEnvironment(ctx.values);
          const value = normalizeStdinValue(yield* io.readStdin);
          const pushed = yield* pushVariable({
            client: context.client,
            environmentId: context.environmentId,
            recipient: context.recipient,
            name: ctx.values.name,
            value,
            verified: context.verified,
            resync: context.resync,
            // 値署名(§4.1)/ 作成時のステートメント著者署名(§4.2):
            // writer / author = 自分の内部 user_id、鍵 = master sig 鍵
            writerUserId: context.session.userId,
            signingKey: context.masterKeys.sigKeyPair.privateKey,
            floor: context.floorHandle,
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
          const context = yield* openEnvironment(ctx.values);
          const pulled = yield* pullVariables({
            client: context.client,
            verified: context.verified,
            environmentId: context.environmentId,
            recipient: context.recipient,
            resync: context.resync,
            floor: context.floorHandle,
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
            // ファイルなので破棄してよい — CLI 内から復旧不能にしない)。
            // ただし既存設定の喪失を伴うため、無言では飲まず警告を出す
            const config = yield* store.load.pipe(
              Effect.catch((error) =>
                Effect.gen(function* () {
                  yield* io.logError(
                    `警告: ${toCliError(error).message} — 既存の設定を破棄し、このキーのみで作り直します`,
                  );
                  return {} satisfies CliConfig;
                }),
              ),
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
