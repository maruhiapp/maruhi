// maruhi CLI のコマンド定義と Effect 実行の結線。
//
// **移行中**(ADR-0016 の第 1〜3 段階): `pull` / `run` / `env` / `server` /
// `invite` / `member` / `push` / `config` は `effect/unstable/cli`
// (effect-cli.ts)、残り(login / logout / key / project / rotation / audit)は
// Gunshi のまま。runCli が解決済みのコマンド名で振り分ける(migratedCommandKey)。
//
// Gunshi 側のコマンド階層は 1 段(サブコマンド + positional の action)。
// 値の入力は stdin(argv に平文値を載せない)、値の表示は pull --show のみで、
// 対話端末以外では拒否する(agent-gate.ts)。`maruhi run` は許可される。

import { hostname } from "node:os";

import {
  AUDIT_ROW_ID_PATTERN,
  DEFAULT_AUDIT_EVENTS_PAGE_LIMIT,
  MAX_AUDIT_EVENTS_PAGE_LIMIT,
  MAX_TOKEN_NAME_LENGTH,
} from "@maruhi/api-schema";
import { isEnvironmentId, isVariableId } from "@maruhi/core";
import { Effect, Layer } from "effect";
import { cli, define } from "gunshi";

import {
  type ArgCheckContext,
  argsRejection,
  type ArgsCheckOptions,
  type ArgTable,
  type ArgTokenShape,
  commandNameAfterTerminator,
  commandTokens,
  type CommandTable,
  declaredOptionName,
  TERMINATOR_BEFORE_COMMAND,
  typedName,
  usageErrorMessages,
} from "./args.ts";
import {
  type AuditListFilters,
  auditInvitesOp,
  auditListOp,
  type AuditPageOptions,
  auditSelfOp,
  auditVerifyOp,
} from "./audit.ts";
import { ConfigStore } from "./config.ts";
import type { CliServices } from "./context.ts";
import { openMetadataProject, openSession } from "./context.ts";
import { displayText } from "./display.ts";
import { COMMAND_SPECS, runEffectCli } from "./effect-cli.ts";
import { type CliError, usageError } from "./errors.ts";
import { internalErrorKind, toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import { loginOp, logoutOp, resolveClientId } from "./login.ts";
import { resolveDismissTargets, rotationDismissOp, rotationListOp } from "./rotation.ts";
import { normalizeHttpOrigin, resolveServerOrigin } from "./session.ts";
import { CLI_VERSION } from "./version.ts";

export type { CliServices } from "./context.ts";

type CliProgram = Effect.Effect<number | void, CliError, CliServices>;

/**
 * 引数の書き方を検査してからコマンド本体(Effect プログラム)を実行し、
 * 終了コードを蓄積する。ctx を必ず渡す形にしてあるので、新しいコマンドが
 * 共通検査(args.ts)を通し忘れることがない。
 */
type Execute = (
  ctx: ArgCheckContext,
  program: CliProgram,
  /** コマンドごとの検査の調整(型と既定は args.ts が持つ)。 */
  options?: ArgsCheckOptions,
) => Promise<void>;

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
        ctx,
        Effect.gen(function* () {
          // **どの通信よりも先**に見る。上限は api-schema と共有する
          // (MAX_TOKEN_NAME_LENGTH)。ここで見ないと、長すぎる名前は device flow
          // (**ブラウザでの承認**)を完走した後にリクエストの encode 失敗として
          // 現れる。`resolveClientId` より後ろでも駄目で、あちらは client_id が
          // フラグにも config にも無いとき `/auth/config` を引く(= 往復が先に
          // 起きるうえ、その取得が失敗すると書き方の誤りが接続失敗に隠れる)
          const tokenName = yield* requireTokenName(ctx.values["token-name"]);
          const store = yield* ConfigStore;
          const config = yield* store.load;
          const origin = yield* resolveServerOrigin(ctx.values.server, config);
          // --github-base-url は GHES / テスト用の上書き。既定の GitHub から
          // 外す以上、http を任意ホストへ向ける経路を塞ぐ(https か loopback のみ)。
          // 形式の検査は**通信より前**に置く(後ろだと、書き方の誤りが
          // 「サーバーへの接続に失敗しました」として報告される)
          const githubBaseUrl =
            ctx.values["github-base-url"] === undefined
              ? undefined
              : yield* normalizeHttpOrigin(ctx.values["github-base-url"], "GitHub base URL");
          // フラグ → config → サーバーの公開設定エンドポイント(AUTH_SPEC §4)
          const clientId = yield* resolveClientId({
            origin,
            explicit: ctx.values["github-client-id"],
            configured: config.githubClientId,
          });
          const minIntervalSeconds = ctx.values["github-poll-interval"];
          yield* loginOp({
            origin,
            clientId,
            tokenName,
            ...(githubBaseUrl === undefined ? {} : { githubBaseUrl }),
            ...(minIntervalSeconds === undefined ? {} : { minIntervalSeconds }),
          });
        }),
      ),
  });
}

/**
 * `--token-name` の長さ検査(**指定値そのものはエラーに出さない**)。
 *
 * 上限は `@maruhi/api-schema` の宣言と同じ定数を見る(CLI 側に数字を写すと、
 * 宣言を緩めたときにこちらだけ古い上限で拒否し続ける)。
 */
function requireTokenName(value: string | undefined): Effect.Effect<string, CliError> {
  const name = value ?? `cli:${hostname()}`;
  return name.length > MAX_TOKEN_NAME_LENGTH
    ? Effect.fail(usageError(`--token-name は ${MAX_TOKEN_NAME_LENGTH} 文字以内で指定してください`))
    : Effect.succeed(name);
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
        ctx,
        Effect.gen(function* () {
          const store = yield* ConfigStore;
          const config = yield* store.load;
          const origin = yield* resolveServerOrigin(ctx.values.server, config);
          yield* logoutOp({ origin });
        }),
      ),
  });
}

/**
 * Given an action → action-specific-options table, reports whether `action` may
 * use `declared`: null when it may, otherwise the actions the option is
 * restricted to (for naming them in the diagnostic).
 *
 * 判定は「そのオプションを**持つ操作**(自分を含む)」で行う。**「他の操作の分」
 * だけを数えてはならない**: それだと 1 つのオプションを複数の操作が共有する形で、
 * 共有元のどちらでも拒否される(= 宣言したとおりに使えない)。
 *
 * 表を引数に取るのはその形をテストから固定するため — 実際の表
 * (AUDIT_ACTION_FLAGS。第 2 段階の移行で残る利用者は audit だけ)は互いに
 * 素なので、共有の形はコマンドラインからは到達できない。
 */
export function optionRestrictedTo<A extends string>(
  actions: readonly A[],
  flags: Readonly<Record<A, ReadonlySet<string>>>,
  action: A,
  declared: string,
): readonly A[] | null {
  const owners = actions.filter((owner) => flags[owner].has(declared));
  // 持ち主が居ない = 全操作で使える共通オプション(--server / --project)。
  // 自分が持ち主なら当然使える(共有していても)
  return owners.length === 0 || owners.includes(action) ? null : owners;
}

/** auditActionFlagRejection の共通本体(第 2 段階の移行で利用者は audit だけになった)。 */
function actionFlagRejection<A extends string>(
  command: string,
  actions: readonly A[],
  flags: Readonly<Record<A, ReadonlySet<string>>>,
  action: A,
  tokens: readonly ArgTokenShape[],
  args: ArgTable,
): string | null {
  for (const token of tokens) {
    // 打たれた綴り(短縮形・`--no-` の否定形)から宣言名へ戻して照合する。
    // 綴りのまま引くと `env create --no-new-epoch` が rotate 専用として
    // 弾かれず、指定した意図が黙って無視される
    const declared = declaredOptionName(token, args);
    if (declared === undefined) {
      continue;
    }
    const owners = optionRestrictedTo(actions, flags, action, declared);
    if (owners === null) {
      continue;
    }
    const usable = owners.map((owner) => `${command} ${owner}`).join(" / ");
    return `${typedName(token)} は ${command} ${action} では使えません(${usable} 用のオプションです)`;
  }
  return null;
}

/** `maruhi rotation` が取る操作(一覧の出所はここだけ — KEY_ACTIONS と同じ形)。 */
const ROTATION_ACTIONS = ["list", "dismiss"] as const;

const ROTATION_ACTION_HELP = `不明な操作です(${ROTATION_ACTIONS.join(" | ")})`;

function isRotationAction(action: string | undefined): action is (typeof ROTATION_ACTIONS)[number] {
  return ROTATION_ACTIONS.some((known) => known === action);
}

/**
 * `maruhi rotation list|dismiss`(AUDIT_SPEC §4.1 / §7 — Wave 2 B2)。
 * どちらも master 鍵を要求しない(フラグは非機密メタデータで、名前解決も
 * 検証済みステートメントの読み取りのみ — project verify と同じ鍵なしクラス)。
 * dismiss の権限(admin 以上 × admin スコープ)はサーバー側が強制する。
 */
function rotationCommand(execute: Execute) {
  return define({
    name: "rotation",
    description: `要ローテーションフラグの管理(${ROTATION_ACTIONS.join(" / ")} — AUDIT_SPEC §4.1)`,
    args: {
      action: { type: "positional", description: ROTATION_ACTIONS.join(" | ") },
      variable: {
        type: "positional",
        required: false,
        description: "dismiss: 取り下げる variableId(--all の場合は指定しない)",
      },
      env: {
        type: "string",
        description: "dismiss: 対象の環境 ID(--all と併用すると当該環境に絞る)",
      },
      all: {
        type: "boolean",
        description: "dismiss: 現在有効な全フラグを取り下げる(リスク受容の明示)",
      },
      server: { type: "string", description: "サーバー URL(省略時は config の server)" },
      project: {
        type: "string",
        description: "プロジェクト ID(省略時は config の defaultProject)",
      },
    },
    run: (ctx) =>
      execute(
        ctx,
        Effect.gen(function* () {
          const action = ctx.values.action;
          if (!isRotationAction(action)) {
            return yield* Effect.fail(usageError(ROTATION_ACTION_HELP));
          }
          const flags = { server: ctx.values.server, project: ctx.values.project };
          if (action === "list") {
            const context = yield* openMetadataProject(flags);
            return yield* rotationListOp(context);
          }
          // dismiss: 対象の形式はネットワークより先に検査する
          const environmentId = ctx.values.env;
          if (environmentId !== undefined && !isEnvironmentId(environmentId)) {
            return yield* Effect.fail(
              usageError(
                "--env の環境 ID の形式が正しくありません(英数字で始まり、英数字と _ - が続く 64 字まで)",
              ),
            );
          }
          const variableId = ctx.values.variable;
          if (variableId !== undefined && !isVariableId(variableId)) {
            return yield* Effect.fail(usageError("variableId の形式が正しくありません"));
          }
          const context = yield* openMetadataProject(flags);
          const resolved = yield* resolveDismissTargets({
            client: context.client,
            projectId: context.projectId,
            all: ctx.values.all === true,
            environmentId: environmentId ?? null,
            variableId: variableId ?? null,
          });
          return yield* rotationDismissOp({
            client: context.client,
            projectId: context.projectId,
            targets: resolved.targets,
          });
        }),
        {
          // 2 つ目の位置引数(variable)は dismiss 専用(envCommand の diff と同じ形)
          withoutPositionals:
            isRotationAction(ctx.values.action) && ctx.values.action !== "dismiss"
              ? ["variable"]
              : undefined,
        },
      ),
  });
}

/** `maruhi audit` が取る操作(一覧の出所はここだけ — KEY_ACTIONS と同じ形)。 */
const AUDIT_ACTIONS = ["list", "invites", "self", "verify"] as const;

type AuditAction = (typeof AUDIT_ACTIONS)[number];

const AUDIT_ACTION_HELP = `不明な操作です(${AUDIT_ACTIONS.join(" | ")} — 省略時は list)`;

function isAuditAction(action: string | undefined): action is AuditAction {
  return AUDIT_ACTIONS.some((known) => known === action);
}

/** AUDIT_ACTIONS の分岐漏れを型で捕まえる(引数が never の網羅検査)。 */
function unhandledAuditAction(action: never): CliError {
  return usageError(`${AUDIT_ACTION_HELP}(未対応の操作: ${displayText(String(action))})`);
}

/**
 * 操作専用のオプション(gunshi の 1 段制約による操作フラグ表 — audit が最後の
 * 利用者)。`--project` は self 以外の共有(self はアカウント全域でプロジェクトを
 * 取らない — 黙って無視しない)。
 */
const AUDIT_ACTION_FLAGS: Readonly<Record<AuditAction, ReadonlySet<string>>> = {
  list: new Set(["limit", "before", "event", "actor", "target", "env", "var", "project"]),
  invites: new Set(["limit", "before", "project"]),
  self: new Set(["limit", "before"]),
  verify: new Set(["project"]),
};

function auditActionFlagRejection(
  action: string | undefined,
  tokens: readonly ArgTokenShape[],
  args: ArgTable,
): string | null {
  // 省略時の既定(list)は本体と同じ解釈で検査する
  const resolved = action ?? "list";
  if (!isAuditAction(resolved)) {
    return null;
  }
  return actionFlagRejection("audit", AUDIT_ACTIONS, AUDIT_ACTION_FLAGS, resolved, tokens, args);
}

/** 未指定は許容し、指定時は [1, max] の整数のみ通す。 */
function outsideIntRange(value: number | undefined, max: number): boolean {
  if (value === undefined) {
    return false;
  }
  return !Number.isInteger(value) || value < 1 || value > max;
}

function parseAuditPage(
  limit: number | undefined,
  before: string | undefined,
): Effect.Effect<AuditPageOptions, CliError> {
  if (outsideIntRange(limit, MAX_AUDIT_EVENTS_PAGE_LIMIT)) {
    return Effect.fail(
      usageError(
        `--limit は 1〜${MAX_AUDIT_EVENTS_PAGE_LIMIT} の整数で指定してください(AUDIT_SPEC §7 の上限)`,
      ),
    );
  }
  // カーソルは行 id(AUDIT_SPEC §5.1 row_id — 形式は api-schema の Schema と
  // 共有)。前ページ末尾の「続きを見るには」案内が示す値をそのまま渡す
  if (before !== undefined && !AUDIT_ROW_ID_PATTERN.test(before)) {
    return Effect.fail(
      usageError(
        "--before は前ページ末尾の行 id(hex 小文字 32 文字 — 「続きを見るには」の案内に表示される値)で指定してください",
      ),
    );
  }
  return Effect.succeed({ limit: limit ?? null, before: before ?? null });
}

interface AuditFilterFlags {
  readonly event: string | undefined;
  readonly actor: string | undefined;
  readonly target: string | undefined;
  readonly env: string | undefined;
  readonly var: string | undefined;
}

/** 未指定は許容し、指定時は非空かつ max 文字以内のみ通す。 */
function boundedFlagValue(value: string | undefined, max: number): boolean {
  return value === undefined || (value.length > 0 && value.length <= max);
}

/** フィルタフラグの最初の書き方の誤り(なければ null)。 */
function auditFilterProblem(values: AuditFilterFlags): string | null {
  if (!boundedFlagValue(values.event, 64)) {
    return "--event はイベント名(領域.動詞 — 例: var.version_pushed)で指定してください";
  }
  if (!boundedFlagValue(values.actor, 1024)) {
    return "--actor は対象の user_id で指定してください";
  }
  if (!boundedFlagValue(values.target, 1024)) {
    return "--target は対象の user_id で指定してください";
  }
  if (values.env !== undefined && !isEnvironmentId(values.env)) {
    return "--env の環境 ID の形式が正しくありません(英数字で始まり、英数字と _ - が続く 64 字まで)";
  }
  if (values.var !== undefined && !isVariableId(values.var)) {
    return "--var の variableId の形式が正しくありません";
  }
  return null;
}

/** list のフィルタフラグの検査(形式はネットワークより先に見る)。 */
function parseAuditFilters(values: AuditFilterFlags): Effect.Effect<AuditListFilters, CliError> {
  const problem = auditFilterProblem(values);
  if (problem !== null) {
    return Effect.fail(usageError(problem));
  }
  return Effect.succeed({
    event: values.event ?? null,
    actorUserId: values.actor ?? null,
    targetUserId: values.target ?? null,
    environmentId: values.env ?? null,
    variableId: values.var ?? null,
  });
}

/**
 * `maruhi audit [list|invites|self|verify]`(AUDIT_SPEC §6 / §7 — C1)。
 * master 鍵を要求しない(監査行は非機密メタデータで、名前解決・ミラー突合も
 * 検証済み材料の読み取りのみ — rotation list と同じ鍵なしクラス)。可視性
 * クラス・invite.* の権限軸はサーバー側が強制する。
 */
function auditCommand(execute: Execute) {
  return define({
    name: "audit",
    description: `監査イベントの閲覧と検証(${AUDIT_ACTIONS.join(" / ")} — AUDIT_SPEC §7)`,
    args: {
      action: {
        type: "positional",
        required: false,
        description: `${AUDIT_ACTIONS.join(" | ")}(省略時は list)`,
      },
      limit: {
        type: "number",
        description: `1 ページの件数(1〜${MAX_AUDIT_EVENTS_PAGE_LIMIT}。既定 ${DEFAULT_AUDIT_EVENTS_PAGE_LIMIT})`,
      },
      before: {
        type: "string",
        description:
          "この行より古い行から表示する(前ページ末尾の行 id — 続きの案内に表示される値 — を渡して遡る)",
      },
      event: {
        type: "string",
        description: "list: イベント種別で絞る(例: var.version_pushed / chain.member_added)",
      },
      actor: {
        type: "string",
        description:
          "list: actor の user_id で絞る(admin 未満は自分の user_id のみ — AUDIT_SPEC §6)",
      },
      target: { type: "string", description: "list: 対象(target)の user_id で絞る" },
      env: { type: "string", description: "list: 環境 ID で絞る" },
      var: { type: "string", description: "list: variableId で絞る" },
      server: { type: "string", description: "サーバー URL(省略時は config の server)" },
      project: {
        type: "string",
        description: "プロジェクト ID(省略時は config の defaultProject。self では不要)",
      },
    },
    run: (ctx) =>
      execute(
        ctx,
        Effect.gen(function* () {
          const action = ctx.values.action ?? "list";
          if (!isAuditAction(action)) {
            return yield* Effect.fail(usageError(AUDIT_ACTION_HELP));
          }
          const page = yield* parseAuditPage(ctx.values.limit, ctx.values.before);
          const flags = { server: ctx.values.server, project: ctx.values.project };
          if (action === "self") {
            const context = yield* openSession(ctx.values.server);
            return yield* auditSelfOp(context, page);
          }
          if (action === "invites") {
            const context = yield* openMetadataProject(flags);
            return yield* auditInvitesOp(context, page);
          }
          if (action === "verify") {
            const context = yield* openMetadataProject(flags);
            return yield* auditVerifyOp(context);
          }
          if (action === "list") {
            const filters = yield* parseAuditFilters({
              event: ctx.values.event,
              actor: ctx.values.actor,
              target: ctx.values.target,
              env: ctx.values.env,
              var: ctx.values.var,
            });
            const context = yield* openMetadataProject(flags);
            return yield* auditListOp(context, page, filters);
          }
          return yield* Effect.fail(unhandledAuditAction(action));
        }),
        {
          commandRejection: auditActionFlagRejection(ctx.values.action, ctx.tokens, ctx.args),
        },
      ),
  });
}

function entryCommand(execute: Execute, commands: readonly string[]) {
  return define({
    name: "maruhi",
    description: "maruhi — ディスクレス secrets 管理 CLI",
    run: (ctx) =>
      execute(
        ctx,
        Effect.gen(function* () {
          const io = yield* CliIo;
          yield* io.log("使い方: maruhi <command> [options]");
          // 一覧は登録済みサブコマンドから導く(手書きすると、コマンドを
          // 増やしたときにヘルプだけ古いまま残る)
          yield* io.log(`commands: ${commands.join(" / ")}`);
          yield* io.log("詳細: maruhi <command> --help");
        }),
      ),
  });
}

/**
 * `effect/unstable/cli` へ移したコマンド(ADR-0016 第 1〜2 段階)への振り分け。
 * 戻り値は診断の宛先(解決済みのコマンド段)にそのまま使う。
 *
 * コマンドの解決は **gunshi と同じ規則**(args.ts の commandTokens)で行う。
 * 自前の argv 走査を持たないためと、振り分けから漏れた形が gunshi 側で
 * 「不明なコマンドです」になる — 実在するコマンドについて嘘をつく — のを
 * 避けるため。`--` の後ろはコマンドの段ではないので見ない(先頭のコマンド名を
 * `--` の後ろへ書いた形は commandNameAfterTerminator が手前で落とす)。
 *
 * 入れ子の段(`env`)は先頭のコマンド名で丸ごと移行済みへ振り分ける。2 語目が
 * 既知のサブコマンドなら診断の宛先をその段(`env rotate`)まで確定し、そうで
 * なければ親の段(`env`)のまま渡す — 不明なサブコマンドの診断は effect 側
 * (UnknownSubcommand)が受け持つ。段の一覧は COMMAND_SPECS から引く
 * (手書きの写しを持たない)。
 */
function migratedCommandKey(argv: readonly string[]): string | null {
  const tokens = commandTokens(argv);
  const head = tokens[0];
  if (head === undefined || !Object.hasOwn(COMMAND_SPECS, head)) {
    return null;
  }
  const nested = tokens[1] === undefined ? null : `${head} ${tokens[1]}`;
  return nested !== null && Object.hasOwn(COMMAND_SPECS, nested) ? nested : head;
}

/**
 * 内部エラー(バグ)の報告と終了コード。**message は出さない** — 打たれた値を
 * 埋め込んだ文面でも到達しうるので、型の名前だけを添える(failure.ts の
 * internalErrorKind)。無言で飲まないための最後の網でもある。
 */
async function reportInternalError(
  report: (messages: readonly string[]) => Promise<void>,
  error: unknown,
): Promise<number> {
  await report([`内部エラー(${internalErrorKind(error)})`]);
  return 1;
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

  /** 診断 1 件以上を stderr へ出す(gunshi 自身の描画は止めてある)。 */
  const reportUsageError = async (messages: readonly string[]): Promise<void> => {
    await Effect.runPromise(
      Effect.gen(function* () {
        const io = yield* CliIo;
        for (const message of messages) {
          yield* io.logError(`maruhi: ${message}`);
        }
      }).pipe(Effect.provide(layer)),
    );
  };

  // コマンド名が `--` の**後ろ**にある実行(`maruhi -- run printenv`)は、
  // どのコマンドへ振り分けるかを決めるより先に落とす。gunshi は `--` を跨いで
  // コマンドを解決するため、通すと「`--` の後ろの先頭 = コマンド名そのもの」が
  // 実行対象として渡る。移行先(effect/unstable/cli)は跨がないが、そちらでは
  // 「余分な引数です」としか言えない — 直し方(コマンド名を前に出す)を
  // 伝えられる位置はここだけなので、振り分けの手前に置く
  if (commandNameAfterTerminator(argv)) {
    await reportUsageError([TERMINATOR_BEFORE_COMMAND]);
    return 2;
  }

  const migrated = migratedCommandKey(argv);
  if (migrated !== null) {
    // コマンド本体の defect は runEffectCli の中(`Effect.exit` + reportFailure)
    // が拾う。ここで受けるのは層の構築や logError 自体の失敗 = reject だけだが、
    // bin.ts は runCli を await するだけなので、拾わないと maruhi の文面ではなく
    // Bun の unhandled rejection が出る。内部エラーの報告経路を 1 本に保つ
    try {
      return await runEffectCli(migrated, argv, layer);
    } catch (error) {
      return await reportInternalError(reportUsageError, error);
    }
  }

  const execute: Execute = async (ctx, program, options) => {
    // 書き方の検査はコマンド本体より前 = 通信・復号より前に置く。
    // `pull --show=false` のような「書いたことと逆」の実行を、値を復号して
    // から拒否しない(復号された平文をそもそも作らない)。
    //
    // コマンド固有の拒否を**先に**見る: そのオプションが操作にそもそも
    // 適用されないなら、綴りの助言(`--new-epoch` と書き直せ)を先に出しても
    // 次の実行でまた落ちる(`env create --new-epoch=false` の 2 度手間)
    // 検査の一覧は args.ts が持つ(ここで項目を転記すると、増やしたときに
    // 渡し忘れた検査が黙って死ぬ)
    const rejection = argsRejection(ctx, options);
    if (rejection !== null) {
      await reportUsageError([rejection]);
      // 引数の書き方の誤りは usage エラー(2)。gunshi の strict が落とす
      // 未宣言オプションと同じ終了コードで揃える
      exitCode = 2;
      return;
    }
    const handled = program.pipe(
      Effect.map((code) => (typeof code === "number" ? code : 0)),
      Effect.catch((error) =>
        Effect.gen(function* () {
          const io = yield* CliIo;
          const failure = toCliError(error);
          yield* io.logError(`maruhi: ${failure.message}`);
          // 引数の書き方の誤りは、コマンド本体が見つけた場合でも usage エラー
          // (2)。実行の失敗(1)と混ぜると、スクリプトが打ち間違いを
          // 「操作が失敗した」と読む
          return failure.usage === true ? 2 : 1;
        }),
      ),
      // defect(バグ)を usage エラー(2)に化けさせない: runPromise の
      // reject → gunshi 経由で外側 catch へ落ちると exit 2 になってしまう
      Effect.catchDefect((defect) =>
        Effect.gen(function* () {
          const io = yield* CliIo;
          // defect の message は出さない(打たれた値を埋め込んだ文面でも到達
          // しうる)。型の名前だけを添える — 移行先(effect-cli.ts の
          // reportFailure)と同じ形で、内部エラーの見え方を 1 つに保つ
          yield* io.logError(`maruhi: 内部エラー(${internalErrorKind(defect)})`);
          return 1;
        }),
      ),
      Effect.provide(layer),
    );
    exitCode = await Effect.runPromise(handled);
  };

  const subCommands = {
    login: loginCommand(execute),
    logout: logoutCommand(execute),
    rotation: rotationCommand(execute),
    audit: auditCommand(execute),
  };

  // コマンドの一覧は「gunshi に残っているもの + 移行済みのもの」。登録済みの
  // 表から導くのは変わらないが、移行済みのコマンドは gunshi の subCommands に
  // 居ないので、ここで合流させる — ヘルプの一覧と**打ち間違いの候補**の両方が
  // これを読む。合流させないと `maruhi pul` が「不明なコマンドです」の候補に
  // pull を出せず、実在するコマンドについて嘘をつく
  // (段は先頭だけ: `env create` は `env` として既に並んでいる)
  const migratedNames = [
    ...new Set(Object.keys(COMMAND_SPECS).map((key) => key.split(" ")[0] ?? key)),
  ].filter((name) => !Object.hasOwn(subCommands, name));
  const knownCommands: CommandTable = {
    ...subCommands,
    // 移行済みは引数表を持たない(gunshi の execute へは来ない)。候補の
    // 名前としてだけ並べる
    ...Object.fromEntries(migratedNames.map((name) => [name, {}])),
  };
  const commandNames = Object.keys(knownCommands);

  try {
    await cli([...argv], entryCommand(execute, commandNames), {
      name: "maruhi",
      version: CLI_VERSION,
      description: "maruhi — ディスクレス secrets 管理 CLI",
      // 未宣言のオプションを runner 実行前に検証エラーにする(既定は false =
      // 黙って無視)。`maruhi pull --shwo` が `--show` なしで実行される形と、
      // 位置引数の名前をオプションとして書いた形(`env create dev
      // --environment-id prod`= 値が捨てられる)を全コマンドで塞ぐ。
      // `--` の後ろ(`maruhi run -- cmd --flag`)は検査対象外
      strict: true,
      // gunshi 自身の描画(いずれも console.log = **stdout**)は止め、診断は
      // 下の catch から stderr へ 1 本化する。ヘッダ(バナー)は成功した実行
      // でも毎回出るため、`V=$(maruhi config get server)` が値ではなくバナーを
      // 捕まえていた — stdout はコマンドの出力だけにする
      renderValidationErrors: null,
      renderHeader: null,
      subCommands,
    });
  } catch (error) {
    // 引数検証・未知コマンドは usage エラー(2)。それ以外(コマンド定義の
    // 組み立てで throw した等のバグ)は 1 で報告する — 打ち間違いと区別できないと
    // 直しようがないうえ、無言で飲むことにもなる(CLAUDE.md)
    if (error instanceof AggregateError) {
      await reportUsageError(usageErrorMessages(error, argv, knownCommands));
      return 2;
    }
    return await reportInternalError(reportUsageError, error);
  }
  return exitCode;
}
