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
import {
  type ArgCheckContext,
  argsRejection,
  type ArgsCheckOptions,
  type ArgTable,
  type ArgTokenShape,
  declaredOptionName,
  restArguments,
  typedName,
  usageErrorMessages,
} from "./args.ts";
import { asConfigKey, type CliConfig, CONFIG_KEYS, ConfigStore } from "./config.ts";
import type { CliServices, CommonFlags } from "./context.ts";
import {
  commitVerifiedHead,
  loadCheckedFloor,
  openEnvironment,
  openMetadataEnvironmentPair,
  openProject,
  openSession,
  resolveProjectId,
} from "./context.ts";
import { displayText, formatPulledLine, logWarnings, showValues } from "./display.ts";
import { envCreateOp } from "./env-create.ts";
import { envDiffOp, reportEnvironmentDiff } from "./env-diff.ts";
import { envRotateOp, type RotationSummary } from "./env-rotate.ts";
import { type CliError, usageError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import { keyGenerateOp, keyShowOp } from "./keygen.ts";
import { loginOp, logoutOp, resolveClientId } from "./login.ts";
import { projectInitOp } from "./project-init.ts";
import { type PulledVariables, pullVariables } from "./pull.ts";
import { pushVariable } from "./push.ts";
import { issueRecoveryCodeOp, recoverMasterKeyOp } from "./recovery.ts";
import { RUN_COMMAND_REQUIRED, runOp } from "./run.ts";
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

/** `maruhi key` が取る操作(綴りの検査はセッションより前に行う)。 */
const KEY_ACTIONS = ["generate", "show", "recover", "recovery"] as const;
/** 操作の一覧は上の表が唯一の出所(文面と検査で二重管理しない)。 */
const KEY_ACTION_HELP = `不明な操作です(${KEY_ACTIONS.join(" | ")})`;

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
        ctx,
        Effect.gen(function* () {
          // 操作の綴りはセッション(キーチェーン / 通信)より前に検査する。
          // 後ろに置くと `key bogus` が「ログインしていません」で落ちて、
          // 打ち間違いが伝わらない
          if (!KEY_ACTIONS.some((action) => action === ctx.values.action)) {
            return yield* Effect.fail(usageError(KEY_ACTION_HELP));
          }
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
          // KEY_ACTIONS の全分岐を上で処理済み(到達しない)
          return yield* Effect.fail(usageError(KEY_ACTION_HELP));
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
        ctx,
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
          return yield* Effect.fail(usageError("不明な操作です(init | verify)"));
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
      // メンバー数は**実際に登録したラップ集合**の大きさ(CAS リトライで作り
      // 直した場合、コマンド開始時のビューのメンバー数とは食い違いうる)
      `環境を作成しました: ${environmentId}(epoch=${created.currentEpoch}、DEK を現メンバー ${created.memberCount} 名へラップ済み)`,
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
    // 断定せず「未確認を含む」と示す — 巡を使い切っただけの残数は再走査を
    // 通った実測なので、そちらに但し書きを付けて疑わしく見せない
    const scale =
      summary.remaining > 0
        ? `未完了 ${summary.remaining} 変数${summary.remainingExact ? "" : "(未確認を含む)"}`
        : "完了を検証できませんでした";
    yield* io.log(`部分完了: ${scope}(再暗号化 ${summary.reencrypted} 変数${skipped}、${scale})`);
    // 失敗の原因がある場合はそれを明示する(エポックだけが進んだ事実を、生の
    // エラーだけ出して伝え損ねない)。「中断」と言えるのは再走査へ到達できず
    // 途中で降りた場合だけで、巡を使い切った場合は最後まで走ったうえでの未完了である
    const stopped = summary.remainingExact
      ? "再暗号化が完了しませんでした"
      : "再暗号化が中断しました";
    const cause =
      summary.failure === null
        ? "並行 push との競合が解消しませんでした"
        : `${stopped}: ${summary.failure}`;
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
  /** 新しいエポックを要求した実行か(--reason 指定 or --new-epoch)。 */
  rotationRequested: boolean,
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
      // 削除に伴う実行が、新エポックなしで成功扱いになる形を塞ぐ)
      yield* io.log(
        `完了: ${scope}しました(再暗号化 ${summary.reencrypted} 変数${skipped})。**新しいエポックは作成していません**(epoch は ${summary.epoch} のまま)`,
      );
      if (!rotationRequested) {
        // 理由なしの実行 = 「未完了があれば再開する」ことだけを要求している
        return 0;
      }
      // ローテーションを要求した実行(--reason / --new-epoch)が再開へ切り替わった
      // ので、**終了コードでも**成功と言わない: `maruhi env rotate prod --reason ...
      // || exit 1` のようなスクリプトが、新エポックなしで成功と受け取る形を塞ぐ
      yield* io.logError(
        `警告: 要求されたローテーションは実行していません(未完了の再暗号化を先に片付けたため)。この実行の後に新しいエポックが必要な場合は、もう一度実行するか --new-epoch を付けて実行してください`,
      );
      return 1;
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
      // 未指定(undefined)と空文字列は**別物**として渡す: `--reason "$UNSET"`
      // のような空指定を「理由なしの確認実行」に潰すと、ローテーションを
      // 要求した実行が何も送らないまま成功終了する(env-rotate の checkReasonLength)
      reason: flags.reason,
      forceNewEpoch: flags.newEpoch === true,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
      floor: context.floorHandle,
    });
    // 「新しいエポックを要求したか」は起動時のフラグで決まる(--reason は
    // 新エポックを作る経路でのみ必須 — env-rotate.ts の requireReason)。
    // 空の --reason は envRotateOp が既に落としているので、ここに来る
    // flags.reason !== undefined は必ず「中身のある理由の指定」である
    return yield* reportRotation(
      environmentId,
      summary,
      flags.newEpoch === true || flags.reason !== undefined,
    );
  });
}

/**
 * `maruhi env diff <a> <b>`: 2 環境の**変数名の集合**を比較する(値は取得も
 * 復号もしない)。差分があっても終了コードは 0 のまま: 「差分あり」は成功した
 * 実行の**報告内容**であって実行の失敗ではなく、1 に混ぜると検証失敗・床違反
 * (= サーバー不正の証拠)や通信失敗と区別できなくなる。
 */
function envDiff(
  flags: CommonFlags,
  environmentId: EnvironmentId,
  otherEnvironmentId: EnvironmentId,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    // 前段(チェーン同期 + §6.3 検証)は 1 回だけ。master 鍵は要求しない
    // (復号しないため — context.ts の openMetadataProjectWith)
    const context = yield* openMetadataEnvironmentPair(flags, environmentId, otherEnvironmentId);
    const result = yield* envDiffOp({
      client: context.client,
      verified: context.verified,
      resync: context.resync,
      first: { environmentId: context.first.environmentId, floor: context.first.floorHandle },
      second: { environmentId: context.second.environmentId, floor: context.second.floorHandle },
    });
    // 環境のメタ水準の床は作らない(値を読んでいないため)が、**チェーン床の
    // ヘッド**は pull / push と同じく前進させる。有界再同期でビューが前進した
    // 場合、ここで記録しないと検証済みの最新ヘッドが openProject 時点のまま残る
    yield* commitVerifiedHead(context.projectId, result.verified);
    yield* reportEnvironmentDiff(result.diff);
  });
}

/**
 * `maruhi env` が取る操作。**一覧の出所はここだけ**で、綴りの検査・不明な操作の
 * 文面・コマンドと位置引数の description がすべてこれを読む(KEY_ACTIONS と同じ形)。
 */
const ENV_ACTIONS = ["create", "rotate", "diff"] as const;

type EnvAction = (typeof ENV_ACTIONS)[number];

const ENV_ACTION_HELP = `不明な操作です(${ENV_ACTIONS.join(" | ")})`;

/**
 * ENV_ACTIONS の分岐漏れを**型で**捕まえる(引数が never なので、操作を足して
 * 分岐を書き忘れると呼び出し位置がコンパイルエラーになる)。
 *
 * 実行時のフォールバックでは足りない: env の分岐は最後が envCreate なので、
 * 新しい操作が黙って**環境作成 = チェーンへの取り消せない追記**へ落ちる。
 * keyCommand は末尾の usageError で同じ穴を塞いでいるが、あちらは実行時。
 */
function unhandledEnvAction(action: never): CliError {
  return usageError(`${ENV_ACTION_HELP}(未対応の操作: ${displayText(String(action))})`);
}

/**
 * **操作専用**のオプション(ここに無い宣言済みオプションは全操作で使える)。
 * 未宣言かどうかは `CliOptions.strict` が引数表から判定するので、この表に
 * 載せ忘れても新しいオプションが不明扱いで拒否されることはない。
 */
const ENV_ACTION_FLAGS: Readonly<Record<EnvAction, ReadonlySet<string>>> = {
  create: new Set(["name"]),
  rotate: new Set(["reason", "new-epoch"]),
  // diff は専用オプションを持たない(差分の有無を終了コードへ載せる
  // `--exit-code` は今回入れない — 裁定は「差分あり = 成功(0)」)
  diff: new Set(),
};

function isEnvAction(action: string | undefined): action is EnvAction {
  return ENV_ACTIONS.some((known) => known === action);
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
 * 表を引数に取るのはその形をテストから固定するため — 実際の ENV_ACTION_FLAGS は
 * 互いに素なので、共有の形はコマンドラインからは到達できない。
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

/**
 * 操作に適用されないオプション(create への `--reason` 等)の拒否。gunshi は
 * 1 コマンド 1 引数表なので、**全操作**のフラグが常に受理される — 指定した
 * 意図が黙って無視されたことに気付けるようにする。
 *
 * 操作は 3 つ以上あるので「もう一方の操作」では足りない。そのオプションを
 * 使える操作を表から引いて名指しする(操作が増えても文面が嘘にならない)。
 *
 * 書き方そのものの誤り(未宣言オプション・boolean への値・余分な位置引数)は
 * コマンドに依らないので args.ts と `CliOptions.strict` が受け持つ。
 */
function envActionFlagRejection(
  action: string | undefined,
  tokens: readonly ArgTokenShape[],
  args: ArgTable,
): string | null {
  // 不明な操作(`env bogus`)はコマンド本体が報告する。適用可否をここで
  // 語れるのは操作が確定している場合だけ
  if (!isEnvAction(action)) {
    return null;
  }
  for (const token of tokens) {
    // 打たれた綴り(短縮形・`--no-` の否定形)から宣言名へ戻して照合する。
    // 綴りのまま引くと `env create --no-new-epoch` が rotate 専用として
    // 弾かれず、指定した意図が黙って無視される
    const declared = declaredOptionName(token, args);
    if (declared === undefined) {
      continue;
    }
    const owners = optionRestrictedTo(ENV_ACTIONS, ENV_ACTION_FLAGS, action, declared);
    if (owners === null) {
      continue;
    }
    const usable = owners.map((owner) => `env ${owner}`).join(" / ");
    return `${typedName(token)} は env ${action} では使えません(${usable} 用のオプションです)`;
  }
  return null;
}

/**
 * 位置引数で受けた環境 ID の形式検証。**指定値そのものはエラーに出さない**
 * (位置引数には値が書かれうる — args.ts の規律)。
 *
 * positional 未指定(undefined)も型で明示的に弾く。位置引数を**書かずに**
 * `--environment-id` だけで渡した実行はここまで来ない(strict が未宣言
 * オプションとして runner より前に落とす — args.ts)。
 */
function requireEnvironmentId(
  value: string | undefined,
  action: EnvAction,
): Effect.Effect<EnvironmentId, CliError> {
  if (value === undefined || !isEnvironmentId(value)) {
    const example = action === "diff" ? "dev prod" : "dev";
    return Effect.fail(
      usageError(
        `環境 ID の形式が正しくありません(英数字で始まり、英数字と _ - が続く 64 字まで。例: maruhi env ${action} ${example})`,
      ),
    );
  }
  return Effect.succeed(value);
}

function envCommand(execute: Execute) {
  return define({
    name: "env",
    description: `環境の管理(${ENV_ACTIONS.join(" / ")})`,
    args: {
      action: { type: "positional", description: ENV_ACTIONS.join(" | ") },
      "environment-id": { type: "positional", description: "環境 ID(例: dev / prod)" },
      "other-environment-id": {
        type: "positional",
        // diff 専用の 3 つ目。**required: false が必須**: gunshi の positional は
        // 既定で必須なので、付け忘れると create / rotate が必須検査で落ちる。
        // optional は必須検査が効かないため、diff で欠けている場合は本体が
        // usage エラーにする(`config set` の「設定する値を…」と同型)
        required: false,
        description: "比較するもう一方の環境 ID(diff のみ)",
      },
      name: { type: "string", description: "表示名(create のみ。省略時は環境 ID)" },
      reason: {
        type: "string",
        description: "ローテーションの理由(新しいエポックを作る場合は必須。チェーンに記録される)",
      },
      "new-epoch": {
        type: "boolean",
        // 否定形(`--no-new-epoch`)を宣言する: gunshi は boolean へ書いた値を
        // 読まないので、宣言しないと「無効にする書き方」が存在しないまま
        // `--new-epoch false` のような形だけが増える
        negatable: true,
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
        ctx,
        Effect.gen(function* () {
          const action = ctx.values.action;
          // 操作の綴りは環境 ID の形式検査より前に見る(`env bogus` が
          // 「環境 ID の形式が…」で落ちると、打ち間違いが伝わらない)
          if (!isEnvAction(action)) {
            return yield* Effect.fail(usageError(ENV_ACTION_HELP));
          }
          const environmentId = yield* requireEnvironmentId(ctx.values["environment-id"], action);
          const flags = { server: ctx.values.server, project: ctx.values.project };
          if (action === "diff") {
            const other = ctx.values["other-environment-id"];
            if (other === undefined) {
              return yield* Effect.fail(
                usageError("比較する環境を 2 つ指定してください(例: maruhi env diff dev prod)"),
              );
            }
            const otherEnvironmentId = yield* requireEnvironmentId(other, action);
            if (otherEnvironmentId === environmentId) {
              // 同じ環境どうしの比較は必ず空になる = 要求そのものが書き間違い。
              // 指定値は出さない(位置引数には値が書かれうる)
              return yield* Effect.fail(
                usageError(
                  "同じ環境 ID を 2 つ指定しています。比較する 2 つの環境を指定してください",
                ),
              );
            }
            return yield* envDiff(flags, environmentId, otherEnvironmentId);
          }
          if (action === "rotate") {
            // 空の `--reason`(`--reason ""` / `--reason=`)は共通の引数検査が
            // 落とす(args.ts の emptyOptionValueRejection — 「未指定」と
            // 区別できない値を既定へ潰さない)。ここへ来る undefined は
            // **`--reason` 自体が無い**実行だけ
            return yield* envRotate(
              { ...flags, reason: ctx.values.reason, newEpoch: ctx.values["new-epoch"] },
              environmentId,
            );
          }
          if (action === "create") {
            return yield* envCreate({ ...flags, name: ctx.values.name }, environmentId);
          }
          // ENV_ACTIONS の全分岐を上で処理済み(到達しない)。操作を足して
          // ここを書き忘れると**コンパイルエラー**になる
          return yield* Effect.fail(unhandledEnvAction(action));
        }),
        {
          commandRejection: envActionFlagRejection(ctx.values.action, ctx.tokens, ctx.args),
          // 3 つ目の位置引数は diff 専用。**既知の非 diff 操作のときだけ**除く:
          // 未知の操作でも除くと `env bogus a b` が「余分な引数です」で落ちて、
          // 本当の誤り(操作名の綴り)が伝わらない(config の get / set と同じ形)。
          //
          // 効くのは**余分な位置引数の検査だけではない**: `without` は空の位置
          // 引数の検査(args.ts の emptyPositionalRejection)にも渡るので、
          // 未知の操作に空の 3 つ目を書くと「位置引数 other-environment-id が
          // 空です」が「不明な操作です」より先に出る。args.ts は構造的な誤りを
          // 操作別の指摘より先に言う並び順なのでこれは意図どおりで、空の引数を
          // 渡した事実自体は本当(直して再実行すれば操作名の誤りが出る)
          withoutPositionals:
            isEnvAction(ctx.values.action) && ctx.values.action !== "diff"
              ? ["other-environment-id"]
              : undefined,
        },
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
        // 否定形(`--no-show`)を宣言する(既定と同じだが、明示的に「表示しない」
        // と書けるようにする — `--show=false` を書きたくなる形の受け皿)
        negatable: true,
        description: "値を端末に表示する(AI エージェント環境では拒否される)",
      },
    },
    run: (ctx) =>
      execute(
        ctx,
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
        ctx,
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
        {
          // `maruhi push API_KEY "$SECRET"` は最も起こりやすい書き間違い。
          // 拒否した引数の中身は出さない(平文でありうる)ので、代わりに
          // 「値は stdin から」を必ず添える — でないと直しようがない
          strayPositionalHint:
            '。値は stdin から読みます(例: printf %s "$SECRET" | maruhi push API_KEY)',
        },
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
    run: (ctx) => {
      // `--` の後ろは 1 度だけ組む(検査と実行で食い違わせない)
      const command = restArguments(ctx.tokens);
      return execute(
        ctx,
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
          // 実行制御系変数名 denylist(run.ts)は検証済み name に適用される防衛層。
          // 子プロセスの引数は `ctx.rest` ではなくトークンから組む(空文字列の
          // 引数が rest から落ちる gunshi の挙動 — args.ts の restArguments)
          return yield* runOp({ command, variables: pulled.variables });
        }),
        {
          // `maruhi run npm test`(`--` 忘れ)は位置引数として落ちる。run は
          // 実行対象を `--` の後ろからしか取らないので、書き方を示して案内する
          strayPositionalHint:
            "。実行するコマンドは `--` の後に並べてください(例: maruhi run -- printenv MY_VAR)",
          // `--` の後ろを読む唯一のコマンド(他コマンドでは黙って捨てられる)
          acceptsRest: true,
          // 実行対象が無い実行(`maruhi run` / `maruhi run --` / `--` の後ろが
          // 空文字列 = `maruhi run -- "$CMD"` の未設定形)は**書き方の誤り**
          // なので入口で落とす。ここを通すと pull と全変数の復号まで進んでから
          // spawn が失敗する(平文を作る意味が無い)。runOp 側の同じ検査は
          // 直接呼び出し向けの防衛線として残す
          restRequired: RUN_COMMAND_REQUIRED,
          // 実行に使うものと同じ配列を渡す(検査と実行で 2 度組まない)
          rest: command,
        },
      );
    },
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
        ctx,
        Effect.gen(function* () {
          const io = yield* CliIo;
          const store = yield* ConfigStore;
          const key = asConfigKey(ctx.values.key);
          if (key === null) {
            return yield* Effect.fail(usageError(`不明な設定キーです(${CONFIG_KEYS.join(" | ")})`));
          }
          if (ctx.values.action === "get") {
            const config = yield* store.load;
            yield* io.log(config[key] ?? "");
            return;
          }
          if (ctx.values.action === "set") {
            const value = ctx.values.value;
            if (value === undefined) {
              return yield* Effect.fail(usageError("設定する値を指定してください"));
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
          return yield* Effect.fail(usageError("不明な操作です(get | set)"));
        }),
        {
          // `value` は set 専用の optional positional。共通検査は引数表の
          // **最大数**しか知らないので、get への余分なトークンはそのスロットへ
          // 黙って束縛される。操作ごとの差はここで伝える
          withoutPositionals: ctx.values.action === "get" ? ["value"] : undefined,
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
          const message = displayText(defect instanceof Error ? defect.message : String(defect));
          yield* io.logError(`maruhi: 内部エラー: ${message}`);
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
    key: keyCommand(execute),
    project: projectCommand(execute),
    env: envCommand(execute),
    pull: pullCommand(execute),
    push: pushCommand(execute),
    run: runCommand(execute),
    config: configCommand(execute),
  };

  try {
    await cli([...argv], entryCommand(execute, Object.keys(subCommands)), {
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
      await reportUsageError(usageErrorMessages(error, argv, subCommands));
      return 2;
    }
    const message = displayText(error instanceof Error ? error.message : String(error));
    await reportUsageError([`内部エラー: ${message}`]);
    return 1;
  }
  return exitCode;
}
