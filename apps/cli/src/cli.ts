// maruhi CLI のコマンド定義(Gunshi)と Effect 実行の結線。
//
// コマンド階層は 1 段(サブコマンド + positional の action)。値の入力は
// stdin(argv に平文値を載せない)、値の表示は pull --show のみで、AI
// エージェント検出時は拒否する(agent.ts)。`maruhi run` は許可される。

import { readFile } from "node:fs/promises";
import { hostname } from "node:os";

import { type EnvironmentId, isEnvironmentId, isProjectId, isVariableId } from "@maruhi/core";
import type { LeasePolicyIssuer, Role } from "@maruhi/crypto";
import { Effect, Layer } from "effect";
import { cli, define } from "gunshi";

import { version as packageVersion } from "../package.json";
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
import {
  type AuditListFilters,
  auditInvitesOp,
  auditListOp,
  type AuditPageOptions,
  auditSelfOp,
  auditVerifyOp,
} from "./audit.ts";
import { asConfigKey, type CliConfig, CONFIG_KEYS, ConfigStore } from "./config.ts";
import type { CliServices, CommonFlags, ProjectContext } from "./context.ts";
import {
  checkInviteAnchor,
  commitVerifiedHead,
  floorHandleFor,
  loadCheckedFloor,
  openEnvironment,
  openMetadataEnvironmentPair,
  openMetadataProject,
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
import { type InviteRole, parseInviteAcceptInput } from "./invite-link.ts";
import {
  type AcceptTarget,
  inviteAcceptOp,
  inviteCreateOp,
  inviteListOp,
  inviteRevokeOp,
} from "./invite.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { keyGenerateOp, keyShowOp } from "./keygen.ts";
import { loginOp, logoutOp, resolveClientId } from "./login.ts";
import {
  MEMBER_REMOVED_ROTATION_REASON,
  memberAddOp,
  memberChangeRoleOp,
  memberRemoveOp,
  ROLE_DEMOTED_ROTATION_REASON,
  type MemberAddSummary,
} from "./member.ts";
import { PinStore } from "./pins.ts";
import { projectInitOp } from "./project-init.ts";
import { type PulledVariables, pullVariables } from "./pull.ts";
import { pushVariable } from "./push.ts";
import { issueRecoveryCodeOp, recoverMasterKeyOp } from "./recovery.ts";
import {
  describeUnconvergedMandate,
  resolveUnconvergedMandates,
  type SweepOutcome,
  type SweepRotateMode,
} from "./rotation-sweep.ts";
import {
  reportRotationFlagCount,
  resolveDismissTargets,
  rotationDismissOp,
  rotationListOp,
} from "./rotation.ts";
import { RUN_COMMAND_REQUIRED, runOp } from "./run.ts";
import { serverGrantOp } from "./server-grant.ts";
import { REVOKE_ROTATION_REASON, type RevokeSummary, serverRevokeOp } from "./server-revoke.ts";
import { loadMasterKeys, normalizeHttpOrigin, resolveServerOrigin } from "./session.ts";
import { syncProject } from "./sync.ts";

export type { CliServices } from "./context.ts";

// バージョンの単一の出所は apps/cli/package.json。リリース時はタグとの一致を
// release workflow が検査する(docs/RELEASING.md)。named import は必須:
// default import に変えるとマニフェスト全体(scripts・依存ピン)が npm 配布物と
// 全バイナリへ埋め込まれる(実測。npm-dist.test.ts が成果物側で固定)
const CLI_VERSION: string = packageVersion;

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

/** `maruhi project verify`: チェーン検証 + 床・アンカー検査 + 状態表示。 */
function projectVerify(
  serverFlag: string | undefined,
  projectFlag: string | undefined,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const context = yield* openSession(serverFlag);
    const projectId = yield* resolveProjectId(projectFlag, context.config);
    const synced = yield* syncProject(context.client, projectId);
    // チェーン床の検査(§6.3 規則 (a))も verify の一部
    const verified = (yield* loadCheckedFloor(
      projectId,
      synced,
      syncProject(context.client, projectId),
    )).verified;
    // 招待リンクアンカーの機械照合(§6.3 (a) / §6.5)も verify の一部
    yield* checkInviteAnchor(projectId, verified);
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
    // 未収束のローテーション義務(§7 — チェーン導出 + 検証済み削除の除外)も
    // verify の一部(常時警告 — rotation-sweep.ts — の詳細表示。候補ゼロなら
    // 通信なしで確定する)。削除済み環境の検証失敗は「確定できません」の注意
    // だけで verify 自体は成功扱い(チェーン検証は済んでいる — Cursor bot 指摘)
    const pending = yield* resolveUnconvergedMandates({ client: context.client, verified });
    if (pending === null) {
      return;
    }
    if (pending.length === 0) {
      yield* io.log("ローテーション義務: 未収束なし(CRYPTO_SPEC §7)");
      return;
    }
    for (const mandate of pending) {
      yield* io.logError(
        `未収束のローテーション義務: ${describeUnconvergedMandate(verified, mandate)}(旧 DEK 保持者が現在値を読める可能性)`,
      );
    }
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
            return yield* projectVerify(ctx.values.server, ctx.values.project);
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
    // 環境床(§6.3)を使うため環境コンテキストで開く(env は positional 優先)。
    // 収束系コマンドなので未収束義務の常時警告は抑制する(このコマンド自身の
    // ローテーション報告が同じ事実を伝える — context.ts の OpenProjectOptions)
    const context = yield* openEnvironment(
      { ...flags, env: environmentId },
      { quietMandateWarning: true },
    );
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
    const diff = yield* envDiffOp({
      client: context.client,
      verified: context.verified,
      resync: context.resync,
      first: { environmentId: context.first.environmentId, floor: context.first.floorHandle },
      second: { environmentId: context.second.environmentId, floor: context.second.floorHandle },
      // 環境のメタ水準の床は作らない(値を読んでいないため)が、**チェーン床の
      // ヘッド**は pull / push と同じく前進させる。記録は pull ごと(envDiffOp)
      commitHead: (verified) => commitVerifiedHead(context.projectId, verified),
    });
    yield* reportEnvironmentDiff(diff);
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
  return actionFlagRejection("env", ENV_ACTIONS, ENV_ACTION_FLAGS, action, tokens, args);
}

/** envActionFlagRejection / serverActionFlagRejection の共通本体。 */
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

/**
 * `maruhi server` が取る操作。一覧の出所はここだけ(ENV_ACTIONS と同じ形)。
 */
const SERVER_ACTIONS = ["grant", "revoke"] as const;

type ServerAction = (typeof SERVER_ACTIONS)[number];

const SERVER_ACTION_HELP = `不明な操作です(${SERVER_ACTIONS.join(" | ")})`;

function isServerAction(action: string | undefined): action is ServerAction {
  return SERVER_ACTIONS.some((known) => known === action);
}

/** SERVER_ACTIONS の分岐漏れを型で捕まえる(unhandledEnvAction と同じ形)。 */
function unhandledServerAction(action: never): CliError {
  return usageError(`${SERVER_ACTION_HELP}(未対応の操作: ${displayText(String(action))})`);
}

/** 操作専用のオプション(ENV_ACTION_FLAGS と同じ形)。 */
const SERVER_ACTION_FLAGS: Readonly<Record<ServerAction, ReadonlySet<string>>> = {
  grant: new Set(["environments", "lease-policy", "expect-fingerprint"]),
  revoke: new Set(["fingerprint"]),
};

function serverActionFlagRejection(
  action: string | undefined,
  tokens: readonly ArgTokenShape[],
  args: ArgTable,
): string | null {
  if (!isServerAction(action)) {
    return null;
  }
  return actionFlagRejection("server", SERVER_ACTIONS, SERVER_ACTION_FLAGS, action, tokens, args);
}

/**
 * `--environments dev,prod` の解釈(grant では必須 — 最小開示の既定として
 * 環境は明示指定。session-22 §2 の裁定)。空要素は書き間違いとして拒否する。
 */
function parseEnvironmentsFlag(
  value: string | undefined,
): Effect.Effect<readonly EnvironmentId[], CliError> {
  if (value === undefined) {
    return Effect.fail(
      usageError(
        "grant には --environments が必須です(開示する環境をカンマ区切りで明示 — 例: --environments dev,prod)",
      ),
    );
  }
  const ids = value.split(",").map((part) => part.trim());
  if (ids.length === 0 || ids.some((id) => id.length === 0)) {
    return Effect.fail(
      usageError("--environments の形式が正しくありません(カンマ区切りの環境 ID。空要素は不可)"),
    );
  }
  const invalid = ids.filter((id) => !isEnvironmentId(id));
  if (invalid.length > 0) {
    return Effect.fail(
      usageError(
        "--environments に形式の正しくない環境 ID が含まれています(英数字で始まり、英数字と _ - が続く 64 字まで)",
      ),
    );
  }
  return Effect.succeed(ids as readonly EnvironmentId[]);
}

/**
 * 鍵 FP を受けるフラグの形式検証(hex 小文字 32 文字 = 16 バイト)。
 * エラーは**打たれたフラグ名**で報告する(grant の --expect-fingerprint /
 * revoke の --fingerprint / invite・member の FP フラグで共用 — 存在しない
 * フラグ名を指して混乱させない)。`hint` は FP の出所の案内(鍵種別ごと)。
 */
function parseFingerprintFlag(
  flagName: string,
  value: string | undefined,
  hint = "サーバー鍵 FP は hex 小文字 32 文字 — /auth/config の serverKeyFingerprintHex",
): Effect.Effect<string | null, CliError> {
  if (value === undefined) {
    return Effect.succeed(null);
  }
  if (!/^[0-9a-f]{32}$/.test(value)) {
    return Effect.fail(usageError(`${flagName} の形式が正しくありません(${hint})`));
  }
  return Effect.succeed(value);
}

// lease_policy(CRYPTO_SPEC §6.2)のファイル入力の上限。合意規則の値と同じ
// (超過はチェーン検証 invalid-payload になるため、入力段で先に落とす)
const MAX_LEASE_POLICY_ISSUERS = 8;
const MAX_LEASE_CLAIM_CONSTRAINTS = 8;
const MAX_LEASE_FIELD_BYTES = 1024;

function leaseFieldOk(value: unknown, allowEmpty: boolean): value is string {
  if (typeof value !== "string") {
    return false;
  }
  if (!allowEmpty && value.length === 0) {
    return false;
  }
  return new TextEncoder().encode(value).length <= MAX_LEASE_FIELD_BYTES;
}

/**
 * lease_policy ファイル(JSON)の解釈と正規化。ファイル形式は camelCase +
 * claimConstraints をオブジェクト(claim 名 → 値)で書く — 同一 claim の矛盾する
 * 重複制約(完全一致 AND では常に偽)を構造的に表現できなくするため。
 * チェーン形式(順序付き配列)への変換で §6.2 の SHOULD(コードポイント昇順・
 * 重複なし)を適用する。
 */
function parseLeasePolicy(content: string): readonly LeasePolicyIssuer[] | string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return "JSON として解釈できません";
  }
  if (!Array.isArray(parsed)) {
    return "トップレベルは要素の配列である必要があります";
  }
  if (parsed.length > MAX_LEASE_POLICY_ISSUERS) {
    return `要素は ${MAX_LEASE_POLICY_ISSUERS} 個以下です(合意規則 — CRYPTO_SPEC §6.2)`;
  }
  const elements: LeasePolicyIssuer[] = [];
  for (const element of parsed) {
    const result = parseLeaseElement(element);
    if (typeof result === "string") {
      return result;
    }
    elements.push(result);
  }
  return canonicalizeLeaseElements(elements);
}

/** lease_policy の 1 要素の解釈(不正なら理由の文字列)。 */
function parseLeaseElement(element: unknown): LeasePolicyIssuer | string {
  if (typeof element !== "object" || element === null || Array.isArray(element)) {
    return "各要素は { issuerUrl, audience, claimConstraints } のオブジェクトである必要があります";
  }
  const record = element as Record<string, unknown>;
  if (!leaseFieldOk(record["issuerUrl"], false) || !leaseFieldOk(record["audience"], false)) {
    return `issuerUrl / audience は非空の文字列(${MAX_LEASE_FIELD_BYTES} バイト以下)である必要があります`;
  }
  const claimConstraints = parseLeaseConstraints(record["claimConstraints"] ?? {});
  if (typeof claimConstraints === "string") {
    return claimConstraints;
  }
  return {
    issuerUrl: record["issuerUrl"] as string,
    audience: record["audience"] as string,
    claimConstraints,
  };
}

/** claimConstraints オブジェクトの解釈と昇順ソート(不正なら理由の文字列)。 */
function parseLeaseConstraints(
  value: unknown,
): { claimName: string; claimValue: string }[] | string {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return "claimConstraints は { claim 名: 値 } のオブジェクトである必要があります";
  }
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > MAX_LEASE_CLAIM_CONSTRAINTS) {
    return `claimConstraints は要素あたり ${MAX_LEASE_CLAIM_CONSTRAINTS} 件以下です(合意規則)`;
  }
  const claimConstraints: { claimName: string; claimValue: string }[] = [];
  for (const [claimName, claimValue] of entries) {
    if (!leaseFieldOk(claimName, false) || !leaseFieldOk(claimValue, true)) {
      return `claim 制約の名前は非空・値は文字列(いずれも ${MAX_LEASE_FIELD_BYTES} バイト以下)である必要があります`;
    }
    claimConstraints.push({ claimName, claimValue });
  }
  // 制約はコードポイント昇順(§6.2 の SHOULD)。名前はオブジェクトキーなので一意
  claimConstraints.sort((a, b) => (a.claimName < b.claimName ? -1 : 1));
  return claimConstraints;
}

/**
 * 要素のコードポイント昇順 + 重複除去(SHOULD。評価は存在量化 — AUTH_SPEC §14-1 —
 * なので順序・重複は意味論に影響しないが、署名対象バイト列を決定論にする)。
 */
function canonicalizeLeaseElements(
  elements: readonly LeasePolicyIssuer[],
): readonly LeasePolicyIssuer[] {
  const canonical = elements
    .map((element) => ({ element, key: JSON.stringify(element) }))
    .toSorted((a, b) => (a.key < b.key ? -1 : 1));
  const deduped: LeasePolicyIssuer[] = [];
  let previousKey: string | null = null;
  for (const { element, key } of canonical) {
    if (key !== previousKey) {
      deduped.push(element);
      previousKey = key;
    }
  }
  return deduped;
}

/** `--lease-policy <file>` の読み込み(省略時は空 = リース経路なし)。 */
function loadLeasePolicy(
  path: string | undefined,
): Effect.Effect<readonly LeasePolicyIssuer[], CliError> {
  if (path === undefined) {
    return Effect.succeed([]);
  }
  return Effect.gen(function* () {
    const content = yield* Effect.tryPromise({
      try: () => readFile(path, "utf8"),
      catch: () => usageError("--lease-policy のファイルを読み込めません(パスを確認してください)"),
    });
    const parsed = parseLeasePolicy(content);
    if (typeof parsed === "string") {
      return yield* Effect.fail(usageError(`--lease-policy の内容が不正です: ${parsed}`));
    }
    return parsed;
  });
}

/** `maruhi server grant --environments <ids> [--lease-policy <file>]`(§9 / §12-6)。 */
function serverGrant(
  flags: CommonFlags & {
    readonly environments?: string | undefined;
    readonly leasePolicyPath?: string | undefined;
    readonly expectFingerprint?: string | undefined;
  },
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const environmentIds = yield* parseEnvironmentsFlag(flags.environments);
    const leasePolicy = yield* loadLeasePolicy(flags.leasePolicyPath);
    const expectFingerprintHex = yield* parseFingerprintFlag(
      "--expect-fingerprint",
      flags.expectFingerprint,
    );
    const context = yield* openProject(flags);
    const summary = yield* serverGrantOp({
      client: context.client,
      verified: context.verified,
      environmentIds,
      leasePolicy,
      expectFingerprintHex,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      recipient: context.recipient,
      resync: context.resync,
    });
    const policyNote =
      summary.leasePolicyCount === 0
        ? "リース経路なし(lease_policy は空)"
        : `lease_policy ${summary.leasePolicyCount} 要素`;
    yield* io.log(
      `完了: サーバー鍵 ${summary.serverKeyFingerprintHex} への開示が有効です(scope=${summary.scopeEnvironmentIds.join(", ")}、${policyNote})。バックフィル: 新規 ${summary.registered} 件、登録済み ${summary.alreadyRegistered} 件`,
    );
    // §9: 開示中であることを常時明示する(失効経路もその場で案内する)
    yield* io.log(
      "注意: 開示スコープ内の環境のエポック DEK はサーバーに開示されています(CRYPTO_SPEC §9)。取り消すには maruhi server revoke を実行してください(全環境ローテーションを伴います — §7)",
    );
  });
}

/** `maruhi server revoke [--fingerprint <hex>]`(§7 / §9)。 */
function serverRevoke(
  flags: CommonFlags & { readonly fingerprint?: string | undefined },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const fingerprintHex =
      flags.fingerprint === undefined
        ? null
        : yield* parseFingerprintFlag("--fingerprint", flags.fingerprint);
    // 収束系コマンド: 未収束義務の常時警告は抑制(自分の sweep 報告が担う)
    const context = yield* openProject(flags, { quietMandateWarning: true });
    // 1 環境のローテーション(PR-1 の envRotateOp の再利用 — sweepRotateFor)
    const summary = yield* serverRevokeOp({
      client: context.client,
      verified: context.verified,
      fingerprintHex,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
      rotate: sweepRotateFor(context, REVOKE_ROTATION_REASON),
    });
    yield* reportRevokeOutcome(io, summary);
    const exitCode = yield* reportRevokeRotations(io, summary);
    // 要ローテーションフラグの件数と導線(B2 — AUDIT_SPEC §4.1 の revoke 変種)
    if (summary.serverKeyFingerprintHex !== null) {
      yield* reportRotationFlagCount({
        client: context.client,
        projectId: context.projectId,
        target: { kind: "server", fingerprintHex: summary.serverKeyFingerprintHex },
      });
    }
    return exitCode;
  });
}

/** revoke の追記結果とスキップ・確認済み環境の報告(終了コードには影響しない部分)。 */
function reportRevokeOutcome(
  io: CliIoShape,
  summary: RevokeSummary,
): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    if (summary.appended) {
      yield* io.log(
        `revoke_server をチェーンへ追記しました(FP=${summary.serverKeyFingerprintHex ?? ""})。全環境の強制ローテーションを実行します(§7)`,
      );
    } else if (summary.serverKeyFingerprintHex !== null) {
      // 対象の grant はあったが、CAS 競合の再同期で既に失効済みと判明した
      // (並行 revoke)。誰かが同じ鍵を失効させた事実は運用上重要なので明示する
      yield* io.log(
        `対象の grant(FP=${summary.serverKeyFingerprintHex})は並行実行により既に失効済みでした — 追記せず、全環境ローテーションへ進みます(§7)`,
      );
    } else {
      yield* io.log(
        "有効な grant はありません — 失効後の全環境ローテーションの続きから再開します(中断復旧)",
      );
    }
    if (summary.skippedDeleted.length > 0) {
      yield* io.log(
        `削除済み環境(署名済み削除ステートメントを検証済み)のためスキップ: ${summary.skippedDeleted.join(", ")}`,
      );
    }
    if (summary.alreadyRotated.length > 0) {
      yield* io.log(
        `ローテーション済み(失効より後のエポック・未完了の再暗号化なしを確認): ${summary.alreadyRotated.join(", ")}`,
      );
    }
  });
}

/** revoke のローテーション結果の報告と終了コードの導出。 */
function reportRevokeRotations(
  io: CliIoShape,
  summary: RevokeSummary,
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    let exitCode = 0;
    for (const item of summary.rotated) {
      const code = yield* reportRotation(
        item.environmentId as EnvironmentId,
        item.summary,
        item.forcedNewEpoch,
      );
      if (code !== 0) {
        exitCode = 1;
      }
    }
    for (const failure of summary.failed) {
      // §7: active と信じる環境の rotate 拒否を黙ってスキップしない(悪意サーバーに
      // よる選択的なローテーション阻止を不可視にしない)
      yield* io.logError(
        `警告: 環境 ${displayText(failure.environmentId)} のローテーションに失敗しました: ${failure.message} — 解消して maruhi server revoke を再実行すると続きから再開します(環境を削除済みの場合は、検証済みの削除ステートメントを確認してください)`,
      );
      exitCode = 1;
    }
    if (exitCode === 0) {
      yield* io.log("完了: 失効と全環境ローテーションが完了しました");
    }
    return exitCode;
  });
}

/** チェーン導出の環境 ID が CLI の形式検査に通らない場合の防衛(通常は到達しない)。 */
function cliErrorForInvalidChainEnvironmentId(): CliError {
  return usageError(
    "チェーン導出の環境 ID が CLI の形式検査に通りません(サーバー受理ポリシーと矛盾するチェーンです)",
  );
}

function serverCommand(execute: Execute) {
  return define({
    name: "server",
    description: `サーバーへの選択的開示の管理(${SERVER_ACTIONS.join(" / ")} — CRYPTO_SPEC §9)`,
    args: {
      action: { type: "positional", description: SERVER_ACTIONS.join(" | ") },
      environments: {
        type: "string",
        description:
          "開示する環境 ID のカンマ区切り(grant では必須 — 最小開示の既定として環境は明示指定)",
      },
      "lease-policy": {
        type: "string",
        description:
          "ワークロードリースポリシーの JSON ファイル(grant のみ。省略時はリース経路なし)",
      },
      "expect-fingerprint": {
        type: "string",
        description:
          "帯域外で控えたサーバー鍵 FP(hex 32 文字。grant のみ — 指定時は対話確認の代わりに照合する)",
      },
      fingerprint: {
        type: "string",
        description: "失効対象のサーバー鍵 FP(revoke のみ。有効な grant が 1 つなら省略可)",
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
          if (!isServerAction(action)) {
            return yield* Effect.fail(usageError(SERVER_ACTION_HELP));
          }
          const flags = { server: ctx.values.server, project: ctx.values.project };
          if (action === "grant") {
            return yield* serverGrant({
              ...flags,
              environments: ctx.values.environments,
              leasePolicyPath: ctx.values["lease-policy"],
              expectFingerprint: ctx.values["expect-fingerprint"],
            });
          }
          if (action === "revoke") {
            return yield* serverRevoke({ ...flags, fingerprint: ctx.values.fingerprint });
          }
          return yield* Effect.fail(unhandledServerAction(action));
        }),
        {
          commandRejection: serverActionFlagRejection(ctx.values.action, ctx.tokens, ctx.args),
        },
      ),
  });
}

// ---------------------------------------------------------------------------
// invite(AUTH_SPEC §15 / CRYPTO_SPEC §6.5 — B1b)
// ---------------------------------------------------------------------------

const INVITE_ACTIONS = ["create", "accept", "list", "revoke"] as const;

type InviteAction = (typeof INVITE_ACTIONS)[number];

const INVITE_ACTION_HELP = `不明な操作です(${INVITE_ACTIONS.join(" | ")})`;

function isInviteAction(action: string | undefined): action is InviteAction {
  return INVITE_ACTIONS.some((known) => known === action);
}

/** INVITE_ACTIONS の分岐漏れを型で捕まえる(unhandledEnvAction と同じ形)。 */
function unhandledInviteAction(action: never): CliError {
  return usageError(`${INVITE_ACTION_HELP}(未対応の操作: ${displayText(String(action))})`);
}

const INVITE_ACTION_FLAGS: Readonly<Record<InviteAction, ReadonlySet<string>>> = {
  create: new Set(["role"]),
  accept: new Set(["inviter-fingerprint"]),
  list: new Set([]),
  revoke: new Set([]),
};

function inviteActionFlagRejection(
  action: string | undefined,
  tokens: readonly ArgTokenShape[],
  args: ArgTable,
): string | null {
  if (!isInviteAction(action)) {
    return null;
  }
  return actionFlagRejection("invite", INVITE_ACTIONS, INVITE_ACTION_FLAGS, action, tokens, args);
}

const INVITE_ROLES = ["reader", "member", "admin"] as const;

function isInviteRole(value: string | undefined): value is InviteRole {
  return INVITE_ROLES.some((known) => known === value);
}

/** ユーザー鍵 FP フラグ(CRYPTO_SPEC §3)— 共用パーサに出所の案内だけを差す。 */
function parseUserFingerprintFlag(
  flagName: string,
  value: string | undefined,
): Effect.Effect<string | null, CliError> {
  return parseFingerprintFlag(
    flagName,
    value,
    "ユーザー鍵 FP は hex 小文字 32 文字 — maruhi key show の key fingerprint",
  );
}

/** `maruhi invite create --role <r>`(§15-2 発行 + §15-3 リンク組み立て)。 */
function inviteCreate(
  flags: CommonFlags & { readonly role?: string | undefined },
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    if (!isInviteRole(flags.role)) {
      return yield* Effect.fail(
        usageError(
          `--role を指定してください(${INVITE_ROLES.join(" | ")} — owner は招待経由で付与できません。AUTH_SPEC §15-1)`,
        ),
      );
    }
    // リンク材料(ヘッド・自分の FP)はチェーン導出 — master 鍵は不要
    const context = yield* openMetadataProject(flags);
    yield* inviteCreateOp({
      client: context.client,
      verified: context.verified,
      origin: context.origin,
      role: flags.role,
      sessionUserId: context.session.userId,
    });
  });
}

/** `invite accept` の入力拒否理由 → usage 文言。 */
function acceptInputRejectionMessage(
  reason: "unsupported-version" | "missing-or-invalid-fragment-params" | "not-a-link-or-token",
): string {
  if (reason === "unsupported-version") {
    return "この招待リンクの形式バージョンには対応していません(maruhi CLI を更新してください)";
  }
  if (reason === "missing-or-invalid-fragment-params") {
    return "招待リンクのフラグメント(# 以降)が不完全または不正です。リンクが途中で切れずにコピーされているか確認してください(壊れたリンクをアンカーなしで受諾することはできません)";
  }
  return "招待リンク(…/invite#v=1&…)または招待トークン(maruhi_inv_…)を指定してください。リンクはシェルに解釈されないよう引用符で囲んでください";
}

/** `invite accept` の入力(リンク | トークン + --project)の解決。 */
function resolveAcceptTarget(
  rawTarget: string | undefined,
  projectFlag: string | undefined,
): Effect.Effect<AcceptTarget, CliError> {
  if (rawTarget === undefined) {
    return Effect.fail(
      usageError(
        "受諾する招待リンクまたはトークンを指定してください(リンクはシェルに解釈されないよう引用符で囲んでください)",
      ),
    );
  }
  const parsed = parseInviteAcceptInput(rawTarget);
  if (parsed.kind === "rejected") {
    return Effect.fail(usageError(acceptInputRejectionMessage(parsed.reason)));
  }
  if (parsed.kind === "token") {
    // 受諾署名(CRYPTO_SPEC §6.5)は project_id を署名対象に含むため、リンク
    // なしの受諾にはプロジェクト ID の帯域外供給が必須(config の
    // defaultProject へはフォールバックしない — 別プロジェクトへの署名を
    // 黙って作らない)
    if (projectFlag === undefined) {
      return Effect.fail(
        usageError(
          "生トークンでの受諾には --project <プロジェクト ID> が必須です(受諾署名はプロジェクト ID を署名対象に含みます — CRYPTO_SPEC §6.5)。招待リンクで受諾する場合は不要です",
        ),
      );
    }
    if (!isProjectId(projectFlag)) {
      return Effect.fail(usageError("プロジェクト ID の形式が正しくありません(64 桁の 16 進数)"));
    }
    return Effect.succeed({ kind: "token", token: parsed.token, projectId: projectFlag });
  }
  if (projectFlag !== undefined && projectFlag !== parsed.link.projectId) {
    return Effect.fail(
      usageError(
        "--project が招待リンクの p(プロジェクト ID)と一致しません。リンクで受諾する場合 --project は不要です",
      ),
    );
  }
  return Effect.succeed({ kind: "link", link: parsed.link });
}

/** `maruhi invite accept <link|token>`(§15-3 / CRYPTO_SPEC §6.3 (a) / §6.5)。 */
function inviteAccept(flags: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly target: string | undefined;
  readonly inviterFingerprint?: string | undefined;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const target = yield* resolveAcceptTarget(flags.target, flags.project);
    const expectInviterFingerprintHex = yield* parseUserFingerprintFlag(
      "--inviter-fingerprint",
      flags.inviterFingerprint,
    );
    const context = yield* openSession(flags.server);
    yield* inviteAcceptOp({
      client: context.client,
      session: context.session,
      target,
      expectInviterFingerprintHex,
      keyGenerate: keyGenerateOp({ session: context.session, client: context.client }),
    });
  });
}

/** `maruhi invite list`(受諾ブロックの §6.5 独立検証 + 発行ピン突合)。 */
function inviteList(flags: CommonFlags): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const context = yield* openMetadataProject(flags);
    const store = yield* PinStore;
    const loaded = yield* store.load(context.projectId);
    const summary = yield* inviteListOp({
      client: context.client,
      verified: context.verified,
      pins: loaded.pins,
      nowMs: Date.now(),
    });
    // 署名検証失敗・ピン不一致は「読み取りの成功」ではなく証拠の検出 — 0 に
    // しない(スクリプトが健全性チェックとして使える)
    return summary.integrityFailures > 0 ? 1 : 0;
  });
}

function inviteCommand(execute: Execute) {
  return define({
    name: "invite",
    description: `招待の管理(${INVITE_ACTIONS.join(" / ")} — AUTH_SPEC §15 / CRYPTO_SPEC §6.5)`,
    args: {
      action: { type: "positional", description: INVITE_ACTIONS.join(" | ") },
      target: {
        type: "positional",
        required: false,
        description: "accept: 招待リンクまたはトークン / revoke: 招待 id",
      },
      role: {
        type: "string",
        description: `付与する role(create では必須 — ${INVITE_ROLES.join(" | ")})`,
      },
      "inviter-fingerprint": {
        type: "string",
        description:
          "帯域外で控えた招待者の鍵 FP(hex 32 文字。accept のみ — 指定時は対話確認の代わりにリンクの if= と照合する)",
      },
      server: { type: "string", description: "サーバー URL(省略時は config の server)" },
      project: {
        type: "string",
        description:
          "プロジェクト ID(create / list / revoke は省略時 config の defaultProject。accept は生トークン受諾時のみ必須)",
      },
    },
    run: (ctx) =>
      execute(
        ctx,
        Effect.gen(function* () {
          const action = ctx.values.action;
          if (!isInviteAction(action)) {
            return yield* Effect.fail(usageError(INVITE_ACTION_HELP));
          }
          const flags = { server: ctx.values.server, project: ctx.values.project };
          if (action === "create") {
            return yield* inviteCreate({ ...flags, role: ctx.values.role });
          }
          if (action === "accept") {
            return yield* inviteAccept({
              ...flags,
              target: ctx.values.target,
              inviterFingerprint: ctx.values["inviter-fingerprint"],
            });
          }
          if (action === "list") {
            return yield* inviteList(flags);
          }
          if (action === "revoke") {
            const inviteId = ctx.values.target;
            if (inviteId === undefined) {
              return yield* Effect.fail(
                usageError(
                  "失効させる招待 id を指定してください(maruhi invite list で確認できます)",
                ),
              );
            }
            const context = yield* openMetadataProject(flags);
            return yield* inviteRevokeOp({
              client: context.client,
              verified: context.verified,
              inviteId,
            });
          }
          return yield* Effect.fail(unhandledInviteAction(action));
        }),
        {
          commandRejection: inviteActionFlagRejection(ctx.values.action, ctx.tokens, ctx.args),
          // 2 つ目の位置引数は accept / revoke 専用(env diff の 3 つ目と同じ形)
          withoutPositionals:
            isInviteAction(ctx.values.action) &&
            ctx.values.action !== "accept" &&
            ctx.values.action !== "revoke"
              ? ["target"]
              : undefined,
        },
      ),
  });
}

// ---------------------------------------------------------------------------
// member(CRYPTO_SPEC §6.2 / §6.5 / §7、AUTH_SPEC §12-6 — B1b)
// ---------------------------------------------------------------------------

const MEMBER_ACTIONS = ["add", "remove", "change-role"] as const;

type MemberAction = (typeof MEMBER_ACTIONS)[number];

const MEMBER_ACTION_HELP = `不明な操作です(${MEMBER_ACTIONS.join(" | ")})`;

function isMemberAction(action: string | undefined): action is MemberAction {
  return MEMBER_ACTIONS.some((known) => known === action);
}

/** MEMBER_ACTIONS の分岐漏れを型で捕まえる(unhandledEnvAction と同じ形)。 */
function unhandledMemberAction(action: never): CliError {
  return usageError(`${MEMBER_ACTION_HELP}(未対応の操作: ${displayText(String(action))})`);
}

const MEMBER_ACTION_FLAGS: Readonly<Record<MemberAction, ReadonlySet<string>>> = {
  add: new Set(["expect-fingerprint"]),
  remove: new Set([]),
  "change-role": new Set(["role"]),
};

function memberActionFlagRejection(
  action: string | undefined,
  tokens: readonly ArgTokenShape[],
  args: ArgTable,
): string | null {
  if (!isMemberAction(action)) {
    return null;
  }
  return actionFlagRejection("member", MEMBER_ACTIONS, MEMBER_ACTION_FLAGS, action, tokens, args);
}

const MEMBER_ROLES = ["reader", "member", "admin", "owner"] as const;

function isMemberRole(value: string | undefined): value is Role {
  return MEMBER_ROLES.some((known) => known === value);
}

/** sweep 結果(§7 の全環境走査)の報告と終了コードの導出(remove / 降格共通)。 */
function reportMemberSweep(
  sweep: SweepOutcome & { readonly skippedDeleted: readonly string[] },
  rerunCommand: string,
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (sweep.skippedDeleted.length > 0) {
      yield* io.log(
        `削除済み環境(署名済み削除ステートメントを検証済み)のためスキップ: ${sweep.skippedDeleted.join(", ")}`,
      );
    }
    if (sweep.alreadyRotated.length > 0) {
      yield* io.log(
        `ローテーション済み(義務エントリより後のエポック・未完了の再暗号化なしを確認): ${sweep.alreadyRotated.join(", ")}`,
      );
    }
    let exitCode = 0;
    for (const item of sweep.rotated) {
      const code = yield* reportRotation(
        item.environmentId as EnvironmentId,
        item.summary,
        item.forcedNewEpoch,
      );
      if (code !== 0) {
        exitCode = 1;
      }
    }
    for (const failure of sweep.failed) {
      // §7: active と信じる環境の rotate 拒否を黙ってスキップしない(悪意サーバーに
      // よる選択的なローテーション阻止を不可視にしない)
      yield* io.logError(
        `警告: 環境 ${displayText(failure.environmentId)} のローテーションに失敗しました: ${failure.message} — 解消して ${rerunCommand} を再実行すると続きから再開します(環境を削除済みの場合は、検証済みの削除ステートメントを確認してください)`,
      );
      exitCode = 1;
    }
    return exitCode;
  });
}

/**
 * §7 の全環境走査へ注入する 1 環境ローテーション(server revoke / member
 * remove / change-role で共用)。義務エントリの追記や先行の rotate でチェーンは
 * 前進しているので、各環境は再同期済みビューで開始する。force = §7 の強制
 * (新エポック必須)/ verify = 検証パス(未完了の再暗号化があれば再開)。
 */
function sweepRotateFor(
  context: ProjectContext,
  reason: string,
): (
  environmentId: string,
  mode: SweepRotateMode,
) => Effect.Effect<RotationSummary, CliError, CliServices> {
  return (environmentId: string, mode: SweepRotateMode) =>
    Effect.gen(function* () {
      if (!isEnvironmentId(environmentId)) {
        return yield* Effect.fail(cliErrorForInvalidChainEnvironmentId());
      }
      const floorHandle = yield* floorHandleFor(context, environmentId);
      const verified = yield* context.resync;
      return yield* envRotateOp({
        client: context.client,
        verified,
        environmentId,
        recipient: context.recipient,
        reason: mode === "force" ? reason : undefined,
        forceNewEpoch: mode === "force",
        signerUserId: context.session.userId,
        signingKeyPair: context.masterKeys.sigKeyPair,
        resync: context.resync,
        floor: floorHandle,
      });
    });
}

/** `maruhi member add [invite-id]`(§6.5 の相互確認 + add_member + バックフィル)。 */
function memberAdd(
  flags: CommonFlags & {
    readonly invite?: string | undefined;
    readonly expectFingerprint?: string | undefined;
  },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const expectFingerprintHex = yield* parseUserFingerprintFlag(
      "--expect-fingerprint",
      flags.expectFingerprint,
    );
    const context = yield* openProject(flags);
    const store = yield* PinStore;
    const loaded = yield* store.load(context.projectId);
    const summary = yield* memberAddOp({
      client: context.client,
      verified: context.verified,
      inviteId: flags.invite ?? null,
      expectFingerprintHex,
      pins: loaded.pins,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      recipient: context.recipient,
      resync: context.resync,
    });
    return yield* reportMemberAdd(io, summary);
  });
}

/** member add の結果報告と終了コード(バックフィル失敗 = 部分完了)。 */
function reportMemberAdd(
  io: CliIoShape,
  summary: MemberAddSummary,
): Effect.Effect<number, CliError> {
  return Effect.gen(function* () {
    const repaired = summary.repaired > 0 ? `、旧鍵ラップの修復 ${summary.repaired} 件` : "";
    yield* io.log(
      `メンバー追加: ${displayText(summary.targetUserId)}(role=${summary.role})。バックフィル: 新規 ${summary.registered} 件、登録済み ${summary.alreadyRegistered} 件${repaired}`,
    );
    if (summary.failed.length === 0) {
      yield* io.log(
        "完了: 新メンバーに全環境 × 全エポックの DEK ラップを配布しました(CRYPTO_SPEC §7)。新メンバー側で maruhi pull を実行し、復号できることを確認してもらってください",
      );
      return 0;
    }
    for (const failure of summary.failed) {
      yield* io.logError(
        `警告: 環境 ${displayText(failure.environmentId)} のバックフィルに失敗しました: ${failure.message} — 解消して maruhi member add を再実行すると続きから再開します(409 = 登録済みとして収束します)`,
      );
    }
    return 1;
  });
}

/** `maruhi member remove <user-id>`(§7 — 全環境の強制ローテーションを伴う)。 */
function memberRemove(
  flags: CommonFlags & { readonly target: string },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // 収束系コマンド: 未収束義務の常時警告は抑制(自分の sweep 報告が担う)
    const context = yield* openProject(flags, { quietMandateWarning: true });
    const summary = yield* memberRemoveOp({
      client: context.client,
      verified: context.verified,
      targetUserId: flags.target,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
      rotate: sweepRotateFor(context, MEMBER_REMOVED_ROTATION_REASON),
    });
    if (summary.appended) {
      yield* io.log(
        `remove_member をチェーンへ追記しました(target=${displayText(summary.targetUserId)})。全環境の強制ローテーションを実行します(CRYPTO_SPEC §7)`,
      );
    } else {
      yield* io.log(
        "対象は既に削除済みでした — 追記せず、全環境ローテーションの続きから再開します(中断復旧)",
      );
    }
    const exitCode = yield* reportMemberSweep(summary, "maruhi member remove");
    if (exitCode === 0) {
      yield* io.log("完了: メンバー削除と全環境ローテーションが完了しました");
    }
    // 要ローテーションフラグの件数と導線(B2 — AUDIT_SPEC §4.1。ローテーションは
    // 新しい DEK を配るだけで、既読の値そのものは取り消せない)
    yield* reportRotationFlagCount({
      client: context.client,
      projectId: context.projectId,
      target: { kind: "member", userId: summary.targetUserId },
    });
    return exitCode;
  });
}

/** `maruhi member change-role <user-id> --role <r>`(降格は §7 のローテーション義務)。 */
function memberChangeRole(
  flags: CommonFlags & { readonly target: string; readonly role?: string | undefined },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (!isMemberRole(flags.role)) {
      return yield* Effect.fail(
        usageError(`--role を指定してください(${MEMBER_ROLES.join(" | ")})`),
      );
    }
    // 収束系コマンド: 未収束義務の常時警告は抑制(降格の sweep 報告が担う)
    const context = yield* openProject(flags, { quietMandateWarning: true });
    const summary = yield* memberChangeRoleOp({
      client: context.client,
      verified: context.verified,
      targetUserId: flags.target,
      newRole: flags.role,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
      rotate: sweepRotateFor(context, ROLE_DEMOTED_ROTATION_REASON),
    });
    if (summary.appended) {
      yield* io.log(
        `change_role をチェーンへ追記しました(target=${displayText(summary.targetUserId)}、role=${summary.newRole})`,
      );
    } else {
      yield* io.log("対象は既に指定の role です — 追記していません");
    }
    if (summary.sweep === null) {
      yield* io.log("完了: role を変更しました(ローテーション義務はありません)");
      return 0;
    }
    yield* io.log(
      "member 未満への降格のため、全環境の強制ローテーションを実行します(CRYPTO_SPEC §7 — エポックアンカーの健全性)",
    );
    const exitCode = yield* reportMemberSweep(summary.sweep, "maruhi member change-role");
    if (exitCode === 0) {
      yield* io.log("完了: 降格と全環境ローテーションが完了しました");
    }
    return exitCode;
  });
}

function memberCommand(execute: Execute) {
  return define({
    name: "member",
    description: `メンバーの管理(${MEMBER_ACTIONS.join(" / ")} — CRYPTO_SPEC §6.2 / §6.5 / §7)`,
    args: {
      action: { type: "positional", description: MEMBER_ACTIONS.join(" | ") },
      target: {
        type: "positional",
        required: false,
        description: "add: 招待 id(受諾済みが 1 件なら省略可)/ remove・change-role: 対象 user_id",
      },
      role: {
        type: "string",
        description: `新しい role(change-role では必須 — ${MEMBER_ROLES.join(" | ")})`,
      },
      "expect-fingerprint": {
        type: "string",
        description:
          "帯域外で控えた受諾者の鍵 FP(hex 32 文字。add のみ — 指定時は対話確認の代わりに照合する)",
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
          if (!isMemberAction(action)) {
            return yield* Effect.fail(usageError(MEMBER_ACTION_HELP));
          }
          const flags = { server: ctx.values.server, project: ctx.values.project };
          if (action === "add") {
            return yield* memberAdd({
              ...flags,
              invite: ctx.values.target,
              expectFingerprint: ctx.values["expect-fingerprint"],
            });
          }
          const target = ctx.values.target;
          if (target === undefined || target.length === 0) {
            return yield* Effect.fail(
              usageError(
                "対象の user_id を指定してください(maruhi project verify のメンバー一覧で確認できます)",
              ),
            );
          }
          if (action === "remove") {
            return yield* memberRemove({ ...flags, target });
          }
          if (action === "change-role") {
            return yield* memberChangeRole({ ...flags, target, role: ctx.values.role });
          }
          return yield* Effect.fail(unhandledMemberAction(action));
        }),
        {
          commandRejection: memberActionFlagRejection(ctx.values.action, ctx.tokens, ctx.args),
        },
      ),
  });
}

/** `maruhi rotation` が取る操作(一覧の出所はここだけ — ENV_ACTIONS と同じ形)。 */
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

/** `maruhi audit` が取る操作(一覧の出所はここだけ — ENV_ACTIONS と同じ形)。 */
const AUDIT_ACTIONS = ["list", "invites", "self", "verify"] as const;

type AuditAction = (typeof AUDIT_ACTIONS)[number];

const AUDIT_ACTION_HELP = `不明な操作です(${AUDIT_ACTIONS.join(" | ")} — 省略時は list)`;

function isAuditAction(action: string | undefined): action is AuditAction {
  return AUDIT_ACTIONS.some((known) => known === action);
}

/** AUDIT_ACTIONS の分岐漏れを型で捕まえる(unhandledEnvAction と同じ形)。 */
function unhandledAuditAction(action: never): CliError {
  return usageError(`${AUDIT_ACTION_HELP}(未対応の操作: ${displayText(String(action))})`);
}

/**
 * 操作専用のオプション(ENV_ACTION_FLAGS と同じ形)。`--project` は self 以外の
 * 共有(self はアカウント全域でプロジェクトを取らない — 黙って無視しない)。
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

/** ページ指定フラグの検査(limit 1〜200・before ≥ 1 の整数)。 */
/** 未指定は許容し、指定時は [1, max] の整数のみ通す(max = null は上限なし)。 */
function outsideIntRange(value: number | undefined, max: number | null): boolean {
  if (value === undefined) {
    return false;
  }
  return !Number.isInteger(value) || value < 1 || (max !== null && value > max);
}

function parseAuditPage(
  limit: number | undefined,
  before: number | undefined,
): Effect.Effect<AuditPageOptions, CliError> {
  if (outsideIntRange(limit, 200)) {
    return Effect.fail(
      usageError("--limit は 1〜200 の整数で指定してください(AUDIT_SPEC §7 の上限)"),
    );
  }
  if (outsideIntRange(before, null)) {
    return Effect.fail(usageError("--before は 1 以上の整数(監査 seq カーソル)で指定してください"));
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
      limit: { type: "number", description: "1 ページの件数(1〜200。既定 50)" },
      before: {
        type: "number",
        description: "この監査 seq より古い行から表示する(前ページ末尾の seq を渡して遡る)",
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
    server: serverCommand(execute),
    invite: inviteCommand(execute),
    member: memberCommand(execute),
    rotation: rotationCommand(execute),
    audit: auditCommand(execute),
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
