// `maruhi push` 直後の同期(SY2 第 3 段 — integration-options.md §3「同期の最終形」
// の表「運ぶ主体」の行: 値を変えられるのは人間だけ → 変更の瞬間には書き手の CLI
// がいる → 書き手の CLI が直接同期するか、`gh workflow run` で CI を起動する。
// 補足 4 N1 / 補足 7 P1)。
//
// 同期設定のターゲットが `onPush` を持てば、push が受理された**後始末**として:
// - `"apply"`: 既存の `syncApplyOp`(sync-plan.ts — 復号 → ドライバの stdin / API
//   本文 → レシート)をそのまま呼ぶ。plan はレシートと現在の version の差なので、
//   書くのは今 push した変数だけ(前回の取りこぼしがあればそれも)。production
//   ターゲットには設定の段階で拒まれている(sync-config.ts — production を書くのは
//   人が `--yes` を打つ `maruhi sync apply` だけ)
// - `"workflow"`: 書き手の `gh`(利用者自身の GitHub 認証)で
//   `gh workflow run <file> -f target=<name>` を叩き、CI(`maruhi ci sync`)に運ばせる。
//   書き手は同期先のトークンを持たない(P1)。**値も変数名も載せない**: argv は
//   設定由来のターゲット名と workflow の名前だけで、値は CI が maruhi から取る。
//   起動の受理だけを報告し、結果は待たない(一方通行)。レシートは CI が書けない
//   ので進まない(docs「In CI」の 3 点目)
//
// 後始末であって push の一部ではない(2b の裁定 D と同じ規律): 通信・権限・競合・
// ベンダー / gh の失敗は警告に留め、push の終了コードを変えない — 未同期の印は
// レシートの遅れそのもの(次の `maruhi sync plan` が pending と示す)で、次の apply
// か CI が回収する。**証拠**(`CliError.evidence`)だけはそのまま失敗として通す
// (asCleanupOutcome — errors.ts)。push 自体の報告と checkpoint / アンカーの提案は
// ここより前に出ている。
//
// 設定の所在(裁定 B): `--config` 明示か、cwd の既定パス(`maruhi.sync.json`)。
// 既定パスは黙って使うので、`project` を名乗る設定にしか使わず(sync-config.ts が
// `onPush` に `project` を要求する)、push 先のプロジェクトと違えば何もしない
// (note)。明示の `--config` で食い違えば書き方の誤り(2)— push の前に止める
// (2b の裁定 B)。`--no-sync` は設定を読まずに push だけを行う(補足 14 M8 —
// 連続 push の末尾で 1 回 `maruhi sync apply`)。
//
// 既定パスの設定が**実行体を名指し**するターゲット(exec の `command` /
// `workflow.command`)は動かさない(改訂 2): プロジェクト ID は公開リポジトリでは
// 公開情報で、fork に置かれた設定が「その ID + 任意のプログラム」を名指しして書き手の
// 平文を stdin で受け取る形を、cwd だけで成立させない。プリセットの既定の実行体
// (PATH 上の `vercel` / `wrangler` / `gh`)だけが既定パスから動く。
//
// エージェント環境の専用ゲートは無い(補足 9 — `sync` は `run` と同じ扱い)。
// 出力に出るのはターゲット名・workflow 名・件数・version・変数名(displayText)だけ。

import type { EnvironmentId } from "@maruhi/core";
import { Effect, Redacted } from "effect";

import { type CliServices, type EnvironmentContext, floorHandleFor } from "./context.ts";
import { displayText } from "./display.ts";
import { asCleanupOutcome, type CliError, usageError } from "./errors.ts";
import type { FloorHandle } from "./floor-check.ts";
import { CliIo } from "./io.ts";
import { logNote, logWarning } from "./notice.ts";
import { type ExecInput, ProcessRunner } from "./run.ts";
import {
  DEFAULT_SYNC_CONFIG_PATH,
  loadSyncConfig,
  loadSyncConfigIfPresent,
  type OnPush,
  type SyncConfig,
  type SyncTarget,
} from "./sync-config.ts";
import { scrubVendorOutput } from "./sync-exec.ts";
import { syncApplyOp } from "./sync-plan.ts";

/** The sync config `maruhi push` found, and how. */
export interface PushSyncSetup {
  readonly config: SyncConfig;
  readonly path: string;
  /** `--config` で明示された(true)か、cwd の既定パスを黙って読んだ(false)か。 */
  readonly explicit: boolean;
}

/**
 * Reads the sync config before the push touches the network: the explicit
 * `--config` must exist; the default path is optional. `--no-sync` reads
 * nothing (the push behaves as if no config existed) and cannot be combined
 * with `--config`.
 */
export function loadPushSyncConfig(input: {
  readonly config: string | undefined;
  readonly noSync: boolean;
}): Effect.Effect<PushSyncSetup | null, CliError> {
  return Effect.gen(function* () {
    if (input.noSync) {
      if (input.config !== undefined) {
        // 指した設定を読まずに済ませる形を黙って通さない(pullfrog 指摘)
        return yield* Effect.fail(
          usageError("--no-sync and --config cannot be combined (drop one of them)"),
        );
      }
      return null;
    }
    if (input.config !== undefined) {
      const config = yield* loadSyncConfig(input.config);
      return { config, path: input.config, explicit: true };
    }
    const config = yield* loadSyncConfigIfPresent(DEFAULT_SYNC_CONFIG_PATH);
    return config === null ? null : { config, path: DEFAULT_SYNC_CONFIG_PATH, explicit: false };
  });
}

/** What the cleanup will do (decided before the push, so a usage error stops it). */
export type PushSyncDecision =
  /** 既定パスの設定が別プロジェクトのもの(何もしない — note)。 */
  | { readonly kind: "other-project" }
  /** push 先の環境からこの変数を運ぶ `onPush` ターゲットが無い。 */
  | { readonly kind: "none" }
  | {
      readonly kind: "targets";
      readonly targets: readonly SyncTarget[];
      /**
       * 既定パスの設定が**実行体を名指し**しているターゲット(exec の `command` /
       * `workflow.command`)。cwd で見つけただけの設定から、その設定が名指しする
       * プログラムに平文を渡す形を作らない: 同期しない旨を note で言い、`--config`
       * 明示(利用者がそのファイルを指す動作)でだけ動かす(pullfrog 指摘 — 改訂 2)
       */
      readonly namesCommand: readonly SyncTarget[];
    };

/** ターゲットがこの変数を運ぶか(明示リスト / `"all"` − exclude)。 */
function targetCarries(target: SyncTarget, name: string): boolean {
  return target.variables === "all"
    ? !target.exclude.includes(name)
    : target.variables.includes(name);
}

/**
 * Decides the cleanup from the resolved project, environment, and variable
 * name. An explicit config that belongs to another project is a usage error
 * (before the push); the default config is then simply not used.
 */
export function decidePushSync(
  setup: PushSyncSetup,
  input: {
    readonly projectId: string;
    readonly environmentId: string;
    readonly name: string;
  },
): Effect.Effect<PushSyncDecision, CliError> {
  const { config } = setup;
  const onPush = [...config.targets.values()].filter((target) => target.onPush !== null);
  if (onPush.length === 0) {
    // 手動同期だけの設定: push には無関係(`project` の照合もしない — 設定は
    // `onPush` を持つときだけ `project` を名乗る義務がある)
    return Effect.succeed({ kind: "none" });
  }
  if (config.projectId !== undefined && config.projectId !== input.projectId) {
    if (setup.explicit) {
      return Effect.fail(
        usageError(
          "The sync config belongs to a different project (its `project` does not match the project being pushed to)",
        ),
      );
    }
    return Effect.succeed({ kind: "other-project" });
  }
  const selected = onPush.filter(
    (target) => target.environment === input.environmentId && targetCarries(target, input.name),
  );
  if (selected.length === 0) {
    return Effect.succeed({ kind: "none" });
  }
  const namesCommand = setup.explicit ? [] : selected.filter(namesCommandToRun);
  return Effect.succeed({
    kind: "targets",
    targets: selected.filter((target) => !namesCommand.includes(target)),
    namesCommand,
  });
}

/**
 * The target names the program to run (an exec `command` other than the
 * preset's own CLI name, or a `workflow.command` other than `gh`): the
 * preset's default is looked up on PATH, a named one is whatever the file
 * says. Only an explicitly passed config may do that after a push.
 */
function namesCommandToRun(target: SyncTarget): boolean {
  const onPush = target.onPush;
  if (onPush?.kind === "workflow") {
    return onPush.command !== DEFAULT_GH_COMMAND;
  }
  return target.driver.kind === "exec" && target.driver.command !== target.driver.spec.command;
}

/** `gh` の既定の実行体(PATH 上)。 */
const DEFAULT_GH_COMMAND = "gh";

/** `gh` に足す非機密の環境変数(テレメトリ off — SY1 の実測表の gh 行。対話とアップデート確認も切る)。 */
const GH_ENV: Readonly<Record<string, string>> = {
  GH_TELEMETRY: "false",
  DO_NOT_TRACK: "1",
  GH_NO_UPDATE_NOTIFIER: "1",
  GH_PROMPT_DISABLED: "1",
};

/** gh の終了コード 4 = 認証が要る(cli/cli internal/ghcmd/cmd.go の exitAuth)。 */
const GH_EXIT_AUTH = 4;

/**
 * The `gh workflow run` invocation for one target: the workflow file, the
 * target name as the only input, and `--ref` when the config pins one. No
 * value and no variable name is on the command line — CI reads the values
 * from maruhi. Stdin is empty.
 */
function buildWorkflowDispatch(
  target: SyncTarget,
  onPush: Extract<OnPush, { kind: "workflow" }>,
): ExecInput {
  return {
    command: [
      onPush.command,
      "workflow",
      "run",
      onPush.file,
      "-f",
      `target=${target.name}`,
      ...(onPush.ref === undefined ? [] : ["--ref", onPush.ref]),
    ],
    cwd: onPush.cwd,
    extraEnv: GH_ENV,
    stdin: Redacted.make(new Uint8Array(0), { label: "sync-stdin" }),
  };
}

/** 回収の案内(直接 apply と CI 起動の失敗で共通 — 2b の文面と同じ方向)。 */
function recoveryHint(target: SyncTarget): string {
  return `The next \`maruhi sync plan ${displayText(target.name)}\` shows the pushed variable as pending; \`maruhi sync apply ${displayText(target.name)}\` or CI delivers it`;
}

/** CI 起動: `gh workflow run` を叩き、受理(終了コード 0)だけを報告する。 */
function triggerWorkflow(
  target: SyncTarget,
  onPush: Extract<OnPush, { kind: "workflow" }>,
): Effect.Effect<void, CliError, CliIo | ProcessRunner> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const runner = yield* ProcessRunner;
    const invocation = buildWorkflowDispatch(target, onPush);
    const name = displayText(target.name);
    const file = displayText(onPush.file);
    const outcome = yield* runner.exec(invocation);
    if (outcome.exitCode === 0) {
      yield* io.log(
        `Triggered workflow ${file} for target ${name} (\`gh workflow run\` in ${displayText(onPush.cwd)}). CI applies it with \`maruhi ci sync\` and keeps no receipt, so the next local \`maruhi sync plan ${name}\` still shows the pushed variable as pending`,
      );
      return;
    }
    if (outcome.exitCode === GH_EXIT_AUTH) {
      yield* logWarning(
        `the push is done, but workflow ${file} was not triggered for target ${name}: gh is not signed in (run \`gh auth login\`, or trigger the workflow yourself). ${recoveryHint(target)}`,
      );
      return;
    }
    // gh の出力は信用しない: 値は無いはずだが、伏せてから切る規律は同じ
    for (const line of scrubVendorOutput(outcome.output, [])) {
      yield* io.logError(`  ${displayText(onPush.command)}: ${line}`);
    }
    yield* logWarning(
      `the push is done, but workflow ${file} was not triggered for target ${name} (${displayText(onPush.command)} exited with code ${outcome.exitCode}; its output is shown above). Check that the workflow exists on the branch gh dispatches to and has a workflow_dispatch trigger with a "target" input, then trigger it yourself or let the next push retry. ${recoveryHint(target)}`,
    );
  });
}

/**
 * 1 回の push で環境ごとに床ハンドルを 1 つだけ持つ台帳(同じ環境に 2 つのハンドルを
 * 開かない — `openSyncTarget` と同じ規律。複数ターゲットが 1 つのトークン環境を共有
 * するとき、2 つ目が push 前の床のスナップショットから始まらないように — pullfrog 指摘)。
 */
function floorLedger(
  context: EnvironmentContext,
): (environmentId: string) => Effect.Effect<FloorHandle, never, CliServices> {
  const handles = new Map<string, FloorHandle>([[context.environmentId, context.floorHandle]]);
  return (environmentId) =>
    Effect.gen(function* () {
      const known = handles.get(environmentId);
      if (known !== undefined) {
        return known;
      }
      const handle = yield* floorHandleFor(context, environmentId);
      handles.set(environmentId, handle);
      return handle;
    });
}

/** 直接 apply: 既存の apply をそのまま(unchanged の行は省く)。 */
function applyTarget(
  context: EnvironmentContext,
  setup: PushSyncSetup,
  target: SyncTarget,
  floorOf: (environmentId: string) => Effect.Effect<FloorHandle, never, CliServices>,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* io.log(
      `Syncing target ${displayText(target.name)} after the push (onPush in ${displayText(setup.path)})`,
    );
    // 床ハンドルは環境ごとに 1 つ(同期元 = push 先は push のハンドル、レシート環境と
    // 統合トークンの環境は台帳が返す同じもの)
    const receiptsFloor = yield* floorOf(setup.config.receiptsEnvironment);
    const tokenFloor =
      target.driver.kind !== "http" ? null : yield* floorOf(target.driver.token.environment);
    yield* syncApplyOp({
      client: context.client,
      verified: context.verified,
      recipient: context.recipient,
      resync: context.resync,
      target,
      // push 先の環境 = 同期元: push が進めた床ハンドルをそのまま渡す
      sourceFloor: context.floorHandle,
      receiptsEnvironment: setup.config.receiptsEnvironment as EnvironmentId,
      receiptsFloor,
      writerUserId: context.session.userId,
      signingKey: context.masterKeys.sigKeyPair.privateKey,
      // production ターゲットは設定の段階で "apply" になれない(sync-config.ts)。
      // 万一到達しても requireProductionConsent が止め、警告になる
      yes: false,
      now: () => new Date(),
      tokenFloor,
      display: { showUnchanged: false },
    });
  });
}

/**
 * Runs the sync each `onPush` target asked for, after the push was reported.
 * A failure on one target is a warning (the push is done; the receipt lag is
 * the mark, and the next apply or CI run delivers it) and the remaining
 * targets are still processed. Only evidence fails the command.
 */
export function syncAfterPush(input: {
  readonly context: EnvironmentContext;
  readonly setup: PushSyncSetup;
  readonly decision: PushSyncDecision;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const { context, setup, decision } = input;
    if (decision.kind === "other-project") {
      yield* logNote(
        `the sync config ${displayText(setup.path)} belongs to a different project, so nothing was synced after the push`,
      );
      return;
    }
    if (decision.kind === "none") {
      if (setup.explicit) {
        yield* logNote(
          `no target in the sync config copies this variable from environment ${displayText(context.environmentId)} on push, so nothing was synced (set "onPush" on a target to sync it after every push)`,
        );
      }
      return;
    }
    for (const target of decision.namesCommand) {
      yield* logNote(
        `target ${displayText(target.name)} names the program to run (its command in ${displayText(setup.path)}), and a config found in the working directory does not start one after a push. Pass --config ${displayText(setup.path)} to sync it after this push, or run \`maruhi sync apply ${displayText(target.name)}\``,
      );
    }
    const floorOf = floorLedger(context);
    for (const target of decision.targets) {
      const onPush = target.onPush;
      if (onPush === null) {
        continue;
      }
      const attempt = yield* asCleanupOutcome(
        onPush.kind === "apply"
          ? applyTarget(context, setup, target, floorOf)
          : triggerWorkflow(target, onPush),
      );
      if (attempt.kind === "failed") {
        yield* logWarning(
          `the push is done, but target ${displayText(target.name)} could not be synced (${attempt.error.message}). ${recoveryHint(target)}`,
        );
      }
    }
  });
}
