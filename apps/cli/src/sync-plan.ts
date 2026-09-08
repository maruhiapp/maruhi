// `maruhi sync plan` / `maruhi sync apply`(SY2 第 1 段 — integration-options.md
// §3「同期の最終形」の表: ドライバ × リポジトリ設定 × レシート × plan / apply。
// 第 2 段で http ドライバと、レシートを持たない CI の経路〔sync-ci.ts〕が同じ
// 芯〔{@link runDriver}〕に載った)。
//
// plan = 「レシート(前回届いた version)と maruhi の現在の version の差」を
// 名前と version だけで示す。同期先は**読み戻さない**(一方通行 — ADR-0014。
// Vercel の sensitive 値は読み戻せないので、レシートが唯一の突合材料 — 補足 13 W2)。
// plan は同期元の値を復号しない(値署名の検証までで止まる — values.ts の
// pullVerifiedEnvironment)し、ベンダー API にも触れない。apply は復号し
// (pull.ts)、exec ドライバならベンダー CLI の stdin に一度だけ書き(sync-exec.ts)、
// http ドライバならベンダー API のリクエスト本文に載せる(sync-http.ts)。値は
// stdout / stderr / エラー文面に出ない。
//
// production の既定は plan のみ(補足 14 M4): production 扱いのターゲットへの
// apply は `--yes` を要求する。エージェント環境の専用ゲートは作らない(補足 9 —
// `run` と同じ扱い)。
//
// 完全性(補足 14 M5): required と宣言された変数に値が無ければ、`run` の
// presence fail-fast と同じ規則で何も運ばずに止める。required の active 変数が
// ターゲットの選択から漏れていれば警告する(同期先で欠けるのは契約違反だが、
// 運ぶものを選ぶのは設定の責務)。

import type { EnvironmentId } from "@maruhi/core";
import { Effect, Redacted } from "effect";
import type { HttpClient } from "effect/unstable/http";

import type { MaruhiClient } from "./api.ts";
import type { DekRecipient } from "./deks.ts";
import { countNoun, decodeValueText, displayText, logWarnings } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { FloorHandle } from "./floor-check.ts";
import { CliIo } from "./io.ts";
import { logNote, logWarning } from "./notice.ts";
import { type DeclaredVariable, pullVariables, toDeclaredVariables } from "./pull.ts";
import { enforceDeclaredPresence, ProcessRunner } from "./run.ts";
import type { SyncTarget, TargetDriver } from "./sync-config.ts";
import {
  buildInvocations,
  checkValueConstraints,
  scrubVendorOutput,
  type SyncWrite,
} from "./sync-exec.ts";
import {
  buildBatches,
  checkIntegrationToken,
  DEFAULT_HTTP_RETRY,
  type HttpRetryPolicy,
  type IntegrationToken,
  resolveOptions,
  runBatch,
} from "./sync-http.ts";
import {
  loadReceipt,
  type LoadedReceipt,
  receiptVariableName,
  receiptVersionWarning,
  storeReceipt,
  type SyncReceipt,
} from "./sync-receipt.ts";
import type { VerifiedProject } from "./sync.ts";
import { pullVerifiedEnvironment } from "./values.ts";

/** One line of a plan. `blocked` = apply would refuse it (reason names only the variable). */
export type PlanEntry =
  | { readonly action: "add"; readonly name: string; readonly version: number }
  | {
      readonly action: "update";
      readonly name: string;
      readonly version: number;
      readonly previousVersion: number;
    }
  | { readonly action: "unchanged"; readonly name: string; readonly version: number }
  | { readonly action: "delete"; readonly name: string; readonly previousVersion: number }
  | {
      readonly action: "blocked";
      readonly name: string;
      readonly version: number;
      readonly reason: string;
    };

/** A computed plan for one target. */
export interface SyncPlan {
  readonly entries: readonly PlanEntry[];
  /** 選択されているが required の宣言だけで値が無い変数(apply は何も運ばない)。 */
  readonly declaredRequired: readonly DeclaredVariable[];
  /** required の active 変数のうち、ターゲットの選択から漏れている名前(警告)。 */
  readonly requiredNotSelected: readonly string[];
}

/** 同期元の 1 変数(plan は暗号文の長さから平文長を出す — 復号しない)。 */
export interface SourceVariable {
  readonly name: string;
  readonly version: number;
  /** 平文のバイト長(plan = 暗号文長 − GCM タグ 16 バイト、apply = 実測)。 */
  readonly byteLength: number;
  /** required の宣言(レイアウト v1 = false)。 */
  readonly required: boolean;
}

const GCM_TAG_BYTES = 16;

function byName<T extends { readonly name: string }>(entries: readonly T[]): Map<string, T> {
  return new Map(entries.map((entry) => [entry.name, entry] as const));
}

/** 復号済み変数 → plan の材料(apply / ci sync)。平文長は実測する。 */
export function sourceVariablesOf(
  variables: readonly {
    readonly name: string;
    readonly version: number;
    readonly required: boolean;
    readonly value: Redacted.Redacted<Uint8Array>;
  }[],
): readonly SourceVariable[] {
  return variables.map((variable) => ({
    name: variable.name,
    version: variable.version,
    // 剥がす理由: 平文長の実測(産物は長さだけ)。plan 段の暗号文長からの推定と
    // 同じ値になるが、apply は実際に送るバイト列で判定する
    byteLength: Redacted.value(variable.value).byteLength,
    required: variable.required,
  }));
}

/** 復号済み変数 → 名前で引ける書き込み材料(値は包んだまま)。 */
export function writesOf(
  variables: readonly { readonly name: string; readonly value: Redacted.Redacted<Uint8Array> }[],
): ReadonlyMap<string, SyncWrite> {
  return byName(variables.map((variable) => ({ name: variable.name, value: variable.value })));
}

/** 文面用のドライバの呼び名("the vercel CLI" / "the Vercel API")。 */
function driverLabel(driver: TargetDriver): string {
  return driver.kind === "exec" ? `the ${driver.spec.command} CLI` : driver.spec.label;
}

/**
 * Resolves which variables the target carries: the explicit list, or every
 * active variable minus `exclude`. Names in an explicit list that exist
 * neither as an active nor as a declared variable are a hard error (the
 * config and the environment disagree — nothing is synced).
 */
function selectNames(
  target: SyncTarget,
  source: ReadonlyMap<string, SourceVariable>,
  declared: ReadonlyMap<string, DeclaredVariable>,
): Effect.Effect<readonly string[], CliError> {
  if (target.variables === "all") {
    const excluded = new Set(target.exclude);
    return Effect.succeed([...source.keys()].filter((name) => !excluded.has(name)).toSorted());
  }
  const missing = target.variables.filter((name) => !source.has(name) && !declared.has(name));
  if (missing.length > 0) {
    return Effect.fail(
      cliError(
        `The target lists variables that do not exist in environment ${displayText(target.environment)}: ${missing.map(displayText).join(", ")}. Push them first, or remove them from the target's variables in the sync config`,
      ),
    );
  }
  return Effect.succeed([...target.variables].toSorted());
}

/** 1 変数の plan 行(名前 / size / 空の制約はここで、内容の制約は apply で)。 */
function classifyVariable(
  driver: TargetDriver,
  variable: SourceVariable,
  previousVersion: number | undefined,
): PlanEntry {
  const { name, version } = variable;
  const { constraints } = driver.spec;
  // 名前の規則は平文を要しない = plan で判定できる(apply の checkValueConstraints は
  // 防衛線として残る)。理由文は名前と規則だけを運ぶ
  if (constraints.name !== null && !constraints.name.regex.test(name)) {
    return {
      action: "blocked",
      name,
      version,
      reason: `a name ${driverLabel(driver)} cannot store as is: ${constraints.name.rule}`,
    };
  }
  if (constraints.nonEmpty && variable.byteLength === 0) {
    return {
      action: "blocked",
      name,
      version,
      reason: `empty value (${driverLabel(driver)} reads an empty stdin as no value)`,
    };
  }
  if (constraints.maxBytes !== null && variable.byteLength > constraints.maxBytes) {
    return {
      action: "blocked",
      name,
      version,
      reason: `${variable.byteLength} bytes, above the ${constraints.maxBytes}-byte limit for ${driverLabel(driver)}`,
    };
  }
  if (previousVersion === undefined) {
    return { action: "add", name, version };
  }
  if (previousVersion === version) {
    return { action: "unchanged", name, version };
  }
  return { action: "update", name, version, previousVersion };
}

function compareByName(a: { readonly name: string }, b: { readonly name: string }): number {
  return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
}

/**
 * Computes the plan: receipt versions vs current versions, names only.
 * `blocked` entries come from the driver's name / size / emptiness
 * constraints (content constraints need the plaintext and are checked at
 * apply). A receipt-only name is a `delete` even when the driver could not
 * store it today: the delete carries no value, and the vendor reports a name
 * it cannot address.
 */
export function computePlan(input: {
  readonly target: SyncTarget;
  readonly source: readonly SourceVariable[];
  readonly declared: readonly DeclaredVariable[];
  readonly receipt: SyncReceipt | null;
}): Effect.Effect<SyncPlan, CliError> {
  return Effect.gen(function* () {
    const source = byName(input.source);
    const declared = byName(input.declared);
    const selected = yield* selectNames(input.target, source, declared);
    const selectedSet = new Set(selected);
    const previous = input.receipt?.variables ?? {};
    // declared のみ(値なし)は運ぶものが無い: required なら enforceDeclaredPresence
    // が止める材料、optional なら plan に載せない
    const current = selected.flatMap((name) => {
      const variable = source.get(name);
      if (variable === undefined) {
        return [];
      }
      const previousVersion = Object.hasOwn(previous, name) ? previous[name] : undefined;
      return [classifyVariable(input.target.driver, variable, previousVersion)];
    });
    // レシートにあって今は運ばない名前(選択から外れた・maruhi から消えた)= 削除
    const deleted = Object.keys(previous)
      .filter((name) => !selectedSet.has(name) || !source.has(name))
      .map((name): PlanEntry => ({
        action: "delete",
        name,
        previousVersion: previous[name] as number,
      }));
    const declaredRequired = selected.flatMap((name) => {
      const statement = declared.get(name);
      return statement !== undefined && statement.required ? [statement] : [];
    });
    const requiredNotSelected = [...source.values()]
      .filter((variable) => variable.required && !selectedSet.has(variable.name))
      .map((variable) => variable.name)
      .toSorted();
    return {
      entries: [...current, ...deleted].toSorted(compareByName),
      declaredRequired,
      requiredNotSelected,
    };
  });
}

function countOf(plan: SyncPlan, action: PlanEntry["action"]): number {
  return plan.entries.filter((entry) => entry.action === action).length;
}

/** 1 行の描画(記号 + 名前 + version。値は決して載らない)。 */
function planLine(entry: PlanEntry): string {
  const name = displayText(entry.name);
  switch (entry.action) {
    case "add":
      return `+ ${name}\tversion ${entry.version} (new)`;
    case "update":
      return `~ ${name}\tversion ${entry.previousVersion} -> ${entry.version}`;
    case "unchanged":
      return `= ${name}\tversion ${entry.version} (unchanged)`;
    case "delete":
      return `- ${name}\t(no longer synced; last delivered version ${entry.previousVersion})`;
    case "blocked":
      return `! ${name}\tversion ${entry.version} (cannot be synced: ${entry.reason})`;
  }
}

/**
 * 同期先の説明(ヘッダー行用): プリセット id と、プリセットが `describeOptions` で
 * 宣言した「同期先の呼び名」のオプション値(設定されている文字列だけ・宣言順)と
 * ドライバ。値も秘密も載らない(宣言に非機密のオプション名しか無い)。
 */
function describeDestination(target: SyncTarget): string {
  const shown = target.driver.spec.describeOptions.flatMap((option) => {
    const value = target.options[option];
    return typeof value === "string" ? [displayText(value)] : [];
  });
  return `${[target.preset.id, ...shown].join(" ")} via ${target.driver.kind}`;
}

/** plan の描画の選択(push 直後の apply は unchanged の行を省く — 第 3 段)。 */
interface PlanDisplay {
  /** `=` の行を出すか(既定 true。ヘッダーの件数は常に全部)。 */
  readonly showUnchanged: boolean;
}

const FULL_PLAN: PlanDisplay = { showUnchanged: true };

/** plan を stdout に出す(コマンドの出力 — 名前と version だけ)。 */
function reportPlan(
  target: SyncTarget,
  plan: SyncPlan,
  receipt: SyncReceipt | null | "none-in-ci",
  display: PlanDisplay,
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* io.log(
      `Sync plan for target ${displayText(target.name)} (environment ${displayText(target.environment)} -> ${describeDestination(target)}): ${countOf(plan, "add")} to add, ${countOf(plan, "update")} to update, ${countOf(plan, "delete")} to delete, ${countOf(plan, "unchanged")} unchanged, ${countOf(plan, "blocked")} blocked`,
    );
    yield* io.log(
      receipt === "none-in-ci"
        ? "Last delivery: not tracked in CI (no receipt — every selected variable is written again, and nothing is deleted)"
        : receipt === null
          ? "Last delivery: none (no receipt yet — every selected variable is new to this target)"
          : `Last delivery: ${displayText(receipt.syncedAt)} (receipt ${displayText(receiptVariableName(target.name))})`,
    );
    for (const entry of plan.entries) {
      if (entry.action === "unchanged" && !display.showUnchanged) {
        continue;
      }
      yield* io.log(planLine(entry));
    }
  });
}

/** Everything a plan or apply needs from the project context. */
export interface SyncContextInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly target: SyncTarget;
  readonly sourceFloor: FloorHandle;
  readonly receiptsEnvironment: EnvironmentId;
  readonly receiptsFloor: FloorHandle;
}

/** plan / apply 共通の前段: レシートを読む(警告はここで流す)。 */
function loadTargetReceipt(input: SyncContextInput): Effect.Effect<LoadedReceipt, CliError, CliIo> {
  return Effect.gen(function* () {
    const loaded = yield* loadReceipt({
      client: input.client,
      verified: input.verified,
      environmentId: input.receiptsEnvironment,
      recipient: input.recipient,
      resync: input.resync,
      floor: input.receiptsFloor,
      target: input.target.name,
      preset: input.target.preset.id,
    });
    yield* logWarnings(loaded.warnings);
    return loaded;
  });
}

/**
 * plan / apply 共通の後段: plan を出し、契約の助言を流し、レシートの上限接近を
 * 警告し、blocked が 1 件でもあれば失敗する(apply は何も送らない)。
 * CI(レシート無し)は `receipt: "none-in-ci"` で同じ段を通る。
 */
export function reviewPlan(
  target: SyncTarget,
  plan: SyncPlan,
  receipt:
    | { readonly kind: "loaded"; readonly loaded: LoadedReceipt; readonly environmentId: string }
    | { readonly kind: "none-in-ci" },
  display: PlanDisplay = FULL_PLAN,
): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    yield* reportPlan(
      target,
      plan,
      receipt.kind === "none-in-ci" ? "none-in-ci" : receipt.loaded.receipt,
      display,
    );
    if (plan.requiredNotSelected.length > 0) {
      yield* logWarning(
        `required variables are not part of this target: ${plan.requiredNotSelected.map(displayText).join(", ")}. The target's runtime will not receive them (add them to the target's variables in the sync config if it needs them)`,
      );
    }
    // required の宣言だけで値が無い変数が選択にある = 何も運ばない(run と同じ規則)
    yield* enforceDeclaredPresence(plan.declaredRequired, "Nothing was sent");
    if (receipt.kind === "loaded") {
      const warning = receiptVersionWarning({
        target: target.name,
        environmentId: receipt.environmentId,
        variableVersion: receipt.loaded.variableVersion,
      });
      if (warning !== null) {
        yield* logWarning(warning);
      }
    }
    const blocked = plan.entries.filter((entry) => entry.action === "blocked");
    if (blocked.length > 0) {
      return yield* Effect.fail(
        cliError(
          `${countNoun(blocked.length, "variable")} cannot be synced with this driver (marked ! above): ${blocked.map((entry) => displayText(entry.name)).join(", ")}. Leave them out of the target, rename them, or push values ${driverLabel(target.driver)} can carry (each line above says which). Nothing was sent`,
        ),
      );
    }
  });
}

/**
 * `maruhi sync plan <target>`: receipt + verified names and versions of the
 * source environment. The source values are not decrypted, and the vendor
 * API is not contacted.
 */
export function syncPlanOp(input: SyncContextInput): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const loaded = yield* loadTargetReceipt(input);
    const pulled = yield* pullVerifiedEnvironment({
      client: input.client,
      verified: loaded.verified,
      environmentId: input.target.environment as EnvironmentId,
      resync: input.resync,
      floor: input.sourceFloor,
    });
    yield* logWarnings(pulled.warnings);
    const source: SourceVariable[] = pulled.variables.map((variable) => ({
      name: variable.name,
      version: variable.version,
      // 暗号文 = ct || tag(16 バイト)。復号せずに平文長だけを知る
      byteLength: Math.max(0, variable.ciphertextHex.length / 2 - GCM_TAG_BYTES),
      required: variable.schema?.required ?? false,
    }));
    const plan = yield* computePlan({
      target: input.target,
      source,
      declared: toDeclaredVariables(pulled.declared),
      receipt: loaded.receipt,
    });
    yield* reviewPlan(input.target, plan, {
      kind: "loaded",
      loaded,
      environmentId: input.receiptsEnvironment,
    });
    if (input.target.production) {
      yield* logNote(
        `target ${displayText(input.target.name)} is a production target: \`maruhi sync apply ${displayText(input.target.name)}\` needs --yes`,
      );
    }
  });
}

/** apply の入力(plan に加えて署名鍵・`--yes`)。 */
export interface SyncApplyInput extends SyncContextInput {
  readonly writerUserId: string;
  readonly signingKey: CryptoKey;
  /** production ターゲットへの apply の明示(補足 14 M4)。 */
  readonly yes: boolean;
  /** 書き手の時計(レシートの syncedAt。判定には使わない)。 */
  readonly now: () => Date;
  /** 統合トークンの環境の床(http ドライバのときだけ。exec は null)。 */
  readonly tokenFloor: FloorHandle | null;
  /** ベンダー API のリトライ(既定は本番の調律。テストで短くする)。 */
  readonly httpRetry?: HttpRetryPolicy;
  /** plan の描画(push 直後の apply は unchanged を省く)。 */
  readonly display?: PlanDisplay;
}

/** apply が送るもの(plan の add / update / delete を材料に組む)。 */
export interface ApplyWork {
  readonly writes: readonly SyncWrite[];
  readonly deletes: readonly string[];
  /** 書く変数の version(レシートに記録する座標)。 */
  readonly versions: ReadonlyMap<string, number>;
}

/**
 * Turns the plan into writes and deletes, checking every value's content
 * constraints first (UTF-8, emptiness, size, trailing newline). One
 * refused value means nothing is sent.
 */
export function prepareWork(
  target: SyncTarget,
  plan: SyncPlan,
  values: ReadonlyMap<string, SyncWrite>,
): Effect.Effect<ApplyWork, CliError> {
  return Effect.gen(function* () {
    const writes: SyncWrite[] = [];
    const versions = new Map<string, number>();
    for (const entry of plan.entries) {
      if (entry.action !== "add" && entry.action !== "update") {
        continue;
      }
      const write = values.get(entry.name);
      if (write === undefined) {
        return yield* Effect.fail(
          cliError("The plan names a variable that was not pulled (internal inconsistency)"),
        );
      }
      // 剥がす理由: 送る前の制約検査の入力(産物は真偽と変数名だけ)
      const plaintext = Redacted.value(write.value);
      if (decodeValueText(plaintext) === null) {
        return yield* Effect.fail(
          cliError(
            `The value of variable ${displayText(write.name)} is not valid UTF-8 (${driverLabel(target.driver)} takes text). Nothing was sent`,
          ),
        );
      }
      const problem = checkValueConstraints(
        { constraints: target.driver.spec.constraints, label: driverLabel(target.driver) },
        write.name,
        plaintext,
      );
      if (problem !== null) {
        return yield* Effect.fail(cliError(`${problem.message}. Nothing was sent`));
      }
      writes.push(write);
      versions.set(entry.name, entry.version);
    }
    const deletes = plan.entries.flatMap((entry) =>
      entry.action === "delete" ? [entry.name] : [],
    );
    return { writes, deletes, versions };
  });
}

/** ドライバの実行結果(成功した名前だけをレシートへ進める材料)。 */
export interface DriverResult {
  readonly written: readonly string[];
  readonly deleted: readonly string[];
  /** 失敗した呼び出し(無ければ null)。 */
  readonly failure: {
    readonly names: readonly string[];
    readonly kind: "write" | "delete";
    /** 何が失敗したか(実行体名と終了コード / API の呼び名)。値は運ばない。 */
    readonly what: string;
    /**
     * maruhi 自身の説明(起動失敗の理由と案内 — 完成した文)。ベンダーの出力では
     * ないので `output` に置かない(failDriver は output をベンダーの発言として
     * 実行体名 / ホスト名の接頭辞つきで見せる — pullfrog 指摘・改訂 1)。
     */
    readonly detail: string | null;
    /** 伏せ字化済みの出力・応答の断片(ベンダーの発言。無ければ空)。 */
    readonly output: readonly string[];
  } | null;
}

/**
 * Runs the vendor processes in order and stops at the first failure. What
 * succeeded before it is reported so the receipt can record it. A process
 * that cannot be started (the CLI is not installed, or the cwd is gone) is
 * that invocation's failure too — like the http driver's runBatch, so a
 * typed error never drops the names delivered by the invocations before it.
 */
function runInvocations(
  driver: Extract<TargetDriver, { kind: "exec" }>,
  options: SyncTarget["options"],
  work: ApplyWork,
): Effect.Effect<DriverResult, never, ProcessRunner> {
  return Effect.gen(function* () {
    const runner = yield* ProcessRunner;
    const invocations = buildInvocations({
      preset: driver.spec,
      command: driver.command,
      cwd: driver.cwd,
      options,
      writes: work.writes,
      deletes: work.deletes,
    });
    const written: string[] = [];
    const deleted: string[] = [];
    const deleteSet = new Set(work.deletes);
    for (const invocation of invocations) {
      // 起動の失敗(型付きエラー — live.ts の execStartFailure)もこの呼び出しの失敗に
      // 畳む: ここで generator ごと中断すると、前の呼び出しで届いた名前が written /
      // deleted に畳まれずレシートに残らない(http の runBatch と同じ形 — SY4 改訂 5)
      const outcome = yield* runner
        .exec(invocation)
        .pipe(Effect.catch((error: CliError) => Effect.succeed({ startFailure: error.message })));
      if ("startFailure" in outcome) {
        return {
          written,
          deleted,
          failure: {
            names: invocation.names,
            kind: invocation.kind,
            what: `${displayText(driver.command)} could not be started`,
            // 起動失敗の文面は maruhi 自身のもの(値を運ばない)。走らなかった
            // プロセスに出力は無いので、ベンダー出力の置き場ではなく detail で運ぶ
            detail: displayText(outcome.startFailure),
            output: [],
          },
        };
      }
      if (outcome.exitCode !== 0) {
        return {
          written,
          deleted,
          failure: {
            names: invocation.names,
            kind: invocation.kind,
            what: `${displayText(driver.command)} exited with code ${outcome.exitCode}`,
            detail: null,
            // ベンダーの出力は信用しない: 値を伏せ、制御文字を中和し、末尾だけ
            output: scrubVendorOutput(outcome.output, work.writes),
          },
        };
      }
      // JSON の 1 バッチには書き込みと削除(null)が同居する — 名前で振り分ける
      for (const name of invocation.names) {
        (deleteSet.has(name) ? deleted : written).push(name);
      }
    }
    return { written, deleted, failure: null };
  });
}

/** ベンダー API への送信(バッチ順。最初の失敗で止め、届いた分を返す)。 */
function runBatches(
  driver: Extract<TargetDriver, { kind: "http" }>,
  options: SyncTarget["options"],
  work: ApplyWork,
  token: IntegrationToken,
  retry: HttpRetryPolicy,
): Effect.Effect<DriverResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const batches = buildBatches({
      preset: driver.spec,
      writes: work.writes,
      deletes: work.deletes,
    });
    const target = {
      preset: driver.spec,
      options: resolveOptions(driver.spec, options),
      token,
      retry,
    };
    const written: string[] = [];
    const deleted: string[] = [];
    const deleteSet = new Set(work.deletes);
    for (const batch of batches) {
      const result = yield* runBatch(target, batch);
      for (const name of result.delivered) {
        (deleteSet.has(name) ? deleted : written).push(name);
      }
      if (result.failure !== null) {
        return {
          written,
          deleted,
          failure: {
            names: result.failure.names,
            kind: batch.kind,
            // 何が起きたか(拒否 / 未確認の応答 / 送信の失敗 / 一覧の失敗 / 未送信)は
            // runBatch が失敗の作り手として言い分ける — 「refused」を試行の使い切りに
            // 付けない
            what: result.failure.what,
            detail: null,
            output: result.failure.lines,
          },
        };
      }
    }
    return { written, deleted, failure: null };
  });
}

/** ドライバの実行に要るもの(exec = プロセス、http = トークン + 通信)。 */
export interface RunDriverInput {
  readonly target: SyncTarget;
  readonly work: ApplyWork;
  /** http ドライバの統合トークン(exec では null)。 */
  readonly token: IntegrationToken | null;
  readonly httpRetry: HttpRetryPolicy;
}

/**
 * Runs the target's driver over the prepared work: the installed vendor CLI
 * (values on stdin) or the vendor API (values in the request body). Prints
 * one line naming where the plaintext goes before sending anything.
 */
export function runDriver(
  input: RunDriverInput,
): Effect.Effect<DriverResult, CliError, CliIo | ProcessRunner | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { driver } = input.target;
    if (driver.kind === "exec") {
      // どの実行体に・どこで渡すかを出力に残す(設定の command / cwd で平文の行き先が
      // 変わるので、差分だけでなく端末と CI ログでも見えるように — pullfrog 指摘)
      yield* io.log(`Running ${displayText(driver.command)} in ${displayText(driver.cwd)}`);
      return yield* runInvocations(driver, input.target.options, input.work);
    }
    if (input.token === null) {
      return yield* Effect.fail(
        cliError("The http driver needs the integration token (internal inconsistency)"),
      );
    }
    yield* io.log(
      `Sending to ${driver.spec.host} with the token from variable ${displayText(driver.token.name)} in environment ${displayText(driver.token.environment)}`,
    );
    return yield* runBatches(
      driver,
      input.target.options,
      input.work,
      input.token,
      input.httpRetry,
    );
  });
}

/** 復号済み変数の中から統合トークンを取り出す(検査つき)。 */
export function integrationTokenOf(
  token: { readonly environment: string; readonly name: string },
  variables: readonly { readonly name: string; readonly value: Redacted.Redacted<Uint8Array> }[],
): Effect.Effect<IntegrationToken, CliError> {
  const variable = variables.find((entry) => entry.name === token.name);
  if (variable === undefined) {
    return Effect.fail(
      cliError(
        `The token variable ${displayText(token.name)} does not exist in environment ${displayText(token.environment)}. Push the vendor's token there with \`maruhi push ${displayText(token.name)} --env ${displayText(token.environment)}\` (the token on stdin, without a trailing newline), or fix the target's token in the sync config`,
      ),
    );
  }
  // 剥がす理由: トークンの形の検査(ヘッダーに載る文字か)。産物は再び Redacted
  const checked = checkIntegrationToken(token.name, Redacted.value(variable.value));
  return typeof checked === "string"
    ? Effect.succeed(Redacted.make(checked, { label: "integration-token" }))
    : Effect.fail(checked);
}

/** 統合トークンの取り出し(手元: トークン環境を検証し、その 1 変数だけを復号する)。 */
function fetchIntegrationToken(
  input: SyncApplyInput,
  driver: Extract<TargetDriver, { kind: "http" }>,
  verified: VerifiedProject,
): Effect.Effect<
  { readonly token: IntegrationToken; readonly verified: VerifiedProject },
  CliError,
  CliIo
> {
  return Effect.gen(function* () {
    if (input.tokenFloor === null) {
      return yield* Effect.fail(
        cliError("No floor handle for the token environment (internal inconsistency)"),
      );
    }
    const pulled = yield* pullVariables({
      client: input.client,
      verified,
      environmentId: driver.token.environment as EnvironmentId,
      recipient: input.recipient,
      resync: input.resync,
      floor: input.tokenFloor,
      select: (name) => name === driver.token.name,
    });
    yield* logWarnings(pulled.warnings);
    const token = yield* integrationTokenOf(driver.token, pulled.variables);
    return { token, verified: pulled.verified };
  });
}

/** レシートの次の内容(成功した書き込み・削除だけを前回に重ねる)。 */
function nextReceipt(input: {
  readonly target: SyncTarget;
  readonly previous: SyncReceipt | null;
  readonly result: DriverResult;
  readonly versions: ReadonlyMap<string, number>;
  readonly syncedAt: string;
}): SyncReceipt {
  const variables: Record<string, number> = Object.assign(
    Object.create(null) as Record<string, number>,
    input.previous?.variables ?? {},
  );
  for (const name of input.result.deleted) {
    delete variables[name];
  }
  for (const name of input.result.written) {
    variables[name] = input.versions.get(name) as number;
  }
  return {
    version: 1,
    target: input.target.name,
    preset: input.target.preset.id,
    syncedAt: input.syncedAt,
    variables,
  };
}

function sameVariables(a: SyncReceipt | null, b: SyncReceipt): boolean {
  if (a === null) {
    // レシートがまだ無く、届いたものも無い(最初の呼び出しで失敗)= 書くものが無い
    return Object.keys(b.variables).length === 0;
  }
  const left = Object.entries(a.variables).toSorted();
  const right = Object.entries(b.variables).toSorted();
  return JSON.stringify(left) === JSON.stringify(right);
}

/**
 * Saves the receipt when its variables changed. Returns the new version, or
 * null when nothing was written (unchanged, or the write failed — a warning,
 * because the target is already updated and the next apply is idempotent).
 */
function saveReceipt(
  input: SyncApplyInput,
  loaded: LoadedReceipt,
  receipt: SyncReceipt,
): Effect.Effect<number | null, never, CliIo> {
  if (sameVariables(loaded.receipt, receipt)) {
    return Effect.succeed(null);
  }
  return storeReceipt({
    client: input.client,
    verified: loaded.verified,
    environmentId: input.receiptsEnvironment,
    recipient: input.recipient,
    resync: input.resync,
    floor: input.receiptsFloor,
    writerUserId: input.writerUserId,
    signingKey: input.signingKey,
    receipt,
  }).pipe(
    Effect.flatMap((stored) => Effect.as(logWarnings(stored.warnings), stored.version)),
    Effect.catch((error: CliError) =>
      Effect.as(
        logWarning(
          `the target was updated, but the receipt could not be saved (${error.message}). The next \`maruhi sync plan\` will show the delivered variables as pending; applying again overwrites them with the same versions`,
        ),
        null,
      ),
    ),
  );
}

/** ドライバの失敗の本文(純関数 — failDriver がそのまま型付きエラーにする)。 */
function driverFailureMessage(
  input: {
    readonly target: SyncTarget;
    readonly work: ApplyWork;
    readonly receiptsEnvironment: string | null;
    readonly next: string;
  },
  result: DriverResult,
  failure: NonNullable<DriverResult["failure"]>,
): string {
  // 削除の失敗は「同期先で既に消されていた」形がありうる(同期先は読み戻さない
  // ので、レシートに残った名前を消し続ける)。復旧はレシートの作り直し —
  // ただし作り直すと**まだ試していない削除**も忘れるので、その名前を添えて
  // 先に同期先で手で消すよう言う(pullfrog 指摘)
  const failed = new Set(failure.names);
  const notAttempted = input.work.deletes.filter(
    (name) => !result.deleted.includes(name) && !failed.has(name),
  );
  const pendingHint =
    notAttempted.length === 0
      ? ""
      : ` Resetting the receipt also forgets the deletions not attempted yet, so remove these at the target yourself first: ${notAttempted.map(displayText).join(", ")}.`;
  const deleteHint =
    failure.kind === "delete" && input.receiptsEnvironment !== null
      ? ` If the variable was already removed at the target (for example in its dashboard), reset the receipt with \`maruhi var rm ${displayText(receiptVariableName(input.target.name))} --env ${displayText(input.receiptsEnvironment)}\` and apply again (the next apply rewrites every variable of the target once).${pendingHint}`
      : "";
  // 出力が 1 行も無ければ「上に出ている」と言わない(空の出力で失敗する CLI が
  // あり、起動できなかったプロセスに出力は無い)
  const outputHint =
    failure.output.length === 0 ? "" : " Its output is shown above with values filtered out.";
  // maruhi 自身の説明(起動失敗の理由と案内)は本文の続きとして言う
  const detail = failure.detail === null ? "" : ` ${failure.detail}.`;
  return `${failure.what} while ${failure.kind === "write" ? "writing" : "deleting"} ${failure.names.map(displayText).join(", ")} (delivered before that: ${countNoun(result.written.length, "variable")} written, ${result.deleted.length} deleted).${detail}${outputHint}${deleteHint} Fix the cause, then ${input.next}`;
}

/** ドライバの失敗の報告(伏せ字化した出力を添えて型付きエラー)。 */
export function failDriver(input: {
  readonly target: SyncTarget;
  readonly work: ApplyWork;
  readonly result: DriverResult;
  /** レシートの作り直しの案内に添える環境(CI = null: レシートが無い)。 */
  readonly receiptsEnvironment: string | null;
  /** 残りを見る手段(手元 = plan、CI = 再実行)。 */
  readonly next: string;
}): Effect.Effect<never, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { target, result } = input;
    if (result.failure === null) {
      return yield* Effect.fail(
        cliError("failDriver called without a failure (internal inconsistency)"),
      );
    }
    // output はベンダーの発言なので、実行体名 / ホスト名の接頭辞つきで見せる
    const prefix = target.driver.kind === "exec" ? target.driver.command : target.driver.spec.host;
    for (const line of result.failure.output) {
      yield* io.logError(`  ${displayText(prefix)}: ${line}`);
    }
    return yield* Effect.fail(cliError(driverFailureMessage(input, result, result.failure)));
  });
}

/** 実行結果の報告(失敗は伏せ字化した出力を添えて型付きエラー)。 */
function reportApply(
  input: SyncApplyInput,
  work: ApplyWork,
  result: DriverResult,
  receiptVersion: number | null,
): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const targetName = displayText(input.target.name);
    if (result.failure !== null) {
      return yield* failDriver({
        target: input.target,
        work,
        result,
        receiptsEnvironment: input.receiptsEnvironment,
        next: `run \`maruhi sync plan ${targetName}\` to see what is left`,
      });
    }
    const saved =
      receiptVersion === null
        ? ""
        : `. Receipt saved as version ${receiptVersion} of ${displayText(receiptVariableName(input.target.name))} in environment ${displayText(input.receiptsEnvironment)}`;
    yield* io.log(
      `Applied to target ${targetName}: ${countNoun(result.written.length, "variable")} written, ${result.deleted.length} deleted${saved}`,
    );
  });
}

/** production ターゲットへの apply には `--yes` が要る(補足 14 M4)。 */
export function requireProductionConsent(
  target: SyncTarget,
  yes: boolean,
  command: string,
): Effect.Effect<void, CliError> {
  if (target.production && !yes) {
    return Effect.fail(
      cliError(
        `Target ${displayText(target.name)} is a production target, so apply needs an explicit --yes. Review the plan above, then re-run \`${command} ${displayText(target.name)} --yes\`. Nothing was sent`,
      ),
    );
  }
  return Effect.void;
}

/**
 * `maruhi sync apply <target>`: plan, then write the changed variables to
 * the target through its driver, then record what landed in the receipt.
 */
export function syncApplyOp(
  input: SyncApplyInput,
): Effect.Effect<void, CliError, CliIo | ProcessRunner | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const loaded = yield* loadTargetReceipt(input);
    // apply は復号する(run と同じ経路 — pull.ts)。平文は Redacted のまま
    // ドライバの本文 / stdin の組み立てまで運ぶ
    const pulled = yield* pullVariables({
      client: input.client,
      verified: loaded.verified,
      environmentId: input.target.environment as EnvironmentId,
      recipient: input.recipient,
      resync: input.resync,
      floor: input.sourceFloor,
    });
    yield* logWarnings(pulled.warnings);
    const plan = yield* computePlan({
      target: input.target,
      source: sourceVariablesOf(pulled.variables),
      // pull.ts はすでに declared を材料形へ写している
      declared: pulled.declared,
      receipt: loaded.receipt,
    });
    yield* reviewPlan(
      input.target,
      plan,
      { kind: "loaded", loaded, environmentId: input.receiptsEnvironment },
      input.display ?? FULL_PLAN,
    );
    const work = yield* prepareWork(input.target, plan, writesOf(pulled.variables));
    if (work.writes.length === 0 && work.deletes.length === 0) {
      yield* io.log(
        "Nothing to apply: the target already has every selected variable at its current version",
      );
      return;
    }
    yield* requireProductionConsent(input.target, input.yes, "maruhi sync apply");
    // 統合トークンは送る直前に取り出す(送らずに終わる経路では復号しない)
    let verified = pulled.verified;
    let token: IntegrationToken | null = null;
    if (input.target.driver.kind === "http") {
      const fetched = yield* fetchIntegrationToken(input, input.target.driver, verified);
      token = fetched.token;
      verified = fetched.verified;
    }
    const result = yield* runDriver({
      target: input.target,
      work,
      token,
      httpRetry: input.httpRetry ?? DEFAULT_HTTP_RETRY,
    });
    // レシートは「実際に届いた分」だけ進める。失敗した回でも届いた分は記録し、
    // 次の plan が残りだけを示すようにする
    const receipt = nextReceipt({
      target: input.target,
      previous: loaded.receipt,
      result,
      versions: work.versions,
      syncedAt: input.now().toISOString(),
    });
    // レシートの push は、同期元(とトークン環境)の pull で前進していることのある
    // ビューから始める(loadReceipt 時点のビューは古いことがある — Bugbot 指摘)
    const receiptVersion = yield* saveReceipt(input, { ...loaded, verified }, receipt);
    yield* reportApply(input, work, result, receiptVersion);
  });
}
