// `maruhi sync plan` / `maruhi sync apply`(SY2 第 1 段 — integration-options.md
// §3「同期の最終形」の表: exec ドライバ × リポジトリ設定 × レシート × plan / apply)。
//
// plan = 「レシート(前回届いた version)と maruhi の現在の version の差」を
// 名前と version だけで示す。同期先は**読み戻さない**(一方通行 — ADR-0014。
// Vercel の sensitive 値は読み戻せないので、レシートが唯一の突合材料 — 補足 13 W2)。
// plan は同期元の値を復号しない(値署名の検証までで止まる — values.ts の
// pullVerifiedEnvironment)。apply は復号し(pull.ts)、ベンダー CLI の stdin に
// 一度だけ書く(sync-exec.ts)。値は stdout / stderr / エラー文面に出ない。
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

import type { MaruhiClient } from "./api.ts";
import type { DekRecipient } from "./deks.ts";
import { countNoun, decodeValueText, displayText, logWarnings } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { FloorHandle } from "./floor-check.ts";
import { CliIo } from "./io.ts";
import { logNote, logWarning } from "./notice.ts";
import { type DeclaredVariable, pullVariables, toDeclaredVariables } from "./pull.ts";
import { enforceDeclaredPresence, ProcessRunner } from "./run.ts";
import type { SyncTarget } from "./sync-config.ts";
import {
  buildInvocations,
  checkValueConstraints,
  type ExecPreset,
  scrubVendorOutput,
  type SyncWrite,
} from "./sync-exec.ts";
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

/** 1 変数の plan 行(size / 空の制約はここで、内容の制約は apply で)。 */
function classifyVariable(
  preset: ExecPreset,
  variable: SourceVariable,
  previousVersion: number | undefined,
): PlanEntry {
  const { name, version } = variable;
  const { constraints } = preset;
  if (constraints.nonEmpty && variable.byteLength === 0) {
    return {
      action: "blocked",
      name,
      version,
      reason: `empty value (the ${preset.command} CLI reads an empty stdin as no value)`,
    };
  }
  if (constraints.maxBytes !== null && variable.byteLength > constraints.maxBytes) {
    return {
      action: "blocked",
      name,
      version,
      reason: `${variable.byteLength} bytes, above the ${constraints.maxBytes}-byte limit for the ${preset.command} CLI`,
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
 * `blocked` entries come from the preset's size / emptiness constraints
 * (content constraints need the plaintext and are checked at apply).
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
      return [classifyVariable(input.target.preset, variable, previousVersion)];
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

/** 同期先の説明(ヘッダー行用 — プリセットと同期先の環境)。 */
function describeDestination(target: SyncTarget): string {
  const environment = target.options["environment"];
  const where = typeof environment === "string" ? ` ${displayText(environment)}` : "";
  return `${target.preset.id}${where}`;
}

/** plan を stdout に出す(コマンドの出力 — 名前と version だけ)。 */
function reportPlan(
  target: SyncTarget,
  plan: SyncPlan,
  receipt: SyncReceipt | null,
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* io.log(
      `Sync plan for target ${displayText(target.name)} (environment ${displayText(target.environment)} -> ${describeDestination(target)}): ${countOf(plan, "add")} to add, ${countOf(plan, "update")} to update, ${countOf(plan, "delete")} to delete, ${countOf(plan, "unchanged")} unchanged, ${countOf(plan, "blocked")} blocked`,
    );
    yield* io.log(
      receipt === null
        ? "Last delivery: none (no receipt yet — every selected variable is new to this target)"
        : `Last delivery: ${displayText(receipt.syncedAt)} (receipt ${displayText(receiptVariableName(target.name))})`,
    );
    for (const entry of plan.entries) {
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
    });
    yield* logWarnings(loaded.warnings);
    return loaded;
  });
}

/**
 * plan / apply 共通の後段: plan を出し、契約の助言を流し、レシートの上限接近を
 * 警告し、blocked が 1 件でもあれば失敗する(apply は何も送らない)。
 */
function reviewPlan(
  input: SyncContextInput,
  plan: SyncPlan,
  loaded: LoadedReceipt,
): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    yield* reportPlan(input.target, plan, loaded.receipt);
    if (plan.requiredNotSelected.length > 0) {
      yield* logWarning(
        `required variables are not part of this target: ${plan.requiredNotSelected.map(displayText).join(", ")}. The target's runtime will not receive them (add them to the target's variables in the sync config if it needs them)`,
      );
    }
    // required の宣言だけで値が無い変数が選択にある = 何も運ばない(run と同じ規則)
    yield* enforceDeclaredPresence(plan.declaredRequired, "Nothing was sent");
    const warning = receiptVersionWarning({
      target: input.target.name,
      environmentId: input.receiptsEnvironment,
      variableVersion: loaded.variableVersion,
    });
    if (warning !== null) {
      yield* logWarning(warning);
    }
    const blocked = plan.entries.filter((entry) => entry.action === "blocked");
    if (blocked.length > 0) {
      return yield* Effect.fail(
        cliError(
          `${countNoun(blocked.length, "variable")} cannot be synced with this preset (marked ! above): ${blocked.map((entry) => displayText(entry.name)).join(", ")}. Leave them out of the target, or push values the vendor CLI can carry. Nothing was sent`,
        ),
      );
    }
  });
}

/**
 * `maruhi sync plan <target>`: receipt + verified names and versions of the
 * source environment. The source values are not decrypted.
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
    yield* reviewPlan(input, plan, loaded);
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
}

/** apply が送るもの(plan の add / update / delete を材料に組む)。 */
interface ApplyWork {
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
function prepareWork(
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
            `The value of variable ${displayText(write.name)} is not valid UTF-8 (the ${target.preset.command} CLI takes text on stdin). Nothing was sent`,
          ),
        );
      }
      const problem = checkValueConstraints(target.preset, write.name, plaintext);
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

/** ベンダー CLI の実行結果(成功した名前だけをレシートへ進める材料)。 */
interface ExecResult {
  readonly written: readonly string[];
  readonly deleted: readonly string[];
  /** 失敗した呼び出し(無ければ null)。 */
  readonly failure: {
    readonly names: readonly string[];
    readonly kind: "write" | "delete";
    readonly exitCode: number;
    readonly output: readonly string[];
  } | null;
}

/**
 * Runs the vendor processes in order and stops at the first failure. What
 * succeeded before it is reported so the receipt can record it.
 */
function runInvocations(
  target: SyncTarget,
  work: ApplyWork,
): Effect.Effect<ExecResult, CliError, ProcessRunner> {
  return Effect.gen(function* () {
    const runner = yield* ProcessRunner;
    const invocations = buildInvocations({
      preset: target.preset,
      command: target.command,
      cwd: target.cwd,
      options: target.options,
      writes: work.writes,
      deletes: work.deletes,
    });
    const written: string[] = [];
    const deleted: string[] = [];
    const deleteSet = new Set(work.deletes);
    for (const invocation of invocations) {
      const outcome = yield* runner.exec(invocation);
      if (outcome.exitCode !== 0) {
        return {
          written,
          deleted,
          failure: {
            names: invocation.names,
            kind: invocation.kind,
            exitCode: outcome.exitCode,
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

/** レシートの次の内容(成功した書き込み・削除だけを前回に重ねる)。 */
function nextReceipt(input: {
  readonly target: SyncTarget;
  readonly previous: SyncReceipt | null;
  readonly result: ExecResult;
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

/** 実行結果の報告(失敗はベンダー出力の伏せ字化した末尾を添えて型付きエラー)。 */
function reportApply(
  input: SyncApplyInput,
  result: ExecResult,
  receiptVersion: number | null,
): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const targetName = displayText(input.target.name);
    if (result.failure !== null) {
      for (const line of result.failure.output) {
        yield* io.logError(`  ${input.target.command}: ${line}`);
      }
      return yield* Effect.fail(
        cliError(
          `${displayText(input.target.command)} exited with code ${result.failure.exitCode} while ${result.failure.kind === "write" ? "writing" : "deleting"} ${result.failure.names.map(displayText).join(", ")} (delivered before that: ${countNoun(result.written.length, "variable")} written, ${result.deleted.length} deleted). Its output is shown above with values filtered out. Fix the cause, then run \`maruhi sync plan ${targetName}\` to see what is left`,
        ),
      );
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

/**
 * `maruhi sync apply <target>`: plan, then write the changed variables to
 * the vendor CLI (stdin only), then record what landed in the receipt.
 */
export function syncApplyOp(
  input: SyncApplyInput,
): Effect.Effect<void, CliError, CliIo | ProcessRunner> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const loaded = yield* loadTargetReceipt(input);
    // apply は復号する(run と同じ経路 — pull.ts)。平文は Redacted のまま
    // sync-exec.ts の stdin 組み立てまで運ぶ
    const pulled = yield* pullVariables({
      client: input.client,
      verified: loaded.verified,
      environmentId: input.target.environment as EnvironmentId,
      recipient: input.recipient,
      resync: input.resync,
      floor: input.sourceFloor,
    });
    yield* logWarnings(pulled.warnings);
    const source: SourceVariable[] = pulled.variables.map((variable) => ({
      name: variable.name,
      version: variable.version,
      // 剥がす理由: 平文長の実測(産物は長さだけ)。plan 段の暗号文長からの推定と
      // 同じ値になるが、apply は実際に送るバイト列で判定する
      byteLength: Redacted.value(variable.value).byteLength,
      required: variable.required,
    }));
    const plan = yield* computePlan({
      target: input.target,
      source,
      // pull.ts はすでに declared を材料形へ写している
      declared: pulled.declared,
      receipt: loaded.receipt,
    });
    yield* reviewPlan(input, plan, loaded);
    const work = yield* prepareWork(
      input.target,
      plan,
      byName(pulled.variables.map((variable) => ({ name: variable.name, value: variable.value }))),
    );
    if (work.writes.length === 0 && work.deletes.length === 0) {
      yield* io.log(
        "Nothing to apply: the target already has every selected variable at its current version",
      );
      return;
    }
    if (input.target.production && !input.yes) {
      return yield* Effect.fail(
        cliError(
          `Target ${displayText(input.target.name)} is a production target, so apply needs an explicit --yes. Review the plan above, then re-run \`maruhi sync apply ${displayText(input.target.name)} --yes\`. Nothing was sent`,
        ),
      );
    }
    const result = yield* runInvocations(input.target, work);
    // レシートは「実際に届いた分」だけ進める。失敗した回でも届いた分は記録し、
    // 次の plan が残りだけを示すようにする
    const receipt = nextReceipt({
      target: input.target,
      previous: loaded.receipt,
      result,
      versions: work.versions,
      syncedAt: input.now().toISOString(),
    });
    const receiptVersion = yield* saveReceipt(input, loaded, receipt);
    yield* reportApply(input, result, receiptVersion);
  });
}
