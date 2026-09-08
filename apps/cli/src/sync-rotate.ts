// `maruhi env rotate --config` によるレシートの前進(SY2 第 2 段 2b — integration-options.md
// §3 補足 14 M1)。
//
// エポックローテーション(CRYPTO_SPEC §7 / §4.1)は現在値を**新 version として
// 再暗号化する**(平文は不変)。レシート(sync-receipt.ts)は version だけを持つので、
// ローテーション後の `maruhi sync plan` は全変数を changed と示し、次の apply が同じ
// 平文を書き直す — 無害だが無駄で、production では `--yes` の儀式を伴う。平文が
// 不変であることを知っている唯一の主体は**ローテーションの実行者の CLI**なので、
// その実行の中でレシートを新 version へ進める。暗号操作の追加はない: レシートの
// 書き込みは storeReceipt = §4.1 の署名つきの普通の push(実行者の master 鍵)。
//
// 進めてよいのは「この実行が再暗号化を**完了した**変数」(RotationSummary.written)
// で、かつ「レシートがその変数の**直前 version** を指している」ときだけ。遅れていた
// レシート(同期先に届いているのは古い平文)を進めると未同期の差分を隠すので進めない。
// `alreadyCurrent`(並行 push — 平文が変わりうる)・未完了・レシートに無い名前
// (未同期)も進めない — 判定に迷う変数は「次の apply が無害に書き直す」側へ倒す。
//
// 後始末であってローテーションの一部ではない: ここでの失敗(通信・権限・競合 —
// 再同期・レシートの読み・書きのどれでも)は警告に留め、ローテーション自体の終了
// コードを変えない(sync-plan.ts の saveReceipt と同じ)。**例外は証拠**(`CliError.evidence`
// — 床違反・チェーン置換・equivocation): 正規署名済みデータ同士の矛盾は「次の apply が
// 書き直す」種類の失敗ではなく、警告に畳むと「apply し直せ」という誤った案内で
// 改竄の証拠を隠す。証拠だけはそのまま失敗として通す(env-rotate.ts の再走査と同じ規律)。
// maruhi サーバーとしか話さず、同期先(ベンダー API / CLI)には触れない。出力に
// 出るのはターゲット名・件数・version・変数名(displayText)だけである。

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { DekRecipient } from "./deks.ts";
import { countNoun, displayText, logWarnings } from "./display.ts";
import type { ReencryptedVariable } from "./env-rotate.ts";
import { asCleanupOutcome, type CliError, usageError } from "./errors.ts";
import type { FloorHandle } from "./floor-check.ts";
import { CliIo } from "./io.ts";
import { logWarning } from "./notice.ts";
import type { SyncConfig, SyncTarget } from "./sync-config.ts";
import {
  loadReceipt,
  receiptVariableName,
  receiptVersionWarning,
  storeReceipt,
  type SyncReceipt,
} from "./sync-receipt.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";

/**
 * 設定の `project` と、実際に回したプロジェクトの照合(食い違いは書き方の誤り = 2)。
 * `--project` の有無に関わらず解決済みのプロジェクト ID と比べる — ローテーションの
 * **前**に呼び、別プロジェクトの設定でエポックを進めてしまう形を塞ぐ。
 */
export function checkRotateConfigProject(
  config: SyncConfig,
  projectId: string,
): Effect.Effect<void, CliError> {
  if (config.projectId !== undefined && config.projectId !== projectId) {
    return Effect.fail(
      usageError(
        "The sync config belongs to a different project (its `project` does not match the project being rotated)",
      ),
    );
  }
  return Effect.void;
}

/** 回した環境を同期元にするターゲット(設定の順)。 */
function targetsSyncedFrom(config: SyncConfig, environmentId: string): readonly SyncTarget[] {
  return [...config.targets.values()].filter((target) => target.environment === environmentId);
}

/** レシートの前進の判定結果(1 ターゲット分)。 */
interface AdvancedReceipt {
  readonly receipt: SyncReceipt;
  /** 直前 version を指していたので新 version へ進めた名前。 */
  readonly advanced: readonly string[];
  /** レシートにあるが直前 version を指していなかった名前(遅れ・別系統 — 進めない)。 */
  readonly behind: readonly string[];
}

/**
 * Advances a receipt to the re-encrypted versions: a variable moves only when
 * the receipt points at the version just before the accepted write (that
 * version and the new one carry the same plaintext). Names the receipt does
 * not know stay unsynced, and a receipt that was behind stays behind.
 */
function advanceReceipt(
  previous: SyncReceipt,
  written: readonly ReencryptedVariable[],
  syncedAt: string,
): AdvancedReceipt {
  const variables: Record<string, number> = Object.assign(
    Object.create(null) as Record<string, number>,
    previous.variables,
  );
  const advanced: string[] = [];
  const behind: string[] = [];
  for (const entry of written) {
    const delivered = variables[entry.name];
    if (delivered === undefined) {
      continue;
    }
    if (delivered === entry.version - 1) {
      variables[entry.name] = entry.version;
      advanced.push(entry.name);
    } else {
      behind.push(entry.name);
    }
  }
  return {
    receipt: { ...previous, syncedAt, variables },
    advanced: advanced.toSorted(),
    behind: behind.toSorted(),
  };
}

export interface AdvanceReceiptsInput {
  readonly client: MaruhiClient;
  /** ローテーション前の検証済みビュー(再同期したチェーンがこれの延長であることを検査する基準)。 */
  readonly verified: VerifiedProject;
  readonly recipient: DekRecipient;
  /**
   * 再同期(チェーン全再検証)。ローテーションでチェーンは前進しているので、後始末は
   * これで取り直し、`verified` の**延長**であることを確かめた検証済みビューから始める
   * (前進したビューから始める規律)。通信の失敗は後始末の内側で警告に畳み、検証の
   * 拒否(証拠)は通す(ローテーションの終了コードを変えるのは証拠だけ)。
   */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly config: SyncConfig;
  /** 回した環境(この環境を同期元にするターゲットだけが対象)。 */
  readonly environmentId: EnvironmentId;
  readonly written: readonly ReencryptedVariable[];
  /** レシート環境の床ハンドル(回した環境と同じなら rotate のものを共有する)。 */
  readonly receiptsFloor: FloorHandle;
  readonly writerUserId: string;
  readonly signingKey: CryptoKey;
  readonly now: () => Date;
}

/** 1 ターゲット分の結果(表示用)。 */
type TargetOutcome =
  | { readonly kind: "no-receipt" }
  | { readonly kind: "nothing-to-advance"; readonly behind: readonly string[] }
  | { readonly kind: "advanced"; readonly version: number; readonly result: AdvancedReceipt };

/** 1 ターゲットのレシートを読み、進められる分だけ書く。失敗は型付きエラーのまま返す。 */
function advanceTarget(
  input: AdvanceReceiptsInput,
  target: SyncTarget,
  verified: VerifiedProject,
): Effect.Effect<
  { readonly outcome: TargetOutcome; readonly verified: VerifiedProject },
  CliError,
  CliIo
> {
  return Effect.gen(function* () {
    const receiptsEnvironment = input.config.receiptsEnvironment as EnvironmentId;
    const loaded = yield* loadReceipt({
      client: input.client,
      verified,
      environmentId: receiptsEnvironment,
      recipient: input.recipient,
      resync: input.resync,
      floor: input.receiptsFloor,
      target: target.name,
      preset: target.preset.id,
    });
    yield* logWarnings(loaded.warnings);
    if (loaded.receipt === null) {
      // 初回同期前 = 進めるものが無い(静かに飛ばす — plan が全件 new と言う)
      return { outcome: { kind: "no-receipt" }, verified: loaded.verified };
    }
    const result = advanceReceipt(loaded.receipt, input.written, input.now().toISOString());
    if (result.advanced.length === 0) {
      // 内容が変わらないなら書かない(version を消費しない)
      return {
        outcome: { kind: "nothing-to-advance", behind: result.behind },
        verified: loaded.verified,
      };
    }
    const stored = yield* storeReceipt({
      client: input.client,
      verified: loaded.verified,
      environmentId: receiptsEnvironment,
      recipient: input.recipient,
      resync: input.resync,
      floor: input.receiptsFloor,
      writerUserId: input.writerUserId,
      signingKey: input.signingKey,
      receipt: result.receipt,
    });
    yield* logWarnings(stored.warnings);
    const warning = receiptVersionWarning({
      target: target.name,
      environmentId: receiptsEnvironment,
      variableVersion: stored.version,
    });
    if (warning !== null) {
      yield* logWarning(warning);
    }
    // レシートの push は前進したビュー(pull で進んでいることがある)を次へ引き継ぐ
    return {
      outcome: { kind: "advanced", version: stored.version, result },
      verified: loaded.verified,
    };
  });
}

function behindNote(behind: readonly string[]): string {
  return behind.length === 0
    ? ""
    : `; ${countNoun(behind.length, "variable")} left as delivered (${behind.map(displayText).join(", ")}: the receipt was already behind before the rotation, so the next \`maruhi sync plan\` shows them as pending)`;
}

function reportTarget(
  target: SyncTarget,
  outcome: TargetOutcome,
  receiptsEnvironment: string,
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    switch (outcome.kind) {
      case "no-receipt":
        // レシートが無い = まだ一度も同期していない。何も言わない
        return;
      case "nothing-to-advance":
        if (outcome.behind.length > 0) {
          yield* io.log(
            `Receipt for target ${target.name} not advanced: ${countNoun(outcome.behind.length, "variable")} left as delivered (${outcome.behind.map(displayText).join(", ")}: the receipt was already behind before the rotation, so the next \`maruhi sync plan\` shows them as pending)`,
          );
        }
        return;
      case "advanced":
        yield* io.log(
          `Advanced the receipt for target ${target.name} to the re-encrypted versions of ${countNoun(outcome.result.advanced.length, "variable")} (saved as version ${outcome.version} of ${displayText(receiptVariableName(target.name))} in environment ${displayText(receiptsEnvironment)})${behindNote(outcome.result.behind)}`,
        );
        return;
    }
  });
}

/**
 * Advances the receipts of every target synced from the rotated environment
 * to the versions this rotation wrote. A failure on one target is a warning
 * (the rotation is already done; the next apply rewrites the same plaintext),
 * and the remaining targets are still processed. Only evidence (a floor or
 * chain verification rejection) fails the command.
 */
export function advanceReceiptsAfterRotation(
  input: AdvanceReceiptsInput,
): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (input.written.length === 0) {
      // 何も再暗号化していない(確認だけ・押せなかった)= 進めるものが無い
      return;
    }
    const targets = targetsSyncedFrom(input.config, input.environmentId);
    if (targets.length === 0) {
      yield* io.log(
        `No sync target in the config is synced from environment ${displayText(input.environmentId)}, so no receipt was advanced`,
      );
      return;
    }
    // 再同期の失敗も後始末の失敗: ローテーションは済んでいるので警告に留める
    // (受け皿の外で失敗させると、成功した報告の後で終了コードが 1 に化ける)
    const synced = yield* asCleanupOutcome(resyncExtended(input.resync, input.verified));
    if (synced.kind === "failed") {
      yield* logWarning(
        `the rotation is done, but the receipts could not be advanced because the chain could not be re-verified (${synced.error.message}). The next \`maruhi sync plan\` shows the re-encrypted variables as pending; applying again overwrites them with the same plaintext`,
      );
      return;
    }
    let verified = synced.value;
    for (const target of targets) {
      const attempt = yield* asCleanupOutcome(advanceTarget(input, target, verified));
      if (attempt.kind === "failed") {
        // 1 ターゲットの失敗で残りを止めない。終了コードも変えない(後始末)
        yield* logWarning(
          `the rotation is done, but the receipt for target ${target.name} could not be advanced (${attempt.error.message}). The next \`maruhi sync plan ${target.name}\` shows the re-encrypted variables as pending; applying again overwrites them with the same plaintext`,
        );
        continue;
      }
      verified = attempt.value.verified;
      yield* reportTarget(target, attempt.value.outcome, input.config.receiptsEnvironment);
    }
  });
}
