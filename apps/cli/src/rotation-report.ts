// ローテーション結果の報告と終了コードの導出(env rotate / server revoke /
// member remove / change-role の sweep が共用)。
//
// ADR-0016 第 2 段階の移行で cli.ts(gunshi 側)から切り出した。第 2 段階の
// 完了により、利用者は全員 effect/unstable/cli 側(effect-cli.ts)になった。
// 文言は ADR-0017(ユーザーに見える文言は英語)に従い英語。

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import { countNoun, logWarnings } from "./display.ts";
import type { RotationSummary } from "./env-rotate.ts";
import type { CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logWarning } from "./notice.ts";

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
        ? `${countNoun(summary.remaining, "variable")} incomplete${summary.remainingExact ? "" : " (may include unconfirmed ones)"}`
        : "completion could not be verified";
    yield* io.log(
      `Partial completion: ${scope} (re-encrypted ${countNoun(summary.reencrypted, "variable")}${skipped}, ${scale})`,
    );
    // 失敗の原因がある場合はそれを明示する(エポックだけが進んだ事実を、生の
    // エラーだけ出して伝え損ねない)。「中断」と言えるのは再走査へ到達できず
    // 途中で降りた場合だけで、巡を使い切った場合は最後まで走ったうえでの未完了である
    const stopped = summary.remainingExact
      ? "re-encryption did not complete"
      : "re-encryption was interrupted";
    const cause =
      summary.failure === null
        ? "conflicts with concurrent pushes did not resolve"
        : `${stopped}: ${summary.failure}`;
    yield* logWarning(
      `re-encryption for environment ${environmentId} has not completed (${cause}). Values not yet re-encrypted remain under DEKs older than epoch ${summary.epoch} — resolve the cause and re-run \`maruhi env rotate ${environmentId}\` to resume from the remainder without advancing the epoch (the re-run rescans the remainder, so the actual number of incomplete variables is confirmed there). However, if the cause is a verification failure or a local floor violation (= contradicting server responses), re-running will not resolve it — investigate the served evidence`,
    );
    return 1;
  });
}

/**
 * ローテーション結果の報告と終了コード。完了サマリは再暗号化の実績を報告し、
 * 未完了分(部分完了)は警告として明示する — 「エポックだけ進んで再暗号化が
 * 残っている」状態を成功の顔で終わらせない。
 */
export function reportRotation(
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
        : `, ${countNoun(summary.alreadyCurrent, "variable")} already re-encrypted by concurrent updates`;
    if (summary.mode === "up-to-date") {
      // 確認のみ(未完了なし・新エポック未要求)。部分完了の案内が勧める
      // 再実行の着地点でもあるので、何もしなかったことを明示する
      yield* io.log(
        `Check complete: every active variable in environment ${environmentId} is encrypted at epoch ${summary.epoch} (no incomplete re-encryption). To create a new epoch, pass --reason`,
      );
      return 0;
    }
    const scope =
      summary.mode === "rotated"
        ? `rotated environment ${environmentId}: epoch ${summary.previousEpoch} → ${summary.epoch}`
        : `resumed re-encryption for environment ${environmentId} (epoch ${summary.epoch})`;
    if (summary.remaining > 0 || summary.failure !== null) {
      return yield* reportPartialRotation(environmentId, summary, scope, skipped);
    }
    if (summary.mode === "resumed") {
      // 再開は「要求されたローテーション」ではない: 新しいエポックは作られて
      // いないので、完了報告がローテーション成功に見えてはならない(退職者の
      // 削除に伴う実行が、新エポックなしで成功扱いになる形を塞ぐ)
      yield* io.log(
        `Done: ${scope} (re-encrypted ${countNoun(summary.reencrypted, "variable")}${skipped}). No new epoch was created (epoch remains ${summary.epoch})`,
      );
      if (!rotationRequested) {
        // 理由なしの実行 = 「未完了があれば再開する」ことだけを要求している
        return 0;
      }
      // ローテーションを要求した実行(--reason / --new-epoch)が再開へ切り替わった
      // ので、**終了コードでも**成功と言わない: `maruhi env rotate prod --reason ...
      // || exit 1` のようなスクリプトが、新エポックなしで成功と受け取る形を塞ぐ
      yield* logWarning(
        `the requested rotation was not performed (the incomplete re-encryption was resumed first). If you still need a new epoch after this run, run the command again or pass --new-epoch`,
      );
      return 1;
    }
    yield* io.log(
      `Done: ${scope} (re-encrypted ${countNoun(summary.reencrypted, "variable")}${skipped})`,
    );
    return 0;
  });
}
