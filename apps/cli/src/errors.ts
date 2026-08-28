// CLI のユーザー向けエラー。
//
// 絶対規則(CLAUDE.md ディスクレス不変条件): message に平文のシークレット値・
// 鍵素材・トークン生値を含めない。文脈は識別子(プロジェクト ID・変数名・
// エポック・鍵フィンガープリント等)のみで表現する。

import { Data, Runtime } from "effect";

/** A user-facing CLI failure. The message never carries secret material. */
export class CliError extends Data.TaggedError("CliError")<{
  readonly message: string;
  /** 引数の書き方の誤り(usage エラー = 終了コード 2)か。 */
  readonly usage?: boolean;
  /**
   * 暗号学的証拠(署名検証済みデータとチェーン公証・床の矛盾 — 再実行では
   * 解消しない)を運ぶ失敗か。rotate の巡末分類(env-rotate.ts の settlePass)が
   * 「再実行すれば直る」案内への格下げを避けるために読む(PR-F4 の規律の
   * 規則 2 / 床違反への適用 — PR-M3)。
   */
  readonly evidence?: boolean;
}> {
  /**
   * 終了コードは**エラー型自身が持つ**(ADR-0016 決定 4)。ランナーに
   * 「usage は 2、失敗は 1」の写像表を置かないための Effect の機構で、
   * `Runtime.defaultTeardown`(= `runMain` の既定 teardown)がこれを読む。
   */
  override get [Runtime.errorExitCode](): number {
    return this.usage === true ? 2 : 1;
  }
}

/** Builds a {@link CliError} from a user-facing message. */
export function cliError(message: string): CliError {
  return new CliError({ message });
}

/**
 * Builds a {@link CliError} carrying cryptographic evidence (a contradiction
 * between verified data and the chain's notarization or the local floor —
 * a failure re-running cannot resolve).
 */
export function evidenceError(message: string): CliError {
  return new CliError({ message, evidence: true });
}

/**
 * Builds a {@link CliError} for a malformed invocation (exit code 2).
 *
 * パーサ層で落とせない「語が何も指していない」形 — 不明な操作 / 不明な設定
 * キー / 形式の合わない ID — に使う。実行の失敗(1)と区別できないと、
 * スクリプトが打ち間違いを実行失敗として扱ってしまう。
 */
export function usageError(message: string): CliError {
  return new CliError({ message, usage: true });
}
