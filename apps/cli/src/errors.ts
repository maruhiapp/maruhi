// CLI のユーザー向けエラー。
//
// 絶対規則(CLAUDE.md ディスクレス不変条件): message に平文のシークレット値・
// 鍵素材・トークン生値を含めない。文脈は識別子(プロジェクト ID・変数名・
// エポック・鍵フィンガープリント等)のみで表現する。

import { Data } from "effect";

/** A user-facing CLI failure. The message never carries secret material. */
export class CliError extends Data.TaggedError("CliError")<{
  readonly message: string;
  /** 引数の書き方の誤り(usage エラー = 終了コード 2)か。 */
  readonly usage?: boolean;
}> {}

/** Builds a {@link CliError} from a user-facing message. */
export function cliError(message: string): CliError {
  return new CliError({ message });
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
