// CLI のユーザー向けエラー。
//
// 絶対規則(CLAUDE.md ディスクレス不変条件): message に平文のシークレット値・
// 鍵素材・トークン生値を含めない。文脈は識別子(プロジェクト ID・変数名・
// エポック・鍵フィンガープリント等)のみで表現する。

import { Data } from "effect";

/** A user-facing CLI failure. The message never carries secret material. */
export class CliError extends Data.TaggedError("CliError")<{
  readonly message: string;
}> {}

/** Builds a {@link CliError} from a user-facing message. */
export function cliError(message: string): CliError {
  return new CliError({ message });
}
