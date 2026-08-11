// API・crypto の型付きエラーをユーザー向け CliError へ写す。
//
// 規律: メッセージは識別子(ID・理由コード・上限値・HTTP ステータス)のみで
// 構成し、平文値・鍵素材・トークン生値を運ばない(CLAUDE.md)。
// `_tag` への直接アクセスは oxlint が禁止するため、判定は instanceof で行う
// (Schema.TaggedError は instanceof が使える — session-07 の知見)。

import {
  AuthFlowError,
  ChainCapacityExceededError,
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  ChainHeadConflictError,
  CompositeRequiredError,
  DataLimitExceededError,
  DekWrapExistsError,
  DekWrapNotFoundError,
  DekWrapRejectedError,
  EnvironmentConflictError,
  EnvironmentNotFoundError,
  EpochConflictError,
  ForbiddenError,
  PayloadMismatchError,
  ProjectAlreadyInitializedError,
  ProjectNotFoundError,
  SetupIncompleteError,
  TokenLimitError,
  UnauthorizedError,
  ValueTooLargeError,
  VariableConflictError,
  VariableNotFoundError,
  VersionConflictError,
} from "@maruhi/api-schema";
import { ChainInvalidError } from "@maruhi/core";
import { HttpClientError } from "effect/unstable/http";

import { displayText } from "./display.ts";
import { CliError, cliError } from "./errors.ts";

type Renderer = (error: unknown) => string | null;

function when<T>(guard: (error: unknown) => error is T, render: (error: T) => string): Renderer {
  return (error) => (guard(error) ? render(error) : null);
}

function isInstanceOf<T>(ctor: new (...args: never[]) => T) {
  return (error: unknown): error is T => error instanceof ctor;
}

function renderHttpFailure(error: HttpClientError.HttpClientError): string {
  const status = error.response?.status;
  if (status === 413) {
    // スキーマ外の素の 413(HTTP 生ボディ上限 — session-07 §5 の申し送り分岐)
    return "サーバーがリクエストサイズで拒否しました(HTTP 413)。値が大きすぎます";
  }
  if (status !== undefined) {
    return `サーバー応答を解釈できません(HTTP ${status})。サーバー URL と CLI のバージョン整合を確認してください`;
  }
  return "サーバーへの接続に失敗しました(ネットワーク・サーバー URL を確認してください)";
}

const renderers: readonly Renderer[] = [
  when(isInstanceOf(CliError), (e) => e.message),
  when(
    isInstanceOf(UnauthorizedError),
    () =>
      "認証に失敗しました(トークンが失効している可能性があります)。`maruhi login` で再ログインしてください",
  ),
  when(isInstanceOf(ForbiddenError), (e) => `権限が不足しています(${e.reason})`),
  // エラー Schema の ID / field 列はワイヤ上無制約の Schema.String(サーバーが
  // 自由に埋められる)— reason / op / resource(Literals)と異なり中和が必要
  when(
    isInstanceOf(ProjectNotFoundError),
    (e) =>
      `プロジェクトが見つかりません: ${displayText(e.projectId)}(非メンバーには存在自体が秘匿されます。ID とアクセス権を確認してください)`,
  ),
  when(
    isInstanceOf(EnvironmentNotFoundError),
    (e) => `環境が見つかりません: ${displayText(e.environmentId)}`,
  ),
  when(
    isInstanceOf(VariableNotFoundError),
    (e) => `変数が見つかりません: ${displayText(e.variableId)}`,
  ),
  when(
    isInstanceOf(ProjectAlreadyInitializedError),
    (e) => `プロジェクトは初期化済みです: ${displayText(e.projectId)}`,
  ),
  when(
    isInstanceOf(ChainHeadConflictError),
    (e) =>
      `チェーンヘッドが競合しました(現ヘッド seq=${e.currentHeadSeq})。再同期してやり直してください`,
  ),
  when(
    isInstanceOf(ChainEntryInvalidError),
    (e) => `チェーンエントリがサーバー検証で拒否されました(seq=${e.seq}, reason=${e.reason})`,
  ),
  when(
    isInstanceOf(ChainEntryTooLargeError),
    (e) => `チェーンエントリが大きすぎます(上限 ${e.limitBytes} バイト)`,
  ),
  when(
    isInstanceOf(ChainCapacityExceededError),
    (e) =>
      `チェーン容量の上限に達しています(最大 ${e.maxEntries} エントリ / ${e.maxTotalBytes} バイト)`,
  ),
  when(
    isInstanceOf(CompositeRequiredError),
    (e) => `この操作(${e.op})は複合エンドポイント経由でのみ受理されます(AUTH_SPEC §12-4)`,
  ),
  when(
    isInstanceOf(ChainInvalidError),
    (e) =>
      `チェーン検証に失敗しました(seq=${e.seq}, reason=${e.reason})。サーバーが不正なチェーンを配布している可能性があります`,
  ),
  when(
    isInstanceOf(EnvironmentConflictError),
    (e) => `環境が競合しています: ${displayText(e.environmentId)}(${e.reason})`,
  ),
  when(
    isInstanceOf(VariableConflictError),
    (e) => `変数が競合しています: ${displayText(e.variableId)}(${e.reason})`,
  ),
  when(
    isInstanceOf(VersionConflictError),
    (e) =>
      `バージョンが競合しました(現在 version=${e.currentVersion})。リトライ上限に達したため中断します`,
  ),
  when(
    isInstanceOf(EpochConflictError),
    (e) =>
      `エポックが競合しました(現在 epoch=${e.currentEpoch})。リトライ上限に達したため中断します`,
  ),
  when(
    isInstanceOf(PayloadMismatchError),
    (e) => `申告 AAD が保存先座標と一致しません(${displayText(e.field)})`,
  ),
  when(
    isInstanceOf(ValueTooLargeError),
    (e) => `値が大きすぎます(暗号文の上限 ${e.limitBytes} バイト)`,
  ),
  when(
    isInstanceOf(DataLimitExceededError),
    (e) => `サーバーの受理上限を超えます(${e.resource} の上限 ${e.limit})`,
  ),
  when(isInstanceOf(DekWrapRejectedError), (e) => `DEK ラップ登録が拒否されました(${e.reason})`),
  // recipientUserId はサーバー応答の自由文字列 — 端末へ出す前に中和する
  when(
    isInstanceOf(DekWrapExistsError),
    (e) =>
      `DEK ラップが既に存在します(epoch=${e.epoch}, recipient=${displayText(e.recipientUserId)})。上書きは禁止されています`,
  ),
  when(
    isInstanceOf(DekWrapNotFoundError),
    (e) =>
      `DEK ラップが見つかりません(epoch=${e.epoch}, recipient=${displayText(e.recipientUserId)})`,
  ),
  when(isInstanceOf(AuthFlowError), (e) => `認証フローに失敗しました(${e.reason})`),
  when(
    isInstanceOf(SetupIncompleteError),
    (e) =>
      `サーバーのセルフホスト初期セットアップが未完了です(${e.reason})。サーバー管理者は docs/SELF_HOSTING.md の手順で GitHub OAuth App を登録してください`,
  ),
  when(isInstanceOf(TokenLimitError), (e) => `API トークンの発行上限に達しています(${e.limit} 本)`),
  when(isInstanceOf(HttpClientError.HttpClientError), renderHttpFailure),
];

/**
 * Collapses any failure into a user-facing {@link CliError}. Unknown failures
 * keep only their `Error#message`(our own code never puts secret material in
 * messages; crypto errors carry identifiers only by contract).
 */
export function toCliError(error: unknown): CliError {
  for (const render of renderers) {
    const message = render(error);
    if (message !== null) {
      return cliError(message);
    }
  }
  if (error instanceof Error) {
    // 未知エラーの message は応答本文の断片等を含みうる — 無条件に中和する
    return cliError(`予期しないエラー: ${displayText(error.message)}`);
  }
  return cliError("予期しないエラーが発生しました");
}
