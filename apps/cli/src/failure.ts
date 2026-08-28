// API・crypto の型付きエラーをユーザー向け CliError へ写す。
//
// 規律: メッセージは識別子(ID・理由コード・上限値・HTTP ステータス)のみで
// 構成し、平文値・鍵素材・トークン生値を運ばない(CLAUDE.md)。
// `_tag` への直接アクセスは oxlint が禁止するため、判定は instanceof で行う
// (Schema.TaggedError は instanceof が使える — session-07 の知見)。

import {
  AuditHeadNotReadyError,
  AuthFlowError,
  AuthRateLimitedError,
  ChainCapacityExceededError,
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  ChainHeadConflictError,
  CheckpointStateMismatchError,
  CompositeRequiredError,
  DataLimitExceededError,
  DekWrapExistsError,
  DekWrapNotFoundError,
  DekWrapRejectedError,
  EnvironmentConflictError,
  EnvironmentNotFoundError,
  EpochConflictError,
  ForbiddenError,
  LeaseRateLimitedError,
  LeaseUnauthorizedError,
  LeaseUnavailableError,
  ManifestRejectedError,
  ManifestVersionConflictError,
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
import { Schema } from "effect";
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

/**
 * スキーマ不一致(`Schema.SchemaError`)。
 *
 * 型付きクライアントの失敗は `HttpApiClient` の宣言どおり
 * 「エンドポイントの宣言済みエラー | `HttpClientError` | `Schema.SchemaError`」
 * の 3 種で、前 2 つは上の写像が受け持つ。**残る 1 種がこれ**。
 *
 * **向きは型からは分からない**(レビュー指摘): 上流は応答の decode だけでなく
 * リクエストの encode(`encodePayload` / `encodeParams` / `encodeHeaders` /
 * `encodeQuery`)も**同じエラーチャネル**へ流すので、`Schema.isSchemaError` は
 * 両方を捕まえる。したがって文面で**サーバー側の異常と断定しない**し、
 * 誘導先も両向きを並べる(リクエスト側 = 指定した値 / 応答側 = バージョン整合。
 * 「バージョン整合」だけだと断定を外した前半と裏腹にサーバーへ誘導する) — 実際、
 * `--token-name` の長すぎる値はここへ encode 失敗として届いていた(現在は
 * 引数層が通信より前に落とす。cli.ts の requireTokenName)。
 * リクエスト側の値は引数層で検査する、が塞ぎ方であって、この写像ではない。
 *
 * `message` を通してよい根拠(実測。rc.109 で 8 形を確認): 上流の整形は
 * **期待した型と場所だけ**を出し、**食い違った値そのものは出さない**
 * (`Expected number at ["variables"][0]["version"]`)。応答本文には変数名も
 * 暗号文も載るので、ここが値を含む整形に変わったら診断が漏洩経路になる —
 * その性質は units.test.ts が**負の検査**で固定する(上流が変えたら落ちる)。
 *
 * 改行は 1 行へ畳んでから中和する(`displayText` は改行も置換文字にするため、
 * 畳まないと `Expected number\uFFFD at …` になって読めない)。
 */
function renderSchemaFailure(error: Schema.SchemaError): string {
  const detail = displayText(error.message.replace(/\s+/g, " ").trim());
  return `Some data does not match the schema (${detail}). Check the values you provided, and that the CLI and server versions match`;
}

/**
 * 503 `LeaseUnavailable`(AUTH_SPEC §14-3)の理由別の案内。3 理由とも
 * 「資格情報の異常ではなく、発行できない状態」であり、次の一手が違う —
 * 401 と混ぜず、理由ごとに直す先(再実行 / 管理者 / デプロイ設定)を言う。
 */
function renderLeaseUnavailable(error: LeaseUnavailableError): string {
  if (error.reason === "oidc-jwks-unavailable") {
    return "The server could not fetch the OIDC issuer's signing keys (oidc-jwks-unavailable). This is a transient issuer or network condition, not a problem with your credentials — retry the job later";
  }
  if (error.reason === "server-key-unconfigured") {
    return "This deployment has no server key configured (server-key-unconfigured), so leases cannot be issued. The server administrator should complete the setup in docs/SELF_HOSTING.md";
  }
  return "The lease is authorized, but the epoch DEKs have not been re-wrapped to the server key yet (server-wraps-missing). An administrator should complete the pending rotation or grant backfill (maruhi env rotate / maruhi server grant), then retry";
}

function renderHttpFailure(error: HttpClientError.HttpClientError): string {
  const status = error.response?.status;
  if (status === 413) {
    // スキーマ外の素の 413(HTTP 生ボディ上限 — session-07 §5 の申し送り分岐)
    return "The server rejected the request for its size (HTTP 413). The value is too large";
  }
  if (status !== undefined) {
    return `Cannot interpret the server response (HTTP ${status}). Check the server URL, and that the CLI and server versions match`;
  }
  return "Failed to connect to the server (check your network and the server URL)";
}

// CliError は toCliError の入口でそのまま返す(usage フラグを落とさないため)
const renderers: readonly Renderer[] = [
  when(
    isInstanceOf(UnauthorizedError),
    () => "Authentication failed (the token may be revoked). Log in again with `maruhi login`",
  ),
  when(isInstanceOf(ForbiddenError), (e) => `Insufficient permission (${e.reason})`),
  // エラー Schema の ID / field 列はワイヤ上無制約の Schema.String(サーバーが
  // 自由に埋められる)— reason / op / resource(Literals)と異なり中和が必要
  when(
    isInstanceOf(ProjectNotFoundError),
    (e) =>
      `Project not found: ${displayText(e.projectId)} (its existence is hidden from non-members; check the ID and your access)`,
  ),
  when(
    isInstanceOf(EnvironmentNotFoundError),
    (e) => `Environment not found: ${displayText(e.environmentId)}`,
  ),
  when(
    isInstanceOf(VariableNotFoundError),
    (e) => `Variable not found: ${displayText(e.variableId)}`,
  ),
  when(
    isInstanceOf(ProjectAlreadyInitializedError),
    (e) => `The project is already initialized: ${displayText(e.projectId)}`,
  ),
  when(
    isInstanceOf(ChainHeadConflictError),
    (e) => `The chain head conflicted (current head seq=${e.currentHeadSeq}). Re-sync and retry`,
  ),
  // マニフェスト系(§12-5)。各コマンドが専用の写像を持つ経路(env rotate /
  // push の 409 再解決)ではここへ来ない — これは残りの経路の受け皿
  when(
    isInstanceOf(ManifestRejectedError),
    (e) =>
      `The environment manifest was rejected by server-side validation (reason=${e.reason} — AUTH_SPEC §12-5)`,
  ),
  when(
    isInstanceOf(ManifestVersionConflictError),
    (e) =>
      `The manifestVersion conflicted (current manifestVersion=${e.currentManifestVersion}). A concurrent meta operation advanced the environment's manifest — re-run to rebuild it from the refreshed state`,
  ),
  when(
    isInstanceOf(ChainEntryInvalidError),
    (e) =>
      `The chain entry was rejected by server-side validation (seq=${e.seq}, reason=${e.reason})`,
  ),
  when(
    isInstanceOf(ChainEntryTooLargeError),
    (e) => `The chain entry is too large (limit ${e.limitBytes} bytes)`,
  ),
  when(
    isInstanceOf(ChainCapacityExceededError),
    (e) =>
      `The chain capacity limit is reached (max ${e.maxEntries} entries / ${e.maxTotalBytes} bytes)`,
  ),
  when(
    isInstanceOf(CompositeRequiredError),
    (e) =>
      `This operation (${e.op}) is only accepted through the compound endpoint (AUTH_SPEC §12-4)`,
  ),
  // 専用の有界再試行(checkpoint.ts / audit-reconcile.ts)を通らない残りの
  // 経路の受け皿。retryable なので再実行を案内する
  when(
    isInstanceOf(AuditHeadNotReadyError),
    () =>
      "The server is still materializing the audit-head hash column (this happens once on a project with a large existing audit log). Progress is saved server-side — re-run the command to continue",
  ),
  when(
    isInstanceOf(ChainInvalidError),
    (e) =>
      `Chain verification failed (seq=${e.seq}, reason=${e.reason}). The server may be distributing an invalid chain`,
  ),
  when(
    isInstanceOf(EnvironmentConflictError),
    (e) => `Environment conflict: ${displayText(e.environmentId)} (${e.reason})`,
  ),
  when(
    isInstanceOf(VariableConflictError),
    (e) => `Variable conflict: ${displayText(e.variableId)} (${e.reason})`,
  ),
  when(
    isInstanceOf(VersionConflictError),
    (e) =>
      `Version conflict (current version=${e.currentVersion}). Giving up after the retry limit`,
  ),
  when(
    isInstanceOf(EpochConflictError),
    (e) => `Epoch conflict (current epoch=${e.currentEpoch}). Giving up after the retry limit`,
  ),
  when(
    isInstanceOf(PayloadMismatchError),
    (e) => `The declared AAD does not match the storage coordinates (${displayText(e.field)})`,
  ),
  when(
    isInstanceOf(ValueTooLargeError),
    (e) => `The value is too large (ciphertext limit ${e.limitBytes} bytes)`,
  ),
  when(
    isInstanceOf(DataLimitExceededError),
    (e) => `Exceeds a server acceptance limit (${e.resource} limit ${e.limit})`,
  ),
  when(
    isInstanceOf(DekWrapRejectedError),
    (e) => `The DEK-wrap registration was rejected (${e.reason})`,
  ),
  // recipientUserId はサーバー応答の自由文字列 — 端末へ出す前に中和する
  when(
    isInstanceOf(DekWrapExistsError),
    (e) =>
      `A DEK wrap already exists (epoch=${e.epoch}, recipient=${displayText(e.recipientUserId)}). Overwriting is forbidden`,
  ),
  when(
    isInstanceOf(DekWrapNotFoundError),
    (e) => `DEK wrap not found (epoch=${e.epoch}, recipient=${displayText(e.recipientUserId)})`,
  ),
  // Lease 系(AUTH_SPEC §14-3)。reason は Literals(サーバーが自由に埋め
  // られない)なのでそのまま載せる。トークン値・外部識別子は運ばない
  when(
    isInstanceOf(LeaseUnauthorizedError),
    (e) =>
      `The OIDC token was rejected by the lease endpoint (${e.reason}). Check the token's issuer, audience, and validity window (AUTH_SPEC §14-1)`,
  ),
  when(isInstanceOf(LeaseRateLimitedError), (e) =>
    e.scope === "source-address"
      ? `Too many lease requests from this source address (HTTP 429). Retry after ${e.retryAfterSeconds} seconds — if legitimate CI traffic shares this egress IP, the server operator can raise the per-IP limit (docs/SELF_HOSTING.md)`
      : `The project's lease rate limit is exhausted (HTTP 429). Retry after ${e.retryAfterSeconds} seconds — re-run the job later; retrying immediately only consumes the window`,
  ),
  when(isInstanceOf(LeaseUnavailableError), renderLeaseUnavailable),
  when(isInstanceOf(AuthFlowError), (e) => `The authentication flow failed (${e.reason})`),
  when(
    isInstanceOf(AuthRateLimitedError),
    (e) =>
      `Too many login attempts from this address (HTTP 429). Retry after ${e.retryAfterSeconds} seconds`,
  ),
  when(
    isInstanceOf(SetupIncompleteError),
    (e) =>
      `The server's self-hosting setup is incomplete (${e.reason}). The server administrator should register a GitHub OAuth App following docs/SELF_HOSTING.md`,
  ),
  when(
    isInstanceOf(TokenLimitError),
    (e) => `The API-token issuance limit is reached (${e.limit} tokens)`,
  ),
  when(isInstanceOf(HttpClientError.HttpClientError), renderHttpFailure),
  // 型付きクライアントの失敗の 3 種目(上の 2 種と合わせて宣言を尽くす)
  when(Schema.isSchemaError, renderSchemaFailure),
];

/**
 * サーバーが**自前のエラー本文で拒否した**か(= リクエストは届き、処理されて
 * 拒否されたことが確定している)。これらの本文を返せるのは要求を処理した後の
 * サーバーだけなので、受理の有無が確定する。
 *
 * ここに載らない失敗(転送エラー・応答の消失・解釈できない 5xx)は
 * **受理されたかどうか不明**である — 既定を「不明」に倒すため、判定は
 * 許可リストで行う(未知のエラーが黙って「確定」側に落ちない)。
 */
export function isServerRejection(error: unknown): boolean {
  return [
    AuditHeadNotReadyError,
    ChainCapacityExceededError,
    ChainHeadConflictError,
    ChainEntryInvalidError,
    ChainEntryTooLargeError,
    CheckpointStateMismatchError,
    CompositeRequiredError,
    DataLimitExceededError,
    DekWrapExistsError,
    DekWrapNotFoundError,
    DekWrapRejectedError,
    EnvironmentConflictError,
    EnvironmentNotFoundError,
    EpochConflictError,
    ForbiddenError,
    ManifestRejectedError,
    ManifestVersionConflictError,
    PayloadMismatchError,
    ProjectNotFoundError,
    UnauthorizedError,
    ValueTooLargeError,
    VariableConflictError,
    VariableNotFoundError,
    VersionConflictError,
  ].some((ctor) => error instanceof ctor);
}

/**
 * Names the *type* of an internal failure (defect) without echoing its message.
 *
 * defect の `message` は打たれた値を埋め込んだ文面(`Invalid value: <平文>`)
 * でも到達しうるので、制御文字の中和だけでは規律(打たれた値を診断に出さない)
 * を守れない。かといって無言で飲むのも禁止(CLAUDE.md)なので、**コード由来の
 * 語彙**である型の名前だけを手掛かりとして残す — argv からは作れず、
 * `bun build --compile` は minify しないので配布バイナリでも潰れない。
 */
export function internalErrorKind(failure: unknown): string {
  return displayText(failure instanceof Error ? failure.constructor.name : typeof failure);
}

/**
 * Collapses any failure into a user-facing {@link CliError}. Failures that no
 * renderer claims are reported by **type name only** — never by their message
 * (see the comment at the fallback).
 */
export function toCliError(error: unknown): CliError {
  // 既に CliError なら、usage フラグ(終了コード 2)を落とさずそのまま返す
  if (error instanceof CliError) {
    return error;
  }
  for (const render of renderers) {
    const message = render(error);
    if (message !== null) {
      return cliError(message);
    }
  }
  // ここへ来るのは**宣言を尽くした先の未知**だけ(型付きクライアントの失敗 3 種は
  // 上で写像済み)。未知の message は素通しにしない — 応答本文の断片や打たれた値を
  // 含む文面でも到達しうるので、制御文字の中和だけでは規律を守れない。無言でも
  // 飲まず、型の名前(コード由来の語彙)を手掛かりに残す
  return cliError(`Unexpected error (${internalErrorKind(error)})`);
}
