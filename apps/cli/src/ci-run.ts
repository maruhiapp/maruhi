// `maruhi ci run -- <cmd>`: CI ジョブ内のワークロードリース実行
// (CRYPTO_SPEC §9.1 / AUTH_SPEC §14。設計判断は docs/notes/session-25.md)。
//
// 通常の `run` と**前提構造がまるごと別**であることがこのモジュールの要点:
//   - 認証 = リクエスト同梱の OIDC トークンのみ(§14-1)。maruhi トークン・
//     OS キーチェーン・セッション文脈・config ファイルに一切依存しない —
//     依存の不在は要求サービス型(CliIo | ProcessRunner | HttpClient)が示す
//   - 検証材料 = lease 応答に同梱(§14-2)。他の API を呼ばない
//   - 床・ピン = 持たない(使い捨てランナー — §14.3-3)。代替の巻き戻し検出は
//     リポジトリアンカー(--anchor — anchor.ts)
//
// 値の経路は run と同一: 復号値は Redacted のまま runOp(buildInjectionEnv →
// ProcessRunner)へ渡り、子プロセスの環境変数へのメモリ注入のみで消費される
// (ディスクレス不変条件)。これは値の「表示」ではなく「注入」なので
// agent-gate(値表示ゲート)の対象外である(run と同じサンクションされた
// 消費経路 — ADR-0016 決定 7)。

import { LeaseUnauthorizedError } from "@maruhi/api-schema";
import type { EnvironmentId, ProjectId } from "@maruhi/core";
import type { LeaseClaims } from "@maruhi/crypto";
import { encodeHex, exportEncryptionPublicKey, generateEncryptionKeyPair } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { loadRepositoryAnchor } from "./anchor.ts";
import { makeApiClient, type MaruhiClient } from "./api.ts";
import { countNoun, logWarnings } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import type { LeaseResponseWire } from "./lease-client.ts";
import { verifyLeaseResponse } from "./lease-client.ts";
import { fetchGitHubOidcToken, readLeaseClaims } from "./oidc-github.ts";
import { ProcessRunner, runOp } from "./run.ts";

/** `maruhi ci run` の入力(すべて明示フラグ由来 — session-25 §2)。 */
export interface CiRunInput {
  /** 正規化済みサーバー origin(`--server`)。 */
  readonly origin: string;
  /** 事前固定された genesis(`--project` — §9.1 検証義務 (1))。 */
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  /** OIDC audience(`--audience`。既定はサーバー origin — AUTH_SPEC §14-1 の推奨値)。 */
  readonly audience: string;
  /** リポジトリアンカーのパス(`--anchor` — §6.3 (b)。省略可 = SHOULD)。 */
  readonly anchorPath: string | undefined;
  readonly command: readonly string[];
}

/** lease 発行 1 回(ワイヤ境界)。エラーは分類のため型のまま返す。 */
function issueLease(input: {
  readonly client: MaruhiClient;
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly token: Redacted.Redacted<string>;
  readonly ephemeralPubHex: string;
}): Effect.Effect<LeaseResponseWire, unknown> {
  return Effect.gen(function* () {
    // 剥がす理由: lease リクエストのワイヤ境界(payload の oidcToken フィールド)。
    // 平文トークンはリクエスト本文にのみ乗り、ログ・エラーへは出ない
    const oidcToken = Redacted.value(input.token);
    return yield* input.client.lease.issue({
      params: { projectId: input.projectId, environmentId: input.environmentId },
      payload: { oidcToken, ephemeralPubHex: input.ephemeralPubHex },
    });
  });
}

type IssueOutcome =
  | { readonly kind: "ok"; readonly response: LeaseResponseWire }
  | { readonly kind: "replayed" };

/** 発行の 1 試行。`token-replayed` だけを再試行可能として分類する。 */
function attemptLease(
  input: Parameters<typeof issueLease>[0],
): Effect.Effect<IssueOutcome, CliError> {
  return issueLease(input).pipe(
    Effect.map((response) => ({ kind: "ok", response }) as const),
    Effect.catch((error) =>
      error instanceof LeaseUnauthorizedError && error.reason === "token-replayed"
        ? Effect.succeed({ kind: "replayed" } as const)
        : Effect.fail(toCliError(error)),
    ),
  );
}

/**
 * Runs one command with the environment's variables leased through OIDC
 * (CRYPTO_SPEC §9.1 / AUTH_SPEC §14): generate an in-memory ephemeral X25519
 * key pair, mint a fresh GitHub Actions OIDC token, request the lease, run
 * every §9.1 verification duty against the pre-pinned genesis, then inject
 * the decrypted values into the child process environment (memory only).
 */
export function ciRunOp(
  input: CiRunInput,
): Effect.Effect<number, CliError, CliIo | ProcessRunner | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // アンカーはネットワーク・鍵生成より先に読む(壊れたファイルの検出を
    // 往復の後ろに置かない)
    const anchor =
      input.anchorPath === undefined ? null : yield* loadRepositoryAnchor(input.anchorPath);
    const client = yield* makeApiClient({ baseUrl: input.origin });
    // 一時 X25519 鍵ペアはメモリ内で生成し(秘密鍵は非抽出)、ジョブ終了と
    // ともに消える(§9.1)。1 呼び出し = 1 トークン = 1 鍵(session-25 §3 —
    // §14-1 の「1 トークンの全リクエストで同一鍵」は構成上満たされる)
    const workloadKeyPair = yield* Effect.tryPromise({
      try: () => generateEncryptionKeyPair(),
      catch: () => cliError("Failed to generate the ephemeral key pair (crypto error)"),
    });
    const ephemeralPubHex = encodeHex(
      yield* Effect.tryPromise({
        try: () => exportEncryptionPublicKey(workloadKeyPair.publicKey),
        catch: () => cliError("Failed to export the ephemeral public key (crypto error)"),
      }),
    );

    // トークンは lease 要求の直前に発行する(session-24 §8 SHOULD — 先着束縛の
    // 露出窓の最小化)
    let token = yield* fetchGitHubOidcToken(input.audience);
    let claims: LeaseClaims = yield* readLeaseClaims(token);
    const common = {
      client,
      projectId: input.projectId,
      environmentId: input.environmentId,
      ephemeralPubHex,
    };
    let outcome = yield* attemptLease({ ...common, token });
    if (outcome.kind === "replayed") {
      // GitHub はランタイム発行型 issuer なので、新規トークンで 1 回だけ自動
      // 再試行してよい(session-24 §8 MAY — 上限 1 回)。一時鍵は同じものを
      // 提示する(新規トークンは未束縛で、この鍵に束縛される)
      yield* io.logError(
        "The lease was rejected as token-replayed (the token was already bound to a different ephemeral key). Minting a fresh token and retrying once",
      );
      token = yield* fetchGitHubOidcToken(input.audience);
      claims = yield* readLeaseClaims(token);
      outcome = yield* attemptLease({ ...common, token });
      if (outcome.kind === "replayed") {
        // 2 回連続の先着負け = 発行したそばからコピーが使われている。これ以上の
        // 再試行はしない(上限 1 回)— トークン漏洩の兆候として調査を促す
        return yield* Effect.fail(
          cliError(
            "The lease was rejected as token-replayed again with a freshly minted token. Someone else is using this job's OIDC tokens — investigate the job's steps and network path for token exfiltration (AUTH_SPEC §14-1)",
          ),
        );
      }
    }

    // §9.1 の検証義務 (1)〜(4)。何一つ通るまで値は復号されない
    const material = yield* verifyLeaseResponse({
      projectId: input.projectId,
      environmentId: input.environmentId,
      response: outcome.response,
      claims,
      workloadKeyPair,
      anchor,
    });
    yield* logWarnings(material.warnings);
    // 検証の成立は CI ログに残す(stdout は子プロセスの出力のために空けて
    // おく — 決定 9。stderr は診断・情報の宛先)
    yield* io.logError(
      `Lease verified (chain, statements, value signatures, DEK commitments${anchor === null ? "" : ", repository anchor"}): ${countNoun(material.variables.length, "variable")} (environment ${input.environmentId})`,
    );
    return yield* runOp({ command: input.command, variables: material.variables });
  });
}
