// CI ジョブのワークロードリース(CRYPTO_SPEC §9.1 / AUTH_SPEC §14)の取得 —
// `maruhi ci run`(ci-run.ts)と `maruhi ci sync`(sync-ci.ts)が共有する前段。
//
// 通常のコマンドと**前提構造がまるごと別**であることがこのモジュールの要点:
//   - 認証 = リクエスト同梱の OIDC トークンのみ(§14-1)。maruhi トークン・
//     OS キーチェーン・セッション文脈・config ファイルに一切依存しない —
//     依存の不在は要求サービス型(CliIo | HttpClient)が示す
//   - 検証材料 = lease 応答に同梱(§14-2)。他の API を呼ばない
//   - 床・ピン = 持たない(使い捨てランナー — §14.3-3)。代替の巻き戻し検出は
//     リポジトリアンカー(--anchor — anchor.ts)
//
// 複数環境(`ci sync` の同期元とトークン環境)は **1 本の OIDC トークンと 1 つの
// 一時鍵**で順に要求する: サーバーの先着束縛はトークン単位でプロジェクト内の
// 全環境を跨ぐため、同一トークンの全リクエストで同一の一時鍵を用いる義務がある
// (AUTH_SPEC §14-1 / CRYPTO_SPEC §9.1)。

import { LeaseUnauthorizedError, ProjectNotFoundError } from "@maruhi/api-schema";
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
import type { LeaseResponseWire, VerifiedLeaseMaterial } from "./lease-client.ts";
import { verifyLeaseResponse } from "./lease-client.ts";
import { fetchGitHubOidcToken, readLeaseClaims } from "./oidc-github.ts";

/** CI コマンド共通の入力(すべて明示フラグ由来 — session-25 §2)。 */
export interface CiLeaseInput {
  /** 正規化済みサーバー origin(`--server`)。 */
  readonly origin: string;
  /** 事前固定された genesis(`--project` — §9.1 検証義務 (1))。 */
  readonly projectId: ProjectId;
  /** OIDC audience(`--audience`。既定はサーバー origin — AUTH_SPEC §14-1 の推奨値)。 */
  readonly audience: string;
  /** リポジトリアンカーのパス(`--anchor` — §6.3 (b)。省略可 = SHOULD)。 */
  readonly anchorPath: string | undefined;
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

/**
 * lease の 404 は**一様応答**であり(AUTH_SPEC §14-1 の存在秘匿)、CI で最も
 * 起きやすい実因はプロジェクト ID の誤りではなくポリシー不一致(リポジトリ
 * 移転・別ブランチ実行)である。共通写像(failure.ts)の「Project not found —
 * check the ID and your access」はメンバー向けの導線で、ここでは誤った直し先へ
 * 送るため、lease 専用の案内に差し替える。
 */
const LEASE_NOT_FOUND_MESSAGE =
  "The server answered 404 for the lease. The lease endpoint folds these into one uniform answer (existence hiding — AUTH_SPEC §14-1): unknown project, no active grant, a lease-policy mismatch (issuer / audience / claim constraints), and an out-of-scope or unknown environment. Check --server, --project, and the environment in the workflow, and that a project owner granted this workload's identity with `maruhi server grant --lease-policy`";

/** 発行の 1 試行。`token-replayed` だけを再試行可能として分類する。 */
function attemptLease(
  input: Parameters<typeof issueLease>[0],
): Effect.Effect<IssueOutcome, CliError> {
  return issueLease(input).pipe(
    Effect.map((response) => ({ kind: "ok", response }) as const),
    Effect.catch((error) => {
      if (error instanceof LeaseUnauthorizedError && error.reason === "token-replayed") {
        return Effect.succeed({ kind: "replayed" } as const);
      }
      if (error instanceof ProjectNotFoundError) {
        return Effect.fail(cliError(LEASE_NOT_FOUND_MESSAGE));
      }
      return Effect.fail(toCliError(error));
    }),
  );
}

/**
 * Leases every requested environment through OIDC (CRYPTO_SPEC §9.1 /
 * AUTH_SPEC §14): generate an in-memory ephemeral X25519 key pair, mint a
 * fresh GitHub Actions OIDC token, request each lease with that one token
 * and key, and run every §9.1 verification duty against the pre-pinned
 * genesis. Values are decrypted in memory only.
 */
export function leaseEnvironments(
  input: CiLeaseInput & { readonly environmentIds: readonly EnvironmentId[] },
): Effect.Effect<
  ReadonlyMap<EnvironmentId, VerifiedLeaseMaterial>,
  CliError,
  CliIo | HttpClient.HttpClient
> {
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
    // GitHub はランタイム発行型 issuer なので、新規トークンで 1 回だけ自動
    // 再試行してよい(session-24 §8 MAY — 上限 1 回。環境が複数でも合計 1 回)
    let retried = false;
    const materials = new Map<EnvironmentId, VerifiedLeaseMaterial>();
    for (const environmentId of input.environmentIds) {
      const common = { client, projectId: input.projectId, environmentId, ephemeralPubHex };
      let outcome = yield* attemptLease({ ...common, token });
      if (outcome.kind === "replayed") {
        if (retried) {
          // 2 回連続の先着負け = 発行したそばからコピーが使われている。これ以上の
          // 再試行はしない(上限 1 回)— トークン漏洩の兆候として調査を促す
          return yield* Effect.fail(
            cliError(
              "The lease was rejected as token-replayed again with a freshly minted token. Someone else is using this job's OIDC tokens — investigate the job's steps and network path for token exfiltration (AUTH_SPEC §14-1)",
            ),
          );
        }
        // 一時鍵は同じものを提示する(新規トークンは未束縛で、この鍵に束縛される)
        yield* io.logError(
          "The lease was rejected as token-replayed (the token was already bound to a different ephemeral key). Minting a fresh token and retrying once",
        );
        retried = true;
        token = yield* fetchGitHubOidcToken(input.audience);
        claims = yield* readLeaseClaims(token);
        outcome = yield* attemptLease({ ...common, token });
        if (outcome.kind === "replayed") {
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
        environmentId,
        response: outcome.response,
        claims,
        workloadKeyPair,
        anchor,
      });
      yield* logWarnings(material.warnings);
      // 検証の成立は CI ログに残す(stdout は子プロセスの出力のために空けて
      // おく — 決定 9。stderr は診断・情報の宛先)
      yield* io.logError(
        `Lease verified (chain, statements, value signatures, DEK commitments${anchor === null ? "" : ", repository anchor"}): ${countNoun(material.variables.length, "variable")} (environment ${environmentId})`,
      );
      materials.set(environmentId, material);
    }
    return materials;
  });
}
