// ワークロードリースのハンドラ(AUTH_SPEC §14 = CRYPTO_SPEC §9.1)。
//
// **このハンドラだけ RequestAuth を参照しない**: 資格情報はリクエスト同梱の
// OIDC トークンであり、AuthMiddleware は宣言されていない(api-schema の
// lease-api.ts)。
//
// worker が担うのは認証段(§14-1)だけで、認可以降(grant / lease_policy /
// スコープ / レート制限 / 開封 / 再ラップ / 監査)は project DO の 1 RPC に
// 閉じる(programs-lease.ts の冒頭 — 監査の原子性)。この分割が §14-3 の
// 「認証失敗のみ 401 / 認可失敗は一律 404」を実装構造として保証する。

import {
  LeaseRateLimitedError,
  LeaseUnauthorizedError,
  LeaseUnavailableError,
  maruhiApi,
  ProjectNotFoundError,
} from "@maruhi/api-schema";
import { computeLeaseClaimsDigest } from "@maruhi/crypto";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { toWireVariable } from "./data-http.ts";
import { OidcVerifier, type VerifiedOidcToken } from "./oidc.package/index.ts";
import { LEASE_BINDING_RETENTION_MARGIN_MS } from "./policy.ts";
import type { LeaseOutcome, LeaseTokenFacts } from "./programs-lease.ts";
import {
  IP_RATE_LIMIT_PERIOD_SECONDS,
  ipRateLimitAllowed,
  projectStub,
  rpcCall,
  WorkerEnv,
} from "./worker-env.ts";

/**
 * claims_digest(CRYPTO_SPEC §9.1)は**検証済み**トークンの issuer / sub / aud
 * から計算する。`aud` が配列のトークンでは digest に載る audience が一意に
 * 決まらないため、**単一 audience のトークンのみリース経路で受ける**:
 * 複数 audience のどれを digest に採るかを実装が選ぶと、サーバーとワークロードで
 * 選択が食い違って復号不能なリースを発行しうる(§9.1 の「両者が独立に同じ値を
 * 計算できる」前提が崩れる)。GitHub Actions の OIDC トークンは単一 audience
 * であり、v1 の対応 issuer では制約にならない。
 */
function claimsDigestFor(token: VerifiedOidcToken): Effect.Effect<string, LeaseUnauthorizedError> {
  const audience = token.audiences.length === 1 ? token.audiences[0] : undefined;
  if (audience === undefined) {
    // `aud` は存在する(複数あるだけ)ので missing-claim ではない — 運用者が
    // 理由コードを頼りに「存在する claim」を探しに行かないよう別語彙にする
    // (pullfrog 指摘 — PR #65)
    return Effect.fail(new LeaseUnauthorizedError({ reason: "ambiguous-audience" }));
  }
  return Effect.flatMap(
    Effect.promise(() =>
      computeLeaseClaimsDigest({
        issuerUrl: token.issuer,
        subject: token.subject,
        audience,
      }),
    ),
    (digest) =>
      // 空フィールドは verifier が既に落としている(stringClaim / audiencesOf)
      // ため到達しないが、crypto の Result を握り潰さない
      digest.ok
        ? Effect.succeed(digest.value)
        : Effect.fail(new LeaseUnauthorizedError({ reason: "missing-claim" })),
  );
}

/**
 * DO の LeaseOutcome → api-schema の型付きエラー(§14-3 の判定順の応答面)。
 * `not-found` は未知プロジェクト・grant なし・ポリシー不一致・スコープ外・
 * 環境なしをすべて畳んだもの — 呼び出し元から区別できる応答を作らない
 * (§14-1 の存在秘匿)。
 */
function unwrapLeaseOutcome(outcome: LeaseOutcome, projectId: string) {
  if (outcome.kind === "ok") {
    return Effect.succeed(outcome.value);
  }
  const { rejection } = outcome;
  switch (rejection.kind) {
    case "rate-limited": {
      return Effect.fail(
        new LeaseRateLimitedError({
          retryAfterSeconds: rejection.retryAfterSeconds,
          scope: "project-window",
        }),
      );
    }
    case "unavailable": {
      return Effect.fail(new LeaseUnavailableError({ reason: rejection.reason }));
    }
    // 先着束縛違反(§14-1)は 404 に畳まない: 提示資格情報に帰属する失敗であり、
    // 正規ジョブ側で起きたとき(= トークンが盗まれて先に使われた)に診断可能で
    // あることが可視化の半分。認可通過後にのみ到達するため存在秘匿と両立する
    case "replayed": {
      return Effect.fail(new LeaseUnauthorizedError({ reason: "token-replayed" }));
    }
    case "not-found": {
      return Effect.fail(new ProjectNotFoundError({ projectId }));
    }
  }
}

export const leaseLive = HttpApiBuilder.group(maruhiApi, "lease", (handlers) =>
  handlers.handle("issue", ({ params, payload, request }) =>
    Effect.gen(function* () {
      // 0. 発信元 IP の request-level レート制限(deepsec M5)。DO は名前指定で
      // 暗黙生成されるため、有効な OIDC トークンさえあれば異なる project ID で
      // DO(constructor がテーブルを作る)を量産できる — projectStub の手前で
      // 生成レートを有界にする。DO 内の per-project 窓(認可後 — §11-2 の存在
      // 秘匿のため 404 系より後)とは役割が別で、この判定はプロジェクト状態と
      // 無関係(IP のみ)なので存在秘匿を壊さない
      const env = yield* WorkerEnv;
      const allowed = yield* ipRateLimitAllowed(env.LEASE_RATE_LIMIT, request);
      if (!allowed) {
        return yield* Effect.fail(
          new LeaseRateLimitedError({
            retryAfterSeconds: IP_RATE_LIMIT_PERIOD_SECONDS,
            scope: "source-address",
          }),
        );
      }
      // 1. 認証段(§14-1): OIDC トークンの検証。チェーン導出状態は一切見ない
      const verifier = yield* OidcVerifier;
      const token = yield* verifier.verify(payload.oidcToken, Date.now());
      const claimsDigestHex = yield* claimsDigestFor(token);
      // 先着束縛(§14-1)のキーは verifier が署名対象バイト列(signing input)
      // から計算済み(生トークンのハッシュではない — VerifiedOidcToken の
      // signingInputHashHex の doc)。DO へ渡るのはこのハッシュ・検証済み claim・
      // 生存期限のみで、トークン本体は渡さない。生存期限は「時刻検証がこの
      // トークンを受理しうる最終時刻」以上(policy.ts の余裕は clock skew から
      // 導出 — 受理窓より短い束縛保持はその差分だけリプレイ窓になる)
      const facts: LeaseTokenFacts = {
        issuer: token.issuer,
        subject: token.subject,
        audiences: token.audiences,
        claims: token.claims,
        claimsDigestHex,
        bindingKeyHex: token.signingInputHashHex,
        bindingExpiresAtMs: token.expiresAtSec * 1000 + LEASE_BINDING_RETENTION_MARGIN_MS,
      };
      // 2. 認可以降は DO の 1 RPC(監査を同一 permit・同一同期ブロックで書く)
      const outcome = yield* rpcCall<LeaseOutcome>(() =>
        projectStub(env, params.projectId).issueLease(
          params.environmentId,
          payload.ephemeralPubHex,
          facts,
        ),
      );
      const leased = yield* unwrapLeaseOutcome(outcome, params.projectId);
      // 値のワイヤ形は一括 pull(§12-7)と同一(検証材料の同梱規律を共有する —
      // ワークロードのクライアント検証は §6.3 のままでよい)
      return {
        projectId: params.projectId,
        environmentId: leased.environmentId,
        currentEpoch: leased.currentEpoch,
        chain: leased.chain,
        headSeq: leased.headSeq,
        headHashHex: leased.headHashHex,
        statement: leased.statement,
        variables: leased.variables.map((row) =>
          toWireVariable(params.projectId, params.environmentId, row),
        ),
        deletedVariables: leased.deletedVariables,
        leases: leased.leases,
        // 最新マニフェスト(§14-2 — ワークロードの検証義務 §9.1 (5) の材料)
        ...(leased.manifest === undefined ? {} : { manifest: leased.manifest }),
      };
    }),
  ),
);
