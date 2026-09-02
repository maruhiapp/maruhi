// CLI ログイン(サーバー仲介 web-flow ハンドオフ — AUTH_SPEC §4)のハンドラ。
//
// - `flowToken` は CLI 専用の bearer 資格情報。ブラウザチャネル(URL・ページ・
//   リダイレクト)・ログ・エラーメッセージのいずれにも出さない(§4-1 (1))
// - ブラウザ脚(cliVerify / callback の CLI 分岐 / cliApprove)の失敗は §4-2 の
//   一様拒否規律に従い、同一のスクリプトなしエラーページで返す(フロー状態・
//   拒否理由のオラクルを作らない)
// - callback の CLI 分岐(handleCliCallback)は handlers-auth.ts の
//   githubCallback から呼ばれる(GitHub の callback URL は §3 の単一 URL のまま —
//   state の `cli.` プレフィックスで分岐する)

import {
  AuthRateLimitedError,
  CliFlowExpiredError,
  CliFlowRejectedError,
  DEFAULT_TOKEN_TTL_DAYS,
  maruhiApi,
  MIN_CLI_POLL_INTERVAL_SECONDS,
  TokenLimitError,
} from "@maruhi/api-schema";
import type { TokenScope } from "@maruhi/core";
import { TokenService } from "@maruhi/core";
import { Effect, Option } from "effect";
import type { HttpServerRequest } from "effect/unstable/http";
import { HttpServerResponse } from "effect/unstable/http";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import {
  CLI_STATE_COOKIE,
  CLI_STATE_PREFIX,
  callbackUri,
  ensureGitHubOAuthConfigured,
  HOST_COOKIE_OPTIONS,
  recordLoginFailed,
  redirectToGitHubAuthorize,
  requestOrigin,
} from "./auth-shared.ts";
import type { CliVerifyParams } from "./auth.package/index.ts";
import {
  CLI_FLOW_TTL_MS,
  CLI_PAGE_CSP_HEADER,
  computeVsig,
  createFlowToken,
  generateUserCode,
  GitHubApi,
  importFlowSigningKey,
  renderApprovalPage,
  renderApprovedPage,
  renderCliErrorPage,
  renderDeniedPage,
  renderSignupGuidancePage,
  verificationQuery,
  verifyCliVerifyQuery,
  verifyFlowToken,
} from "./auth.package/index.ts";
import type { D1AuditRepo } from "./db.package/index.ts";
import { CliFlowRepo, FlowSigningKeyRepo, IdentityRepo, OpsRepo } from "./db.package/index.ts";
import { constantTimeEqual, randomHex, sha256Hex } from "./ids.ts";
import { noteOpsCounter } from "./ops-signals.ts";
import { IP_RATE_LIMIT_PERIOD_SECONDS, ipRateLimitAllowed, WorkerEnv } from "./worker-env.ts";

/** 発行パラメータ省略時の既定トークン名(§6 の意味論は既定スコープと同じ扱い)。 */
const DEFAULT_TOKEN_NAME = "cli-login";

/** 省略時の既定スコープ(AUTH_SPEC §6: 省略時は * × admin)。 */
const DEFAULT_TOKEN_SCOPES: readonly TokenScope[] = [{ project: "*", permission: "admin" }];

/**
 * フロー署名鍵の解決(AUTH_SPEC §4-2): 初回使用時に候補鍵を自動生成して D1 に
 * 保存する(冪等・先勝ち — 競合時は後着の候補を破棄して保存済みの鍵を使う)。
 * 鍵は isolate にキャッシュしない: フローは 15 分 TTL の低頻度面であり、
 * キャッシュ整合(手動ローテーション時の isolate 間ずれ)を持ち込む価値がない。
 */
const flowSigningKey: Effect.Effect<CryptoKey, never, FlowSigningKeyRepo> = Effect.gen(
  function* () {
    const repo = yield* FlowSigningKeyRepo;
    const keyHex = yield* repo.getOrCreate(randomHex(32), Date.now());
    // 形式不正(自分の生成経路でしか書かれない)は defect
    return yield* Effect.promise(() => importFlowSigningKey(keyHex));
  },
);

/**
 * スクリプトなし HTML ページの応答(§4-1 (4) — §15-3 の招待着地ページと同じ
 * 配信規律)。CSP はページ内 meta と二重化し(frame-ancestors はヘッダー側
 * のみ — meta では無効)、Referrer-Policy でページ URL の外部リーク(承認
 * ページからの遷移)も塞ぐ。X-Frame-Options は frame-ancestors 未対応の古い
 * ブラウザ向けの併記。サインアップ制御の案内ページ(handlers-auth.ts —
 * AUTH_SPEC §3)も同じ応答点を共用する。
 */
export function htmlResponse(html: string, status: number): HttpServerResponse.HttpServerResponse {
  return HttpServerResponse.text(html, {
    status,
    contentType: "text/html; charset=utf-8",
    headers: {
      "content-security-policy": CLI_PAGE_CSP_HEADER,
      "referrer-policy": "no-referrer",
      "x-frame-options": "DENY",
    },
  });
}

/** 一様エラーページ(§4-2 — 失敗理由を HTTP 状態でも出し分けない)。 */
function uniformErrorPage(): HttpServerResponse.HttpServerResponse {
  return htmlResponse(renderCliErrorPage(), 400);
}

/** CLI 分岐の終端応答からフロー束縛クッキーを掃除する(単回使用)。 */
function withCliCookieExpired(
  response: HttpServerResponse.HttpServerResponse,
): Effect.Effect<HttpServerResponse.HttpServerResponse> {
  return HttpServerResponse.expireCookie(response, CLI_STATE_COOKIE, HOST_COOKIE_OPTIONS).pipe(
    Effect.orDie,
  );
}

/** GitHub の state が CLI ブラウザ脚のものか(callback の分岐判定 — §4-1 (3))。 */
export function isCliCallbackState(state: string): boolean {
  return state.startsWith(CLI_STATE_PREFIX);
}

/** (i)-a の復元結果: 検証を通った束縛パラメータ、または一様拒否の区分。 */
type FlowBinding =
  | { readonly params: CliVerifyParams; readonly vsig: string }
  | "state-mismatch"
  | "invalid";

/**
 * callback の CLI 分岐 (i)-a: フロー束縛クッキーの復元と検証。CLI 分岐は専用
 * クッキー(CLI_STATE_COOKIE)に state と vsig 済みパラメータ一式を運ぶ
 * (§4-1 (3) の「state に flow 束縛」— GitHub の state パラメータ自体は乱数のみ
 * とし、束縛の実体は同一ブラウザにしか無いクッキー側に置く)。state 照合の後、
 * vsig を再検証する(verify 到達時と同じ無状態検証 — クッキー値は改竄可能な
 * クライアント保持データであり、署名の通らないパラメータでフロー行を作らない)。
 */
function restoreFlowBinding(
  request: HttpServerRequest.HttpServerRequest,
  queryState: string,
  key: CryptoKey,
): Effect.Effect<FlowBinding> {
  const cookie = request.cookies[CLI_STATE_COOKIE];
  const bound = cookie === undefined ? null : new URLSearchParams(cookie);
  const cookieState = bound?.get("state") ?? null;
  if (bound === null || cookieState === null || !constantTimeEqual(cookieState, queryState)) {
    return Effect.succeed("state-mismatch");
  }
  const readParam = (name: string): string | undefined => bound.get(name) ?? undefined;
  const vsig = readParam("vsig");
  return Effect.promise(async () => {
    const params = await verifyCliVerifyQuery(
      key,
      {
        flow: readParam("flow"),
        exp: readParam("exp"),
        code: readParam("code"),
        name: readParam("name"),
        scopes: readParam("scopes"),
        days: readParam("days"),
        vsig,
      },
      Date.now(),
    );
    return params === null || vsig === undefined ? "invalid" : { params, vsig };
  });
}

/**
 * callback の CLI 分岐 (iii)〜(iv): フロー行の作成 CAS(create-or-match)と
 * 承認ページの描画。user_id・発行パラメータ・チケットは作成と同時に確定する
 * (中間状態が存在しない)。scopesJson は start が自ら JSON.stringify した値で
 * vsig 検証済み — parse 失敗は defect。
 */
function admitAndRenderApproval(
  params: CliVerifyParams,
  userId: string,
  identityLabel: string,
): Effect.Effect<HttpServerResponse.HttpServerResponse, never, CliFlowRepo | OpsRepo> {
  return Effect.gen(function* () {
    const ticket = randomHex(32);
    const ticketHash = yield* Effect.promise(() => sha256Hex(ticket));
    const scopes = JSON.parse(params.scopesJson) as readonly TokenScope[];
    const flows = yield* CliFlowRepo;
    const admission = yield* flows.createOrMatch(
      {
        flowId: params.flowId,
        userId,
        tokenName: params.tokenName,
        scopes,
        expiresInDays: params.expiresInDays,
        userCode: params.userCode,
        ticketHash,
        expiresAtMs: params.expiresAtMs,
      },
      Date.now(),
    );
    // rejected(別 user_id・期限切れ・終端状態)と capacity(全体上限)はどちらも
    // 一様エラーページ(§4-1 (4) (iii) / §4-2 — チケットは回転していない)
    if (admission === "capacity") {
      // 上限到達は正規運用で起きない事象 = H3 のトリップワイヤ(hosted-ops.md §3 行 4)。
      // 計数のみで応答は変えない
      yield* noteOpsCounter("cli_flow_capacity");
    }
    if (admission === "rejected" || admission === "capacity") {
      return uniformErrorPage();
    }
    // (iv): 承認ページ(スクリプトなし)。表示は認証済みアイデンティティ +
    // 付与内容。チケット生値はこのページにのみ埋まる(常に最新 1 枚)
    return htmlResponse(
      renderApprovalPage({
        userCode: params.userCode,
        identityLabel,
        tokenName: params.tokenName,
        scopes,
        expiresInDays: params.expiresInDays,
        flowId: params.flowId,
        ticket,
      }),
      200,
    );
  });
}

/**
 * callback の CLI フロー分岐(AUTH_SPEC §4-1 (4) — 処理順は仕様で固定)。
 * (i) state 検証 + code 交換 + ユーザー情報取得(OAuth 完走の確定)→
 * (ii) アカウント照会(不在 = サインアップ案内で終了・副作用ゼロ)→
 * (iii) フロー行の作成 CAS(create-or-match)→ (iv) 承認ページ。
 *
 * 全終端がブラウザ向け HTML(型付きエラーを返さない)。呼び出し側
 * (githubCallback)は per-IP レート制限を通過済み。
 */
export function handleCliCallback(
  request: HttpServerRequest.HttpServerRequest,
  query: { readonly code: string; readonly state: string },
): Effect.Effect<
  HttpServerResponse.HttpServerResponse,
  never,
  WorkerEnv | GitHubApi | IdentityRepo | CliFlowRepo | FlowSigningKeyRepo | D1AuditRepo | OpsRepo
> {
  return Effect.gen(function* () {
    // (i)-a: フロー束縛クッキーの復元(state 照合 + vsig 再検証)
    const key = yield* flowSigningKey;
    const binding = yield* restoreFlowBinding(request, query.state, key);
    if (binding === "state-mismatch") {
      yield* recordLoginFailed("cli_handoff", "state-mismatch");
      return yield* withCliCookieExpired(uniformErrorPage());
    }
    if (binding === "invalid") {
      return yield* withCliCookieExpired(uniformErrorPage());
    }
    const { params, vsig } = binding;
    // (i)-b: code 交換 + ユーザー情報取得(§3 の 2 段目)。失敗したら以降の
    // 処理は起きない(フロー行の作成が OAuth 完走の後にのみ起きる — §4-1 (4))
    const origin = requestOrigin(request);
    const github = yield* GitHubApi;
    const exchanged = yield* github
      .exchangeCode(query.code, callbackUri(origin))
      .pipe(Effect.option);
    if (Option.isNone(exchanged)) {
      yield* recordLoginFailed("cli_handoff", "code-exchange-failed");
      return yield* withCliCookieExpired(uniformErrorPage());
    }
    const fetched = yield* github.fetchIdentity(exchanged.value).pipe(Effect.option);
    if (Option.isNone(fetched)) {
      yield* recordLoginFailed("cli_handoff", "github-token-invalid");
      return yield* withCliCookieExpired(uniformErrorPage());
    }
    const identity = fetched.value;
    // (ii): アカウント照会のみ(作成しない — 裁定 DH)。不在はサインアップ案内で
    // 終了し、一切の不可逆な副作用を起こさない。再開リンクは verificationUrl
    // (vsig 済みパラメータから復元)— このページ自身は再読込でフローを再開できない
    const identities = yield* IdentityRepo;
    const userId = yield* identities.lookupUser(identity);
    if (userId === null) {
      const verificationUrl = `${origin}/auth/cli/verify?${verificationQuery(params, vsig).toString()}`;
      // 案内文言のみ signupPolicy(AUTH_SPEC §3)へ追随させる — invite 制下で
      // プレーンなサインアップリンクを出すと拒否ページへ誘導するだけになる。
      // 受理の正はサーバーゲート(§3 — Web サインアップ側)のまま
      const signupPolicy = yield* identities.signupPolicy;
      return yield* withCliCookieExpired(
        htmlResponse(renderSignupGuidancePage(origin, verificationUrl, signupPolicy), 200),
      );
    }
    const identityLabel = identity.providerLogin ?? `GitHub account #${identity.providerUserId}`;
    return yield* withCliCookieExpired(
      yield* admitAndRenderApproval(params, userId, identityLabel),
    );
  });
}

export const authCliLive = HttpApiBuilder.group(maruhiApi, "authCli", (handlers) =>
  handlers
    .handle("cliStart", ({ payload, request }) =>
      Effect.gen(function* () {
        const env = yield* WorkerEnv;
        // per-IP レート制限をハンドラ最初に置く(§4-1 (1) — 無記録化により DB
        // 保護ではなく CPU 保護。旧 device 交換と同じ binding パターン)
        const allowed = yield* ipRateLimitAllowed(env.CLI_START_RATE_LIMIT, request);
        if (!allowed) {
          return yield* Effect.fail(
            new AuthRateLimitedError({ retryAfterSeconds: IP_RATE_LIMIT_PERIOD_SECONDS }),
          );
        }
        // 未設定サーバーは GitHub に到達する前に fail-closed(§4-1 (1))
        yield* ensureGitHubOAuthConfigured(env.GITHUB_CLIENT_ID, env.GITHUB_CLIENT_SECRET);
        const key = yield* flowSigningKey;
        const nowMs = Date.now();
        const flowId = randomHex(16);
        const expiresAtMs = nowMs + CLI_FLOW_TTL_MS;
        const params: CliVerifyParams = {
          flowId,
          expiresAtMs,
          userCode: generateUserCode(),
          tokenName: payload.tokenName ?? DEFAULT_TOKEN_NAME,
          scopesJson: JSON.stringify(payload.scopes ?? DEFAULT_TOKEN_SCOPES),
          expiresInDays: payload.expiresInDays ?? DEFAULT_TOKEN_TTL_DAYS,
        };
        // サーバーはこの時点で何も保存しない(無記録 — 裁定 DH)。真正性は
        // flowToken(flowId を署名対象に含む)と vsig の 2 系統 MAC が担う
        const flowToken = yield* Effect.promise(() => createFlowToken(key, flowId, expiresAtMs));
        const vsig = yield* Effect.promise(() => computeVsig(key, params));
        const origin = requestOrigin(request);
        return {
          flowId,
          flowToken,
          userCode: params.userCode,
          verificationUrl: `${origin}/auth/cli/verify?${verificationQuery(params, vsig).toString()}`,
          expiresInSeconds: Math.floor(CLI_FLOW_TTL_MS / 1000),
          pollIntervalSeconds: MIN_CLI_POLL_INTERVAL_SECONDS,
        };
      }),
    )
    .handle("cliVerify", ({ request, query }) =>
      Effect.gen(function* () {
        const env = yield* WorkerEnv;
        // vsig・期限の無状態検証(§4-1 (3))。失敗は GitHub へのリダイレクトが
        // 起きる前に一様エラーページで終了(でっち上げの flowId のために OAuth
        // ダンスを走らせない — fail-closed)。未設定サーバーも同じページ(start が
        // 503 で先に落ちるため、ここへの到達は URL の捏造か設定の喪失)
        const configured = yield* ensureGitHubOAuthConfigured(
          env.GITHUB_CLIENT_ID,
          env.GITHUB_CLIENT_SECRET,
        ).pipe(Effect.option);
        if (Option.isNone(configured)) {
          return uniformErrorPage();
        }
        const key = yield* flowSigningKey;
        const params = yield* Effect.promise(() => verifyCliVerifyQuery(key, query, Date.now()));
        if (params === null || query.vsig === undefined) {
          return uniformErrorPage();
        }
        // §3 の 1 段目(state 発行 → GitHub authorize へ 302)。state は
        // `cli.` プレフィックスで callback に CLI 分岐を伝え、クッキーには
        // state + vsig 済みパラメータ一式(flow 束縛)を運ぶ
        const state = `${CLI_STATE_PREFIX}${randomHex(16)}`;
        const bound = verificationQuery(params, query.vsig);
        bound.set("state", state);
        return yield* redirectToGitHubAuthorize(request, env.GITHUB_CLIENT_ID, state, {
          name: CLI_STATE_COOKIE,
          value: bound.toString(),
        });
      }),
    )
    .handle("cliApprove", ({ payload }) =>
      Effect.gen(function* () {
        // 資格は承認チケットのみ(§4-1 (4) — セッションではない)。欠落・不明な
        // decision は一様エラーページ(§4-2 — チケット照合と出し分けない)
        const { flowId, ticket, decision } = payload;
        if (
          flowId === undefined ||
          ticket === undefined ||
          (decision !== "approve" && decision !== "deny")
        ) {
          return uniformErrorPage();
        }
        const ticketHash = yield* Effect.promise(() => sha256Hex(ticket));
        const flows = yield* CliFlowRepo;
        // awaiting → approved | denied の CAS。資格は最新 1 枚のチケット(不明・
        // 期限切れ・使用済みは一様に false)。承認の auth.login_succeeded
        // (authMethod cli_handoff)は CAS と同一 batch で記録される(repos)
        const decided = yield* flows.decideCas(
          flowId,
          ticketHash,
          decision === "approve" ? "approved" : "denied",
          Date.now(),
        );
        if (!decided) {
          return uniformErrorPage();
        }
        if (decision === "deny") {
          return htmlResponse(renderDeniedPage(), 200);
        }
        // CAS 成功直後の行は必ず存在する(削除は期限 + 余裕後のみ)。表示用の
        // userCode を引く(承認ページと同じ照合コードを完了ページにも見せる)
        const row = yield* flows.findById(flowId);
        return htmlResponse(renderApprovedPage(row === null ? "" : row.userCode), 200);
      }),
    )
    .handle("cliPoll", ({ payload, request }) =>
      Effect.gen(function* () {
        const env = yield* WorkerEnv;
        const allowed = yield* ipRateLimitAllowed(env.CLI_POLL_RATE_LIMIT, request);
        if (!allowed) {
          return yield* Effect.fail(
            new AuthRateLimitedError({ retryAfterSeconds: IP_RATE_LIMIT_PERIOD_SECONDS }),
          );
        }
        // 無状態検証(§4-1 (5)): MAC・期限・署名内 flowId と提示 flowId の
        // 組一致。invalid = 一様拒否(組み替え・改竄 — 資格不一致)、expired =
        // 正当な保持者への型付き終了指示(§4-2)
        const key = yield* flowSigningKey;
        const verdict = yield* Effect.promise(() =>
          verifyFlowToken(key, payload.flowId, payload.flowToken, Date.now()),
        );
        if (verdict === "invalid") {
          return yield* Effect.fail(new CliFlowRejectedError());
        }
        if (verdict === "expired") {
          return yield* Effect.fail(new CliFlowExpiredError());
        }
        const flows = yield* CliFlowRepo;
        const row = yield* flows.findById(payload.flowId);
        // 行なし = ブラウザ脚が未到達なだけ(無記録 start の正常系 — §4-1 (5))
        if (row === null || row.status === "awaiting") {
          return { status: "pending" as const };
        }
        if (row.status === "denied") {
          return { status: "denied" as const };
        }
        if (row.status === "consumed") {
          // 単回発行済みフローへの再 poll(CAS 敗者と同じ一様拒否 — §4-2)
          return yield* Effect.fail(new CliFlowRejectedError());
        }
        // approved: consumed への CAS 勝者だけが発行する(単回 = 二重配布の
        // 構造的排除。flowToken は 1 プロセスに束縛されない bearer であり並行
        // poll は想定内の入力)。CAS 成功後の発行失敗は consumed のまま終わる
        // (fail-closed — 半配布を残さない。CLI は再ログインする)
        const won = yield* flows.consumeCas(payload.flowId);
        if (!won) {
          return yield* Effect.fail(new CliFlowRejectedError());
        }
        const tokens = yield* TokenService;
        // §6 の発行(同名ローテーション・発行上限・auth.token_created 監査 —
        // すべて既存規律のまま)。発行パラメータは行の保持値
        const ttlMs = row.expiresInDays * 24 * 60 * 60 * 1000;
        const issued = yield* tokens
          .issueToken(row.userId, row.tokenName, row.scopes, ttlMs)
          .pipe(
            Effect.catchTag("TokenLimitReached", (error) =>
              Effect.fail(new TokenLimitError({ limit: error.limit })),
            ),
          );
        return {
          status: "approved" as const,
          token: issued.rawToken,
          tokenId: issued.tokenId,
          userId: row.userId,
          expiresAtMs: issued.expiresAtMs,
        };
      }),
    ),
);
