// GitHub Actions の OIDC トークン取得と claims 読み出し(AUTH_SPEC §14-1 の
// クライアント側 — v1 の対応 issuer は GitHub Actions のみ)。
//
// トークンはベアラー資格情報であり、平文値・鍵素材と同じ扱いにする:
// `Redacted` で包み、ログ・エラー・診断に出さない(CLAUDE.md)。剥がすのは
// claims 読み出し(本ファイル)と lease リクエストの payload 組み立て
// (ci-run.ts)の 2 か所のみ(redacted.test.ts の棚卸しに登録)。
//
// claims の読み出しは base64url decode + JSON.parse で足りる: 署名検証は
// サーバーの仕事(AUTH_SPEC §14-1)で、クライアントは**自分の**トークンから
// iss / sub / aud を読んで claims_digest(CRYPTO_SPEC §9.1)を独立計算する
// だけである。JWT ライブラリは足さない(新規依存を増やさない)。
//
// ランナー供給の環境変数は `CliIo.envVar`(Effect サービス境界)経由で読む —
// `process.env` を直接読まない(CLAUDE.md。本番実装は live.ts、テストは
// 差し替え Map)。将来の事前発行型 issuer(GitLab / k8s の projected volume)は
// このモジュールの差し替えで対応する(検証・開封層は lease-client.ts のまま)。

import type { LeaseClaims } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { isLoopbackHostname } from "./session.ts";

/** GitHub Actions ランナーが供給する OIDC 発行エンドポイントの環境変数。 */
export const OIDC_REQUEST_URL_ENV = "ACTIONS_ID_TOKEN_REQUEST_URL";
export const OIDC_REQUEST_TOKEN_ENV = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";

/** OIDC 発行エンドポイントが無い実行への案内(要件をその場で言う)。 */
const OIDC_ENV_MISSING_MESSAGE =
  "The GitHub Actions OIDC endpoint is not available. Run this inside a GitHub Actions job, and grant the job `permissions: id-token: write` (both ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN must be set)";

/** ランナー供給の発行エンドポイント(欠落・空はどちらも「無い」)。 */
function readIssuanceEndpoint(io: {
  readonly envVar: (name: string) => string | undefined;
}): { readonly requestUrl: string; readonly requestToken: string } | null {
  const requestUrl = io.envVar(OIDC_REQUEST_URL_ENV);
  // ランナートークンもベアラー資格情報だが、このモジュールのローカルにのみ
  // 存在し直後のヘッダーで消費される(モジュール境界を渡らないため包まない)。
  // ログ・エラーには出さない
  const requestToken = io.envVar(OIDC_REQUEST_TOKEN_ENV);
  if (
    requestUrl === undefined ||
    requestUrl.length === 0 ||
    requestToken === undefined ||
    requestToken.length === 0
  ) {
    return null;
  }
  return { requestUrl, requestToken };
}

/**
 * 発行エンドポイント URL の検証(M1)と audience パラメータの付与。`https:`
 * 以外・埋め込み資格情報・パース不能は null(呼び出し元が型付きエラーにする)。
 */
function validatedIssuanceUrl(requestUrl: string, audience: string): string | null {
  let url: URL;
  try {
    url = new URL(requestUrl);
  } catch {
    return null;
  }
  // `http:` は loopback のみ許す(テスト・ローカルモック用 — 平文がネットワークを
  // 渡らない)。それ以外は `https:` 必須。loopback 判定は CLI 共通の
  // isLoopbackHostname(session.ts)— IPv4 リテラル厳密検査で "127.evil.com" の
  // ような公開 DNS 名は通らない(レビューループ 1)
  const schemeOk =
    url.protocol === "https:" || (url.protocol === "http:" && isLoopbackHostname(url.hostname));
  if (!schemeOk || url.username !== "" || url.password !== "") {
    return null;
  }
  url.searchParams.set("audience", audience);
  return url.toString();
}

/** 発行エンドポイント応答(`{ value }`)からのトークン取り出し。 */
function tokenOfIssuanceBody(body: unknown): string | null {
  const value =
    typeof body === "object" && body !== null
      ? (body as Record<string, unknown>)["value"]
      : undefined;
  return typeof value === "string" && value.length > 0 ? value : null;
}

/**
 * Fetches a fresh GitHub Actions OIDC token for `audience`.
 *
 * トークンは lease 要求の**直前**に発行する(session-24 §8 SHOULD — 先着束縛の
 * 露出窓の最小化)。呼び出しごとに新規発行なので、`token-replayed` の再試行
 * (ci-run.ts)はこの関数をもう一度呼ぶだけでよい。
 */
export function fetchGitHubOidcToken(
  audience: string,
): Effect.Effect<Redacted.Redacted<string>, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const endpoint = readIssuanceEndpoint(io);
    if (endpoint === null) {
      return yield* Effect.fail(cliError(OIDC_ENV_MISSING_MESSAGE));
    }
    // ランナートークン(bearer 資格情報)を送る前に URL を検証する(deepsec M1):
    // `https:` 以外(平文 http・独自スキーム)と埋め込み資格情報を拒否する。
    // ホストは固定しない — GitHub Hosted Runner のホストは固定名でなく、GHES は
    // 任意ホストであるため、許可リストは正当な実行を壊すだけで攻撃(環境変数を
    // 差し替えられる立場 = 既にジョブ定義を書ける立場)を増やさない
    const url = validatedIssuanceUrl(endpoint.requestUrl, audience);
    if (url === null) {
      return yield* Effect.fail(
        cliError(
          "ACTIONS_ID_TOKEN_REQUEST_URL is not a valid https: URL, so the runner's bearer token will not be sent to it (check the runner environment)",
        ),
      );
    }
    const body = yield* Effect.tryPromise({
      try: async () => {
        // redirect は追従しない(M1): 既定の follow は bearer ヘッダー付きの
        // リクエストをリダイレクト先へ再送しうる。3xx は !ok として失敗に落ちる
        const response = await fetch(url, {
          method: "GET",
          redirect: "manual",
          headers: {
            accept: "application/json",
            authorization: `Bearer ${endpoint.requestToken}`,
            "user-agent": "maruhi-cli",
          },
        });
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        // JSON.parse の例外はここで飲む(守られたパース):
        // parse エラーの message は応答本文の断片を含み、この応答の本文は
        // トークンの運搬路である。素通しにせず「解釈できない」へ畳む
        const text = await response.text();
        try {
          return JSON.parse(text) as unknown;
        } catch {
          return null;
        }
      },
      catch: (error) =>
        cliError(
          `Failed to fetch the GitHub Actions OIDC token (check the runner's network): ${
            error instanceof Error ? error.message : String(error)
          }`,
        ),
    });
    const value = tokenOfIssuanceBody(body);
    if (value === null) {
      return yield* Effect.fail(
        cliError("Cannot interpret the OIDC token response from the GitHub Actions runner"),
      );
    }
    // 環境の外から届いた素の string はここで包む。以降トークンは Redacted と
    // してしか流れない(剥がすのは claims 読み出しと lease payload の 2 か所)
    return Redacted.make(value, { label: "oidc-token" });
  });
}

/** base64url → bytes(不正なら null。トークン断片を例外文面に載せない)。 */
function decodeBase64Url(segment: string): Uint8Array | null {
  const base64 = segment.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    return null;
  }
}

const CLAIM_FAILURE_MESSAGES = {
  malformed:
    "Cannot read the OIDC token's claims (the token is not a compact JWS with a JSON payload)",
  "multiple-audiences":
    "The OIDC token carries multiple audiences, so it cannot be used for a lease (the claims digest is not uniquely determined). Request the token with exactly one audience",
  "missing-claim":
    "The OIDC token is missing a claim the lease needs (iss / sub / aud must be non-empty)",
} as const;

type ClaimsFailure = keyof typeof CLAIM_FAILURE_MESSAGES;

/** compact JWS の payload セグメント → JSON 値(不正なら null)。 */
function decodeTokenPayload(raw: string): unknown | null {
  const segments = raw.split(".");
  const payloadSegment = segments[1];
  if (segments.length !== 3 || payloadSegment === undefined) {
    return null;
  }
  const payloadBytes = decodeBase64Url(payloadSegment);
  if (payloadBytes === null) {
    return null;
  }
  try {
    const payload: unknown = JSON.parse(new TextDecoder().decode(payloadBytes));
    return typeof payload === "object" && payload !== null ? payload : null;
  } catch {
    return null;
  }
}

/** payload → リースが束縛する 3 claim(不正なら理由コード)。 */
function claimsOfPayload(payload: unknown | null): LeaseClaims | ClaimsFailure {
  if (payload === null) {
    return "malformed";
  }
  const record = payload as Record<string, unknown>;
  const issuerUrl = record["iss"];
  const subject = record["sub"];
  const audience = singleAudience(record["aud"]);
  if (audience === "multiple") {
    return "multiple-audiences";
  }
  if (
    typeof issuerUrl !== "string" ||
    issuerUrl.length === 0 ||
    typeof subject !== "string" ||
    subject.length === 0 ||
    audience === null
  ) {
    return "missing-claim";
  }
  return { issuerUrl, subject, audience };
}

/**
 * Reads the claims the lease path binds (CRYPTO_SPEC §9.1: issuer / sub /
 * aud) from the workload's own token. The digest itself is computed by
 * `computeLeaseClaimsDigest` — never from the raw builder (security review
 * A-5: the builder skips the empty-field guard).
 *
 * `aud` が複数のトークンは拒否する: claims_digest が一意に決まらず、サーバーも
 * 同じ理由で `ambiguous-audience` として拒否する(errors/lease.ts)。往復する
 * 前にクライアント側で同じ判定を出す。
 */
export function readLeaseClaims(
  token: Redacted.Redacted<string>,
): Effect.Effect<LeaseClaims, CliError> {
  // 剥がす理由: 自トークンの claims 読み出し(payload セグメントの decode)。
  // 産物は iss / sub / aud の 3 文字列だけで、トークン本体は外へ出ない
  const outcome = claimsOfPayload(decodeTokenPayload(Redacted.value(token)));
  if (typeof outcome === "string") {
    return Effect.fail(cliError(CLAIM_FAILURE_MESSAGES[outcome]));
  }
  return Effect.succeed(outcome);
}

/** `aud` claim の単一値の取り出し(単一文字列 | 要素 1 の配列のみ受理)。 */
function singleAudience(value: unknown): string | null | "multiple" {
  if (typeof value === "string") {
    return value.length > 0 ? value : null;
  }
  if (Array.isArray(value)) {
    if (value.length > 1) {
      return "multiple";
    }
    const only: unknown = value[0];
    return typeof only === "string" && only.length > 0 ? only : null;
  }
  return null;
}
