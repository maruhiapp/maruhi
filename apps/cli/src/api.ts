// api-schema からの型付きクライアント導出(ADR-0005 の「スキーマ定義から
// 型付きクライアントを自動導出」の実装点)。
//
// 認証は Authorization: Bearer ヘッダー(AUTH_SPEC §6)。トークンはリクエスト
// ヘッダーにのみ乗り、ログ・エラーへは出さない。

import { maruhiApi } from "@maruhi/api-schema";
import type { Effect, Redacted } from "effect";
import { HttpClient, HttpClientRequest } from "effect/unstable/http";
import { HttpApiClient } from "effect/unstable/httpapi";

/** The typed maruhi API client derived from {@link maruhiApi}. */
export type MaruhiClient = HttpApiClient.ForApi<typeof maruhiApi>;

/**
 * Derives the typed client. `token` is attached as a Bearer header when
 * present (authConfig and the CLI login handoff — cliStart / cliPoll — are
 * the only unauthenticated calls the CLI makes).
 *
 * 上流の `bearerToken` は `Redacted` をそのまま受ける(ヘッダー組み立ての
 * 内側で剥がす)ため、CLI 側に剥がす箇所を作らずに済む — 手書きの
 * Authorization ヘッダー(テンプレート展開)は伏字をそのまま送ってしまう形
 * なので使わない。
 */
export function makeApiClient(options: {
  readonly baseUrl: string;
  readonly token?: Redacted.Redacted<string>;
}): Effect.Effect<MaruhiClient, never, HttpClient.HttpClient> {
  const token = options.token;
  return HttpApiClient.make(maruhiApi, {
    baseUrl: options.baseUrl,
    transformClient:
      token === undefined ? undefined : HttpClient.mapRequest(HttpClientRequest.bearerToken(token)),
  });
}
