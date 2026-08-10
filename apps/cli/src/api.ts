// api-schema からの型付きクライアント導出(ADR-0005 の「スキーマ定義から
// 型付きクライアントを自動導出」の実装点)。
//
// 認証は Authorization: Bearer ヘッダー(AUTH_SPEC §6)。トークンはリクエスト
// ヘッダーにのみ乗り、ログ・エラーへは出さない。

import { maruhiApi } from "@maruhi/api-schema";
import type { Effect } from "effect";
import { HttpClient, HttpClientRequest } from "effect/unstable/http";
import { HttpApiClient } from "effect/unstable/httpapi";

/** The typed maruhi API client derived from {@link maruhiApi}. */
export type MaruhiClient = HttpApiClient.ForApi<typeof maruhiApi>;

/**
 * Derives the typed client. `token` is attached as a Bearer header when
 * present (authConfig and deviceExchange are the only unauthenticated calls
 * the CLI makes).
 */
export function makeApiClient(options: {
  readonly baseUrl: string;
  readonly token?: string;
}): Effect.Effect<MaruhiClient, never, HttpClient.HttpClient> {
  const token = options.token;
  return HttpApiClient.make(maruhiApi, {
    baseUrl: options.baseUrl,
    transformClient:
      token === undefined
        ? undefined
        : HttpClient.mapRequest(HttpClientRequest.setHeader("authorization", `Bearer ${token}`)),
  });
}
