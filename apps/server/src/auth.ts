// API リクエスト認証の Effect サービス境界(AUTH_SPEC §8 に沿って切る)。
//
// 認証の本実装は認証セッション(AUTH_SPEC)で行う。ここではサービスの「形」だけを
// 確定し、後から SessionService / TokenService の実装が同じ境界に結線される。
//
// 既知の制約(スタブ期間中。docs/notes/session-05.md にも明記):
//   クライアントの身元申告は信用しない。追記 API の保護は現状チェーン署名の
//   検証(CRYPTO_SPEC §6.4)のみであり、リクエスト主体の認証は行われない。
//
// テスト用スタブは apps/server/test/support/auth-stub.ts にのみ置く。本番エントリ
// (src/index.ts)のモジュールグラフからは到達不能で、バンドルに混入しない
// (混入防止の構造はモジュールグラフ分離 — セッション 05 裁定)。

import { Context, Effect } from "effect";

/** リクエストの解決済み主体。認証実装後は user 側が実際に返るようになる。 */
export type Principal =
  | { readonly kind: "anonymous" }
  | { readonly kind: "user"; readonly userId: string };

export const anonymousPrincipal: Principal = { kind: "anonymous" };

/** AUTH_SPEC §8: セッションの発行・検証・失効(検証面のみ先行定義)。 */
export interface SessionServiceShape {
  /** セッション ID(クッキー生値)から主体を解決する。失敗は匿名として扱う。 */
  readonly resolveSession: (sessionId: string) => Effect.Effect<Principal>;
}

export class SessionService extends Context.Service<SessionService, SessionServiceShape>()(
  "SessionService",
) {}

/** AUTH_SPEC §8: API トークンの検証・スコープ判定(検証面のみ先行定義)。 */
export interface TokenServiceShape {
  /** `maruhi_pat_…` トークンから主体を解決する。失敗は匿名として扱う。 */
  readonly resolveApiToken: (token: string) => Effect.Effect<Principal>;
}

export class TokenService extends Context.Service<TokenService, TokenServiceShape>()(
  "TokenService",
) {}

/** ハンドラが要求する境界: リクエスト主体の解決。 */
export interface RequestAuthShape {
  readonly principal: Effect.Effect<Principal>;
}

export class RequestAuth extends Context.Service<RequestAuth, RequestAuthShape>()("RequestAuth") {}

/**
 * 本番プレースホルダ(テスト用スタブではない): 認証未実装の現状を明示的に表す。
 * すべてのリクエストを匿名として解決する。認証セッションで SessionService /
 * TokenService を合成する実装に置き換わる。
 */
export const unauthenticatedRequestAuth: RequestAuthShape = {
  principal: Effect.succeed(anonymousPrincipal),
};
