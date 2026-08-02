// 開発・テスト用の認証スタブ(AUTH_SPEC §8 境界のスタブ実装)。
//
// 混入防止(セッション 05 裁定: モジュールグラフ分離): このファイルは test/ 配下に
// あり、本番エントリ(src/index.ts)の import グラフから到達できない。wrangler の
// バンドルは src/index.ts を起点とするため、スタブが本番ビルドに含まれる経路は
// 構造的に存在しない。スタブを src/ 配下へ移動してはならない。

import { Effect } from "effect";

import type {
  Principal,
  RequestAuthShape,
  SessionServiceShape,
  TokenServiceShape,
} from "../../src/auth.ts";

/** テスト用の認証済み主体を作る。 */
export const stubUserPrincipal = (userId: string): Principal => ({ kind: "user", userId });

/** 常に固定の主体を返す RequestAuth スタブ。 */
export const stubRequestAuth = (principal: Principal): RequestAuthShape => ({
  principal: Effect.succeed(principal),
});

/** 常に固定の主体を返す SessionService スタブ。 */
export const stubSessionService = (principal: Principal): SessionServiceShape => ({
  resolveSession: () => Effect.succeed(principal),
});

/** 常に固定の主体を返す TokenService スタブ。 */
export const stubTokenService = (principal: Principal): TokenServiceShape => ({
  resolveApiToken: () => Effect.succeed(principal),
});
