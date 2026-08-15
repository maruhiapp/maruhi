// テスト用の OIDC issuer(AUTH_SPEC §14-1)のフェイク資材。
//
// vitest.config.ts の outboundService(Node 側)と、workerd 側のテストコードの
// **両方**から読む共有モジュール。前者は discovery / JWKS を配信し、後者は同じ
// 鍵でトークンに署名する — 両側で同じ鍵素材を参照する必要があるため、
// 鍵は固定値としてここに置く。
//
// **鍵はこのテスト専用に生成した使い捨てのダミー**であり、いかなる実環境でも
// 使われない(リポジトリに本物のシークレットを置かない — CLAUDE.md)。
// 実ネットワークへは出ない: 想定外の宛先は outboundService が 500 で落とす。

/** v1 の対応 issuer(src/oidc.package/verifier.ts の SUPPORTED_ISSUERS と一致)。 */
export const OIDC_ISSUER = "https://token.actions.githubusercontent.com";

export const OIDC_KID = "test-key-1";

/** JWKS が配信する公開鍵(ES256 / P-256)。 */
const OIDC_PUBLIC_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "iNfHA_z5to4xNsQixaDJraQDztajJHGeMpfnURO-Neg",
  y: "30E8jN4fba7AKUMLv5XuXorD3QHqAJI-l8_BnMKy0aY",
  use: "sig",
  alg: "ES256",
  kid: OIDC_KID,
} as const;

/** 同じ鍵の秘密側(テストがトークンに署名するためだけに使う)。 */
export const OIDC_PRIVATE_JWK = {
  ...OIDC_PUBLIC_JWK,
  d: "mIuIyT-VxYQPpQMi0zwtrO_1sSATkC633euZ0SrkGBU",
  key_ops: ["sign"],
} as const;

/** discovery ドキュメント(§14-1: issuer の自己申告と jwks_uri の同一オリジン)。 */
export const OIDC_DISCOVERY = {
  issuer: OIDC_ISSUER,
  jwks_uri: `${OIDC_ISSUER}/.well-known/jwks`,
} as const;

export const OIDC_JWKS = { keys: [OIDC_PUBLIC_JWK] } as const;

function body(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * outboundService から呼ぶルーター(issuer 宛でなければ null — 呼び出し側が
 * 他のフェイクへ回す)。**正常応答のみ**を返す: 取得失敗側(fail-closed と
 * 503 `oidc-jwks-unavailable`)は fetch を差し替える単体テスト
 * (test/oidc.test.ts)が検査する — outboundService は Node 側で動くため
 * workerd 側のテストから状態を切り替えられない。
 */
export function fakeOidcIssuer(url: URL): Response | null {
  if (url.origin !== new URL(OIDC_ISSUER).origin) {
    return null;
  }
  if (url.pathname === "/.well-known/openid-configuration") {
    return body(OIDC_DISCOVERY);
  }
  if (url.pathname === "/.well-known/jwks") {
    return body(OIDC_JWKS);
  }
  return new Response(`unexpected issuer path in tests: ${url.pathname}`, { status: 500 });
}
