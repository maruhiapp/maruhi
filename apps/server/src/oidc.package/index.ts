// oidc.package の公開面(ImportLint 境界)。
//
// AUTH_SPEC §14-1 の認証段(OIDC トークンの検証)だけをここに閉じる。
// base64url デコード・JWK → WebCrypto の写像・JWKS キャッシュの内部は
// 境界内に留め、外からは「トークン → 検証済み claim」の 1 操作に見せる。
//
// 認可(lease_policy との突合)はここに置かない: 認証と認可を実装単位で
// 分けることが、§14-3 の「認証失敗のみ 401 / 認可失敗は一律 404」を
// 構造として保証する。

export { makeJwksCache } from "./jwks.ts";
export { makeOidcVerifier, OidcVerifier, type VerifiedOidcToken } from "./verifier.ts";
