// lease_policy の評価(AUTH_SPEC §14-1 の認可段)。
//
// **認可の真実源はチェーン**(CRYPTO_SPEC §9.1): どのワークロードがリースを
// 受けられるかは grant_server payload の lease_policy であり、サーバー可変の
// 設定ではない。ここにあるのは「構造(合意規則)に対する評価意味論」だけで、
// チェーン形式には触れない(§6.2 の構造 / 意味論の分離 — 評価の拡張は
// AUTH_SPEC §14 の改訂で行い、grandfathering を要さない)。
//
// 判定は**存在量化**(§14-1。2026-08-12 レビュー反映): 一致する要素が 1 つでも
// あれば認可する。「一致する要素を選ぶ」形にすると複数要素一致時の選定が
// 非決定になり、どの要素が一致したかは認可結果にもリースラップにも影響しない
// (claims_digest はトークンの issuer / sub / aud から計算され、要素の同定に
// 依存しない)。

import type { LeasePolicyIssuer, ServerGrant } from "@maruhi/crypto";

import type { VerifiedOidcToken } from "./oidc.package/index.ts";

/**
 * ポリシー評価が読むトークンの部分。VerifiedOidcToken(worker 側)と RPC の
 * LeaseTokenFacts(DO 側)の共通部分であり、評価が時刻系フィールドに依存
 * しないこと(時刻検証は認証段で完了済み — §14-1)を型で固定する。
 */
type PolicyEvaluationToken = Pick<VerifiedOidcToken, "issuer" | "audiences" | "claims">;

/**
 * claim 制約 1 件の評価(v1 = 完全一致のみ — §14-1)。
 *
 * **文字列以外の claim 値は決して一致しない**: 数値・真偽・配列を文字列へ
 * 型強制すると、`1` と `"1"`、`["a"]` と `"a"` のような別物が同一視され、
 * 認可を広げる方向の驚きを生む。制約に列挙された claim のみ評価し、列挙外の
 * claim は関与しない(§14-1)。
 */
function claimMatches(
  claims: Readonly<Record<string, unknown>>,
  constraint: { readonly claimName: string; readonly claimValue: string },
): boolean {
  const value = claims[constraint.claimName];
  return typeof value === "string" && value === constraint.claimValue;
}

/**
 * lease_policy 要素 1 件の評価: issuer_url がトークンの issuer と一致し、
 * audience がトークンの `aud` に含まれ、claim_constraints の**すべて**が
 * 完全一致すること。
 *
 * `aud` の包含判定(一致ではなく contains)は、RFC 7519 が `aud` に配列を
 * 許すため。単一文字列の `aud` は verifier が 1 要素配列へ正規化しており、
 * その場合この判定は完全一致に退化する。
 */
function elementMatches(element: LeasePolicyIssuer, token: PolicyEvaluationToken): boolean {
  return (
    element.issuerUrl === token.issuer &&
    token.audiences.includes(element.audience) &&
    element.claimConstraints.every((constraint) => claimMatches(token.claims, constraint))
  );
}

/**
 * 存在量化による認可判定(§14-1)。空 lease_policy は「リース経路なし」を
 * 意味するため常に false になる(その grant はサーバー鍵宛ラップの登録のみを
 * 許す — CRYPTO_SPEC §6.2)。
 */
export function leasePolicyAuthorizes(grant: ServerGrant, token: PolicyEvaluationToken): boolean {
  return grant.leasePolicy.some((element) => elementMatches(element, token));
}

/** 開示スコープ(scope_environments)に対象環境が含まれるか(§14-1)。 */
export function grantCoversEnvironment(grant: ServerGrant, environmentId: string): boolean {
  return grant.scopeEnvironmentIds.includes(environmentId);
}
