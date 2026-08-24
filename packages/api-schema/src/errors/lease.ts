// ワークロードリース API の型付きエラー(AUTH_SPEC §14-3)。
//
// エラーには理由コードとカウンタしか載せない。OIDC トークンの値・claim・
// リポジトリ名等の外部識別子を運ばないこと(§14-4 / AUDIT_SPEC §1-2 と同じ規律 —
// 監査行に書かないものを応答にも書かない)。
//
// 存在秘匿(§14-1 / §11-2): ポリシー不一致・スコープ外・grant なし・未知
// プロジェクトはすべて 404(ProjectNotFound / EnvironmentNotFound)であり、
// このファイルには現れない。ここにあるのは「認証段の失敗」「発行不能」
// 「窓の枯渇」の 3 つだけである。

import { Schema } from "effect";

/**
 * Reason codes for a rejected OIDC token (AUTH_SPEC §14-1 の認証段).
 *
 * All of these are attributable to the presented token alone and carry no
 * project state, so returning the specific reason keeps existence hiding
 * intact while giving CI jobs something actionable to read in a log.
 *
 * - `malformed-token` — not a compact JWS, or the header / payload is not JSON
 * - `unsupported-alg` — `alg` outside the RS256 / ES256 allowlist (`none` and
 *   the symmetric algorithms land here)
 * - `unsupported-crit` — the JOSE header declares a `crit` extension. RFC 7515
 *   §4.1.11 requires rejecting a JWS whose critical extensions the recipient
 *   does not implement, and this deployment implements none
 * - `unsupported-issuer` — `iss` outside this deployment's static issuer list
 * - `unknown-key` — no JWKS key matches the token's `kid`
 * - `signature-invalid` — the signature does not verify under the JWKS key
 * - `token-expired` — `exp` is in the past (beyond the ±60s skew)
 * - `token-not-yet-valid` — `iat` / `nbf` is in the future (beyond the skew)
 * - `missing-claim` — a claim the lease path requires (`iss` / `sub` / `aud` /
 *   `exp` / `iat`) is absent or not a string
 * - `ambiguous-audience` — the token carries several audiences, so the
 *   `claims_digest` (CRYPTO_SPEC §9.1) is not uniquely determined. Distinct
 *   from `missing-claim`: the `aud` claim *is* present, and an operator
 *   reading the reason code should not go looking for a claim that exists
 * - `token-replayed` — the token was already used to issue a lease to a
 *   *different* ephemeral key (first-use binding — AUTH_SPEC §14-1 の先着束縛,
 *   2026-08-15 裁定). Retrying with the same token never succeeds; a runtime
 *   issuer (GitHub Actions) should mint a fresh token and retry once. Unlike
 *   the other reasons this is checked after authorization (it needs the
 *   project's binding state), which keeps existence hiding intact: only a
 *   caller whose token already matches an on-chain lease policy can reach it
 */
export const LeaseUnauthorizedReasonSchema = Schema.Literals([
  "malformed-token",
  "unsupported-alg",
  "unsupported-crit",
  "unsupported-issuer",
  "unknown-key",
  "signature-invalid",
  "token-expired",
  "token-not-yet-valid",
  "missing-claim",
  "ambiguous-audience",
  "token-replayed",
]);

/**
 * 401: the presented OIDC token cannot be used (AUTH_SPEC §14-1 / §14-3).
 * Everything here is attributable to the presented credential alone —
 * everything about *this project's* grant, policy and scope is 404 (§14-1 の
 * 存在秘匿). `token-replayed` is the one reason produced after authorization
 * (see its note above); it still reveals nothing a policy-matching token
 * holder would not learn from a successful lease.
 */
export class LeaseUnauthorizedError extends Schema.TaggedError<LeaseUnauthorizedError>()(
  "LeaseUnauthorized",
  { reason: LeaseUnauthorizedReasonSchema },
  { httpApiStatus: 401 },
) {}

/**
 * Reason codes for a lease that is authorized but cannot be issued right now
 * (AUTH_SPEC §14-3).
 *
 * - `server-wraps-missing` — the grant is valid and the environment is in
 *   scope, but the epoch DEK has not been re-wrapped to the server key
 *   (CRYPTO_SPEC §7 のローテーション義務が未了)。grant 済みだが再ラップ未了の
 *   状態を不透明な失敗にしないための専用理由(§14-3)
 * - `oidc-jwks-unavailable` — the issuer's JWKS could not be fetched, so the
 *   signature could not be checked at all. Verification stays fail-closed
 *   (§14-1) — this reason only changes *how* the refusal is reported: a
 *   transient issuer / network outage is not the workload's credential being
 *   bad, and a 401 would make CI jobs fail permanently on a retryable
 *   condition (2026-08-15 起草 — §14-3 の 1 行改訂)
 * - `server-key-unconfigured` — this deployment has no `SERVER_ENC_KEY_IKM`
 *   (CRYPTO_SPEC §9)。チェーン上に grant があるのにサーバー鍵が未設定なのは
 *   デプロイ設定の欠落であり、SetupIncomplete と同じ「セットアップへ誘導する」
 *   応答にする(秘密鍵なしでは開封経路が存在しない)
 */
export const LeaseUnavailableReasonSchema = Schema.Literals([
  "server-wraps-missing",
  "oidc-jwks-unavailable",
  "server-key-unconfigured",
]);

/**
 * 503: the lease is authorized but cannot be issued (AUTH_SPEC §14-3).
 * Distinct from 404 on purpose — reaching this response already means the
 * caller matched an on-chain lease policy, so it leaks nothing new.
 */
export class LeaseUnavailableError extends Schema.TaggedError<LeaseUnavailableError>()(
  "LeaseUnavailable",
  { reason: LeaseUnavailableReasonSchema },
  { httpApiStatus: 503 },
) {}

/**
 * Which limit produced a lease 429 (deepsec M5 — 2026-08-24):
 *
 * - `project-window` — the per-project fixed window (AUTH_SPEC §14-3, judged
 *   after authorization to preserve existence hiding)
 * - `source-address` — the request-level per-source-IP limit (judged first in
 *   the handler; independent of any project state, so it leaks nothing).
 *   Remedies differ: the project window drains on its own, while a legitimate
 *   shared-egress fleet hitting the per-IP limit needs the operator to raise
 *   the binding limit (docs/SELF_HOSTING.md)
 */
export const LeaseRateLimitScopeSchema = Schema.Literals(["project-window", "source-address"]);

/**
 * 429: a lease rate limit is exhausted (AUTH_SPEC §14-3)。`retryAfterSeconds`
 * は窓の残り秒数(§13-3 の先例と同型)。`scope` は上記 2 窓の判別
 * (省略時 = 旧サーバー応答 = project-window 相当)。
 *
 * プロジェクト窓の判定は認可の**後**に行う: 先に置くと未認可の呼び出し元にも
 * 429 が返り、「そのプロジェクトは実在する」が漏れる(§11-2 違反)。認可後に
 * 置くことで 429 は正当なワークロードにしか届かず、窓を消費できる主体も
 * 「許可 issuer の有効署名 × ポリシー一致」を満たすものだけになる。
 * source-address 窓はプロジェクト状態と無関係のため認可前でも存在情報を漏らさない。
 */
export class LeaseRateLimitedError extends Schema.TaggedError<LeaseRateLimitedError>()(
  "LeaseRateLimited",
  {
    retryAfterSeconds: Schema.Number,
    scope: Schema.optionalKey(LeaseRateLimitScopeSchema),
  },
  { httpApiStatus: 429 },
) {}
