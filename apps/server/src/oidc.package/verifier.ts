// OIDC トークン検証(AUTH_SPEC §14-1 の認証段)。
//
// **検証はここで完結し、チェーン導出状態(grant・lease_policy)を一切参照
// しない**(§14-1)。ポリシーとの突合は認可であり、リースプログラム側に属する。
// この分離が「認証失敗のみ 401 / 認可失敗は一律 404」(§14-3 の存在秘匿)を
// 実装構造として保証する。
//
// 判定順(すべてトークン単体で完結し、プロジェクト状態を一切読まない):
//   1. 形式(compact JWS の 3 セグメント・JSON ヘッダー / ペイロード)
//   2. `alg` が許可リスト(RS256 / ES256)内
//   3. `iss` が**静的な対応 issuer 一覧**内 — **外部 fetch より前**。未認証
//      エンドポイントから任意 URL の取得を誘発できないようにするため
//   4. JWKS の解決(取得失敗は 503。§14-1 の fail-closed)と署名検証
//   5. 必須 claim の存在と時刻検証(clock skew ±60 秒)

import { LeaseUnauthorizedError, LeaseUnavailableError } from "@maruhi/api-schema";
import { Context, Effect } from "effect";

import { decodeBase64Url, decodeBase64UrlJson } from "./base64url.ts";
import type { AllowedAlg } from "./jwk.ts";
import { verifyJwsSignature } from "./jwk.ts";
import { type JwksCacheShape, makeJwksCache } from "./jwks.ts";

/**
 * 対応 issuer 一覧(§14-1): **デプロイメント全体で一様な静的設定**であり、
 * プロジェクトの存在・状態情報を運ばない。v1 は GitHub Actions のみ
 * (session-22 §2 R1 の「v1 の有効化は GitHub のみ」)。GitLab / CircleCI /
 * k8s 等の追加はここへの追記だけで済み、チェーン形式(grant_server payload の
 * issuer 汎用 lease_policy)は変更を要さない。
 */
const SUPPORTED_ISSUERS: readonly string[] = ["https://token.actions.githubusercontent.com"];

/** 許可アルゴリズム(§14-1)。対称鍵 alg と `none` はここに無い。 */
const ALLOWED_ALGS: readonly AllowedAlg[] = ["RS256", "ES256"];

/** 時刻検証の許容ずれ(§14-1: ±60 秒)。 */
const CLOCK_SKEW_MS = 60 * 1000;

/**
 * 検証済みトークンのうち、リース経路が使う値だけを取り出したもの。
 * `claims` は claim 制約の評価(§14-1 の存在量化)に使う生の payload で、
 * **監査にも応答にも出さない**(外部識別子を持ち込まない — §14-4)。
 */
export interface VerifiedOidcToken {
  readonly issuer: string;
  readonly subject: string;
  /** `aud` は文字列 / 配列の両形を取るため、常に配列へ正規化する。 */
  readonly audiences: readonly string[];
  readonly claims: Readonly<Record<string, unknown>>;
}

export interface OidcVerifierShape {
  readonly verify: (
    token: string,
    nowMs: number,
  ) => Effect.Effect<VerifiedOidcToken, LeaseUnauthorizedError | LeaseUnavailableError>;
}

export class OidcVerifier extends Context.Service<OidcVerifier, OidcVerifierShape>()(
  "OidcVerifier",
) {}

const unauthorized = (reason: LeaseUnauthorizedError["reason"]) =>
  Effect.fail(new LeaseUnauthorizedError({ reason }));

function asRecord(value: unknown): Readonly<Record<string, unknown>> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringClaim(claims: Readonly<Record<string, unknown>>, name: string): string | null {
  const value = claims[name];
  return typeof value === "string" && value.length > 0 ? value : null;
}

/** 数値 claim(`exp` / `iat` / `nbf`)は秒単位の有限数のみ受ける。 */
function numericClaim(claims: Readonly<Record<string, unknown>>, name: string): number | null {
  const value = claims[name];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/** `aud` は文字列 / 文字列配列(RFC 7519)。それ以外は claim 不備として扱う。 */
function audiencesOf(claims: Readonly<Record<string, unknown>>): readonly string[] | null {
  const value = claims["aud"];
  if (typeof value === "string") {
    return value.length > 0 ? [value] : null;
  }
  if (Array.isArray(value) && value.length > 0 && value.every((a) => typeof a === "string")) {
    return value as readonly string[];
  }
  return null;
}

interface ParsedToken {
  readonly alg: AllowedAlg;
  readonly kid: string | null;
  readonly claims: Readonly<Record<string, unknown>>;
  readonly signature: Uint8Array;
  readonly signingInput: Uint8Array;
}

/** デコード済みの 3 セグメント(形は満たすが中身は未検査)。 */
interface DecodedSegments {
  readonly header: Readonly<Record<string, unknown>>;
  readonly claims: Readonly<Record<string, unknown>>;
  readonly signature: Uint8Array;
  readonly signingInput: Uint8Array;
}

/**
 * compact JWS の 3 セグメントをデコードする(段 1)。署名対象は**受け取った
 * segment 文字列そのもの**(`header.payload`)であり、デコード → 再直列化した
 * 値ではない(再直列化はバイト列を変え、署名検証を無意味にする)。
 */
function decodeSegments(token: string): DecodedSegments | null {
  const segments = token.split(".");
  if (segments.length !== 3) {
    return null;
  }
  const [headerSegment, payloadSegment, signatureSegment] = segments;
  if (
    headerSegment === undefined ||
    payloadSegment === undefined ||
    signatureSegment === undefined
  ) {
    return null;
  }
  const header = asRecord(decodeBase64UrlJson(headerSegment));
  const claims = asRecord(decodeBase64UrlJson(payloadSegment));
  const signature = decodeBase64Url(signatureSegment);
  if (header === null || claims === null || signature === null) {
    return null;
  }
  return {
    header,
    claims,
    signature,
    signingInput: new TextEncoder().encode(`${headerSegment}.${payloadSegment}`),
  };
}

/** 形式と `alg` 許可リストの検査(段 1〜2)。 */
function parseToken(token: string): Effect.Effect<ParsedToken, LeaseUnauthorizedError> {
  const decoded = decodeSegments(token);
  if (decoded === null) {
    return unauthorized("malformed-token");
  }
  const alg = decoded.header["alg"];
  if (typeof alg !== "string" || !ALLOWED_ALGS.includes(alg as AllowedAlg)) {
    return unauthorized("unsupported-alg");
  }
  const kid = decoded.header["kid"];
  return Effect.succeed({
    alg: alg as AllowedAlg,
    kid: typeof kid === "string" ? kid : null,
    claims: decoded.claims,
    signature: decoded.signature,
    signingInput: decoded.signingInput,
  });
}

/** 時刻検証(段 5。§14-1: clock skew ±60 秒)。 */
function checkTimes(
  claims: Readonly<Record<string, unknown>>,
  nowMs: number,
): Effect.Effect<void, LeaseUnauthorizedError> {
  const exp = numericClaim(claims, "exp");
  const iat = numericClaim(claims, "iat");
  // exp / iat はともに必須(§14-1 の (3))。欠けたトークンは無期限に使える
  // 資格情報になりうるため、寛容側に倒さない
  if (exp === null || iat === null) {
    return unauthorized("missing-claim");
  }
  if (exp * 1000 + CLOCK_SKEW_MS <= nowMs) {
    return unauthorized("token-expired");
  }
  if (iat * 1000 - CLOCK_SKEW_MS > nowMs) {
    return unauthorized("token-not-yet-valid");
  }
  const nbf = numericClaim(claims, "nbf");
  if (nbf !== null && nbf * 1000 - CLOCK_SKEW_MS > nowMs) {
    return unauthorized("token-not-yet-valid");
  }
  return Effect.void;
}

/**
 * OIDC verifier(isolate 単位で 1 つ。JWKS キャッシュを閉じ込める)。
 * `jwks` はテストから差し替えられるよう引数に取る。
 */
export function makeOidcVerifier(
  jwks: JwksCacheShape = makeJwksCache(),
  supportedIssuers: readonly string[] = SUPPORTED_ISSUERS,
): OidcVerifierShape {
  return {
    verify: (token, nowMs) =>
      Effect.gen(function* () {
        const parsed = yield* parseToken(token);
        const issuer = stringClaim(parsed.claims, "iss");
        if (issuer === null) {
          return yield* unauthorized("missing-claim");
        }
        // **外部 fetch より前**の許可リスト照合(冒頭コメントの DoS 論拠)
        if (!supportedIssuers.includes(issuer)) {
          return yield* unauthorized("unsupported-issuer");
        }
        const resolved = yield* jwks.resolveKey(issuer, parsed.kid).pipe(
          // 取得失敗は fail-closed(§14-1)だが 401 ではなく 503:
          // 一過性の issuer / ネットワーク障害を「資格情報が不正」と伝えると
          // CI ジョブがリトライ不能な失敗として扱う(errors/lease.ts)
          Effect.mapError(() => new LeaseUnavailableError({ reason: "oidc-jwks-unavailable" })),
        );
        if (resolved === null) {
          return yield* unauthorized("unknown-key");
        }
        // ヘッダーの alg は「JWK から導いた期待値」との一致検査にのみ使う
        // (分岐の入力にしない — jwk.ts の設計)
        if (parsed.alg !== resolved.binding.headerAlg) {
          return yield* unauthorized("unsupported-alg");
        }
        const verified = yield* Effect.promise(() =>
          verifyJwsSignature({
            key: resolved.key,
            binding: resolved.binding,
            signature: parsed.signature,
            signingInput: parsed.signingInput,
          }),
        );
        if (!verified) {
          return yield* unauthorized("signature-invalid");
        }
        yield* checkTimes(parsed.claims, nowMs);
        const subject = stringClaim(parsed.claims, "sub");
        const audiences = audiencesOf(parsed.claims);
        if (subject === null || audiences === null) {
          return yield* unauthorized("missing-claim");
        }
        return { issuer, subject, audiences, claims: parsed.claims };
      }),
  };
}
