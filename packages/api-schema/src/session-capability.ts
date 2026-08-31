// セッション主体の能力制限の宣言(AUTH_SPEC §5 — W2b)。
//
// セッションクッキーは XSS に最も晒される資格情報であり(同一オリジンの XSS は
// CSRF ヘッダーも自分で付けられる)、セッション主体が呼べるエンドポイントを
// **肯定列挙**で制限する。列挙外は AuthMiddleware(単一実装点 — apps/server の
// authMiddlewareImpl が本モジュールの述語を参照する)が 403
// `session-not-allowed` で一括拒否する — fail-closed: 新設エンドポイントの
// 既定は「セッション不可」であり、セッションに開くには AUTH_SPEC §5 の許可
// 列挙への追加(仕様改訂)と本リストへの追加を同じ PR で行う。
//
// 実装形は §12-10 (1) の strict 受理と同じ型(エンドポイント契約への宣言
// 焼き込み + ロード時スイープ + 受理経路の固定テスト)。ただし挙動の運搬に
// AST 注釈を使わない — 注釈は check 合成順で無警告失効しうる(session-32 の
// 教訓)ため、宣言は本モジュールの列挙のみを真実源とし、ミドルウェアが
// (group, endpoint) 識別子で直接参照する。実効性(実際に 403 が返る)は
// apps/server/test/session-capability.test.ts の全エンドポイント × 主体種別の
// マトリクス(api-schema のエンドポイント列挙から機械導出)が保証する。

import { AuthMiddleware } from "./auth-middleware.ts";

/**
 * Endpoints a session principal may call (AUTH_SPEC §5 の肯定列挙のうち実装済み
 * 面) — `[group, endpoint]` pairs:
 *
 * - 認証・自己情報系: `auth.me` / `auth.logout` / `auth.recoveryStatus`
 *   (§3 のフロー — githubStart / githubCallback — は未認証面であり本表の外)
 * - 読み取り: チェーン取得(§11)、プロジェクト一覧(§11-5 — W2a)、環境一覧
 *   (§12-4)、メタデータのみ pull(§12-7)、監査読み取り(AUDIT_SPEC §7 —
 *   プロジェクト・invite.*・本人軸)、要ローテーションフラグビュー、
 *   招待一覧(§15-2)
 * - 失効系: 招待の失効(§15-2)、トークンの指定失効(§6 — W3a)
 *
 * トークン一覧(`auth.listTokens` — §6 の読み取り面)もここに含む。
 * `audit.auditHead` は列挙外(Web に消費者なし — session-39 §10-4)。
 */
export const SESSION_ALLOWED_ENDPOINTS: ReadonlyArray<readonly [group: string, endpoint: string]> =
  [
    ["auth", "me"],
    ["auth", "logout"],
    ["auth", "recoveryStatus"],
    ["auth", "listTokens"],
    ["auth", "revokeTokenById"],
    ["membership", "get"],
    ["membership", "list"],
    ["environments", "list"],
    ["variables", "pullMetadata"],
    ["audit", "events"],
    ["audit", "invites"],
    ["audit", "self"],
    ["rotation", "flags"],
    ["invites", "list"],
    ["invites", "revoke"],
  ];

/**
 * Endpoints that deliberately run **without** `AuthMiddleware`: the
 * unauthenticated surface (AUTH_SPEC §3 / §4 の認証フロー自体と、資格情報が
 * OIDC トークンであるリース面 — §14-1)。セッション能力制限の対象外(セッション
 * 主体がそもそも成立しない)。API の全エンドポイントは「AuthMiddleware を持つ」
 * か「本リストに載る」かのどちらかでなければならず、スイープが両属・無属を
 * ロード時に拒否する — 認証必須のつもりでミドルウェア宣言を落とした新設面が、
 * 黙って未認証(かつセッションゲート外)にならないための fail-closed。
 */
export const UNAUTHENTICATED_ENDPOINTS: ReadonlyArray<readonly [group: string, endpoint: string]> =
  [
    ["auth", "authConfig"],
    ["auth", "githubStart"],
    ["auth", "githubCallback"],
    // CLI ログイン(AUTH_SPEC §4)は全 4 面が未認証: 資格はフロー資格情報
    // (flowToken / vsig / 単回承認チケット)であってセッションではない
    // (§4-1 (3) — SESSION_ALLOWED_ENDPOINTS には決して追加しない)
    ["authCli", "cliStart"],
    ["authCli", "cliVerify"],
    ["authCli", "cliApprove"],
    ["authCli", "cliPoll"],
    ["lease", "issue"],
  ];

const sessionAllowed = new Set(SESSION_ALLOWED_ENDPOINTS.map(([g, e]) => `${g}.${e}`));

/**
 * Whether a session principal may call the endpoint (AUTH_SPEC §5). The
 * middleware consults this for every authenticated request; everything outside
 * the allow-list is rejected with 403 `session-not-allowed` (fail-closed).
 */
export function isSessionAllowedEndpoint(group: string, endpoint: string): boolean {
  return sessionAllowed.has(`${group}.${endpoint}`);
}

/** The structural slice of an `HttpApi` the sweep walks (strict.ts と同じ理由の構造型). */
interface SweepableApi {
  readonly groups: {
    readonly [group: string]: {
      readonly endpoints: {
        readonly [endpoint: string]: {
          readonly middlewares: ReadonlySet<unknown>;
        };
      };
    };
  };
}

/**
 * Load-time sweep (AUTH_SPEC §5): asserts that the session-capability
 * declaration matches the registered API —
 *
 * 1. every `SESSION_ALLOWED_ENDPOINTS` entry names a real endpoint that
 *    carries `AuthMiddleware`(stale・リネーム済み・未認証面への許可指定を拒否)
 * 2. every endpoint without `AuthMiddleware` is consciously listed in
 *    `UNAUTHENTICATED_ENDPOINTS`, and no listed one carries it(認証必須の
 *    つもりの新設面がミドルウェア宣言を落とした形をロード時に落とす)
 *
 * デフォルト拒否(許可列挙外のセッション = 403)はミドルウェア側の述語が
 * 構造的に担うため、拒否面の明示列挙は持たない — 拒否の実効性はマトリクス
 * テストが保証する。
 */
export function assertSessionCapabilityClassified(api: SweepableApi): void {
  const unauthenticated = new Set(UNAUTHENTICATED_ENDPOINTS.map(([g, e]) => `${g}.${e}`));
  for (const key of sessionAllowed) {
    if (unauthenticated.has(key)) {
      throw new Error(
        `session capability sweep: "${key}" is listed as both session-allowed and unauthenticated`,
      );
    }
  }
  assertListedEndpointsConsistent(api);
  assertEveryEndpointClassified(api, unauthenticated);
}

/** 列挙面の実在 + AuthMiddleware 保持 / 非保持の整合(スイープの 1.〜2.)。 */
function assertListedEndpointsConsistent(api: SweepableApi): void {
  for (const [groupName, endpointName] of SESSION_ALLOWED_ENDPOINTS) {
    if (!hasAuthMiddleware(requireEndpoint(api, groupName, endpointName))) {
      throw new Error(
        `session capability sweep: "${groupName}.${endpointName}" is session-allowed but does ` +
          `not carry AuthMiddleware — a session principal cannot exist there (AUTH_SPEC §5)`,
      );
    }
  }
  for (const [groupName, endpointName] of UNAUTHENTICATED_ENDPOINTS) {
    if (hasAuthMiddleware(requireEndpoint(api, groupName, endpointName))) {
      throw new Error(
        `session capability sweep: "${groupName}.${endpointName}" is listed as unauthenticated ` +
          `but carries AuthMiddleware — remove it from UNAUTHENTICATED_ENDPOINTS (AUTH_SPEC §5)`,
      );
    }
  }
}

/** 逆方向の fail-closed 検査(スイープの 2. 後段): 無ミドルウェア面の完全分類。 */
function assertEveryEndpointClassified(
  api: SweepableApi,
  unauthenticated: ReadonlySet<string>,
): void {
  for (const [groupName, group] of Object.entries(api.groups)) {
    for (const [endpointName, endpoint] of Object.entries(group.endpoints)) {
      const key = `${groupName}.${endpointName}`;
      if (!hasAuthMiddleware(endpoint) && !unauthenticated.has(key)) {
        throw new Error(
          `session capability sweep: "${key}" carries no AuthMiddleware and is not classified — ` +
            `declare AuthMiddleware on it or, if it is deliberately unauthenticated, add it to ` +
            `UNAUTHENTICATED_ENDPOINTS (AUTH_SPEC §5)`,
        );
      }
    }
  }
}

function hasAuthMiddleware(endpoint: { readonly middlewares: ReadonlySet<unknown> }): boolean {
  return endpoint.middlewares.has(AuthMiddleware);
}

/** リスト 1 件の実在検査: グループ・エンドポイントの存在を要求する。 */
function requireEndpoint(
  api: SweepableApi,
  groupName: string,
  endpointName: string,
): SweepableApi["groups"][string]["endpoints"][string] {
  const group = api.groups[groupName];
  if (group === undefined) {
    throw new Error(`session capability sweep: unknown group "${groupName}"`);
  }
  const endpoint = group.endpoints[endpointName];
  if (endpoint === undefined) {
    throw new Error(`session capability sweep: unknown endpoint "${groupName}.${endpointName}"`);
  }
  return endpoint;
}
