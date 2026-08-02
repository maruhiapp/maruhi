// GitHub との認証ダンス(AUTH_SPEC §3 / §4。ADR-0009: 直接実装)。
//
// - GitHub のアクセストークンはリクエスト処理中のメモリにのみ存在し、保存しない
//   (AUTH_SPEC §10: GitHub トークンの永続化禁止)
// - 識別子は数値 ID(providerUserId)。login 名は表示用スナップショットのみ
// - email はプロバイダ側で verified な primary のみ拾う(§3)
// - device 交換で持ち込まれるトークンは check-token API で「自 OAuth App 発行」を
//   検証する(§4-4 の audience 検証。他 App 向けトークンの流用 = confused-deputy 対策)
// - テストは miniflare の outboundService で GitHub をスタブする(実ネットワーク禁止)。
//   本番コードにスタブ分岐は存在しない

import { Context, Data, Effect } from "effect";

import type { VerifiedIdentity } from "../auth-domain.ts";

const OAUTH_TOKEN_URL = "https://github.com/login/oauth/access_token";
const API_BASE = "https://api.github.com";
const API_USER_URL = `${API_BASE}/user`;
const API_EMAILS_URL = `${API_BASE}/user/emails`;

/** GitHub 認証ダンスの失敗(理由コードのみ。トークン値・外部 ID は運ばない)。 */
class GitHubAuthError extends Data.TaggedError("GitHubAuth")<{
  readonly reason: "code-exchange-failed" | "token-invalid";
}> {}

interface GitHubApiShape {
  /** Authorization Code を GitHub アクセストークンへ交換する(§3-2)。 */
  readonly exchangeCode: (
    code: string,
    redirectUri: string,
  ) => Effect.Effect<string, GitHubAuthError>;
  /**
   * 自 App の code 交換で得たトークンからアイデンティティを取得する(§3-2)。
   * トークンの出所が自明(直前の exchangeCode)な web フロー専用。
   */
  readonly fetchIdentity: (accessToken: string) => Effect.Effect<VerifiedIdentity, GitHubAuthError>;
  /**
   * 外部(CLI)から持ち込まれたトークンを check-token API で検証し、自 OAuth App
   * 発行であることを確認した上でアイデンティティを返す(§4-4)。device 交換専用。
   */
  readonly verifyAppToken: (
    accessToken: string,
  ) => Effect.Effect<VerifiedIdentity, GitHubAuthError>;
}

export class GitHubApi extends Context.Service<GitHubApi, GitHubApiShape>()("GitHubApi") {}

interface TokenResponse {
  readonly access_token?: string;
}

interface UserResponse {
  readonly id?: number;
  readonly login?: string;
}

interface CheckTokenResponse {
  readonly user?: UserResponse;
}

interface EmailEntry {
  readonly email?: string;
  readonly primary?: boolean;
  readonly verified?: boolean;
}

// github.com / api.github.com とも UA を要求しうるため常に付与する
const COMMON_HEADERS = { accept: "application/json", "user-agent": "maruhi" };
const GITHUB_API_HEADERS = { accept: "application/vnd.github+json", "user-agent": "maruhi" };

async function exchangeCodeRequest(
  clientId: string,
  clientSecret: string,
  code: string,
  redirectUri: string,
): Promise<string | null> {
  const response = await fetch(OAUTH_TOKEN_URL, {
    method: "POST",
    headers: { ...COMMON_HEADERS, "content-type": "application/json" },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri,
    }),
  });
  if (!response.ok) {
    return null;
  }
  const body = (await response.json()) as TokenResponse;
  return typeof body.access_token === "string" ? body.access_token : null;
}

async function fetchUserRequest(accessToken: string): Promise<UserResponse | null> {
  const response = await fetch(API_USER_URL, {
    headers: { ...GITHUB_API_HEADERS, authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) {
    return null;
  }
  return (await response.json()) as UserResponse;
}

/**
 * §4-4 の audience 検証: check-token API(Basic 認証 = client_id:client_secret)は
 * トークンが「この App に対して発行されたもの」でなければ 404 を返す。
 * 他 App 向けに発行された(漏洩・流用)トークンをここで遮断する。
 */
async function checkAppTokenRequest(
  clientId: string,
  clientSecret: string,
  accessToken: string,
): Promise<UserResponse | null> {
  const response = await fetch(`${API_BASE}/applications/${clientId}/token`, {
    method: "POST",
    headers: {
      ...GITHUB_API_HEADERS,
      "content-type": "application/json",
      authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
    },
    body: JSON.stringify({ access_token: accessToken }),
  });
  if (!response.ok) {
    return null;
  }
  const body = (await response.json()) as CheckTokenResponse;
  return body.user ?? null;
}

function isVerifiedPrimary(entry: EmailEntry): boolean {
  return entry.primary === true && entry.verified === true;
}

function pickVerifiedPrimaryEmail(entries: readonly EmailEntry[]): string | null {
  const primary = entries.find(isVerifiedPrimary);
  return typeof primary?.email === "string" ? primary.email : null;
}

/** primary かつ verified なメールのみ返す(§3-3。なければ null = 保存しない)。 */
async function fetchVerifiedPrimaryEmail(accessToken: string): Promise<string | null> {
  const response = await fetch(API_EMAILS_URL, {
    headers: { ...GITHUB_API_HEADERS, authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) {
    return null;
  }
  const entries = (await response.json()) as readonly EmailEntry[];
  return Array.isArray(entries) ? pickVerifiedPrimaryEmail(entries) : null;
}

async function toIdentity(
  user: UserResponse | null,
  accessToken: string,
): Promise<VerifiedIdentity | null> {
  if (user === null || typeof user.id !== "number") {
    return null;
  }
  return {
    provider: "github",
    providerUserId: String(user.id),
    providerLogin: typeof user.login === "string" ? user.login : null,
    verifiedEmail: await fetchVerifiedPrimaryEmail(accessToken),
  };
}

/** fetch 失敗(ネットワーク・GitHub 障害)も型付きエラーへ畳む。 */
function attempt<T>(
  reason: "code-exchange-failed" | "token-invalid",
  evaluate: () => Promise<T | null>,
): Effect.Effect<T, GitHubAuthError> {
  return Effect.tryPromise({ try: evaluate, catch: () => new GitHubAuthError({ reason }) }).pipe(
    Effect.flatMap((value) =>
      value === null ? Effect.fail(new GitHubAuthError({ reason })) : Effect.succeed(value),
    ),
  );
}

/** 本番実装: GitHub の OAuth / REST API を直接呼ぶ。 */
export function makeGitHubApi(clientId: string, clientSecret: string): GitHubApiShape {
  return {
    exchangeCode: (code, redirectUri) =>
      attempt("code-exchange-failed", () =>
        exchangeCodeRequest(clientId, clientSecret, code, redirectUri),
      ),
    fetchIdentity: (accessToken) =>
      attempt("token-invalid", async () =>
        toIdentity(await fetchUserRequest(accessToken), accessToken),
      ),
    verifyAppToken: (accessToken) =>
      attempt("token-invalid", async () =>
        toIdentity(await checkAppTokenRequest(clientId, clientSecret, accessToken), accessToken),
      ),
  };
}
