// GitHub との認証ダンス(AUTH_SPEC §3 / §4。ADR-0009: 直接実装)。
//
// - GitHub のアクセストークンはリクエスト処理中のメモリにのみ存在し、保存しない
//   (AUTH_SPEC §10: GitHub トークンの永続化禁止)
// - 識別子は数値 ID(providerUserId)。login 名は表示用スナップショットのみ
// - email はプロバイダ側で verified な primary のみ拾う(§3)
// - テストは miniflare の outboundService で GitHub をスタブする(実ネットワーク禁止)。
//   本番コードにスタブ分岐は存在しない

import { Context, Data, Effect } from "effect";

import type { VerifiedIdentity } from "../auth-domain.ts";

const OAUTH_TOKEN_URL = "https://github.com/login/oauth/access_token";
const API_USER_URL = "https://api.github.com/user";
const API_EMAILS_URL = "https://api.github.com/user/emails";

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
  /** アクセストークンを検証し、プロバイダ検証済みアイデンティティを返す(§3-2 / §4-4)。 */
  readonly fetchIdentity: (accessToken: string) => Effect.Effect<VerifiedIdentity, GitHubAuthError>;
}

export class GitHubApi extends Context.Service<GitHubApi, GitHubApiShape>()("GitHubApi") {}

interface TokenResponse {
  readonly access_token?: string;
}

interface UserResponse {
  readonly id?: number;
  readonly login?: string;
}

interface EmailEntry {
  readonly email?: string;
  readonly primary?: boolean;
  readonly verified?: boolean;
}

async function exchangeCodeRequest(
  clientId: string,
  clientSecret: string,
  code: string,
  redirectUri: string,
): Promise<string | null> {
  const response = await fetch(OAUTH_TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
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

const GITHUB_HEADERS = { accept: "application/vnd.github+json", "user-agent": "maruhi" };

async function fetchUserRequest(accessToken: string): Promise<UserResponse | null> {
  const response = await fetch(API_USER_URL, {
    headers: { ...GITHUB_HEADERS, authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) {
    return null;
  }
  return (await response.json()) as UserResponse;
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
    headers: { ...GITHUB_HEADERS, authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) {
    return null;
  }
  const entries = (await response.json()) as readonly EmailEntry[];
  return Array.isArray(entries) ? pickVerifiedPrimaryEmail(entries) : null;
}

async function fetchIdentityRequest(accessToken: string): Promise<VerifiedIdentity | null> {
  const user = await fetchUserRequest(accessToken);
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
      attempt("token-invalid", () => fetchIdentityRequest(accessToken)),
  };
}
