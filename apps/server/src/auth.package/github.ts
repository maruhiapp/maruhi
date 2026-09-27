// The authentication dance with GitHub (AUTH_SPEC §3 / §4; ADR-0009:
// direct implementation).
//
// - GitHub access tokens exist only in memory during request handling and
//   are never stored (AUTH_SPEC §10: persisting GitHub tokens is forbidden)
// - The identifier is the numeric ID (providerUserId); the login name is a
//   display snapshot only
// - email picks up only the primary one verified on the provider side (§3)
// - Tokens are always obtained through our own code exchange (§3-2 / §4-1
//   (4)); there is no verification path for externally carried-in tokens
// - Tests stub GitHub via miniflare's outboundService (real network is
//   forbidden). No stub branch exists in production code

import { Context, Data, Effect } from "effect";

import type { VerifiedIdentity } from "../auth-domain.ts";

const OAUTH_TOKEN_URL = "https://github.com/login/oauth/access_token";
const API_BASE = "https://api.github.com";
const API_USER_URL = `${API_BASE}/user`;
const API_EMAILS_URL = `${API_BASE}/user/emails`;

/** Failure of the GitHub authentication dance (reason code only; token values and external IDs are not carried). */
class GitHubAuthError extends Data.TaggedError("GitHubAuth")<{
  readonly reason: "code-exchange-failed" | "token-invalid";
}> {}

/** GitHub authentication-dance operations (exposed for decoration — the counting in ops-signals.ts). */
export interface GitHubApiShape {
  /** Exchanges an Authorization Code for a GitHub access token (§3-2). */
  readonly exchangeCode: (
    code: string,
    redirectUri: string,
  ) => Effect.Effect<string, GitHubAuthError>;
  /**
   * Fetches the identity from a token obtained by our own App's code
   * exchange (§3-2). Web flow only, where the token's provenance is
   * self-evident (the immediately preceding exchangeCode).
   */
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

// Always attached since both github.com / api.github.com may require a UA
const COMMON_HEADERS = { accept: "application/json", "user-agent": "maruhi" };
const GITHUB_API_HEADERS = { accept: "application/vnd.github+json", "user-agent": "maruhi" };

async function exchangeCodeRequest(
  clientId: string,
  clientSecret: string,
  code: string,
  redirectUri: string,
): Promise<string | null> {
  // RFC 6749 §4.1.3: the token endpoint body is application/x-www-form-urlencoded
  const response = await fetch(OAUTH_TOKEN_URL, {
    method: "POST",
    headers: { ...COMMON_HEADERS, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
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

function isVerifiedPrimary(entry: EmailEntry): boolean {
  return entry.primary === true && entry.verified === true;
}

function pickVerifiedPrimaryEmail(entries: readonly EmailEntry[]): string | null {
  const primary = entries.find(isVerifiedPrimary);
  return typeof primary?.email === "string" ? primary.email : null;
}

/** Returns only the primary-and-verified email (§3-3; null = not stored). */
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

/** Folds fetch failures (network errors, GitHub outages) into the typed error too. */
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

/** Production implementation: calls GitHub's OAuth / REST API directly. */
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
  };
}
