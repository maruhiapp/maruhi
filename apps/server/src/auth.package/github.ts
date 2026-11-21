import { decodeProviderUserId, egressHttpClientLayer } from "@maruhi/core";
import { type Cause, Context, Data, Duration, Effect, Redacted, Schema } from "effect";
import {
  type HttpClientError,
  HttpClient,
  HttpClientRequest,
  HttpClientResponse,
} from "effect/http";

import type { VerifiedIdentity } from "../auth-domain.ts";

const OAUTH_TOKEN_URL = "https://github.com/login/oauth/access_token";
const API_BASE = "https://api.github.com";
const API_USER_URL = `${API_BASE}/user`;
const API_EMAILS_URL = `${API_BASE}/user/emails`;

const REQUEST_TIMEOUT = Duration.seconds(5);

class GitHubAuthError extends Data.TaggedError("GitHubAuth")<{
  readonly reason: "code-exchange-failed" | "token-invalid";
}> {}

export interface GitHubApiShape {
  readonly exchangeCode: (
    code: string,
    redirectUri: string,
  ) => Effect.Effect<string, GitHubAuthError>;
  readonly fetchIdentity: (accessToken: string) => Effect.Effect<VerifiedIdentity, GitHubAuthError>;
}

export class GitHubApi extends Context.Service<GitHubApi, GitHubApiShape>()("GitHubApi") {}

const TokenResponseSchema = Schema.Struct({
  access_token: Schema.optionalKey(Schema.String),
});

const UserResponseSchema = Schema.Struct({
  id: Schema.optionalKey(Schema.Int),
  login: Schema.optionalKey(Schema.String),
});
type UserResponse = typeof UserResponseSchema.Type;

const EmailEntrySchema = Schema.Struct({
  email: Schema.optionalKey(Schema.String),
  primary: Schema.optionalKey(Schema.Boolean),
  verified: Schema.optionalKey(Schema.Boolean),
});
const EmailListSchema = Schema.Array(EmailEntrySchema);
type EmailEntry = typeof EmailEntrySchema.Type;

const COMMON_HEADERS = { accept: "application/json", "user-agent": "maruhi" };
const GITHUB_API_HEADERS = { accept: "application/vnd.github+json", "user-agent": "maruhi" };

type CallError = HttpClientError.HttpClientError | Schema.SchemaError | Cause.TimeoutError;

const fetchJson = Effect.fn("github.fetchJson")(function* <S extends Schema.Constraint>(
  request: HttpClientRequest.HttpClientRequest,
  schema: S,
): Effect.fn.Return<S["Type"] | null, CallError, HttpClient.HttpClient | S["DecodingServices"]> {
  const client = yield* HttpClient.HttpClient;
  const response = yield* client.execute(request);
  if (response.status < 200 || response.status >= 300) {
    return null;
  }
  return yield* response.pipe(HttpClientResponse.schemaBodyJson(schema));
}, Effect.timeout(REQUEST_TIMEOUT));

function exchangeCodeRequest(
  clientId: string,
  clientSecret: Redacted.Redacted<string> | undefined,
  code: string,
  redirectUri: string,
): HttpClientRequest.HttpClientRequest {
  return HttpClientRequest.post(OAUTH_TOKEN_URL).pipe(
    HttpClientRequest.setHeaders(COMMON_HEADERS),
    HttpClientRequest.bodyUrlParams({
      client_id: clientId,
      client_secret: clientSecret === undefined ? undefined : Redacted.value(clientSecret),
      code,
      redirect_uri: redirectUri,
    }),
  );
}

function apiRequest(url: string, accessToken: string): HttpClientRequest.HttpClientRequest {
  return HttpClientRequest.get(url).pipe(
    HttpClientRequest.setHeaders(GITHUB_API_HEADERS),
    HttpClientRequest.bearerToken(accessToken),
  );
}

function isVerifiedPrimary(entry: EmailEntry): boolean {
  return entry.primary === true && entry.verified === true;
}

function pickVerifiedPrimaryEmail(entries: readonly EmailEntry[]): string | null {
  const primary = entries.find(isVerifiedPrimary);
  return typeof primary?.email === "string" ? primary.email : null;
}

function fetchVerifiedPrimaryEmail(
  accessToken: string,
): Effect.Effect<string | null, CallError, HttpClient.HttpClient> {
  return Effect.map(
    fetchJson(apiRequest(API_EMAILS_URL, accessToken), EmailListSchema),
    (entries) => (entries === null ? null : pickVerifiedPrimaryEmail(entries)),
  );
}

const toIdentity = Effect.fn("github.toIdentity")(function* (
  user: UserResponse | null,
  accessToken: string,
): Effect.fn.Return<VerifiedIdentity | null, CallError, HttpClient.HttpClient> {
  if (user === null || typeof user.id !== "number") {
    return null;
  }
  return {
    provider: "github" as const,
    providerUserId: decodeProviderUserId(String(user.id)),
    providerLogin: user.login ?? null,
    verifiedEmail: yield* fetchVerifiedPrimaryEmail(accessToken),
  };
});

const githubHttpClient = egressHttpClientLayer();

function attempt<A>(
  reason: "code-exchange-failed" | "token-invalid",
  effect: Effect.Effect<A | null, CallError, HttpClient.HttpClient>,
): Effect.Effect<A, GitHubAuthError> {
  const failure = new GitHubAuthError({ reason });
  return effect.pipe(
    Effect.catchTags({
      HttpClientError: () => Effect.fail(failure),
      SchemaError: () => Effect.fail(failure),
      TimeoutError: () => Effect.fail(failure),
    }),
    Effect.flatMap((value) => (value === null ? Effect.fail(failure) : Effect.succeed(value))),
    Effect.provide(githubHttpClient),
  );
}

export function makeGitHubApi(
  clientId: string,
  clientSecret: Redacted.Redacted<string> | undefined,
): GitHubApiShape {
  return {
    exchangeCode: (code, redirectUri) =>
      attempt(
        "code-exchange-failed",
        Effect.map(
          fetchJson(
            exchangeCodeRequest(clientId, clientSecret, code, redirectUri),
            TokenResponseSchema,
          ),
          (body) => body?.access_token ?? null,
        ),
      ),
    fetchIdentity: (accessToken) =>
      attempt(
        "token-invalid",
        Effect.flatMap(
          fetchJson(apiRequest(API_USER_URL, accessToken), UserResponseSchema),
          (user) => toIdentity(user, accessToken),
        ),
      ),
  };
}
