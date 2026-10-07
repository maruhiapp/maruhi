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

/**
 * Timeout of one outbound GitHub call. Same bound as the OIDC issuer fetch
 * (oidc.package/jwks.ts's FETCH_TIMEOUT_MS): an auth-path request must not
 * hang on a peer that accepts the connection and never answers.
 */
const REQUEST_TIMEOUT = Duration.seconds(5);

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

/**
 * GitHub's token-endpoint answer (§3-2). A 200 carries either a token or an
 * OAuth error body — an absent access_token is a failed exchange, not a
 * malformed answer.
 */
const TokenResponseSchema = Schema.Struct({
  access_token: Schema.optionalKey(Schema.String),
});

/** GitHub's `GET /user` answer: the integer id is the identifier; the login is a display snapshot only. */
const UserResponseSchema = Schema.Struct({
  id: Schema.optionalKey(Schema.Int),
  login: Schema.optionalKey(Schema.String),
});
type UserResponse = typeof UserResponseSchema.Type;

/** One entry of GitHub's `GET /user/emails` answer (only the fields the §3-3 filter reads). */
const EmailEntrySchema = Schema.Struct({
  email: Schema.optionalKey(Schema.String),
  primary: Schema.optionalKey(Schema.Boolean),
  verified: Schema.optionalKey(Schema.Boolean),
});
const EmailListSchema = Schema.Array(EmailEntrySchema);
type EmailEntry = typeof EmailEntrySchema.Type;

// Always attached since both github.com / api.github.com may require a UA
const COMMON_HEADERS = { accept: "application/json", "user-agent": "maruhi" };
const GITHUB_API_HEADERS = { accept: "application/vnd.github+json", "user-agent": "maruhi" };

/** The failure channel of one outbound GitHub call (folded into GitHubAuthError at the operation boundary). */
type CallError = HttpClientError.HttpClientError | Schema.SchemaError | Cause.TimeoutError;

/**
 * One outbound GitHub call: fetch, gate on a 2xx status, schema-decode the
 * JSON body — all inside REQUEST_TIMEOUT. `null` means GitHub answered with
 * a non-ok status (each caller decides its meaning); transport errors,
 * timeouts, and unexpected body shapes stay in the error channel.
 */
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

/**
 * RFC 6749 §4.1.3: the token endpoint body is application/x-www-form-urlencoded.
 * The client secret's only unwrap is this body field. An unconfigured
 * secret (undefined) leaves the field out — the normal path never gets
 * here (start fails closed with 503), and GitHub rejects the exchange.
 */
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

/** Returns only the primary-and-verified email (§3-3; null = not stored). */
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

/** The outbound client: no header of its own (packages/core/src/egress.ts). */
const githubHttpClient = egressHttpClientLayer();

/**
 * Folds outbound failures (transport errors, timeouts, unexpected shapes)
 * and null answers into the typed error, and provides the HTTP client
 * locally (index.ts is not involved in this module's transport).
 */
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

/**
 * Production implementation: calls GitHub's OAuth / REST API directly. The
 * client secret stays `Redacted` until the token-exchange body.
 */
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
