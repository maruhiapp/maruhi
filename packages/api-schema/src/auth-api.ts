// HttpApi definition of the authentication endpoints (AUTH_SPEC §3 / §5 /
// §6 / §11-4). CLI login (§4 — server-mediated web-flow handoff) lives in
// auth-cli-api.ts.
//
// session-06 ruling 4: everything including the OAuth redirect endpoints
// (start / callback) lives in api-schema (keeps the shared source for the
// server implementation and the client derivation single). The success
// response of start / callback is a 302 redirect (+ Set-Cookie); the
// handler returns an HttpServerResponse directly (success schema is Void).
//
// Prohibitions (AUTH_SPEC §10): GitHub tokens are handled only in memory
// during request processing and never appear in any response type.
// Session / token raw values appear in a response only once, at issuance
// (the cliPoll approved response in auth-cli-api.ts).

import { OrgIdSchema, OrgRoleSchema, TokenScopeSchema, UserIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/http-api";

import { AuthMiddleware } from "./auth-middleware.ts";
import {
  AuthFlowError,
  AuthRateLimitedError,
  ForbiddenError,
  RecoveryRateLimitedError,
  RecoveryWrapNotFoundError,
  SetupIncompleteError,
  TokenNotFoundError,
} from "./errors/index.ts";
import { EncPubHex, hexString, KeyFingerprintHex } from "./hex.ts";
import { strictPayload } from "./strict.ts";

/**
 * Success declaration for endpoints that complete with a 302 redirect
 * (+ Set-Cookie). githubStart / githubCallback are browser-navigation
 * only; they are not designed to be called from the HttpApi-derived
 * client (fetch follows redirects by default).
 */
const Redirect = HttpApiSchema.Empty(302);

/**
 * Token-name length limit (`cliStart` payload — AUTH_SPEC §6).
 *
 * **Shared with the CLI argument layer**: if it lived only here, an
 * over-long `maruhi login --token-name` value would first surface as an
 * encode failure after the browser approval completes. Because authoring
 * mistakes are rejected before any network call (CLI discipline), the
 * limit is exported so both sides see the same value.
 */
export const MAX_TOKEN_NAME_LENGTH = 128;

// Character class forbidden in token names (AUTH_SPEC §6 character-class
// constraint): control characters (C0 / DEL / C1) and bidirectional
// control characters (bidi — ALM, LRM/RLM, embeddings, overrides,
// isolates). Names are rendered as caller-supplied text on the approval
// page (§4-1 (4)), the list API, and the dashboard, so the shared
// display-surface protection is placed at acceptance time (the §4-2
// "approval-text impersonation" mitigation). **Not retroactive** — names
// stored under the old Schema are not cleaned up.
export const TOKEN_NAME_FORBIDDEN_CLASS =
  "\\u0000-\\u001f\\u007f-\\u009f\\u061c\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069";

/**
 * Check whether a token name contains forbidden characters (shared with
 * the CLI argument layer — authoring mistakes are rejected before any
 * network call, not surfaced as an encode failure after the browser
 * approval completes).
 */
export const TOKEN_NAME_FORBIDDEN_CHARS = new RegExp(`[${TOKEN_NAME_FORBIDDEN_CLASS}]`, "u");

/**
 * Wire acceptance shape of a token name (AUTH_SPEC §6): 128 characters or
 * fewer, no control or bidi control characters. The `cliStart` payload
 * and the CLI argument check share this Schema.
 */
export const TokenNameSchema = Schema.String.check(
  Schema.isMaxLength(MAX_TOKEN_NAME_LENGTH),
  Schema.isPattern(new RegExp(`^[^${TOKEN_NAME_FORBIDDEN_CLASS}]*$`, "u"), {
    description: "token name without control or bidirectional control characters",
  }),
);

/**
 * Default TTL of an API token (AUTH_SPEC §6 — W3a). expires_at is fixed
 * at issuance (intentionally asymmetric with the §5 session sliding
 * renewal — tokens enforce periodic re-authentication). Self-hosts may
 * adjust the value (it is an acceptance policy, not a consensus rule).
 */
export const DEFAULT_TOKEN_TTL_DAYS = 90;

/**
 * Upper bound of the TTL that can be explicitly requested at issuance
 * (AUTH_SPEC §6 — W3a ruling CF). A relief valve for unattended PAT use
 * in environments without lease support (GitLab CI / k8s / cron etc. —
 * the §14-1 supported issuer is only v1 = GitHub Actions); the fact that
 * it is capped is itself what prevents reintroducing L-2 (non-expiring
 * tokens). Shared with the CLI argument layer (same reason as
 * MAX_TOKEN_NAME_LENGTH — authoring mistakes are rejected before any
 * network call).
 */
export const MAX_TOKEN_TTL_DAYS = 365;

/** Explicit TTL at issuance (days). Integer 1..MAX_TOKEN_TTL_DAYS (default 90 days when omitted). */
export const TokenTtlDays = Schema.Number.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
  Schema.isLessThanOrEqualTo(MAX_TOKEN_TTL_DAYS),
);

/**
 * Signup acceptance policy (AUTH_SPEC §3 — H1). A per-deployment server
 * acceptance policy; it does not appear on the chain or in signatures
 * (same class as §12-11's schemaPolicy). The default `open` is identical
 * to the previous behavior.
 */
export const SignupPolicySchema = Schema.Literals(["open", "invite", "closed"]);
export type SignupPolicy = (typeof SignupPolicySchema)["Type"];

/**
 * Wire acceptance shape of the invite code carried by a signup link
 * (AUTH_SPEC §3 — `maruhi_sgn_` + 43 Base62 characters). Unauthenticated
 * surface, so only the size limit is bound (the real verification is the
 * server's hash comparison — do not leak existence information through
 * the format).
 */
export const SignupCodeSchema = Schema.String.check(Schema.isMaxLength(128));

/**
 * Public (unauthenticated) server configuration (AUTH_SPEC §4). The GitHub
 * OAuth client_id is public information — it appears in the authorize URL —
 * so exposing it lets a self-hosted CLI resolve it from the server URL alone.
 *
 * serverKeyFingerprintHex (AUTH_SPEC §4) is present only when the
 * deployment keypair (CRYPTO_SPEC §9) is configured. It is the comparison
 * target when running grant_server.
 * serverEncPubHex is the distribution channel for the "enc public key the
 * server distributes" of §9 (a public key is public information; the FP
 * is the first 16 bytes of its SHA-256, and the CLI recomputes and
 * verifies the two are consistent).
 *
 * signupPolicy (AUTH_SPEC §3 — H1) is advisory (public information — the
 * same content as the landing-page guidance text; never an input to
 * verification or authorization rules).
 */
export const AuthConfigSchema = Schema.Struct({
  githubClientId: Schema.String,
  serverKeyFingerprintHex: Schema.optionalKey(KeyFingerprintHex),
  serverEncPubHex: Schema.optionalKey(EncPubHex),
  signupPolicy: SignupPolicySchema,
});

/**
 * One API token in the self-inventory listing (AUTH_SPEC §6 — W3a).
 * The raw value and token_hash **do not exist, structurally** (no column
 * in the schema = the type closes the path by which an implementation
 * could return them by mistake).
 */
export const TokenSummarySchema = Schema.Struct({
  id: Schema.String,
  name: Schema.String,
  tokenPrefix: Schema.String,
  scopes: Schema.Array(TokenScopeSchema),
  createdAtMs: Schema.Number,
  lastUsedAtMs: Schema.NullOr(Schema.Number),
  expiresAtMs: Schema.Number,
});

/** GET /auth/tokens: the caller's own tokens (AUTH_SPEC §6 — W3a). */
export const TokenListSchema = Schema.Struct({
  tokens: Schema.Array(TokenSummarySchema),
});

/** One org the authenticated user belongs to (AUTH_SPEC §9-1). */
export const UserOrgSchema = Schema.Struct({
  orgId: OrgIdSchema,
  slug: Schema.String,
  name: Schema.String,
  role: OrgRoleSchema,
});

/** The authenticated user and their orgs (project creation needs an org id — §11-3). */
export const MeSchema = Schema.Struct({
  userId: UserIdSchema,
  orgs: Schema.Array(UserOrgSchema),
  /**
   * Only for token principals: the scopes of the presented token
   * (AUTH_SPEC §6). Absent for session principals (sessions carry no
   * scopes; the surfaces they can call are limited to the §5 capability
   * allowlist, and within it the chain role is the binding constraint —
   * W2b). Material for the client to determine its effective permission
   * (min(scope, chain role) — §9-2) **in advance** (so the checkpoint's
   * audit-head notarization does not hit a 403 — §16-2 — PR-M2).
   */
  tokenScopes: Schema.optionalKey(Schema.Array(TokenScopeSchema)),
  /**
   * Only for token principals: the expiry of the presented token
   * (AUTH_SPEC §6 — W3a ruling CI). Like tokenScopes it is an attribute
   * of the credential the caller itself presented, so it discloses no new
   * information. Material for unattended use (PATs in environments
   * without lease support — ruling CF) to observe their own expiry and
   * arrange a warning / reissuance before a 401. It is also a path to
   * learn only one's own expiry without opening the listing
   * `GET /auth/tokens` (token principals require `*` × admin — ruling
   * CH).
   */
  tokenExpiresAtMs: Schema.optionalKey(Schema.Number),
  /**
   * Snapshot of the GitHub display login (2026-09-13 IV — AUTH_SPEC
   * §15-3). Material for the inviter's client to build the invite link's
   * `il` (the comparison material for the `github-signing-keys` backing
   * source). Absent when unlinked or not yet stored. Disclosure of
   * self-information only (another user's login cannot be obtained here).
   */
  providerLogin: Schema.optionalKey(Schema.String),
});

// Recovery blob (AUTH_SPEC §13; the wrapped master secret key of
// CRYPTO_SPEC §8). Opaque ciphertext from the server's point of view; the
// recovery code itself never appears on the wire.
const RecoveryNonceHex = hexString(12);
// AES-256-GCM ct || tag: 16 bytes to 16 KiB including the tag (§13-4 acceptance policy)
const RecoveryCiphertextHex = Schema.String.check(
  Schema.isPattern(/^(?:[0-9a-f]{2}){16,16384}$/, {
    description: "lowercase hex AES-GCM ciphertext (16 bytes .. 16 KiB incl. tag)",
  }),
);

/** A wrapped master-secret blob on the wire (AUTH_SPEC §13-4). */
export const RecoveryWrapSchema = Schema.Struct({
  suite: Schema.Literal("maruhi/v1"),
  nonceHex: RecoveryNonceHex,
  ciphertextHex: RecoveryCiphertextHex,
});

/** GET /auth/recovery: the stored blob plus its last-update time. */
export const RecoveryWrapResultSchema = Schema.Struct({
  suite: Schema.Literal("maruhi/v1"),
  nonceHex: RecoveryNonceHex,
  ciphertextHex: RecoveryCiphertextHex,
  updatedAtMs: Schema.Number,
});

/** GET /auth/recovery/status: registration state only — never the blob (§13-2). */
export const RecoveryStatusSchema = Schema.Struct({
  registered: Schema.Boolean,
  updatedAtMs: Schema.NullOr(Schema.Number),
});

/**
 * Authentication endpoints (AUTH_SPEC §3 web OAuth, §5 sessions, §6 tokens).
 * Token issuance happens only through the CLI login handoff (§4 — the
 * authCli group in auth-cli-api.ts); management is the presented-token
 * self-revocation (for CLI logout) plus the W3a token-management surface:
 * self-inventory listing and targeted revocation (the §6 line-drawing
 * updated by the W0 ruling — no additional issuance UI / API is built).
 */
export const authGroup = HttpApiGroup.make("auth")
  .add(
    // Public configuration endpoint (AUTH_SPEC §4; session-11 ruling B).
    // Unauthenticated. An unconfigured server (the §3 self-diagnosis
    // conditions: client_id is a placeholder / empty / absent, or no
    // client_secret registered) answers 503 and directs to the setup guide
    HttpApiEndpoint.get("authConfig", "/auth/config", {
      success: AuthConfigSchema,
      error: [SetupIncompleteError],
    }),
  )
  .add(
    // signup_code (AUTH_SPEC §3 — H1): the entry point that carries the
    // signup invite code. When present, the handler pre-verifies it at
    // start (with a per-IP rate limit); if invalid it ends on a
    // script-free guidance page (HTML — a direct response that does not go
    // through the success 302), if valid it is carried on a __Host-
    // cookie through to callback. A plain start (no code) = the
    // traditional login flow, unchanged
    HttpApiEndpoint.get("githubStart", "/auth/github/start", {
      query: { signup_code: Schema.optionalKey(SignupCodeSchema) },
      success: Redirect,
      error: [SetupIncompleteError, AuthRateLimitedError],
    }),
  )
  .add(
    HttpApiEndpoint.get("githubCallback", "/auth/github/callback", {
      // Reachable unauthenticated, and each request causes an outbound
      // call to GitHub (the code exchange; on success also /user and
      // /user/emails), so the query carries an explicit cap (512
      // characters) (supplement 3 A-6). The OAuth spec does not define the
      // code format, so only its length is checked (real GitHub code /
      // state values are orders of magnitude shorter than this cap). A
      // length cap bounds the payload but not the frequency, so the
      // **number** of exchanges is bounded by per-source-IP Workers Rate
      // Limiting (a path that consumes the OAuth App's shared quota)
      query: {
        code: Schema.String.check(Schema.isMaxLength(512)),
        state: Schema.String.check(Schema.isMaxLength(512)),
      },
      success: Redirect,
      error: [AuthFlowError, AuthRateLimitedError],
    }),
  )
  .add(
    HttpApiEndpoint.get("me", "/auth/me", {
      success: MeSchema,
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("logout", "/auth/logout", {
      success: HttpApiSchema.NoContent,
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("revokeToken", "/auth/token/revoke", {
      success: HttpApiSchema.NoContent,
    }).middleware(AuthMiddleware),
  )
  .add(
    // Listing (AUTH_SPEC §6 — W3a): metadata of the caller's own tokens
    // only. The raw value and token_hash are never returned (no such
    // columns exist on TokenSummarySchema). Token principals only when
    // they include `*` × admin scope (ruling CH — same level as §13-2 /
    // self-axis audit: a stolen scope-limited token must not receive an
    // account-wide token inventory = reconnaissance material). Bounded by
    // the 100-token cap (§6), so no paging
    HttpApiEndpoint.get("listTokens", "/auth/tokens", {
      success: TokenListSchema,
      error: [ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // Targeted revocation (AUTH_SPEC §6 — W3a): authorization = session
    // principals, or tokens including `*` × admin scope. Targets are the
    // caller's own tokens only — another user's or a nonexistent token id
    // is a uniform 404 (existence concealment — the same discipline as the
    // §12-6 deletion surfaces; the decision order is ruling CG: 401 → 403
    // [computed from the caller's credentials alone] → uniform 404)
    HttpApiEndpoint.delete("revokeTokenById", "/auth/tokens/:tokenId", {
      params: { tokenId: Schema.String },
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, TokenNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // Registration / reissuance = replace upsert (AUTH_SPEC §13-1; the
    // old wrap disappears at acceptance)
    HttpApiEndpoint.put("recoveryPut", "/auth/recovery", {
      // strict acceptance (§12-10 (1)). The shared RecoveryWrapSchema
      // itself is not wrapped (the change must not propagate into other
      // endpoints' responses). strict applies only to this payload's
      // decode / encode, not to the success / error encoding.
      payload: strictPayload(RecoveryWrapSchema),
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("recoveryGet", "/auth/recovery", {
      success: RecoveryWrapResultSchema,
      error: [ForbiddenError, RecoveryWrapNotFoundError, RecoveryRateLimitedError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("recoveryStatus", "/auth/recovery/status", {
      success: RecoveryStatusSchema,
    }).middleware(AuthMiddleware),
  );
