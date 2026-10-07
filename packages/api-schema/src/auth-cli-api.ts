// HttpApi definition of CLI login (the server-mediated web-flow handoff)
// (AUTH_SPEC §4).
//
// Principle (§4): the CLI does not know the identity provider. This
// group's wire carries no provider-specific fields, and verificationUrl
// is an opaque URL to the CLI. flowToken is a CLI-only bearer credential
// and is never carried on the browser channel (URL, page, redirect)
// (§4-1 (1)).
//
// The browser legs (cliVerify / cliApprove) are browser-navigation /
// form-POST only; the handler returns HTML (script-free — §4-1 (4)) as an
// HttpServerResponse directly. Failure differentiation follows the §4-2
// uniform-refusal discipline: no typed errors are declared (no oracle of
// flow state).
//
// No operation in this group is added to the session-capability allowlist
// (SESSION_ALLOWED_ENDPOINTS in session-capability.ts) — the
// authorization credential is a ticket, not a session (§4-1 (3); all four
// surfaces are classified as unauthenticated surfaces).

import { TokenScopeSchema, UserIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/http-api";

import { TokenNameSchema, TokenTtlDays } from "./auth-api.ts";
import {
  AuthRateLimitedError,
  CliFlowExpiredError,
  CliFlowRejectedError,
  SetupIncompleteError,
  TokenLimitError,
} from "./errors/index.ts";
import { hexString } from "./hex.ts";

/**
 * Lower bound of the polling interval (seconds — AUTH_SPEC §4-1 (5)).
 * The server puts this value on the response's `pollIntervalSeconds`, and
 * the CLI clamps the response value at this bound (so a hostile or
 * misconfigured server's 0 / negative value does not cause a busy spin).
 * The server may reject over-frequent polling with 429.
 */
export const MIN_CLI_POLL_INTERVAL_SECONDS = 5;

/** Public correlator flowId (128-bit random hex — the §4-1 (1) unguessability requirement). */
export const CliFlowIdSchema = hexString(16);

/**
 * CLI-only bearer credential (self-contained signed form — §4-1 (1)).
 * Opaque to the CLI; the format is a server implementation detail.
 * Unauthenticated write surface, so only the size limit is bound on the
 * wire.
 */
const CliFlowTokenSchema = Schema.String.check(Schema.isMaxLength(512));

/**
 * Response of `POST /auth/cli/start` (AUTH_SPEC §4-1 (1)). The server
 * stores nothing at this point (recordless — ruling DH).
 * verificationUrl is covered by a vsig (a domain-separated MAC); knowing
 * the URL grants no polling credential whatsoever.
 */
export const CliStartResultSchema = Schema.Struct({
  flowId: CliFlowIdSchema,
  flowToken: Schema.String,
  userCode: Schema.String,
  verificationUrl: Schema.String,
  expiresInSeconds: Schema.Number,
  pollIntervalSeconds: Schema.Number,
});

/** poll: the browser leg has not arrived (no row = the normal case of a recordless start) or approval is pending. */
export const CliPollPendingSchema = Schema.Struct({
  status: Schema.Literal("pending"),
});

/**
 * poll: the single-issuance result of an approved flow (AUTH_SPEC §4-1
 * (5) — same response shape as the old device exchange). The raw `token`
 * appears on the wire only this once (§6 / §10). `expiresAtMs` is the
 * expiry fixed at issuance (§6 default TTL).
 */
export const CliPollApprovedSchema = Schema.Struct({
  status: Schema.Literal("approved"),
  token: Schema.String,
  tokenId: Schema.String,
  userId: UserIdSchema,
  expiresAtMs: Schema.Number,
});

/** poll: explicitly denied on the approval page (the §4-1 (4) deny action). */
export const CliPollDeniedSchema = Schema.Struct({
  status: Schema.Literal("denied"),
});

/**
 * Response of `POST /auth/cli/poll` (§4-1 (5)). pending / denied are
 * typed states returned to a legitimate flowToken holder (= the flow
 * creator itself) and carry no new information (§4-2). expired is a
 * typed error (CliFlowExpired); a credential mismatch is the uniform
 * refusal (CliFlowRejected).
 */
export const CliPollResultSchema = Schema.Union([
  CliPollApprovedSchema,
  CliPollPendingSchema,
  CliPollDeniedSchema,
]);

/**
 * Query of the browser leg `GET /auth/cli/verify` (§4-1 (3)): the set of
 * vsig-signed parameters carried by verificationUrl. All are declared
 * optionalKey; checking for missing or tampered values is done by the
 * handler, which refuses with a uniform **error page** (HTML) — the
 * schema boundary's JSON 400 is never shown to the browser. The limits
 * are just the unauthenticated-surface size discipline (same rationale
 * as githubCallback's query limits).
 */
const cliVerifyQuery = {
  flow: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(64))),
  exp: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(32))),
  code: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(64))),
  name: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(512))),
  scopes: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(16384))),
  days: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(8))),
  vsig: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(128))),
};

/**
 * Acceptance shape of the approval form `POST /auth/cli/approve` (§4-1
 * (4)): a raw form POST (application/x-www-form-urlencoded) from the
 * script-free approval page. The credential is a single-use, short-lived
 * approval ticket embedded in the page, not a session. Missing or
 * mismatched values are checked by the handler, which refuses with a
 * uniform error page.
 */
const CliApproveFormSchema = Schema.Struct({
  flowId: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(64))),
  ticket: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(128))),
  decision: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(16))),
}).pipe(HttpApiSchema.asFormUrlEncoded());

/** 302 for browser navigation (same declaration as Redirect in auth-api.ts). */
const Redirect = HttpApiSchema.Empty(302);

/** Success declaration for surfaces whose handler returns an HttpServerResponse (HTML) directly. */
const HtmlPage = Schema.String.pipe(HttpApiSchema.asText({ contentType: "text/html" }));

/**
 * CLI login endpoints (AUTH_SPEC §4). All surfaces are unauthenticated
 * (classified in UNAUTHENTICATED_ENDPOINTS in session-capability.ts):
 *
 * - `cliStart`: recordless start (issues the flow credentials only —
 *   ruling DH)
 * - `cliVerify`: stateless vsig verification → redirect into §3 web OAuth
 * - `cliApprove`: the approval page's form POST (credential = single-use
 *   approval ticket)
 * - `cliPoll`: stateless flowToken verification → row fetch →
 *   single-issuance (CAS gate)
 */
export const authCliGroup = HttpApiGroup.make("authCli")
  .add(
    HttpApiEndpoint.post("cliStart", "/auth/cli/start", {
      // The issuance parameters' semantics are §6 (identical to the old
      // device exchange). Unauthenticated surface, so the size limits are
      // bound on the wire (100 scope entries, TTL 1..365)
      payload: Schema.Struct({
        tokenName: Schema.optionalKey(TokenNameSchema),
        scopes: Schema.optionalKey(Schema.Array(TokenScopeSchema).check(Schema.isMaxLength(100))),
        expiresInDays: Schema.optionalKey(TokenTtlDays),
      }),
      success: CliStartResultSchema,
      error: [SetupIncompleteError, AuthRateLimitedError],
    }),
  )
  .add(
    HttpApiEndpoint.get("cliVerify", "/auth/cli/verify", {
      query: cliVerifyQuery,
      success: Redirect,
    }),
  )
  .add(
    HttpApiEndpoint.post("cliApprove", "/auth/cli/approve", {
      payload: CliApproveFormSchema,
      success: HtmlPage,
    }),
  )
  .add(
    HttpApiEndpoint.post("cliPoll", "/auth/cli/poll", {
      payload: Schema.Struct({
        flowId: CliFlowIdSchema,
        flowToken: CliFlowTokenSchema,
      }),
      success: CliPollResultSchema,
      error: [CliFlowExpiredError, CliFlowRejectedError, AuthRateLimitedError, TokenLimitError],
    }),
  );
