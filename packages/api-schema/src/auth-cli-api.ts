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
} from "./errors.package/index.ts";
import { hexString } from "./hex.ts";

export const MIN_CLI_POLL_INTERVAL_SECONDS = 5;

export const CliFlowIdSchema = hexString(16);

const CliFlowTokenSchema = Schema.String.check(Schema.isMaxLength(512));

export const CliStartResultSchema = Schema.Struct({
  flowId: CliFlowIdSchema,
  flowToken: Schema.String,
  userCode: Schema.String,
  verificationUrl: Schema.String,
  expiresInSeconds: Schema.Number,
  pollIntervalSeconds: Schema.Number,
});

export const CliPollPendingSchema = Schema.Struct({
  status: Schema.Literal("pending"),
});

export const CliPollApprovedSchema = Schema.Struct({
  status: Schema.Literal("approved"),
  token: Schema.String,
  tokenId: Schema.String,
  userId: UserIdSchema,
  expiresAtMs: Schema.Number,
});

export const CliPollDeniedSchema = Schema.Struct({
  status: Schema.Literal("denied"),
});

export const CliPollResultSchema = Schema.Union([
  CliPollApprovedSchema,
  CliPollPendingSchema,
  CliPollDeniedSchema,
]);

const cliVerifyQuery = {
  flow: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(64))),
  exp: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(32))),
  code: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(64))),
  name: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(512))),
  scopes: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(16384))),
  days: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(8))),
  vsig: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(128))),
};

const CliApproveFormSchema = Schema.Struct({
  flowId: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(64))),
  ticket: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(128))),
  decision: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(16))),
}).pipe(HttpApiSchema.asFormUrlEncoded());

const Redirect = HttpApiSchema.Empty(302);

const HtmlPage = Schema.String.pipe(HttpApiSchema.asText({ contentType: "text/html" }));

export const authCliGroup = HttpApiGroup.make("authCli")
  .add(
    HttpApiEndpoint.post("cliStart", "/auth/cli/start", {
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
      error: [SetupIncompleteError, AuthRateLimitedError],
    }),
  )
  .add(
    HttpApiEndpoint.post("cliApprove", "/auth/cli/approve", {
      payload: CliApproveFormSchema,
      success: HtmlPage,
      error: [SetupIncompleteError, AuthRateLimitedError],
    }),
  )
  .add(
    HttpApiEndpoint.post("cliPoll", "/auth/cli/poll", {
      payload: Schema.Struct({
        flowId: CliFlowIdSchema,
        flowToken: CliFlowTokenSchema,
      }),
      success: CliPollResultSchema,
      error: [
        CliFlowExpiredError,
        CliFlowRejectedError,
        SetupIncompleteError,
        AuthRateLimitedError,
        TokenLimitError,
      ],
    }),
  );
