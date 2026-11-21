import {
  KeyFingerprintHexSchema,
  OrgIdSchema,
  OrgRoleSchema,
  TokenScopeSchema,
  UserIdSchema,
} from "@maruhi/core";
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
} from "./errors.package/index.ts";
import { EncPubHex, hexString } from "./hex.ts";
import { strictPayload } from "./strict.ts";

const Redirect = HttpApiSchema.Empty(302);

export const MAX_TOKEN_NAME_LENGTH = 128;

export const TOKEN_NAME_FORBIDDEN_CLASS =
  "\\u0000-\\u001f\\u007f-\\u009f\\u061c\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069";

export const TOKEN_NAME_FORBIDDEN_CHARS = new RegExp(`[${TOKEN_NAME_FORBIDDEN_CLASS}]`, "u");

export const TokenNameSchema = Schema.String.check(
  Schema.isMaxLength(MAX_TOKEN_NAME_LENGTH),
  Schema.isPattern(new RegExp(`^[^${TOKEN_NAME_FORBIDDEN_CLASS}]*$`, "u"), {
    description: "token name without control or bidirectional control characters",
  }),
);

export const DEFAULT_TOKEN_TTL_DAYS = 90;

export const MAX_TOKEN_TTL_DAYS = 365;

export const TokenTtlDays = Schema.Number.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
  Schema.isLessThanOrEqualTo(MAX_TOKEN_TTL_DAYS),
);

export const SignupPolicySchema = Schema.Literals(["open", "invite", "closed"]);
export type SignupPolicy = (typeof SignupPolicySchema)["Type"];

export const SignupCodeSchema = Schema.String.check(Schema.isMaxLength(128));

export const AuthConfigSchema = Schema.Struct({
  githubClientId: Schema.String,
  serverKeyFingerprintHex: Schema.optionalKey(KeyFingerprintHexSchema),
  serverEncPubHex: Schema.optionalKey(EncPubHex),
  signupPolicy: SignupPolicySchema,
});

export const TokenSummarySchema = Schema.Struct({
  id: Schema.String,
  name: Schema.String,
  tokenPrefix: Schema.String,
  scopes: Schema.Array(TokenScopeSchema),
  createdAtMs: Schema.Number,
  lastUsedAtMs: Schema.NullOr(Schema.Number),
  expiresAtMs: Schema.Number,
});

export const TokenListSchema = Schema.Struct({
  tokens: Schema.Array(TokenSummarySchema),
});

export const UserOrgSchema = Schema.Struct({
  orgId: OrgIdSchema,
  slug: Schema.String,
  name: Schema.String,
  role: OrgRoleSchema,
});

export const MeSchema = Schema.Struct({
  userId: UserIdSchema,
  orgs: Schema.Array(UserOrgSchema),
  tokenScopes: Schema.optionalKey(Schema.Array(TokenScopeSchema)),
  tokenExpiresAtMs: Schema.optionalKey(Schema.Number),
  providerLogin: Schema.optionalKey(Schema.String),
});

const RecoveryNonceHex = hexString(12);
const RecoveryCiphertextHex = Schema.String.check(
  Schema.isPattern(/^(?:[0-9a-f]{2}){16,16384}$/, {
    description: "lowercase hex AES-GCM ciphertext (16 bytes .. 16 KiB incl. tag)",
  }),
);

export const RecoveryWrapSchema = Schema.Struct({
  suite: Schema.Literal("maruhi/v1"),
  nonceHex: RecoveryNonceHex,
  ciphertextHex: RecoveryCiphertextHex,
});

export const RecoveryWrapResultSchema = Schema.Struct({
  suite: Schema.Literal("maruhi/v1"),
  nonceHex: RecoveryNonceHex,
  ciphertextHex: RecoveryCiphertextHex,
  updatedAtMs: Schema.Number,
});

export const RecoveryStatusSchema = Schema.Struct({
  registered: Schema.Boolean,
  updatedAtMs: Schema.NullOr(Schema.Number),
});

export const authGroup = HttpApiGroup.make("auth")
  .add(
    HttpApiEndpoint.get("authConfig", "/auth/config", {
      success: AuthConfigSchema,
      error: [SetupIncompleteError],
    }),
  )
  .add(
    HttpApiEndpoint.get("githubStart", "/auth/github/start", {
      query: { signup_code: Schema.optionalKey(SignupCodeSchema) },
      success: Redirect,
      error: [SetupIncompleteError, AuthRateLimitedError],
    }),
  )
  .add(
    HttpApiEndpoint.get("githubCallback", "/auth/github/callback", {
      query: {
        code: Schema.String.check(Schema.isMaxLength(512)),
        state: Schema.String.check(Schema.isMaxLength(512)),
      },
      success: Redirect,
      error: [AuthFlowError, SetupIncompleteError, AuthRateLimitedError],
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
    HttpApiEndpoint.get("listTokens", "/auth/tokens", {
      success: TokenListSchema,
      error: [ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.delete("revokeTokenById", "/auth/tokens/:tokenId", {
      params: { tokenId: Schema.String },
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, TokenNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.put("recoveryPut", "/auth/recovery", {
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
