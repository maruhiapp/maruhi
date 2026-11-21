import { KeyFingerprintHexSchema, UserIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/http-api";

import { RecoveryWrapSchema, TOKEN_NAME_FORBIDDEN_CLASS } from "./auth-api.ts";
import { AuthMiddleware } from "./auth-middleware.ts";
import {
  ForbiddenError,
  HandoffConflictError,
  HandoffNotFoundError,
  KeyWrapNotFoundError,
  KeyWrapPolicyError,
  KeyWrapRateLimitedError,
} from "./errors.package/index.ts";
import { EncPubHex, hexString, HpkeEncHex, KeyFingerprintHex, Sha256Hex } from "./hex.ts";
import { strictPayload } from "./strict.ts";

export const GuardianModeSchema = Schema.Literals(["any", "all"]);

export const MAX_PASSKEY_WRAPS_PER_USER = 5;
export const MAX_GUARDIAN_GROUPS_PER_USER = 5;
export const MAX_GUARDIAN_SHARES_PER_GROUP = 5;
export const MAX_GUARDIAN_DEVICES_PER_GUARDIAN = 16;
export const MAX_GUARDIAN_SHARE_ROWS_PER_GROUP =
  MAX_GUARDIAN_SHARES_PER_GROUP * MAX_GUARDIAN_DEVICES_PER_GUARDIAN;
export const MAX_HANDOFF_APPROVALS_PER_REQUEST =
  MAX_GUARDIAN_GROUPS_PER_USER * MAX_GUARDIAN_SHARES_PER_GROUP;
export const HANDOFF_REQUEST_TTL_MS = 15 * 60 * 1000;

const LedgerIdSchema = Schema.String.check(
  Schema.isPattern(/^[0-9A-HJKMNP-TV-Z]{26}$/, { description: "ULID" }),
);

const CredentialIdHex = Schema.String.check(
  Schema.isPattern(/^(?:[0-9a-f]{2}){1,1024}$/, {
    description: "lowercase hex credential id (1 .. 1024 bytes)",
  }),
);

const ShareCiphertextHex = hexString(48);

const ShareIndexSchema = Schema.Int.check(
  Schema.isBetween({ minimum: 1, maximum: MAX_GUARDIAN_SHARES_PER_GROUP }),
);

export const PASSKEY_LABEL_PATTERN = new RegExp(`^[^${TOKEN_NAME_FORBIDDEN_CLASS}]{1,64}$`, "u");

export const PasskeyLabelSchema = Schema.String.check(
  Schema.isPattern(PASSKEY_LABEL_PATTERN, {
    description: "passkey label (1 .. 64 chars, no control / bidi characters)",
  }),
);

export const PasskeyWrapRegistrationSchema = Schema.Struct({
  wrapId: LedgerIdSchema,
  wrap: RecoveryWrapSchema,
  credentialIdHex: CredentialIdHex,
  prfSaltHex: hexString(32),
  rpId: Schema.Literal("localhost"),
  label: Schema.optionalKey(PasskeyLabelSchema),
});

export const PasskeyWrapResultSchema = Schema.Struct({
  wrapId: LedgerIdSchema,
  wrap: RecoveryWrapSchema,
  credentialIdHex: CredentialIdHex,
  prfSaltHex: hexString(32),
  rpId: Schema.Literal("localhost"),
  label: Schema.NullOr(PasskeyLabelSchema),
  updatedAtMs: Schema.Number,
});

export const GuardianShareSchema = Schema.Struct({
  shareIndex: Schema.Int.check(
    Schema.isBetween({ minimum: 1, maximum: MAX_GUARDIAN_SHARES_PER_GROUP }),
  ),
  guardianUserId: UserIdSchema,
  guardianEncPubHex: EncPubHex,
  guardianKeyFingerprintHex: KeyFingerprintHexSchema,
  encHex: HpkeEncHex,
  ciphertextHex: ShareCiphertextHex,
});

export const GuardianGroupRegistrationSchema = Schema.Struct({
  groupId: LedgerIdSchema,
  mode: GuardianModeSchema,
  wrap: RecoveryWrapSchema,
  shares: Schema.Array(GuardianShareSchema).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(MAX_GUARDIAN_SHARE_ROWS_PER_GROUP),
  ),
});

export const GuardianGroupResultSchema = Schema.Struct({
  groupId: LedgerIdSchema,
  mode: GuardianModeSchema,
  wrap: RecoveryWrapSchema,
  createdAtMs: Schema.Number,
});

export const KeyWrapStatusSchema = Schema.Struct({
  recoveryCode: Schema.Struct({
    registered: Schema.Boolean,
    updatedAtMs: Schema.NullOr(Schema.Number),
  }),
  passkeys: Schema.Array(
    Schema.Struct({
      wrapId: LedgerIdSchema,
      label: Schema.NullOr(PasskeyLabelSchema),
      credentialIdHex: CredentialIdHex,
      prfSaltHex: hexString(32),
      updatedAtMs: Schema.Number,
    }),
  ),
  guardianGroups: Schema.Array(
    Schema.Struct({
      groupId: LedgerIdSchema,
      mode: GuardianModeSchema,
      createdAtMs: Schema.Number,
      guardians: Schema.Array(
        Schema.Struct({
          shareIndex: Schema.Int,
          guardianUserId: UserIdSchema,
          guardianKeyFingerprintHex: KeyFingerprintHex,
        }),
      ),
    }),
  ),
});

export const WardSummarySchema = Schema.Struct({
  wardUserId: UserIdSchema,
  wardLogin: Schema.NullOr(Schema.String),
  groupId: LedgerIdSchema,
  mode: GuardianModeSchema,
  shareIndex: Schema.Int,
  createdAtMs: Schema.Number,
});

export const GuardianDeviceShareSchema = Schema.Struct({
  guardianKeyFingerprintHex: KeyFingerprintHex,
  guardianEncPubHex: EncPubHex,
  encHex: HpkeEncHex,
  ciphertextHex: ShareCiphertextHex,
});

export const GuardianShareResultSchema = Schema.Struct({
  groupId: LedgerIdSchema,
  wardUserId: UserIdSchema,
  mode: GuardianModeSchema,
  shareIndex: Schema.Int,
  deviceShares: Schema.Array(GuardianDeviceShareSchema),
});

export const HandoffRequestIdSchema = Sha256Hex;

export const HandoffSourceSchema = LedgerIdSchema;

export const HandoffLookupSchema = Schema.Struct({
  wardUserId: UserIdSchema,
  wardLogin: Schema.NullOr(Schema.String),
  expiresAtMs: Schema.Number,
  roles: Schema.Array(
    Schema.Struct({ groupId: LedgerIdSchema, mode: GuardianModeSchema, shareIndex: Schema.Int }),
  ),
});

export const HandoffApprovalSchema = Schema.Struct({
  source: HandoffSourceSchema,
  shareIndex: ShareIndexSchema,
  approverKeyFingerprintHex: KeyFingerprintHexSchema,
  encHex: HpkeEncHex,
  ciphertextHex: ShareCiphertextHex,
});

export const HandoffApprovalResultSchema = Schema.Struct({
  source: HandoffSourceSchema,
  shareIndex: ShareIndexSchema,
  approverUserId: UserIdSchema,
  approverKeyFingerprintHex: KeyFingerprintHex,
  encHex: HpkeEncHex,
  ciphertextHex: ShareCiphertextHex,
  createdAtMs: Schema.Number,
});

export const PasskeyWrapRegisterResultSchema = Schema.Struct({ wrapId: LedgerIdSchema });

export const GuardianGroupCreateResultSchema = Schema.Struct({ groupId: LedgerIdSchema });

export const WardListSchema = Schema.Struct({ wards: Schema.Array(WardSummarySchema) });

export const HandoffCreateResultSchema = Schema.Struct({ expiresAtMs: Schema.Number });

export const HandoffApprovalListSchema = Schema.Struct({
  approvals: Schema.Array(HandoffApprovalResultSchema),
});

export const keyWrapsGroup = HttpApiGroup.make("keyWraps")
  .add(
    HttpApiEndpoint.get("status", "/auth/key-wraps", {
      success: KeyWrapStatusSchema,
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("passkeyRegister", "/auth/key-wraps/passkey", {
      payload: strictPayload(PasskeyWrapRegistrationSchema),
      success: PasskeyWrapRegisterResultSchema,
      error: [ForbiddenError, KeyWrapPolicyError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("passkeyGet", "/auth/key-wraps/passkey/:wrapId", {
      params: { wrapId: LedgerIdSchema },
      success: PasskeyWrapResultSchema,
      error: [ForbiddenError, KeyWrapNotFoundError, KeyWrapRateLimitedError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.delete("passkeyDelete", "/auth/key-wraps/passkey/:wrapId", {
      params: { wrapId: LedgerIdSchema },
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, KeyWrapNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("guardianCreate", "/auth/key-wraps/guardians", {
      payload: strictPayload(GuardianGroupRegistrationSchema),
      success: GuardianGroupCreateResultSchema,
      error: [ForbiddenError, KeyWrapPolicyError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("guardianGet", "/auth/key-wraps/guardians/:groupId", {
      params: { groupId: LedgerIdSchema },
      success: GuardianGroupResultSchema,
      error: [ForbiddenError, KeyWrapNotFoundError, KeyWrapRateLimitedError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.delete("guardianDelete", "/auth/key-wraps/guardians/:groupId", {
      params: { groupId: LedgerIdSchema },
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, KeyWrapNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("wards", "/auth/guardian/wards", {
      success: WardListSchema,
      error: [ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("myShare", "/auth/guardian/shares/:groupId", {
      params: { groupId: LedgerIdSchema },
      success: GuardianShareResultSchema,
      error: [ForbiddenError, KeyWrapNotFoundError, KeyWrapRateLimitedError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("handoffCreate", "/auth/handoff", {
      payload: Schema.Struct({ requestId: HandoffRequestIdSchema }),
      success: HandoffCreateResultSchema,
      error: [ForbiddenError, HandoffConflictError, KeyWrapRateLimitedError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("handoffLookup", "/auth/handoff/:requestId", {
      params: { requestId: HandoffRequestIdSchema },
      success: HandoffLookupSchema,
      error: [ForbiddenError, HandoffNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("handoffApprove", "/auth/handoff/:requestId/approvals", {
      params: { requestId: HandoffRequestIdSchema },
      payload: strictPayload(HandoffApprovalSchema),
      success: HttpApiSchema.NoContent,
      error: [
        ForbiddenError,
        HandoffNotFoundError,
        HandoffConflictError,
        KeyWrapPolicyError,
        KeyWrapRateLimitedError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("handoffApprovals", "/auth/handoff/:requestId/approvals", {
      params: { requestId: HandoffRequestIdSchema },
      success: HandoffApprovalListSchema,
      error: [ForbiddenError, HandoffNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.delete("handoffCancel", "/auth/handoff/:requestId", {
      params: { requestId: HandoffRequestIdSchema },
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, HandoffNotFoundError],
    }).middleware(AuthMiddleware),
  );
