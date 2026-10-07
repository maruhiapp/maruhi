// HttpApi definition of the master-key wrap ledger API (AUTH_SPEC §13-6
// through §13-10 — KL3; the server storage / distribution surface of
// CRYPTO_SPEC §8 classes S [passkey-prf] / G [guardians] / H [handoff]).
// The recovery-code path (§13-1 through §13-5) stays in auth-api.ts.
//
// - Every wrap and segment is opaque ciphertext to the server. KEK
//   material (the PRF output, segment plaintexts, ephemeral private
//   keys) appears in no type
// - Authorization (§13-7): `status` is open to every authenticated
//   principal (sessions allowed — §5's allowlist). Everything else is
//   `*` × admin tokens only (§13-2's key-material condition; session
//   principals are refused)
// - The handoff's ephemeral public key E.pub never touches the wire
//   (CRYPTO_SPEC §8.4 — the code is carried by a human). All the server
//   learns is request_id (a value derived from E.pub)

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
} from "./errors/index.ts";
import { EncPubHex, hexString, HpkeEncHex, KeyFingerprintHex, Sha256Hex } from "./hex.ts";
import { strictPayload } from "./strict.ts";

/** Guardian-group threshold mode (CRYPTO_SPEC §8.3): any = 1-of-n / all = n-of-n. */
export const GuardianModeSchema = Schema.Literals(["any", "all"]);

/** The ledger's acceptance policy (AUTH_SPEC §13-8 — not a consensus rule). */
export const MAX_PASSKEY_WRAPS_PER_USER = 5;
export const MAX_GUARDIAN_GROUPS_PER_USER = 5;
export const MAX_GUARDIAN_SHARES_PER_GROUP = 5;
/**
 * Cap on a segment's device rows / group (AUTH_SPEC §13-6 — 2026-09-19
 * DK): 5 logical segments (guardians) × 16 active devices per guardian
 * (§12-8). The same share_index appears once per guardian device.
 */
export const MAX_GUARDIAN_DEVICES_PER_GUARDIAN = 16;
export const MAX_GUARDIAN_SHARE_ROWS_PER_GROUP =
  MAX_GUARDIAN_SHARES_PER_GROUP * MAX_GUARDIAN_DEVICES_PER_GUARDIAN;
/**
 * The per-request approval cap = the structural ceiling itself (groups
 * × segment cap — AUTH_SPEC §13-8; the old device-path row was removed
 * in 2026-09-19 DK K4). Because the approval row's PK `(request_id,
 * source, share_index)` and the role check (a segment only for one's
 * own (group, index)) prevent rows beyond this value, the cap check is
 * a declaration of acceptance policy and the effective bound is carried
 * by the structure (PR #168 review comment — made a derived value so
 * the two agree).
 */
export const MAX_HANDOFF_APPROVALS_PER_REQUEST =
  MAX_GUARDIAN_GROUPS_PER_USER * MAX_GUARDIAN_SHARES_PER_GROUP;
/** Handoff-request lifetime (§13-8: 15 minutes). */
export const HANDOFF_REQUEST_TTL_MS = 15 * 60 * 1000;

/** ULID-shaped identifier (wrap_id / group_id). */
const LedgerIdSchema = Schema.String.check(
  Schema.isPattern(/^[0-9A-HJKMNP-TV-Z]{26}$/, { description: "ULID" }),
);

/** WebAuthn credential id (variable length; 1..1024 bytes hex). */
const CredentialIdHex = Schema.String.check(
  Schema.isPattern(/^(?:[0-9a-f]{2}){1,1024}$/, {
    description: "lowercase hex credential id (1 .. 1024 bytes)",
  }),
);

/** Ciphertext of an HPKE single-shot Seal over a 32-byte plaintext (a segment / KEK_h) = 32 + 16 tag. */
const ShareCiphertextHex = hexString(48);

/** Segment number (1..n) / the handoff's share_index. */
const ShareIndexSchema = Schema.Int.check(
  Schema.isBetween({ minimum: 1, maximum: MAX_GUARDIAN_SHARES_PER_GROUP }),
);

/**
 * A passkey's display label (§13-9 — contains no control characters or
 * bidi controls; same acceptance discipline as token names; 64 chars or
 * fewer).
 */
/**
 * The accepted form of a passkey label (the CLI's declaring side
 * pre-checks with the same regexp). Sharing the forbidden class with
 * TOKEN_NAME_FORBIDDEN_CLASS keeps §13-9's "same acceptance discipline
 * as token names" from drifting.
 */
export const PASSKEY_LABEL_PATTERN = new RegExp(`^[^${TOKEN_NAME_FORBIDDEN_CLASS}]{1,64}$`, "u");

export const PasskeyLabelSchema = Schema.String.check(
  Schema.isPattern(PASSKEY_LABEL_PATTERN, {
    description: "passkey label (1 .. 64 chars, no control / bidi characters)",
  }),
);

/**
 * Payload of a registration (POST) (§13-9 PasskeyWrapRegistration).
 * `wrapId` is client-assigned (ULID): because the wrap's AAD binds
 * wrap_id (CRYPTO_SPEC §8.1), a server-assigned id would not be known
 * before encryption. A collision is 422 `duplicate-id`.
 */
export const PasskeyWrapRegistrationSchema = Schema.Struct({
  wrapId: LedgerIdSchema,
  wrap: RecoveryWrapSchema,
  credentialIdHex: CredentialIdHex,
  /** Per-registration random PRF salt (CRYPTO_SPEC §8.2 — a public parameter) */
  prfSaltHex: hexString(32),
  rpId: Schema.Literal("localhost"),
  label: Schema.optionalKey(PasskeyLabelSchema),
});

/** The distribution form of a passkey wrap (§13-9 PasskeyWrapResult). */
export const PasskeyWrapResultSchema = Schema.Struct({
  wrapId: LedgerIdSchema,
  wrap: RecoveryWrapSchema,
  credentialIdHex: CredentialIdHex,
  prfSaltHex: hexString(32),
  rpId: Schema.Literal("localhost"),
  label: Schema.NullOr(PasskeyLabelSchema),
  updatedAtMs: Schema.Number,
});

/**
 * One guardian-device's worth of a segment (§13-9 GuardianShare —
 * 2026-09-19 DK: the same logical segment share_index is sealed to each
 * of the guardian's active device keys, so the same shareIndex appears
 * once per device).
 */
export const GuardianShareSchema = Schema.Struct({
  shareIndex: Schema.Int.check(
    Schema.isBetween({ minimum: 1, maximum: MAX_GUARDIAN_SHARES_PER_GROUP }),
  ),
  guardianUserId: UserIdSchema,
  guardianEncPubHex: EncPubHex,
  guardianKeyFingerprintHex: KeyFingerprintHex,
  encHex: HpkeEncHex,
  ciphertextHex: ShareCiphertextHex,
});

/**
 * Payload of group creation (POST) (§13-9 GuardianGroupRegistration).
 * `groupId` is client-assigned (ULID — the AAD / segment info binds
 * group_id; same as passkey).
 */
export const GuardianGroupRegistrationSchema = Schema.Struct({
  groupId: LedgerIdSchema,
  mode: GuardianModeSchema,
  wrap: RecoveryWrapSchema,
  shares: Schema.Array(GuardianShareSchema).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(MAX_GUARDIAN_SHARE_ROWS_PER_GROUP),
  ),
});

/** The blob distribution form of a group (§13-9 GuardianGroupResult). Carries no segments. */
export const GuardianGroupResultSchema = Schema.Struct({
  groupId: LedgerIdSchema,
  mode: GuardianModeSchema,
  wrap: RecoveryWrapSchema,
  createdAtMs: Schema.Number,
});

/** The ledger's status (`GET /auth/key-wraps` — carries no wraps, segments, or secret parameters). */
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
      /**
       * Per-registration prf_salt (CRYPTO_SPEC §8.2's public parameter —
       * §13-7 2026-09-13 revision). The restoring client needs it before
       * the PRF ceremony (integration-options.md supplement 20-6 ②′).
       */
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
          guardianUserId: Schema.String,
          guardianKeyFingerprintHex: KeyFingerprintHex,
        }),
      ),
    }),
  ),
});

/** One row of the wards-I-guard list (§13-7 `GET /auth/guardian/wards`). */
export const WardSummarySchema = Schema.Struct({
  wardUserId: Schema.String,
  /** Display snapshot of linked_identities.provider_login (not an identifier — §2) */
  wardLogin: Schema.NullOr(Schema.String),
  groupId: LedgerIdSchema,
  mode: GuardianModeSchema,
  shareIndex: Schema.Int,
  createdAtMs: Schema.Number,
});

/** A segment row addressed to one of my devices (element of `deviceShares` — 2026-09-19 DK K3). */
export const GuardianDeviceShareSchema = Schema.Struct({
  guardianKeyFingerprintHex: KeyFingerprintHex,
  guardianEncPubHex: EncPubHex,
  encHex: HpkeEncHex,
  ciphertextHex: ShareCiphertextHex,
});

/**
 * The segment addressed to me (§13-7 `GET /auth/guardian/shares/:groupId`).
 * Device axis (2026-09-19 DK K3 — design record dk-design.md §8 K3-10):
 * `deviceShares` holds **all my device rows** (FP ascending). The client
 * picks the row matching its on-hand device-key FP.
 */
export const GuardianShareResultSchema = Schema.Struct({
  groupId: LedgerIdSchema,
  wardUserId: Schema.String,
  mode: GuardianModeSchema,
  shareIndex: Schema.Int,
  deviceShares: Schema.Array(GuardianDeviceShareSchema),
});

/** The handoff's request_id (CRYPTO_SPEC §8.4 — SHA-256 hex). */
export const HandoffRequestIdSchema = Sha256Hex;

/**
 * An approval's source = the guardian group's id (§13-9). The old
 * device-path `"device"` was removed in 2026-09-19 DK (K4) — the
 * Schema refuses it on the wire (400; AUTH_SPEC §13-7).
 */
export const HandoffSourceSchema = LedgerIdSchema;

/** Lookup of a request (for approvers — §13-7). `roles` lists the approval shapes the calling principal can take. */
export const HandoffLookupSchema = Schema.Struct({
  wardUserId: Schema.String,
  wardLogin: Schema.NullOr(Schema.String),
  expiresAtMs: Schema.Number,
  roles: Schema.Array(
    Schema.Struct({ groupId: LedgerIdSchema, mode: GuardianModeSchema, shareIndex: Schema.Int }),
  ),
});

/** Payload of an approval (POST) (§13-9 HandoffApproval — no blob columns; 2026-09-19 DK). */
export const HandoffApprovalSchema = Schema.Struct({
  source: HandoffSourceSchema,
  shareIndex: ShareIndexSchema,
  /**
   * The approver's device-key FP (self-declared; the ward client matches it
   * against the chain-derived FP). Decoding mints the brand: the value lands in
   * the `auth.key_handoff_approved` audit row (AUDIT_SPEC §3.1)
   */
  approverKeyFingerprintHex: KeyFingerprintHexSchema,
  encHex: HpkeEncHex,
  ciphertextHex: ShareCiphertextHex,
});

/** The distribution form of an approval (§13-9 HandoffApprovalResult). */
export const HandoffApprovalResultSchema = Schema.Struct({
  source: HandoffSourceSchema,
  shareIndex: ShareIndexSchema,
  approverUserId: Schema.String,
  approverKeyFingerprintHex: KeyFingerprintHex,
  encHex: HpkeEncHex,
  ciphertextHex: ShareCiphertextHex,
  createdAtMs: Schema.Number,
});

/** Response of registering a passkey wrap (`POST /auth/key-wraps/passkey`): the assigned wrap id. */
export const PasskeyWrapRegisterResultSchema = Schema.Struct({ wrapId: LedgerIdSchema });

/** Response of creating a guardian group (`POST /auth/key-wraps/guardians`): the assigned group id. */
export const GuardianGroupCreateResultSchema = Schema.Struct({ groupId: LedgerIdSchema });

/** Response envelope of the wards-I-guard list (`GET /auth/guardian/wards`). */
export const WardListSchema = Schema.Struct({ wards: Schema.Array(WardSummarySchema) });

/**
 * Response of creating a handoff request (`POST /auth/handoff`): the
 * request's expiry (`HANDOFF_REQUEST_TTL_MS` later). Not shared with
 * the device-add request's `DeviceAddRequestCreateResultSchema` because
 * the expiry means something different (DK K9-4).
 */
export const HandoffCreateResultSchema = Schema.Struct({ expiresAtMs: Schema.Number });

/** Response envelope of the approvals on a handoff request (`GET /auth/handoff/:requestId/approvals`). */
export const HandoffApprovalListSchema = Schema.Struct({
  approvals: Schema.Array(HandoffApprovalResultSchema),
});

/**
 * Master-key wrap ledger endpoints (AUTH_SPEC §13-7). All are token-only
 * (`*` × admin — §13-2) except `status`, which any authenticated principal
 * (session included) may read.
 */
export const keyWrapsGroup = HttpApiGroup.make("keyWraps")
  .add(
    HttpApiEndpoint.get("status", "/auth/key-wraps", {
      success: KeyWrapStatusSchema,
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("passkeyRegister", "/auth/key-wraps/passkey", {
      // strict acceptance (§12-10 (1) — a wrap = registration of key material)
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
      // carries only request_id (the value derived from E.pub) —
      // contains no signed structure, ciphertext, or key material, so it
      // is outside strict scope (STRICT_EXEMPT_PAYLOAD_ENDPOINTS)
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
      // strict acceptance (§12-10 (1) — a re-sealed segment / KEK_h = ciphertext of key material)
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
